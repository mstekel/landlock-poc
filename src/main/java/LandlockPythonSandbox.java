import com.sun.jna.LastErrorException;
import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;

import java.io.File;
import java.util.concurrent.CompletableFuture;
import java.nio.file.Files;
import java.nio.file.Path;

public class LandlockPythonSandbox {

    // Native calls, bound via JNA instead of java.lang.foreign (no preview
    // features / --enable-native-access flags required).
    private interface CLib extends Library {
        CLib INSTANCE = Native.load("c", CLib.class);

        // syscall(sysno, ...): declared with Java varargs so JNA marshals
        // whatever arguments each landlock call needs, matching the C
        // variadic declaration.
        // "throws LastErrorException" makes JNA capture errno right after the
        // call and raise it when set, so failures can report the real errno.
        long syscall(long number, Object... args) throws LastErrorException;

        int open(String path, int flags);

        int close(int fd);

        int prctl(int option, long arg2, long arg3, long arg4, long arg5) throws LastErrorException;

        String strerror(int errnum);
    }

    // Syscall numbers for x86_64
    private static final long SYS_LANDLOCK_CREATE_RULESET = 444;
    private static final long SYS_LANDLOCK_ADD_RULE = 445;
    private static final long SYS_LANDLOCK_RESTRICT_SELF = 446;

    // Landlock Rule Types
    private static final int LANDLOCK_RULE_PATH_BENEATH = 1;

    // Landlock Access Flags (V1 / Linux 5.13)
    private static final long LANDLOCK_ACCESS_FS_EXECUTE = 1L << 0;
    private static final long LANDLOCK_ACCESS_FS_WRITE_FILE = 1L << 1;
    private static final long LANDLOCK_ACCESS_FS_READ_FILE = 1L << 2;
    private static final long LANDLOCK_ACCESS_FS_READ_DIR = 1L << 3;
    private static final long LANDLOCK_ACCESS_FS_REMOVE_DIR = 1L << 4;
    private static final long LANDLOCK_ACCESS_FS_REMOVE_FILE = 1L << 5;
    private static final long LANDLOCK_ACCESS_FS_MAKE_CHAR = 1L << 6;
    private static final long LANDLOCK_ACCESS_FS_MAKE_DIR = 1L << 7;
    private static final long LANDLOCK_ACCESS_FS_MAKE_REG = 1L << 8;
    private static final long LANDLOCK_ACCESS_FS_MAKE_SOCK = 1L << 9;
    private static final long LANDLOCK_ACCESS_FS_MAKE_FIFO = 1L << 10;
    private static final long LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1L << 11;
    private static final long LANDLOCK_ACCESS_FS_MAKE_SYM = 1L << 12;

    // Added by later Landlock ABIs; only requested when the kernel supports them.
    private static final long LANDLOCK_ACCESS_FS_REFER = 1L << 13;    // ABI 2 (5.19)
    private static final long LANDLOCK_ACCESS_FS_TRUNCATE = 1L << 14; // ABI 3 (6.2)

    private static final long LANDLOCK_CREATE_RULESET_VERSION = 1L << 0;

    private static final long FS_ACCESS_V1 =
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
                    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                    LANDLOCK_ACCESS_FS_MAKE_SYM;

    // Read + execute only: enough to run python3 and load libraries, nothing writable.
    private static final long FS_ACCESS_READ_EXEC =
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

    private static final long FS_ACCESS_READ = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

    private static final String PYTHON_HOME = "/opt/pyramid/python";

    private static final String DIVIDER = "-".repeat(60);

    public static void main(String[] args) throws Throwable {
        if (args.length > 0 && args[0].startsWith("--child-")) {
            // Propagate the Python checks' pass/fail as this JVM's own exit
            // code, so the parent below can report a real PASSED/FAILED per
            // process instead of always seeing 0.
            System.exit(runChildProcess(args[0]));
        }

        System.out.println("Landlock Python sandbox demo");
        System.out.println("Each process runs Python restricted to its own folder.");

        // Setup directories, each with a private file for the read/write checks below.
        Path dir1 = Path.of("/tmp/python_proc1");
        Path dir2 = Path.of("/tmp/python_proc2");
        Files.createDirectories(dir1);
        Files.createDirectories(dir2);
        Files.writeString(dir1.resolve("secret.txt"), "secret data belonging to process 1\n");
        Files.writeString(dir2.resolve("secret.txt"), "secret data belonging to process 2\n");

        // Launch Process 1 (Allowed /tmp/python_proc1, Denied /tmp/python_proc2) and
        // Process 2 (the reverse). Output is captured and printed one process at a
        // time so the two don't interleave.
        Process p1 = startChild("--child-1");
        Process p2 = startChild("--child-2");
        CompletableFuture<String> out1 = CompletableFuture.supplyAsync(() -> readAll(p1));
        CompletableFuture<String> out2 = CompletableFuture.supplyAsync(() -> readAll(p2));

        int exit1 = p1.waitFor();
        int exit2 = p2.waitFor();

        System.out.println();
        System.out.println(out1.get());
        System.out.println(out2.get());
        System.out.println(DIVIDER);
        System.out.printf("Result:  P1 %s   P2 %s%n", exit1 == 0 ? "PASSED" : "FAILED", exit2 == 0 ? "PASSED" : "FAILED");
        System.exit(exit1 == 0 && exit2 == 0 ? 0 : 1);
    }

    private static Process startChild(String mode) throws Exception {
        return new ProcessBuilder("java",
                "-cp", System.getProperty("java.class.path"),
                LandlockPythonSandbox.class.getName(), mode)
                .redirectErrorStream(true)
                .start();
    }

    private static String readAll(Process p) {
        try {
            return new String(p.getInputStream().readAllBytes());
        } catch (Exception e) {
            return "(could not read output: " + e + ")";
        }
    }

    /** Runs as a re-exec'd child JVM (see main()); returns the embedded Python script's exit code. */
    private static int runChildProcess(String mode) throws Throwable {
        String procTag = "P" + mode.substring("--child-".length());
        String ownDir = mode.equals("--child-1") ? "/tmp/python_proc1" : "/tmp/python_proc2";
        String targetOtherDir = mode.equals("--child-1") ? "/tmp/python_proc2" : "/tmp/python_proc1";

        // Why the whole child JVM is restricted: Landlock restrictions apply to
        // the calling thread and are inherited across fork/exec, so restricting
        // this JVM before it spawns python3 is what confines the Python script.
        // The restriction is irreversible, hence one re-exec'd JVM per sandbox.

        // Required by Landlock before restricting self without CAP_SYS_ADMIN
        // PR_SET_NO_NEW_PRIVS = 38
        try {
            CLib.INSTANCE.prctl(38, 1L, 0L, 0L, 0L);
        } catch (LastErrorException e) {
            throw sandboxFailure("prctl(PR_SET_NO_NEW_PRIVS)", e);
        }

        // Negotiate the ABI: REFER (ABI 2) and TRUNCATE (ABI 3) are only valid
        // in handled_access_fs on kernels that know them.
        long abi;
        try {
            abi = CLib.INSTANCE.syscall(SYS_LANDLOCK_CREATE_RULESET, 0L, 0L, LANDLOCK_CREATE_RULESET_VERSION);
        } catch (LastErrorException e) {
            throw sandboxFailure("landlock_create_ruleset(VERSION)", e);
        }
        long handled = FS_ACCESS_V1;
        if (abi >= 2) handled |= LANDLOCK_ACCESS_FS_REFER;
        if (abi >= 3) handled |= LANDLOCK_ACCESS_FS_TRUNCATE;

        // 1. Create Ruleset
        // struct landlock_ruleset_attr { __u64 handled_access_fs; };
        Memory attr = new Memory(8);
        attr.setLong(0, handled);

        long rulesetFd;
        try {
            rulesetFd = CLib.INSTANCE.syscall(SYS_LANDLOCK_CREATE_RULESET, attr, 8L, 0L);
        } catch (LastErrorException e) {
            throw sandboxFailure("landlock_create_ruleset", e);
        }

        // 2. Allow system dependencies read-only (Python runtime, shared libs)
        allowPath((int) rulesetFd, "/usr", FS_ACCESS_READ_EXEC);
        allowPath((int) rulesetFd, "/lib", FS_ACCESS_READ_EXEC);
        allowPath((int) rulesetFd, "/lib64", FS_ACCESS_READ_EXEC);
        allowPath((int) rulesetFd, "/etc", FS_ACCESS_READ);
        allowPath((int) rulesetFd, PYTHON_HOME, FS_ACCESS_READ_EXEC);
        // The JVM must still be able to exec its own spawn helper (java.home/lib/jspawnhelper)
        // when the JDK lives outside the system paths above.
        allowPath((int) rulesetFd, System.getProperty("java.home"), FS_ACCESS_READ_EXEC);

        // 3. Allow process-specific workspace directory ONLY (full access, incl. REFER/TRUNCATE if handled)
        allowPath((int) rulesetFd, ownDir, handled);

        // 4. Enforce Landlock ruleset on the current process
        try {
            CLib.INSTANCE.syscall(SYS_LANDLOCK_RESTRICT_SELF, rulesetFd, 0L);
        } catch (LastErrorException e) {
            throw sandboxFailure("landlock_restrict_self", e);
        } finally {
            CLib.INSTANCE.close((int) rulesetFd);
        }

        System.out.println(DIVIDER);
        System.out.printf("%s  sandboxed to %s  (Landlock ABI v%d)%n", procTag, ownDir, abi);
        System.out.println(DIVIDER);

        String ownFile = ownDir + "/secret.txt";
        String otherFile = targetOtherDir + "/secret.txt";
        String plantedFile = targetOtherDir + "/planted_by_" + procTag + ".txt";
        String moveSrc = ownDir + "/move_me.txt";
        String moveDst = targetOtherDir + "/moved_by_" + procTag + ".txt";
        String linkPath = targetOtherDir + "/link_by_" + procTag;

        // Run an inline Python script to test filesystem isolation. The script
        // itself calls no Landlock API and has no idea it's sandboxed -- the
        // restriction was already applied to this JVM process above, and is
        // inherited by python3 across exec. Each check declares what SHOULD
        // happen (own folder -> allowed, other process's folder -> blocked)
        // and prints PASSED/FAILED based on whether the actual outcome
        // matched that expectation, so a BLOCKED result is clearly flagged
        // as correct rather than looking like a failure. Every line is
        // prefixed with this process's tag (P1/P2) so the two processes'
        // interleaved output stays attributable even when they run
        // concurrently and their lines land next to each other.
        String pythonScript = """
                import errno, os, sys

                results = []

                # errnos that mean "Landlock denied it". EXDEV is what a cross-directory
                # rename/link returns when FS_REFER is not granted.
                DENIED = (errno.EACCES, errno.EPERM)

                def check(label, expect_blocked, action, denied=DENIED):
                    note = ''
                    try:
                        detail = action()
                        outcome = 'OK'
                    except OSError as e:  # PermissionError is a subclass
                        detail = str(e)
                        outcome = 'BLOCKED' if e.errno in denied else 'ERROR'
                        note = errno.errorcode.get(e.errno, '')
                    passed = outcome == ('BLOCKED' if expect_blocked else 'OK')
                    results.append(passed)
                    expected = 'blocked' if expect_blocked else 'allowed'
                    if passed:
                        print(f'  [PASS] {expected:<8} {label:<30} {note}')
                    else:
                        print(f'  [FAIL] {expected:<8} {label:<30} got {outcome}: {detail}')

                def list_dir(path):
                    return os.listdir(path)

                def read_file(path):
                    with open(path) as f:
                        return f.read().strip()

                def write_file(path, mode='w'):
                    with open(path, mode) as f:
                        f.write('written by python\\n')
                    return 'wrote line'

                def move_across(src, dst):
                    write_file(src)
                    try:
                        os.rename(src, dst)
                    finally:
                        if os.path.exists(src):
                            os.remove(src)
                    return 'moved'

                check('list own folder', False, lambda: list_dir(%1$s))
                check('read own file', False, lambda: read_file(%2$s))
                check('write own file (append)', False, lambda: write_file(%2$s, 'a'))
                check("list other process's folder", True, lambda: list_dir(%3$s))
                check("read other process's file", True, lambda: read_file(%4$s))
                check("plant file in other's folder", True, lambda: write_file(%5$s))
                check("truncate other's file", True, lambda: os.truncate(%4$s, 0))
                check('move file across boundary', True, lambda: move_across(%7$s, %8$s), DENIED + (errno.EXDEV,))
                check('write under /usr', True, lambda: write_file('/usr/landlock_probe'))
                check("symlink in other's folder", True, lambda: os.symlink(%2$s, %9$s))

                passed_count = sum(results)
                print(f'  -> {passed_count}/{len(results)} checks passed')
                sys.exit(0 if passed_count == len(results) else 1)
                """.formatted(
                pyLiteral(ownDir), pyLiteral(ownFile), pyLiteral(targetOtherDir), pyLiteral(otherFile), pyLiteral(plantedFile),
                pyLiteral(procTag), pyLiteral(moveSrc), pyLiteral(moveDst), pyLiteral(linkPath)
        );

        Process pythonProc = new ProcessBuilder(PYTHON_HOME + "/bin/python3", "-c", pythonScript)
                .inheritIO()
                .start();

        int exitCode = pythonProc.waitFor();
        return exitCode;
    }

    private static RuntimeException sandboxFailure(String call, LastErrorException e) {
        int errno = e.getErrorCode();
        return new RuntimeException("%s failed: errno %d (%s)".formatted(call, errno, CLib.INSTANCE.strerror(errno)));
    }

    /** Renders a path as a single-quoted Python string literal for embedding in the inline script. */
    private static String pyLiteral(String path) {
        return "'" + path.replace("\\", "\\\\").replace("'", "\\'") + "'";
    }

    private static void allowPath(int rulesetFd, String path, long accessFlags) {
        File f = new File(path);
        if (!f.exists()) return;

        // O_PATH 0x200000
        int fd = CLib.INSTANCE.open(path, 0x200000);
        if (fd < 0) return;

        // struct landlock_path_beneath_attr { __u64 allowed_access; __s32 parent_fd; } __attribute__((packed));
        Memory pathBeneath = new Memory(12);
        pathBeneath.setLong(0, accessFlags);
        pathBeneath.setInt(8, fd);

        CLib.INSTANCE.syscall(
                SYS_LANDLOCK_ADD_RULE,
                (long) rulesetFd,
                (long) LANDLOCK_RULE_PATH_BENEATH,
                pathBeneath,
                0L
        );

        CLib.INSTANCE.close(fd);
    }
}
