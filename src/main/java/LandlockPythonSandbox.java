import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;

import java.io.File;
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
        long syscall(long number, Object... args);

        int open(String path, int flags);

        int close(int fd);

        int prctl(int option, long arg2, long arg3, long arg4, long arg5);
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

    private static final long FS_ACCESS_ALL =
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
                    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                    LANDLOCK_ACCESS_FS_MAKE_SYM;

    private static final String DIVIDER = "-".repeat(60);

    public static void main(String[] args) throws Throwable {
        if (args.length > 0 && args[0].startsWith("--child-")) {
            // Propagate the Python checks' pass/fail as this JVM's own exit
            // code, so the parent below can report a real PASSED/FAILED per
            // process instead of always seeing 0.
            System.exit(runChildProcess(args[0]));
        }

        System.out.println("=== Landlock Python Sandbox Demo ===");

        // Setup directories, each with a private file for the read/write checks below.
        Path dir1 = Path.of("/tmp/python_proc1");
        Path dir2 = Path.of("/tmp/python_proc2");
        Files.createDirectories(dir1);
        Files.createDirectories(dir2);
        Files.writeString(dir1.resolve("secret.txt"), "secret data belonging to process 1\n");
        Files.writeString(dir2.resolve("secret.txt"), "secret data belonging to process 2\n");

        System.out.println("Spawning two isolated Python sub-processes (P1, P2)...");
        System.out.println(DIVIDER);

        // Launch Process 1 (Allowed /tmp/python_proc1, Denied /tmp/python_proc2)
        Process p1 = new ProcessBuilder("java",
                "-cp", System.getProperty("java.class.path"),
                LandlockPythonSandbox.class.getName(), "--child-1")
                .inheritIO().start();

        // Launch Process 2 (Allowed /tmp/python_proc2, Denied /tmp/python_proc1)
        Process p2 = new ProcessBuilder("java",
                "-cp", System.getProperty("java.class.path"),
                LandlockPythonSandbox.class.getName(), "--child-2")
                .inheritIO().start();

        int exit1 = p1.waitFor();
        int exit2 = p2.waitFor();

        System.out.println(DIVIDER);
        System.out.println("=== Overall result ===");
        System.out.printf("P1: %s%n", exit1 == 0 ? "PASSED" : "FAILED");
        System.out.printf("P2: %s%n", exit2 == 0 ? "PASSED" : "FAILED");
    }

    /** Runs as a re-exec'd child JVM (see main()); returns the embedded Python script's exit code. */
    private static int runChildProcess(String mode) throws Throwable {
        String procTag = "P" + mode.substring("--child-".length());
        String ownDir = mode.equals("--child-1") ? "/tmp/python_proc1" : "/tmp/python_proc2";
        String targetOtherDir = mode.equals("--child-1") ? "/tmp/python_proc2" : "/tmp/python_proc1";

        System.out.printf("[%s] Applying Landlock restrictions...%n", procTag);

        // Required by Landlock before restricting self without CAP_SYS_ADMIN
        // PR_SET_NO_NEW_PRIVS = 38
        int ret = CLib.INSTANCE.prctl(38, 1L, 0L, 0L, 0L);
        if (ret < 0) throw new RuntimeException("prctl(PR_SET_NO_NEW_PRIVS) failed");

        // 1. Create Ruleset
        // struct landlock_ruleset_attr { __u64 handled_access_fs; };
        Memory attr = new Memory(8);
        attr.setLong(0, FS_ACCESS_ALL);

        long rulesetFd = CLib.INSTANCE.syscall(SYS_LANDLOCK_CREATE_RULESET, attr, 8L, 0L);
        if (rulesetFd < 0) throw new RuntimeException("landlock_create_ruleset failed: " + rulesetFd);

        // 2. Allow system dependencies (Python runtime, shared libs, system /dev)
        allowPath((int) rulesetFd, "/usr", FS_ACCESS_ALL);
        allowPath((int) rulesetFd, "/lib", FS_ACCESS_ALL);
        allowPath((int) rulesetFd, "/lib64", FS_ACCESS_ALL);
        allowPath((int) rulesetFd, "/etc", LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);

        // 3. Allow process-specific workspace directory ONLY
        allowPath((int) rulesetFd, ownDir, FS_ACCESS_ALL);

        // 4. Enforce Landlock ruleset on the current process
        long restrictRes = CLib.INSTANCE.syscall(SYS_LANDLOCK_RESTRICT_SELF, rulesetFd, 0L);

        CLib.INSTANCE.close((int) rulesetFd);

        if (restrictRes < 0) throw new RuntimeException("landlock_restrict_self failed");

        System.out.printf("[%s] Landlock enforced. Launching Python execution test...%n", procTag);

        String ownFile = ownDir + "/secret.txt";
        String otherFile = targetOtherDir + "/secret.txt";
        String plantedFile = targetOtherDir + "/planted_by_" + procTag + ".txt";

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
                import os, sys

                TAG = %6$s
                results = []

                def check(label, expect_blocked, action):
                    try:
                        detail = action()
                        outcome = 'OK'
                    except PermissionError as e:
                        detail = str(e)
                        outcome = 'BLOCKED'
                    passed = (outcome == 'BLOCKED') == expect_blocked
                    results.append(passed)
                    status = 'PASSED' if passed else 'FAILED'
                    print(f'[{TAG}] {status:<6} {outcome:<8} {label:<32} {detail}')

                def list_dir(path):
                    return os.listdir(path)

                def read_file(path):
                    with open(path) as f:
                        return f.read().strip()

                def write_file(path, mode='w'):
                    with open(path, mode) as f:
                        f.write('written by python\\n')
                    return 'wrote line'

                check('list own folder', False, lambda: list_dir(%1$s))
                check('read own file', False, lambda: read_file(%2$s))
                check('write own file (append)', False, lambda: write_file(%2$s, 'a'))
                check("list other process's folder", True, lambda: list_dir(%3$s))
                check("read other process's file", True, lambda: read_file(%4$s))
                check("plant file in other's folder", True, lambda: write_file(%5$s))

                passed_count = sum(results)
                print(f'[{TAG}] SUMMARY: {passed_count}/{len(results)} checks passed')
                sys.exit(0 if passed_count == len(results) else 1)
                """.formatted(
                pyLiteral(ownDir), pyLiteral(ownFile), pyLiteral(targetOtherDir), pyLiteral(otherFile), pyLiteral(plantedFile),
                pyLiteral(procTag)
        );

        Process pythonProc = new ProcessBuilder("python3", "-c", pythonScript)
                .inheritIO()
                .start();

        int exitCode = pythonProc.waitFor();
        System.out.printf("[%s] Python exited with code %d (%s)%n",
                procTag, exitCode, exitCode == 0 ? "all checks passed" : "one or more checks FAILED");
        return exitCode;
    }

    /** Renders a path as a single-quoted Python string literal for embedding in the inline script. */
    private static String pyLiteral(String path) {
        return "'" + path.replace("\\", "\\\\").replace("'", "\\'") + "'";
    }

    private static void allowPath(int rulesetFd, String path, long accessFlags) {
        File f = new File(path);
        if (!f.exists()) return;

        // O_PATH = 00100000 (0x20000)
        int fd = CLib.INSTANCE.open(path, 0x20000);
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
