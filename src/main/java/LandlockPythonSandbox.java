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

    public static void main(String[] args) throws Throwable {
        if (args.length > 0 && args[0].startsWith("--child-")) {
            runChildProcess(args[0]);
            return;
        }

        // Setup directories
        Path dir1 = Path.of("/tmp/python_proc1");
        Path dir2 = Path.of("/tmp/python_proc2");
        Files.createDirectories(dir1);
        Files.createDirectories(dir2);

        System.out.println("Spawning isolated Python sub-processes...");

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

        p1.waitFor();
        p2.waitFor();
    }

    private static void runChildProcess(String mode) throws Throwable {
        String ownDir = mode.equals("--child-1") ? "/tmp/python_proc1" : "/tmp/python_proc2";
        String targetOtherDir = mode.equals("--child-1") ? "/tmp/python_proc2" : "/tmp/python_proc1";

        System.out.printf("[%s] Applying Landlock restrictions...%n", mode);

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

        System.out.printf("[%s] Landlock enforced successfully. Launching Python execution test...%n", mode);

        // Run Python inline script to test filesystem isolation
        String pythonScript = String.format(
                "import os\n" +
                        "print('[Python] Successfully reading own folder contents:', os.listdir('%s'))\n" +
                        "try:\n" +
                        "    print(os.listdir('%s'))\n" +
                        "except PermissionError as e:\n" +
                        "    print('[Python] SUCCESS: Access to other process folder blocked:', e)\n",
                ownDir, targetOtherDir
        );

        Process pythonProc = new ProcessBuilder("python3", "-c", pythonScript)
                .inheritIO()
                .start();

        pythonProc.waitFor();
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
