package io.rulia.jvm;

final class Platform {
    private Platform() {
    }

    static String target() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();

        if (os.contains("linux") && isX86_64(arch)) {
            return "x86_64-unknown-linux-gnu";
        }
        if ((os.contains("mac") || os.contains("darwin")) && isArm64(arch)) {
            return "aarch64-apple-darwin";
        }
        if ((os.contains("mac") || os.contains("darwin")) && isX86_64(arch)) {
            return "x86_64-apple-darwin";
        }
        if (os.contains("windows") && isX86_64(arch)) {
            return "x86_64-pc-windows-msvc";
        }
        throw new IllegalStateException("unsupported platform: " + os + " / " + arch);
    }

    static String libraryFilename() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("windows")) {
            return "rulia.dll";
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return "librulia.dylib";
        }
        return "librulia.so";
    }

    static boolean isLinuxX64() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        return os.contains("linux") && isX86_64(arch);
    }

    private static boolean isX86_64(String arch) {
        return arch.equals("x86_64") || arch.equals("amd64");
    }

    private static boolean isArm64(String arch) {
        return arch.equals("aarch64") || arch.equals("arm64");
    }
}
