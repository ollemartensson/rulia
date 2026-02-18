package io.rulia.jvm;

import java.nio.file.Files;
import java.nio.file.Path;

import jnr.ffi.LibraryLoader;

final class RuliaNativeLoader {
    private RuliaNativeLoader() {
    }

    static RuliaNative load(Path libraryPath) {
        Path absolute = libraryPath.toAbsolutePath();
        if (!Files.isRegularFile(absolute)) {
            throw new IllegalStateException("native library not found: " + absolute);
        }
        System.load(absolute.toString());
        return LibraryLoader.create(RuliaNative.class).load(absolute.toString());
    }
}
