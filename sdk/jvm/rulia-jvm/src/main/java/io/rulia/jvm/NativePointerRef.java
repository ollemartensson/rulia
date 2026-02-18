package io.rulia.jvm;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

final class NativePointerRef {
    private static final Runtime RUNTIME = Runtime.getSystemRuntime();
    private static final int WORD_BYTES = RUNTIME.addressSize();

    private final Pointer pointer;

    NativePointerRef() {
        this.pointer = Memory.allocateDirect(RUNTIME, WORD_BYTES);
        clear();
    }

    Pointer pointer() {
        return pointer;
    }

    Pointer get() {
        long address = WORD_BYTES == 8
            ? pointer.getLong(0)
            : pointer.getInt(0) & 0xffffffffL;
        if (address == 0L) {
            return null;
        }
        return Pointer.wrap(RUNTIME, address);
    }

    void clear() {
        if (WORD_BYTES == 8) {
            pointer.putLong(0, 0L);
        } else {
            pointer.putInt(0, 0);
        }
    }
}
