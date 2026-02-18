package io.rulia.jvm;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

final class NativeLong {
    private static final Runtime RUNTIME = Runtime.getSystemRuntime();
    private static final int WORD_BYTES = RUNTIME.addressSize();

    private final Pointer pointer;

    NativeLong() {
        this.pointer = Memory.allocateDirect(RUNTIME, WORD_BYTES);
        set(0);
    }

    Pointer pointer() {
        return pointer;
    }

    long get() {
        if (WORD_BYTES == 8) {
            return pointer.getLong(0);
        }
        return pointer.getInt(0) & 0xffffffffL;
    }

    void set(long value) {
        if (WORD_BYTES == 8) {
            pointer.putLong(0, value);
        } else {
            pointer.putInt(0, (int) value);
        }
    }
}
