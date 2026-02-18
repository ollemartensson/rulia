package io.rulia.jvm;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

final class NativeBuffers {
    private static final Runtime RUNTIME = Runtime.getSystemRuntime();

    private NativeBuffers() {
    }

    static Pointer toPointer(byte[] data, int offset, int length) {
        if (length == 0) {
            return null;
        }
        Pointer pointer = Memory.allocateDirect(RUNTIME, length);
        pointer.put(0, data, offset, length);
        return pointer;
    }

    static Pointer toCString(String text) {
        byte[] utf8 = text.getBytes(StandardCharsets.UTF_8);
        Pointer pointer = Memory.allocateDirect(RUNTIME, utf8.length + 1);
        if (utf8.length > 0) {
            pointer.put(0, utf8, 0, utf8.length);
        }
        pointer.putByte(utf8.length, (byte) 0);
        return pointer;
    }

    static byte[] takeBytes(RuliaNative ffi, Pointer ptr, long len) {
        if (ptr == null) {
            return new byte[0];
        }
        if (len <= 0) {
            ffi.rulia_bytes_free(ptr, len);
            return new byte[0];
        }
        if (len > Integer.MAX_VALUE) {
            throw new IllegalStateException("native buffer too large: " + len);
        }
        byte[] out = new byte[(int) len];
        ptr.get(0, out, 0, out.length);
        ffi.rulia_bytes_free(ptr, len);
        return out;
    }

    static String takeCString(RuliaNative ffi, Pointer ptr) {
        if (ptr == null) {
            return "";
        }
        String text = readCString(ptr);
        ffi.rulia_string_free(ptr);
        return text;
    }

    static String takeNullableCString(RuliaNative ffi, Pointer ptr) {
        if (ptr == null) {
            return null;
        }
        String text = readCString(ptr);
        ffi.rulia_string_free(ptr);
        return text;
    }

    static String readCString(Pointer ptr) {
        if (ptr == null) {
            return "";
        }
        int len = 0;
        while (ptr.getByte(len) != 0) {
            len++;
        }
        byte[] bytes = new byte[len];
        if (len > 0) {
            ptr.get(0, bytes, 0, len);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    static byte[] copyBytes(RuliaNative.RuliaBytes bytes) {
        long len = bytes.len.get();
        if (len == 0 || bytes.ptr.get() == null) {
            return new byte[0];
        }
        if (len > Integer.MAX_VALUE) {
            throw new IllegalStateException("native buffer too large: " + len);
        }
        byte[] out = new byte[(int) len];
        bytes.ptr.get().get(0, out, 0, out.length);
        return out;
    }

    static byte[] takeBytes(RuliaNative ffi, RuliaNative.RuliaBytes bytes) {
        byte[] out = copyBytes(bytes);
        if (bytes.ptr.get() != null && bytes.len.get() > 0) {
            ffi.rulia_v1_bytes_free(bytes.ptr.get(), bytes.len.get());
        }
        return out;
    }

    static byte[] slice(byte[] input, int offset, int length) {
        if (length == 0) {
            return new byte[0];
        }
        return Arrays.copyOfRange(input, offset, offset + length);
    }
}
