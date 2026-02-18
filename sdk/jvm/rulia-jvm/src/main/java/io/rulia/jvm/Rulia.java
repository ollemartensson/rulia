/* Copyright (c) 2026 Olle Mårtensson. This Source Code Form is subject to the terms of the Eclipse Public License, v. 2.0. */
package io.rulia.jvm;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

public final class Rulia {
    private static final Object LOAD_LOCK = new Object();
    private static volatile RuliaNative nativeLib;
    private static volatile Path loadedPath;

    private Rulia() {
    }

    public static Path installFromManifest(String manifestUrl, String version) {
        return RuliaInstaller.installFromManifest(manifestUrl, version);
    }

    public static Path installFromManifest(String manifestUrl, String version, Path cacheRoot) {
        return RuliaInstaller.installFromManifest(manifestUrl, version, cacheRoot);
    }

    public static void installAndLoad(String manifestUrl, String version) {
        Path libPath = installFromManifest(manifestUrl, version);
        load(libPath);
    }

    public static void load(Path libraryPath) {
        synchronized (LOAD_LOCK) {
            Path absolute = libraryPath.toAbsolutePath();
            if (nativeLib != null) {
                if (!absolute.equals(loadedPath)) {
                    throw new IllegalStateException("native library already loaded from " + loadedPath);
                }
                return;
            }
            RuliaNative ffi = RuliaNativeLoader.load(absolute);
            int abi = ffi.rulia_ffi_abi_version();
            if (abi != 1) {
                throw new IllegalStateException("unsupported rulia ffi abi version: " + abi);
            }
            nativeLib = ffi;
            loadedPath = absolute;
        }
    }

    public static String formatText(String text) {
        if (text == null) {
            throw new IllegalArgumentException("text is required");
        }
        RuliaNative ffi = requireNative();
        byte[] input = text.getBytes(StandardCharsets.UTF_8);
        Pointer ptr = NativeBuffers.toPointer(input, 0, input.length);
        RuliaNative.RuliaBytes out = new RuliaNative.RuliaBytes(Runtime.getSystemRuntime());
        int status = ffi.rulia_v1_format_text(ptr, input.length, out);
        RuliaStatus ruliaStatus = RuliaStatus.fromCode(status);
        if (ruliaStatus != RuliaStatus.OK) {
            throw new RuliaException(ruliaStatus);
        }
        byte[] bytes = NativeBuffers.takeBytes(ffi, out);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public static boolean formatCheck(String text) {
        if (text == null) {
            throw new IllegalArgumentException("text is required");
        }
        RuliaNative ffi = requireNative();
        byte[] input = text.getBytes(StandardCharsets.UTF_8);
        Pointer ptr = NativeBuffers.toPointer(input, 0, input.length);
        int status = ffi.rulia_v1_format_check(ptr, input.length);
        RuliaStatus ruliaStatus = RuliaStatus.fromCode(status);
        if (ruliaStatus == RuliaStatus.OK) {
            return true;
        }
        if (ruliaStatus == RuliaStatus.FORMAT_NOT_CANONICAL) {
            return false;
        }
        throw new RuliaException(ruliaStatus);
    }

    public static byte[] frameEncode(byte[] payload) {
        if (payload == null) {
            throw new IllegalArgumentException("payload is required");
        }
        RuliaNative ffi = requireNative();
        Pointer ptr = NativeBuffers.toPointer(payload, 0, payload.length);
        RuliaNative.RuliaBytes out = new RuliaNative.RuliaBytes(Runtime.getSystemRuntime());
        int status = ffi.rulia_v1_frame_encode(ptr, payload.length, out);
        RuliaStatus ruliaStatus = RuliaStatus.fromCode(status);
        if (ruliaStatus != RuliaStatus.OK) {
            throw new RuliaException(ruliaStatus);
        }
        return NativeBuffers.takeBytes(ffi, out);
    }

    public static byte[] encode(String text) {
        return withParsedValue(text, (ffi, value) -> encodeValue(ffi, value, false));
    }

    public static byte[] encodeCanonical(String text) {
        return withParsedValue(text, (ffi, value) -> encodeValue(ffi, value, true));
    }

    public static String decodeText(byte[] bytes) {
        return withDecodedValue(bytes, (ffi, value) -> toText(ffi, value));
    }

    public static byte[] canonicalizeBinary(byte[] bytes) {
        return withDecodedValue(bytes, (ffi, value) -> encodeValue(ffi, value, true));
    }

    public static String canonicalizeValueText(String text) {
        return withParsedValue(text, Rulia::toText);
    }

    public static RuliaValue parseTyped(String text) {
        return withParsedValue(text, Rulia::toTypedValue);
    }

    public static RuliaValue decodeTyped(byte[] bytes) {
        return withDecodedValue(bytes, Rulia::toTypedValue);
    }

    public static RuliaEncodedWithDigest encodeWithDigest(String text, RuliaDigestAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm is required");
        }
        return withParsedValue(text, (ffi, value) -> {
            NativeLong len = new NativeLong();
            Pointer digestOut = Memory.allocateDirect(Runtime.getSystemRuntime(), 32);
            Pointer ptr = ffi.rulia_encode_with_digest(value, algorithm.id(), len.pointer(), digestOut);
            if (ptr == null) {
                throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "failed to encode value with digest");
            }
            byte[] bytes = NativeBuffers.takeBytes(ffi, ptr, len.get());
            byte[] digest = new byte[32];
            digestOut.get(0, digest, 0, digest.length);
            return new RuliaEncodedWithDigest(bytes, digest, algorithm);
        });
    }

    public static Optional<RuliaDigestAlgorithm> verifyDigest(byte[] encodedBytes) {
        if (encodedBytes == null) {
            throw new IllegalArgumentException("encodedBytes is required");
        }
        RuliaNative ffi = requireNative();
        Pointer ptr = NativeBuffers.toPointer(encodedBytes, 0, encodedBytes.length);
        return RuliaDigestAlgorithm.fromId(ffi.rulia_verify_digest(ptr, encodedBytes.length));
    }

    public static boolean hasValidDigest(byte[] encodedBytes) {
        return verifyDigest(encodedBytes).isPresent();
    }

    public static FrameDecoder newFrameDecoder() {
        return new FrameDecoder(requireNative());
    }

    private static Pointer parseValue(RuliaNative ffi, String text) {
        if (text == null) {
            throw new IllegalArgumentException("text is required");
        }
        Pointer input = NativeBuffers.toCString(text);
        Pointer value = ffi.rulia_parse(input);
        if (value == null) {
            throw new RuliaException(RuliaStatus.PARSE_ERROR, "failed to parse rulia text");
        }
        return value;
    }

    private static Pointer decodeValue(RuliaNative ffi, byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes is required");
        }
        Pointer ptr = NativeBuffers.toPointer(bytes, 0, bytes.length);
        Pointer value = ffi.rulia_decode(ptr, bytes.length);
        if (value == null) {
            throw new RuliaException(RuliaStatus.DECODE_ERROR, "failed to decode rulia bytes");
        }
        return value;
    }

    private static byte[] encodeValue(RuliaNative ffi, Pointer value, boolean canonical) {
        NativeLong len = new NativeLong();
        Pointer ptr = canonical
            ? ffi.rulia_encode_canonical(value, len.pointer())
            : ffi.rulia_encode(value, len.pointer());
        if (ptr == null) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "failed to encode rulia value");
        }
        return NativeBuffers.takeBytes(ffi, ptr, len.get());
    }

    private static String toText(RuliaNative ffi, Pointer value) {
        Pointer ptr = ffi.rulia_to_string(value);
        if (ptr == null) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "failed to convert value to text");
        }
        return NativeBuffers.takeCString(ffi, ptr);
    }

    private static RuliaValue toTypedValue(RuliaNative ffi, Pointer value) {
        Pointer kindPtr = ffi.rulia_kind(value);
        if (kindPtr == null) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "failed to get value kind");
        }
        RuliaValueKind kind = RuliaValueKind.fromNativeName(NativeBuffers.readCString(kindPtr));
        switch (kind) {
            case NIL:
                return RuliaValue.ofNil();
            case BOOL:
                return RuliaValue.ofBoolean(readBoolean(ffi, value));
            case INT:
                return RuliaValue.ofInt(readInt64(ffi, value));
            case UINT:
                return RuliaValue.ofUInt(readUInt64(ffi, value));
            case BIGINT:
                try {
                    return RuliaValue.ofBigInt(readBigInt(ffi, value));
                } catch (UnsatisfiedLinkError e) {
                    return RuliaValue.ofRaw(kind, toText(ffi, value));
                }
            case F32:
                return RuliaValue.ofFloat32(readFloat32(ffi, value));
            case F64:
                return RuliaValue.ofFloat64(readFloat64(ffi, value));
            case STRING:
                return RuliaValue.ofString(readString(ffi, value));
            case BYTES:
                return RuliaValue.ofBytes(readBytes(ffi, value));
            case KEYWORD:
                return RuliaValue.ofKeyword(readKeyword(ffi, value));
            case SYMBOL:
                return RuliaValue.ofSymbol(readSymbol(ffi, value));
            case VECTOR:
                return RuliaValue.ofVector(readVector(ffi, value));
            case SET:
                return RuliaValue.ofSet(readSet(ffi, value));
            case MAP:
                return RuliaValue.ofMap(readMap(ffi, value));
            case TAGGED:
                return RuliaValue.ofTagged(readTagged(ffi, value));
            case ANNOTATED:
                try {
                    return RuliaValue.ofAnnotated(readAnnotated(ffi, value));
                } catch (UnsatisfiedLinkError e) {
                    return RuliaValue.ofRaw(kind, toText(ffi, value));
                }
            case UNKNOWN:
            default:
                return RuliaValue.ofRaw(kind, toText(ffi, value));
        }
    }

    private static RuliaValue toTypedValueOwned(RuliaNative ffi, Pointer value) {
        if (value == null) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "native traversal returned null value");
        }
        try {
            return toTypedValue(ffi, value);
        } finally {
            ffi.rulia_free(value);
        }
    }

    private static String readString(RuliaNative ffi, Pointer value) {
        Pointer ptr = ffi.rulia_get_string(value);
        if (ptr == null) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not a string");
        }
        return NativeBuffers.takeCString(ffi, ptr);
    }

    private static byte[] readBytes(RuliaNative ffi, Pointer value) {
        NativeLong len = new NativeLong();
        Pointer ptr = ffi.rulia_get_bytes(value, len.pointer());
        if (ptr == null) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not bytes");
        }
        return NativeBuffers.takeBytes(ffi, ptr, len.get());
    }

    private static BigInteger readBigInt(RuliaNative ffi, Pointer value) {
        Pointer ptr = ffi.rulia_get_bigint(value);
        if (ptr == null) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not bigint");
        }
        return new BigInteger(NativeBuffers.takeCString(ffi, ptr));
    }

    private static long readInt64(RuliaNative ffi, Pointer value) {
        Pointer out = Memory.allocateDirect(Runtime.getSystemRuntime(), Long.BYTES);
        if (!ffi.rulia_get_int(value, out)) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not int");
        }
        return out.getLong(0);
    }

    private static long readUInt64(RuliaNative ffi, Pointer value) {
        Pointer out = Memory.allocateDirect(Runtime.getSystemRuntime(), Long.BYTES);
        if (!ffi.rulia_get_uint(value, out)) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not uint");
        }
        return out.getLong(0);
    }

    private static double readFloat64(RuliaNative ffi, Pointer value) {
        Pointer out = Memory.allocateDirect(Runtime.getSystemRuntime(), Double.BYTES);
        if (!ffi.rulia_get_float64(value, out)) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not f64");
        }
        return out.getDouble(0);
    }

    private static float readFloat32(RuliaNative ffi, Pointer value) {
        Pointer out = Memory.allocateDirect(Runtime.getSystemRuntime(), Float.BYTES);
        if (!ffi.rulia_get_float32(value, out)) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not f32");
        }
        return out.getFloat(0);
    }

    private static boolean readBoolean(RuliaNative ffi, Pointer value) {
        Pointer out = Memory.allocateDirect(Runtime.getSystemRuntime(), 1);
        if (!ffi.rulia_get_bool(value, out)) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not bool");
        }
        return out.getByte(0) != 0;
    }

    private static RuliaKeyword readKeyword(RuliaNative ffi, Pointer value) {
        Pointer namePtr = ffi.rulia_keyword_name(value);
        if (namePtr == null) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not keyword");
        }
        String name = NativeBuffers.takeCString(ffi, namePtr);
        String namespace = NativeBuffers.takeNullableCString(ffi, ffi.rulia_keyword_namespace(value));
        return new RuliaKeyword(namespace, name);
    }

    private static RuliaSymbol readSymbol(RuliaNative ffi, Pointer value) {
        Pointer namePtr = ffi.rulia_symbol_name(value);
        if (namePtr == null) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not symbol");
        }
        String name = NativeBuffers.takeCString(ffi, namePtr);
        String namespace = NativeBuffers.takeNullableCString(ffi, ffi.rulia_symbol_namespace(value));
        return new RuliaSymbol(namespace, name);
    }

    private static List<RuliaValue> readVector(RuliaNative ffi, Pointer value) {
        long len = ffi.rulia_vector_len(value);
        if (len < 0) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not vector");
        }
        List<RuliaValue> values = new ArrayList<>();
        for (long index = 0; index < len; index++) {
            values.add(toTypedValueOwned(ffi, ffi.rulia_vector_get(value, index)));
        }
        return values;
    }

    private static List<RuliaValue> readSet(RuliaNative ffi, Pointer value) {
        long len = ffi.rulia_set_len(value);
        if (len < 0) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not set");
        }
        List<RuliaValue> values = new ArrayList<>();
        for (long index = 0; index < len; index++) {
            values.add(toTypedValueOwned(ffi, ffi.rulia_set_get(value, index)));
        }
        return values;
    }

    private static List<RuliaMapEntry> readMap(RuliaNative ffi, Pointer value) {
        long len = ffi.rulia_map_len(value);
        if (len < 0) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "value is not map");
        }
        List<RuliaMapEntry> values = new ArrayList<>();
        for (long index = 0; index < len; index++) {
            NativePointerRef outKey = new NativePointerRef();
            NativePointerRef outValue = new NativePointerRef();
            boolean ok = ffi.rulia_map_entry_at(value, index, outKey.pointer(), outValue.pointer());
            if (!ok) {
                throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "failed to read map entry " + index);
            }
            values.add(new RuliaMapEntry(
                toTypedValueOwned(ffi, outKey.get()),
                toTypedValueOwned(ffi, outValue.get())
            ));
        }
        return values;
    }

    private static RuliaTaggedValue readTagged(RuliaNative ffi, Pointer value) {
        RuliaValue tagValue = toTypedValueOwned(ffi, ffi.rulia_tagged_tag(value));
        if (tagValue.kind() != RuliaValueKind.SYMBOL) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "tagged tag is not a symbol");
        }
        RuliaValue payload = toTypedValueOwned(ffi, ffi.rulia_tagged_value(value));
        return new RuliaTaggedValue(tagValue.asSymbol(), payload);
    }

    private static RuliaAnnotatedValue readAnnotated(RuliaNative ffi, Pointer value) {
        RuliaValue metadataValue = toTypedValueOwned(ffi, ffi.rulia_annotated_metadata(value));
        if (metadataValue.kind() != RuliaValueKind.MAP) {
            throw new RuliaException(RuliaStatus.INTERNAL_ERROR, "annotated metadata is not a map");
        }
        RuliaValue payload = toTypedValueOwned(ffi, ffi.rulia_annotated_inner(value));
        return new RuliaAnnotatedValue(metadataValue.asMap(), payload);
    }

    private static <T> T withParsedValue(String text, ValueOperation<T> operation) {
        RuliaNative ffi = requireNative();
        Pointer value = parseValue(ffi, text);
        try {
            return operation.apply(ffi, value);
        } finally {
            ffi.rulia_free(value);
        }
    }

    private static <T> T withDecodedValue(byte[] bytes, ValueOperation<T> operation) {
        RuliaNative ffi = requireNative();
        Pointer value = decodeValue(ffi, bytes);
        try {
            return operation.apply(ffi, value);
        } finally {
            ffi.rulia_free(value);
        }
    }

    private static RuliaNative requireNative() {
        RuliaNative ffi = nativeLib;
        if (ffi == null) {
            throw new IllegalStateException("native library not loaded");
        }
        return ffi;
    }

    @FunctionalInterface
    private interface ValueOperation<T> {
        T apply(RuliaNative ffi, Pointer value);
    }
}
