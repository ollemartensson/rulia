package io.rulia.jvm;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.math.BigInteger;

public final class RuliaValue {
    private final RuliaValueKind kind;
    private final Object value;

    private RuliaValue(RuliaValueKind kind, Object value) {
        this.kind = kind;
        this.value = value;
    }

    static RuliaValue ofNil() {
        return new RuliaValue(RuliaValueKind.NIL, null);
    }

    static RuliaValue ofBoolean(boolean value) {
        return new RuliaValue(RuliaValueKind.BOOL, value);
    }

    static RuliaValue ofInt(long value) {
        return new RuliaValue(RuliaValueKind.INT, value);
    }

    static RuliaValue ofUInt(long value) {
        return new RuliaValue(RuliaValueKind.UINT, value);
    }

    static RuliaValue ofBigInt(BigInteger value) {
        return new RuliaValue(RuliaValueKind.BIGINT, value);
    }

    static RuliaValue ofFloat32(float value) {
        return new RuliaValue(RuliaValueKind.F32, value);
    }

    static RuliaValue ofFloat64(double value) {
        return new RuliaValue(RuliaValueKind.F64, value);
    }

    static RuliaValue ofString(String value) {
        return new RuliaValue(RuliaValueKind.STRING, value);
    }

    static RuliaValue ofBytes(byte[] value) {
        return new RuliaValue(RuliaValueKind.BYTES, Arrays.copyOf(value, value.length));
    }

    static RuliaValue ofKeyword(RuliaKeyword value) {
        return new RuliaValue(RuliaValueKind.KEYWORD, value);
    }

    static RuliaValue ofSymbol(RuliaSymbol value) {
        return new RuliaValue(RuliaValueKind.SYMBOL, value);
    }

    static RuliaValue ofVector(List<RuliaValue> values) {
        return new RuliaValue(RuliaValueKind.VECTOR, Collections.unmodifiableList(values));
    }

    static RuliaValue ofSet(List<RuliaValue> values) {
        return new RuliaValue(RuliaValueKind.SET, Collections.unmodifiableList(values));
    }

    static RuliaValue ofMap(List<RuliaMapEntry> values) {
        return new RuliaValue(RuliaValueKind.MAP, Collections.unmodifiableList(values));
    }

    static RuliaValue ofTagged(RuliaTaggedValue value) {
        return new RuliaValue(RuliaValueKind.TAGGED, value);
    }

    static RuliaValue ofAnnotated(RuliaAnnotatedValue value) {
        return new RuliaValue(RuliaValueKind.ANNOTATED, value);
    }

    static RuliaValue ofRaw(RuliaValueKind kind, String text) {
        return new RuliaValue(kind, text);
    }

    public RuliaValueKind kind() {
        return kind;
    }

    public boolean asBoolean() {
        return (Boolean) requireKind(RuliaValueKind.BOOL);
    }

    public long asInt() {
        return (Long) requireKind(RuliaValueKind.INT);
    }

    public long asUInt() {
        return (Long) requireKind(RuliaValueKind.UINT);
    }

    public BigInteger asBigInt() {
        return (BigInteger) requireKind(RuliaValueKind.BIGINT);
    }

    public float asFloat32() {
        return (Float) requireKind(RuliaValueKind.F32);
    }

    public double asFloat64() {
        return (Double) requireKind(RuliaValueKind.F64);
    }

    public String asString() {
        return (String) requireKind(RuliaValueKind.STRING);
    }

    public byte[] asBytes() {
        byte[] bytes = (byte[]) requireKind(RuliaValueKind.BYTES);
        return Arrays.copyOf(bytes, bytes.length);
    }

    public RuliaKeyword asKeyword() {
        return (RuliaKeyword) requireKind(RuliaValueKind.KEYWORD);
    }

    public RuliaSymbol asSymbol() {
        return (RuliaSymbol) requireKind(RuliaValueKind.SYMBOL);
    }

    @SuppressWarnings("unchecked")
    public List<RuliaValue> asVector() {
        return (List<RuliaValue>) requireKind(RuliaValueKind.VECTOR);
    }

    @SuppressWarnings("unchecked")
    public List<RuliaValue> asSet() {
        return (List<RuliaValue>) requireKind(RuliaValueKind.SET);
    }

    @SuppressWarnings("unchecked")
    public List<RuliaMapEntry> asMap() {
        return (List<RuliaMapEntry>) requireKind(RuliaValueKind.MAP);
    }

    public RuliaTaggedValue asTagged() {
        return (RuliaTaggedValue) requireKind(RuliaValueKind.TAGGED);
    }

    public RuliaAnnotatedValue asAnnotated() {
        return (RuliaAnnotatedValue) requireKind(RuliaValueKind.ANNOTATED);
    }

    public String rawText() {
        if (value instanceof String && kind != RuliaValueKind.STRING) {
            return (String) value;
        }
        throw new IllegalStateException("raw text is only available for raw fallback values");
    }

    private Object requireKind(RuliaValueKind expected) {
        if (kind != expected) {
            throw new IllegalStateException("value kind is " + kind + ", expected " + expected);
        }
        return value;
    }
}
