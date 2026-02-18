package io.rulia.jvm;

public enum RuliaValueKind {
    NIL("nil"),
    BOOL("bool"),
    INT("int"),
    UINT("uint"),
    BIGINT("bigint"),
    F32("f32"),
    F64("f64"),
    STRING("string"),
    BYTES("bytes"),
    SYMBOL("symbol"),
    KEYWORD("keyword"),
    VECTOR("vector"),
    SET("set"),
    MAP("map"),
    TAGGED("tagged"),
    ANNOTATED("annotated"),
    UNKNOWN("unknown");

    private final String nativeName;

    RuliaValueKind(String nativeName) {
        this.nativeName = nativeName;
    }

    static RuliaValueKind fromNativeName(String nativeName) {
        for (RuliaValueKind kind : values()) {
            if (kind.nativeName.equals(nativeName)) {
                return kind;
            }
        }
        return UNKNOWN;
    }
}
