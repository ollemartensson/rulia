package io.rulia.jvm;

public final class RuliaTaggedValue {
    private final RuliaSymbol tag;
    private final RuliaValue value;

    RuliaTaggedValue(RuliaSymbol tag, RuliaValue value) {
        this.tag = tag;
        this.value = value;
    }

    public RuliaSymbol tag() {
        return tag;
    }

    public RuliaValue value() {
        return value;
    }
}
