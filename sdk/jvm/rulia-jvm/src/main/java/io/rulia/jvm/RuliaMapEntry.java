package io.rulia.jvm;

public final class RuliaMapEntry {
    private final RuliaValue key;
    private final RuliaValue value;

    RuliaMapEntry(RuliaValue key, RuliaValue value) {
        this.key = key;
        this.value = value;
    }

    public RuliaValue key() {
        return key;
    }

    public RuliaValue value() {
        return value;
    }
}
