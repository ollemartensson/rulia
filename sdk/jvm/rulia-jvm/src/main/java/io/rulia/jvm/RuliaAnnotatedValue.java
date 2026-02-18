package io.rulia.jvm;

import java.util.Collections;
import java.util.List;

public final class RuliaAnnotatedValue {
    private final List<RuliaMapEntry> metadata;
    private final RuliaValue value;

    RuliaAnnotatedValue(List<RuliaMapEntry> metadata, RuliaValue value) {
        this.metadata = Collections.unmodifiableList(metadata);
        this.value = value;
    }

    public List<RuliaMapEntry> metadata() {
        return metadata;
    }

    public RuliaValue value() {
        return value;
    }
}
