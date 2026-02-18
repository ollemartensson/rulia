package io.rulia.jvm;

public final class RuliaSymbol {
    private final String namespace;
    private final String name;

    RuliaSymbol(String namespace, String name) {
        this.namespace = namespace;
        this.name = name;
    }

    public String namespace() {
        return namespace;
    }

    public String name() {
        return name;
    }

    public String canonical() {
        return namespace == null ? name : namespace + "/" + name;
    }
}
