package io.rulia.jvm;

public final class RuliaKeyword {
    private final String namespace;
    private final String name;

    RuliaKeyword(String namespace, String name) {
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
        return namespace == null ? ":" + name : ":" + namespace + "/" + name;
    }
}
