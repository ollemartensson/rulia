package io.rulia.jvm;

import java.util.Optional;

public enum RuliaDigestAlgorithm {
    SHA256((byte) 1),
    BLAKE3((byte) 2);

    private final byte id;

    RuliaDigestAlgorithm(byte id) {
        this.id = id;
    }

    byte id() {
        return id;
    }

    static Optional<RuliaDigestAlgorithm> fromId(byte id) {
        for (RuliaDigestAlgorithm algorithm : values()) {
            if (algorithm.id == id) {
                return Optional.of(algorithm);
            }
        }
        return Optional.empty();
    }
}
