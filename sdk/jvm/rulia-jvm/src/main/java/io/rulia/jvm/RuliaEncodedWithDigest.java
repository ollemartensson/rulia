package io.rulia.jvm;

import java.util.Arrays;

public final class RuliaEncodedWithDigest {
    private final byte[] bytes;
    private final byte[] digest;
    private final RuliaDigestAlgorithm algorithm;

    RuliaEncodedWithDigest(byte[] bytes, byte[] digest, RuliaDigestAlgorithm algorithm) {
        this.bytes = Arrays.copyOf(bytes, bytes.length);
        this.digest = Arrays.copyOf(digest, digest.length);
        this.algorithm = algorithm;
    }

    public byte[] bytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    public byte[] digest() {
        return Arrays.copyOf(digest, digest.length);
    }

    public RuliaDigestAlgorithm algorithm() {
        return algorithm;
    }
}
