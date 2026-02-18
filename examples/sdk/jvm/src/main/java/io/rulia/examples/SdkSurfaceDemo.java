package io.rulia.examples;

import io.rulia.jvm.FrameDecodeResult;
import io.rulia.jvm.FrameDecoder;
import io.rulia.jvm.Rulia;
import io.rulia.jvm.RuliaDigestAlgorithm;
import io.rulia.jvm.RuliaEncodedWithDigest;
import io.rulia.jvm.RuliaMapEntry;
import io.rulia.jvm.RuliaValue;
import io.rulia.jvm.RuliaValueKind;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public final class SdkSurfaceDemo {
    private SdkSurfaceDemo() {
    }

    public static void main(String[] args) {
        ensureRuntimeLoaded();

        String formatted = Rulia.formatText("(b = 2, a = 1)");
        requireCondition(Rulia.formatCheck(formatted), "formatted text should be canonical");

        byte[] canonicalBytes = Rulia.encodeCanonical("(b = 2, a = 1)");
        String decodedText = Rulia.decodeText(canonicalBytes);
        requireCondition(
            Rulia.formatCheck(decodedText),
            "decoded canonical bytes should be canonical text"
        );
        requireCondition(
            Rulia.formatCheck(Rulia.canonicalizeValueText("(b = 2, a = 1)")),
            "canonicalizeValueText should return canonical text"
        );
        requireCondition(
            Arrays.equals(canonicalBytes, Rulia.canonicalizeBinary(canonicalBytes)),
            "binary recanonicalization mismatch"
        );

        RuliaValue typed = Rulia.parseTyped("(user_first_name = \"Ada\", marker = Tagged(\"complex_ns/tag\", \"data\"))");
        requireCondition(typed.kind() == RuliaValueKind.MAP, "typed parse should return map");
        List<RuliaMapEntry> entries = typed.asMap();
        boolean foundFirstName = entries.stream().anyMatch(entry ->
            entry.key().kind() == RuliaValueKind.KEYWORD
                && "user".equals(entry.key().asKeyword().namespace())
                && "first_name".equals(entry.key().asKeyword().name())
                && entry.value().kind() == RuliaValueKind.STRING
                && "Ada".equals(entry.value().asString())
        );
        requireCondition(foundFirstName, "missing typed user/first_name");

        RuliaValue decodedTyped = Rulia.decodeTyped(canonicalBytes);
        requireCondition(decodedTyped.kind() == RuliaValueKind.MAP, "typed decode should return map");

        RuliaEncodedWithDigest digested = Rulia.encodeWithDigest("(a = 1, b = 2)", RuliaDigestAlgorithm.SHA256);
        requireCondition(digested.digest().length == 32, "sha256 digest length mismatch");
        Optional<RuliaDigestAlgorithm> algorithm = Rulia.verifyDigest(digested.bytes());
        requireCondition(algorithm.isPresent(), "digest verification should return algorithm");
        requireCondition(algorithm.get() == RuliaDigestAlgorithm.SHA256, "digest verification mismatch");
        requireCondition(Rulia.hasValidDigest(digested.bytes()), "hasValidDigest expected true");

        byte[] payload = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] frame = Rulia.frameEncode(payload);
        byte[] firstChunk = Arrays.copyOfRange(frame, 0, 2);
        byte[] secondChunk = Arrays.copyOfRange(frame, 2, frame.length);

        try (FrameDecoder decoder = Rulia.newFrameDecoder()) {
            FrameDecodeResult first = decoder.push(firstChunk);
            requireCondition(first.frames().isEmpty(), "first chunk should not produce a frame");
            requireCondition(first.needMore(), "first chunk should require more data");

            FrameDecodeResult second = decoder.push(secondChunk);
            requireCondition(second.frames().size() == 1, "second chunk should produce one frame");
            requireCondition(Arrays.equals(second.frames().get(0), payload), "frame payload mismatch");
        }

        System.out.println("sdk jvm surface demo passed");
    }

    private static void ensureRuntimeLoaded() {
        String manifestUrl = getenv("RULIA_MANIFEST_URL");
        String version = getenvOrDefault("RULIA_VERSION", "0.1.0");
        if (manifestUrl != null && !manifestUrl.isBlank()) {
            Rulia.installAndLoad(manifestUrl, version);
            System.out.println("loaded via manifest: " + manifestUrl);
            return;
        }

        String libPath = getenv("RULIA_LIB_PATH");
        if (libPath == null || libPath.isBlank()) {
            throw new IllegalStateException("set RULIA_MANIFEST_URL (and optionally RULIA_VERSION) or RULIA_LIB_PATH");
        }
        Rulia.load(Path.of(libPath));
        System.out.println("loaded via library path: " + libPath);
    }

    private static String getenv(String name) {
        String value = System.getenv(name);
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        return value.trim();
    }

    private static String getenvOrDefault(String name, String defaultValue) {
        String value = getenv(name);
        if (value == null) {
            return defaultValue;
        }
        return value;
    }

    private static void requireCondition(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
