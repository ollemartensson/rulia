package io.rulia.jvm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RuliaJvmTest {

    private static final String FIXTURE_VERSION = "0.1.0";

    private Path libPath;

    @BeforeAll
    void setup() throws Exception {
        Assumptions.assumeTrue(
            Platform.isLinuxX64(),
            "fixture is linux x86_64 only"
        );
        String manifestUrl = resolveManifestUrl();
        Path cacheRoot = Files.createTempDirectory("rulia-tools-cache-");
        libPath = RuliaInstaller.installFromManifest(
            manifestUrl,
            FIXTURE_VERSION,
            cacheRoot
        );
        Rulia.load(libPath);
    }

    @Test
    void installFromLocalManifestWorks() throws Exception {
        assertNotNull(libPath);
        assertTrue(Files.isRegularFile(libPath));
    }

    @Test
    void formatRoundtrip() {
        String input = "(b = 2, a = import \"cfg.rjl\", id = @new(:uuid))";
        String formatted = Rulia.formatText(input);
        assertTrue(formatted.contains("import \"cfg.rjl\""));
        assertTrue(formatted.contains("@new(:uuid)"));
        assertTrue(Rulia.formatCheck(formatted));
    }

    @Test
    void framingRoundtrip() {
        byte[] payload = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] frame = Rulia.frameEncode(payload);
        byte[] chunk1 = Arrays.copyOfRange(frame, 0, 2);
        byte[] chunk2 = Arrays.copyOfRange(frame, 2, frame.length);

        try (FrameDecoder decoder = Rulia.newFrameDecoder()) {
            FrameDecodeResult first = decoder.push(chunk1);
            assertTrue(first.needMore());
            assertEquals(0, first.frames().size());
            assertTrue(first.consumed() >= 0);

            FrameDecodeResult second = decoder.push(chunk2);
            assertFalse(second.needMore());
            assertEquals(1, second.frames().size());
            assertArrayEquals(payload, second.frames().get(0));
        }
    }

    @Test
    void invalidSyntax() {
        RuliaException ex = assertThrows(RuliaException.class, () ->
            Rulia.formatText("(a = 1")
        );
        assertEquals(RuliaStatus.FORMAT_INVALID_SYNTAX, ex.status());
    }

    @Test
    void binaryCanonicalRoundtrip() {
        String input = "(b = 2, a = 1, cfg = import \"cfg.rjl\", id = @new(:uuid))";
        byte[] canonical = Rulia.encodeCanonical(input);
        assertTrue(canonical.length > 0);

        String decoded = Rulia.decodeText(canonical);
        assertTrue(decoded.contains("cfg"));

        byte[] recanonical = Rulia.canonicalizeBinary(canonical);
        assertArrayEquals(canonical, recanonical);
    }

    @Test
    void digestRoundtrip() {
        String input = "(a = 1, b = 2)";
        RuliaEncodedWithDigest encoded = Rulia.encodeWithDigest(input, RuliaDigestAlgorithm.SHA256);
        assertEquals(32, encoded.digest().length);
        assertTrue(encoded.bytes().length > 0);

        Optional<RuliaDigestAlgorithm> algorithm = Rulia.verifyDigest(encoded.bytes());
        assertTrue(algorithm.isPresent());
        assertEquals(RuliaDigestAlgorithm.SHA256, algorithm.get());
        assertTrue(Rulia.hasValidDigest(encoded.bytes()));
    }

    @Test
    void keywordAndTagSyntaxCoverage() {
        String[] samples = new String[] {
            ":status",
            "'status",
            "@?entity",
            "_",
            "Keyword(\"my_app/config\")",
            "Symbol(\"special/value\")",
            "Tagged(\"complex_ns/tag\", \"data\")",
            "Point([1, 2])",
            "Set([1, 2, 3])",
            "Ref(:email, \"alice@example.com\")",
            "UUID(\"550e8400-e29b-41d4-a716-446655440000\")",
            "ULID(\"01ARZ3NDEKTSV4RRFFQ69G5FAV\")",
            "Instant(\"2025-01-01T00:00:00Z\")",
            "Generator(:uuid)",
            "@meta(author = \"admin\", :version = \"1.0\", \"x-id\" = \"abc\") User(id = 1)",
            "\"Status doc\" :status",
            "@ns user begin (id = 101, name = \"Ada\") end",
            "let x = 1 x",
            "let [a, b] = [1, 2] [a, b]",
            "let name = \"Ada\" \"Hello $name\"",
            "let f = fn(x) => x f(1)",
            "(user_first_name = \"Ada\", :ce_specversion = \"1.0\", k = Keyword(\"my_app/config\"))"
        };

        for (String sample : samples) {
            String canonicalText = Rulia.canonicalizeValueText(sample);
            assertTrue(Rulia.formatCheck(canonicalText), "expected canonical text for sample: " + sample);
            byte[] canonicalBytes = Rulia.encodeCanonical(sample);
            String decoded = Rulia.decodeText(canonicalBytes);
            assertEquals(canonicalText, decoded, "binary/text canonical mismatch for sample: " + sample);
        }

        String keywordCanonical = Rulia.canonicalizeValueText("Keyword(\"my_app/config\")");
        assertTrue(keywordCanonical.contains("Keyword(\"my_app/config\")"));

        String taggedCanonical = Rulia.canonicalizeValueText("Tagged(\"complex_ns/tag\", \"data\")");
        assertTrue(taggedCanonical.contains("Tagged(\"complex_ns/tag\""));
    }

    @Test
    void typedBigintAndAnnotatedTraversal() {
        Assumptions.assumeTrue(
            hasTypedBigintAndAnnotatedSupport(),
            "fixture library does not expose bigint/annotated typed traversal symbols"
        );

        RuliaValue typed = Rulia.parseTyped(
            "@meta(author = \"ops\", :doc = \"large id\") 123456789012345678901234567890N"
        );
        assertEquals(RuliaValueKind.ANNOTATED, typed.kind());
        RuliaAnnotatedValue annotated = typed.asAnnotated();
        assertEquals(RuliaValueKind.BIGINT, annotated.value().kind());
        assertEquals(
            new BigInteger("123456789012345678901234567890"),
            annotated.value().asBigInt()
        );

        boolean foundAuthor = false;
        boolean foundDoc = false;
        for (RuliaMapEntry entry : annotated.metadata()) {
            if (entry.key().kind() == RuliaValueKind.KEYWORD) {
                String key = entry.key().asKeyword().canonical();
                if (":author".equals(key)) {
                    assertEquals("ops", entry.value().asString());
                    foundAuthor = true;
                }
                if (":doc".equals(key)) {
                    assertEquals("large id", entry.value().asString());
                    foundDoc = true;
                }
            }
        }
        assertTrue(foundAuthor, "missing :author metadata");
        assertTrue(foundDoc, "missing :doc metadata");
    }

    private boolean hasTypedBigintAndAnnotatedSupport() {
        try {
            RuliaValue bigint = Rulia.parseTyped("12345678901234567890N");
            if (bigint.kind() != RuliaValueKind.BIGINT) {
                return false;
            }
            RuliaValue annotated = Rulia.parseTyped("@meta(:doc = \"x\") 1");
            return annotated.kind() == RuliaValueKind.ANNOTATED;
        } catch (RuntimeException | UnsatisfiedLinkError ex) {
            return false;
        }
    }

    @Test
    void typedKeywordTagMapAndVectorTraversal() {
        String input = "(user_first_name = \"Ada\", tags = [:alpha, :beta], marker = Tagged(\"complex_ns/tag\", \"data\"))";
        RuliaValue root = Rulia.parseTyped(input);
        assertEquals(RuliaValueKind.MAP, root.kind());

        List<RuliaMapEntry> entries = root.asMap();
        assertEquals(3, entries.size());

        RuliaMapEntry first = entries.get(0);
        assertEquals(RuliaValueKind.KEYWORD, first.key().kind());
        RuliaKeyword firstKey = first.key().asKeyword();
        assertEquals("user", firstKey.namespace());
        assertEquals("first_name", firstKey.name());
        assertEquals(RuliaValueKind.STRING, first.value().kind());
        assertEquals("Ada", first.value().asString());

        RuliaMapEntry second = entries.get(1);
        assertEquals(RuliaValueKind.KEYWORD, second.key().kind());
        assertEquals("tags", second.key().asKeyword().name());
        assertEquals(RuliaValueKind.VECTOR, second.value().kind());
        List<RuliaValue> tags = second.value().asVector();
        assertEquals(2, tags.size());
        assertEquals(":alpha", tags.get(0).asKeyword().canonical());
        assertEquals(":beta", tags.get(1).asKeyword().canonical());

        RuliaMapEntry third = entries.get(2);
        assertEquals(RuliaValueKind.TAGGED, third.value().kind());
        RuliaTaggedValue tagged = third.value().asTagged();
        assertEquals("complex_ns", tagged.tag().namespace());
        assertEquals("tag", tagged.tag().name());
        assertEquals(RuliaValueKind.STRING, tagged.value().kind());
        assertEquals("data", tagged.value().asString());
    }

    private String fixtureManifestUrl() throws Exception {
        URL url = getClass()
            .getClassLoader()
            .getResource("fixtures/manifest.json");
        assertNotNull(url, "fixture manifest missing");
        URI uri = url.toURI();
        assertEquals(
            "file",
            uri.getScheme(),
            "fixture manifest must be file://"
        );
        return uri.toString();
    }

    private String resolveManifestUrl() throws Exception {
        Path distManifest = findDistManifest(FIXTURE_VERSION);
        if (distManifest != null) {
            System.out.println("using dist manifest: " + distManifest);
            return distManifest.toUri().toString();
        }
        System.out.println(
            "dist manifest not found; falling back to fixture manifest"
        );
        return fixtureManifestUrl();
    }

    private Path findDistManifest(String version) {
        Path current = Path.of("").toAbsolutePath();
        for (int i = 0; i < 6; i++) {
            Path candidate = current
                .resolve("dist")
                .resolve("releases")
                .resolve(version)
                .resolve("manifest.json");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
            Path parent = current.getParent();
            if (parent == null) {
                break;
            }
            current = parent;
        }
        return null;
    }
}
