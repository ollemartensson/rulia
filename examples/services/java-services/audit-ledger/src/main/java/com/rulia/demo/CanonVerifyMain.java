package com.rulia.demo;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

public final class CanonVerifyMain {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CanonVerifyMain() {
    }

    public static void main(String[] args) throws Exception {
        Path vectorsDir = Path.of("..", "..", "..", "contracts", "canon_vectors").normalize();
        List<Path> jsonFiles;
        try (var stream = Files.list(vectorsDir)) {
            jsonFiles = stream
                    .filter(path -> path.getFileName().toString().endsWith(".json"))
                    .sorted()
                    .collect(Collectors.toList());
        }

        if (jsonFiles.isEmpty()) {
            throw new IllegalStateException("no vector files found in " + vectorsDir.toAbsolutePath());
        }

        int verified = 0;
        for (Path jsonPath : jsonFiles) {
            String fileName = jsonPath.getFileName().toString();
            String stem = fileName.substring(0, fileName.length() - ".json".length());

            Object parsed = MAPPER.readValue(Files.readAllBytes(jsonPath), Object.class);
            byte[] actualBytes = CanonJson.canonJson(parsed);
            String actualSha = CanonJson.sha256Hex(actualBytes);

            byte[] expectedBytes = readExpectedHex(vectorsDir.resolve(stem + ".canon.hex"));
            String expectedSha = readExpectedSha(vectorsDir.resolve(stem + ".sha256"));

            if (!Arrays.equals(expectedBytes, actualBytes)) {
                failBytes(stem, expectedBytes, actualBytes);
            }
            if (!expectedSha.equals(actualSha)) {
                throw new IllegalStateException(
                        "[FAIL] " + stem + ": sha256 mismatch\n"
                                + "  expected_sha=" + expectedSha + "\n"
                                + "  actual_sha=" + actualSha + "\n"
                                + "  canonical_json=" + new String(actualBytes, StandardCharsets.UTF_8)
                );
            }

            verified++;
            System.out.println("[OK] " + stem + " bytes+sha256 match");
        }

        System.out.println("canonical verification passed: " + verified + " vector(s)");
    }

    private static byte[] readExpectedHex(Path hexPath) throws IOException {
        String hex = Files.readString(hexPath, StandardCharsets.UTF_8).trim().toLowerCase(Locale.ROOT);
        return HexFormat.of().parseHex(hex);
    }

    private static String readExpectedSha(Path shaPath) throws IOException {
        return Files.readString(shaPath, StandardCharsets.UTF_8).trim().toLowerCase(Locale.ROOT);
    }

    private static int firstDiffIndex(byte[] expected, byte[] actual) {
        int n = Math.min(expected.length, actual.length);
        for (int i = 0; i < n; i++) {
            if (expected[i] != actual[i]) {
                return i;
            }
        }
        return expected.length == actual.length ? -1 : n;
    }

    private static String byteAt(byte[] bytes, int index) {
        if (index < 0 || index >= bytes.length) {
            return "<eof>";
        }
        return String.format("%02x", bytes[index]);
    }

    private static void failBytes(String stem, byte[] expected, byte[] actual) {
        int diff = firstDiffIndex(expected, actual);
        throw new IllegalStateException(
                "[FAIL] " + stem + ": canonical bytes mismatch\n"
                        + "  expected_len=" + expected.length + " actual_len=" + actual.length + "\n"
                        + "  first_diff_byte_index=" + diff + " (0-based)\n"
                        + "  expected_byte=" + byteAt(expected, diff) + " actual_byte=" + byteAt(actual, diff) + "\n"
                        + "  expected_json=" + new String(expected, StandardCharsets.UTF_8) + "\n"
                        + "  actual_json=" + new String(actual, StandardCharsets.UTF_8)
        );
    }
}
