package io.rulia.jvm;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;

public final class RuliaInstaller {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private RuliaInstaller() {
    }

    public static Path installFromManifest(String manifestUrl, String version) {
        return installFromManifest(manifestUrl, version, defaultCacheRoot());
    }

    static Path installFromManifest(String manifestUrl, String version, Path cacheRoot) {
        if (manifestUrl == null || manifestUrl.isBlank()) {
            throw new IllegalArgumentException("manifestUrl is required");
        }
        if (version == null || version.isBlank()) {
            throw new IllegalArgumentException("version is required");
        }
        Path cacheBase = cacheRoot.toAbsolutePath();
        Manifest manifest = loadManifest(URI.create(manifestUrl));

        if (manifest.version == null || manifest.version.isBlank()) {
            throw new IllegalStateException("manifest missing version");
        }
        if (!manifest.version.equals(version)) {
            throw new IllegalStateException("manifest version mismatch: expected " + version + " got " + manifest.version);
        }
        if (manifest.artifacts == null || manifest.artifacts.isEmpty()) {
            throw new IllegalStateException("manifest missing artifacts");
        }

        String target = Platform.target();
        Artifact selected = null;
        for (Artifact artifact : manifest.artifacts) {
            if (target.equals(artifact.target)) {
                selected = artifact;
                break;
            }
        }
        if (selected == null) {
            throw new IllegalStateException("no artifact for target " + target);
        }
        if (selected.sha256 == null || selected.sha256.isBlank()) {
            throw new IllegalStateException("artifact missing sha256");
        }

        URI manifestUri = URI.create(manifestUrl);
        URI artifactUri = resolveArtifactUrl(manifestUri, selected);
        String expectedSha = selected.sha256.toLowerCase(Locale.ROOT);

        Path versionDir = cacheBase.resolve(version);
        Path targetDir = versionDir.resolve(target);
        Path libPath = targetDir.resolve("lib").resolve(Platform.libraryFilename());

        if (Files.isRegularFile(libPath)) {
            return libPath;
        }
        if (Files.exists(targetDir)) {
            throw new IllegalStateException("target directory exists but library is missing: " + libPath);
        }

        try {
            Files.createDirectories(versionDir);
        } catch (IOException e) {
            throw new IllegalStateException("failed to create cache directory: " + versionDir, e);
        }

        Path tempDir = null;
        Path tempFile = null;
        try {
            tempDir = Files.createTempDirectory(versionDir, target + "-tmp-");
            DownloadResult result = downloadWithSha256(artifactUri);
            tempFile = result.path;
            if (!expectedSha.equals(result.sha256)) {
                throw new IllegalStateException("sha256 mismatch for artifact: expected " + expectedSha + " got " + result.sha256);
            }
            extractTarGz(tempFile, tempDir);
            Path extractedLib = tempDir.resolve("lib").resolve(Platform.libraryFilename());
            if (!Files.isRegularFile(extractedLib)) {
                throw new IllegalStateException("shared library not found under " + extractedLib);
            }
            Files.move(tempDir, targetDir, StandardCopyOption.ATOMIC_MOVE);
            return libPath;
        } catch (AtomicMoveNotSupportedException e) {
            throw new IllegalStateException("atomic move not supported when installing tools", e);
        } catch (IOException e) {
            throw new IllegalStateException("failed to install tools", e);
        } finally {
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException ignored) {
                }
            }
            if (tempDir != null && Files.exists(tempDir)) {
                deleteRecursively(tempDir);
            }
        }
    }

    static Path defaultCacheRoot() {
        String home = System.getProperty("user.home");
        if (home == null || home.isBlank()) {
            throw new IllegalStateException("user.home is not set");
        }
        return Path.of(home, ".rulia", "tools");
    }

    private static Manifest loadManifest(URI manifestUri) {
        String text;
        try {
            text = readText(manifestUri);
        } catch (IOException e) {
            throw new IllegalStateException("failed to read manifest: " + manifestUri, e);
        }
        try {
            return MAPPER.readValue(text, Manifest.class);
        } catch (IOException e) {
            throw new IllegalStateException("failed to parse manifest json", e);
        }
    }

    private static String readText(URI uri) throws IOException {
        if (isFile(uri)) {
            return Files.readString(Path.of(uri), StandardCharsets.UTF_8);
        }
        try (InputStream in = openStream(uri)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static URI resolveArtifactUrl(URI manifestUri, Artifact artifact) {
        String url = artifact.url;
        if (url != null && !url.isBlank()) {
            URI parsed = URI.create(url);
            if (parsed.isAbsolute()) {
                return parsed;
            }
            return resolveRelative(manifestUri, url);
        }
        if (artifact.file == null || artifact.file.isBlank()) {
            throw new IllegalStateException("artifact entry missing url or file field");
        }
        return resolveRelative(manifestUri, artifact.file);
    }

    private static URI resolveRelative(URI manifestUri, String rel) {
        URI base = manifestUri;
        if (!manifestUri.toString().endsWith("/")) {
            base = manifestUri.resolve(".");
        }
        return base.resolve(rel);
    }

    private static DownloadResult downloadWithSha256(URI uri) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("sha-256 not available", e);
        }
        Path tempFile;
        try {
            tempFile = Files.createTempFile("rulia-artifact-", ".tmp");
        } catch (IOException e) {
            throw new IllegalStateException("failed to create temp file", e);
        }
        try (InputStream in = openStream(uri); OutputStream out = Files.newOutputStream(tempFile)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
                out.write(buffer, 0, read);
            }
        } catch (IOException e) {
            throw new IllegalStateException("failed to download artifact: " + uri, e);
        }
        return new DownloadResult(tempFile, toHex(digest.digest()));
    }

    private static InputStream openStream(URI uri) throws IOException {
        if (isFile(uri)) {
            return Files.newInputStream(Path.of(uri));
        }
        String scheme = uri.getScheme();
        if (scheme == null || scheme.isBlank()) {
            throw new IllegalStateException("unsupported manifest scheme: " + uri);
        }
        if (scheme.equalsIgnoreCase("https") || scheme.equalsIgnoreCase("http")) {
            return uri.toURL().openStream();
        }
        throw new IllegalStateException("unsupported manifest scheme: " + uri);
    }

    private static boolean isFile(URI uri) {
        return "file".equalsIgnoreCase(uri.getScheme());
    }

    private static void extractTarGz(Path tarPath, Path destDir) {
        try (InputStream fileIn = Files.newInputStream(tarPath);
             GzipCompressorInputStream gzipIn = new GzipCompressorInputStream(fileIn);
             TarArchiveInputStream tarIn = new TarArchiveInputStream(gzipIn)) {
            TarArchiveEntry entry;
            while ((entry = tarIn.getNextTarEntry()) != null) {
                if (entry.isDirectory()) {
                    Path dir = safeResolve(destDir, entry.getName());
                    Files.createDirectories(dir);
                    continue;
                }
                Path outPath = safeResolve(destDir, entry.getName());
                Path parent = outPath.getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
                try (OutputStream out = Files.newOutputStream(outPath)) {
                    tarIn.transferTo(out);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("failed to extract tar.gz", e);
        }
    }

    private static Path safeResolve(Path destDir, String entryName) throws IOException {
        Path resolved = destDir.resolve(entryName).normalize();
        if (!resolved.startsWith(destDir)) {
            throw new IOException("blocked tar entry outside destination: " + entryName);
        }
        return resolved;
    }

    private static String toHex(byte[] digest) {
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void deleteRecursively(Path path) {
        try {
            Files.walk(path)
                .sorted(Comparator.reverseOrder())
                .forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (IOException ignored) {
                    }
                });
        } catch (IOException ignored) {
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class Manifest {
        public String version;
        public List<Artifact> artifacts;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class Artifact {
        public String target;
        public String file;
        public String url;
        public String sha256;
    }

    private static final class DownloadResult {
        private final Path path;
        private final String sha256;

        private DownloadResult(Path path, String sha256) {
            this.path = path;
            this.sha256 = sha256;
        }
    }
}
