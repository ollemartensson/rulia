package com.rulia.demo;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

public final class AuditLedgerServer {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final List<Map<String, Object>> RECEIPTS = new ArrayList<>();
    private static final List<Map<String, Object>> CHAIN_EVENTS = new ArrayList<>();
    private static final String GENESIS_PREV_HASH = "0".repeat(64);
    private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");
    private static final String LEDGER_FILE_NAME = "ledger_chain.jsonl";

    private AuditLedgerServer() {
    }

    public static void main(String[] args) throws IOException {
        loadChainFromDisk();
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/ledger/append", new AppendHandler());
        server.createContext("/ledger/entries", new EntriesHandler());
        server.createContext("/ledger/chain", new ChainHandler());
        server.createContext("/ledger/health", exchange -> writeJson(exchange, 200, Map.of("status", "ok")));
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("audit-ledger listening on :" + port);
    }

    private static final class AppendHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                writeJson(exchange, 405, Map.of("error", "method not allowed"));
                return;
            }

            Map<String, Object> request = readJsonMap(exchange);
            Map<String, Object> canonicalEvent = canonicalEventFromRequest(request);
            String requestId = asString(request.getOrDefault("request_id", "ledger-" + CanonJson.sha256Hex(CanonJson.canonJson(canonicalEvent)).substring(0, 16)));
            if (requestId.isBlank()) {
                requestId = "ledger-" + CanonJson.sha256Hex(CanonJson.canonJson(canonicalEvent)).substring(0, 16);
            }

            long sequence;
            String prevHash;
            String eventHash;
            Map<String, Object> chainEvent = new LinkedHashMap<>();
            synchronized (CHAIN_EVENTS) {
                sequence = CHAIN_EVENTS.size() + 1L;
                prevHash = CHAIN_EVENTS.isEmpty()
                        ? GENESIS_PREV_HASH
                        : asString(CHAIN_EVENTS.get(CHAIN_EVENTS.size() - 1).getOrDefault("event_hash", GENESIS_PREV_HASH));

                chainEvent.put("sequence", sequence);
                chainEvent.put("prev_hash", prevHash);
                chainEvent.put("event", canonicalEvent);
                eventHash = CanonJson.sha256Hex(CanonJson.canonJson(chainEvent));
                chainEvent.put("event_hash", eventHash);

                CHAIN_EVENTS.add(chainEvent);
                appendLedgerLog(chainEvent);
            }

            Map<String, Object> outputs = new LinkedHashMap<>();
            outputs.put("ledger_status", "APPENDED");
            outputs.put("sequence", sequence);
            outputs.put("prev_hash", prevHash);
            outputs.put("event_hash", eventHash);
            outputs.put("head_hash", eventHash);

            Map<String, Object> receiptNoDigest = new LinkedHashMap<>();
            receiptNoDigest.put("receipt_type", "ledger.append.v1");
            receiptNoDigest.put("request_id", requestId);
            receiptNoDigest.put("inputs_digest", CanonJson.sha256Hex(CanonJson.canonJson(canonicalEvent)));
            receiptNoDigest.put("outputs_digest", CanonJson.sha256Hex(CanonJson.canonJson(outputs)));
            receiptNoDigest.put("sequence", sequence);
            receiptNoDigest.put("prev_hash", prevHash);
            receiptNoDigest.put("event_hash", eventHash);
            receiptNoDigest.put("head_hash", eventHash);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("service", "audit-ledger-java");
            evidence.put("event", canonicalEvent);
            evidence.put("sequence", sequence);
            evidence.put("prev_hash", prevHash);
            evidence.put("event_hash", eventHash);
            evidence.put("head_hash", eventHash);
            receiptNoDigest.put("evidence", evidence);

            String receiptDigest = CanonJson.sha256Hex(CanonJson.canonJson(receiptNoDigest));
            Map<String, Object> receipt = new LinkedHashMap<>(receiptNoDigest);
            receipt.put("receipt_digest", receiptDigest);

            synchronized (RECEIPTS) {
                RECEIPTS.add(receipt);
            }

            writeJson(exchange, 200, receipt);
        }
    }

    private static final class EntriesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                writeJson(exchange, 405, Map.of("error", "method not allowed"));
                return;
            }
            List<Map<String, Object>> snapshot;
            synchronized (RECEIPTS) {
                snapshot = new ArrayList<>(RECEIPTS);
            }
            snapshot.sort(Comparator.comparing(o -> (String) o.getOrDefault("request_id", "")));
            writeJson(exchange, 200, snapshot);
        }
    }

    private static final class ChainHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                writeJson(exchange, 405, Map.of("error", "method not allowed"));
                return;
            }

            String headHashRaw = queryParam(exchange, "head_hash");
            String headHash = normalizeHash(headHashRaw);
            if (headHashRaw != null && headHash == null) {
                writeJson(exchange, 400, Map.of("error", "head_hash must be 64 lowercase hex chars"));
                return;
            }
            List<Map<String, Object>> snapshot = new ArrayList<>();
            boolean foundHead = headHash == null;
            synchronized (CHAIN_EVENTS) {
                for (Map<String, Object> event : CHAIN_EVENTS) {
                    snapshot.add(event);
                    if (headHash != null && headHash.equals(asString(event.get("event_hash")))) {
                        foundHead = true;
                        break;
                    }
                }
            }

            if (!foundHead) {
                writeJson(exchange, 404, Map.of(
                        "error", "head_hash not found",
                        "head_hash", headHash
                ));
                return;
            }

            byte[] body = chainJsonl(snapshot);
            exchange.getResponseHeaders().set("Content-Type", "application/x-ndjson");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }
    }

    private static Map<String, Object> readJsonMap(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        if (body.length == 0) {
            return new LinkedHashMap<>();
        }
        Map<String, Object> parsed = MAPPER.readValue(body, new TypeReference<>() {
        });
        return normalizeJsonMap(parsed);
    }

    private static void writeJson(HttpExchange exchange, int status, Object obj) throws IOException {
        byte[] bytes = CanonJson.canonJson(obj);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static Path ledgerPath() {
        String dir = System.getenv().getOrDefault("LEDGER_DIR", "/app/data");
        return Path.of(dir).resolve(LEDGER_FILE_NAME);
    }

    private static void appendLedgerLog(Map<String, Object> chainEvent) {
        try {
            Path ledgerPath = ledgerPath();
            Path root = ledgerPath.getParent();
            if (root != null) {
                Files.createDirectories(root);
            }
            Files.writeString(
                    ledgerPath,
                    new String(CanonJson.canonJson(chainEvent), StandardCharsets.UTF_8) + "\n",
                    StandardCharsets.UTF_8,
                    Files.exists(ledgerPath)
                            ? java.nio.file.StandardOpenOption.APPEND
                            : java.nio.file.StandardOpenOption.CREATE
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void loadChainFromDisk() {
        Path path = ledgerPath();
        if (!Files.exists(path)) {
            return;
        }

        try {
            List<Map<String, Object>> loaded = new ArrayList<>();
            for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                Map<String, Object> parsed = MAPPER.readValue(line, new TypeReference<>() {
                });
                loaded.add(normalizeJsonMap(parsed));
            }
            validateLoadedChain(loaded);
            synchronized (CHAIN_EVENTS) {
                CHAIN_EVENTS.clear();
                CHAIN_EVENTS.addAll(loaded);
            }
            System.out.println("loaded ledger chain events: " + loaded.size());
        } catch (IOException e) {
            throw new RuntimeException("failed to load ledger chain", e);
        }
    }

    private static void validateLoadedChain(List<Map<String, Object>> chainEvents) {
        String expectedPrev = GENESIS_PREV_HASH;
        long expectedSequence = 1L;

        for (Map<String, Object> chainEvent : chainEvents) {
            long sequence = asLong(chainEvent.get("sequence"));
            String prevHash = asString(chainEvent.get("prev_hash"));
            String eventHash = asString(chainEvent.get("event_hash"));
            Object rawEvent = chainEvent.get("event");

            if (sequence != expectedSequence) {
                throw new IllegalStateException("ledger sequence gap at expected sequence " + expectedSequence);
            }
            if (!expectedPrev.equals(prevHash)) {
                throw new IllegalStateException("ledger prev_hash mismatch at sequence " + sequence);
            }
            if (!HEX64.matcher(eventHash).matches()) {
                throw new IllegalStateException("invalid event_hash at sequence " + sequence);
            }

            Map<String, Object> hashScope = new LinkedHashMap<>();
            hashScope.put("sequence", sequence);
            hashScope.put("prev_hash", prevHash);
            hashScope.put("event", normalizeJsonValue(rawEvent));
            String computed = CanonJson.sha256Hex(CanonJson.canonJson(hashScope));
            if (!computed.equals(eventHash)) {
                throw new IllegalStateException("ledger event_hash mismatch at sequence " + sequence);
            }

            expectedPrev = eventHash;
            expectedSequence++;
        }
    }

    private static byte[] chainJsonl(List<Map<String, Object>> events) {
        StringBuilder sb = new StringBuilder();
        for (Map<String, Object> event : events) {
            sb.append(new String(CanonJson.canonJson(event), StandardCharsets.UTF_8)).append('\n');
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String queryParam(HttpExchange exchange, String name) {
        String rawQuery = exchange.getRequestURI().getRawQuery();
        if (rawQuery == null || rawQuery.isBlank()) {
            return null;
        }
        String[] pairs = rawQuery.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx < 0) {
                continue;
            }
            String k = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
            if (!name.equals(k)) {
                continue;
            }
            return URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
        }
        return null;
    }

    private static String normalizeHash(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim().toLowerCase();
        if (normalized.isBlank()) {
            return null;
        }
        if (!HEX64.matcher(normalized).matches()) {
            return null;
        }
        return normalized;
    }

    private static String asString(Object value) {
        if (value == null) {
            return "";
        }
        return String.valueOf(value);
    }

    private static long asLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        String asString = asString(value).trim();
        if (asString.isEmpty()) {
            return 0L;
        }
        return Long.parseLong(asString);
    }

    private static Map<String, Object> canonicalEventFromRequest(Map<String, Object> request) {
        Object rawEvent = request.get("event");
        if (rawEvent instanceof Map<?, ?>) {
            return normalizeJsonMap(rawEvent);
        }
        return normalizeJsonMap(request);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> normalizeJsonMap(Object value) {
        Object normalized = normalizeJsonValue(value);
        if (normalized instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        return new LinkedHashMap<>();
    }

    private static Object normalizeJsonValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                out.put(String.valueOf(entry.getKey()), normalizeJsonValue(entry.getValue()));
            }
            return out;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            for (Object item : list) {
                out.add(normalizeJsonValue(item));
            }
            return out;
        }
        return value;
    }
}
