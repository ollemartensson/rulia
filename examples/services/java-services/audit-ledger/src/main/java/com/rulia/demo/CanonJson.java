package com.rulia.demo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

final class CanonJson {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CanonJson() {
    }

    static byte[] canonJson(Object value) {
        StringBuilder sb = new StringBuilder();
        writeCanon(sb, value);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static void writeCanon(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
            return;
        }
        if (value instanceof Boolean b) {
            sb.append(b ? "true" : "false");
            return;
        }
        if (value instanceof Number n) {
            if (n instanceof Double d) {
                if (!Double.isFinite(d)) {
                    throw new IllegalArgumentException("non-finite float not allowed");
                }
                if (d == 0.0d) {
                    sb.append("0");
                } else {
                    sb.append(normalizeFloat(Double.toString(d)));
                }
                return;
            }
            if (n instanceof Float f) {
                if (!Float.isFinite(f)) {
                    throw new IllegalArgumentException("non-finite float not allowed");
                }
                if (f == 0.0f) {
                    sb.append("0");
                } else {
                    sb.append(normalizeFloat(Float.toString(f)));
                }
                return;
            }
            sb.append(n);
            return;
        }
        if (value instanceof String s) {
            try {
                sb.append(MAPPER.writeValueAsString(s));
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
            return;
        }
        if (value instanceof byte[] b) {
            try {
                sb.append(MAPPER.writeValueAsString(Base64.getEncoder().encodeToString(b)));
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
            return;
        }
        if (value instanceof Map<?, ?> m) {
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> entry : m.entrySet()) {
                sorted.put(String.valueOf(entry.getKey()), entry.getValue());
            }
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> entry : sorted.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeCanon(sb, entry.getKey());
                sb.append(':');
                writeCanon(sb, entry.getValue());
            }
            sb.append('}');
            return;
        }
        if (value instanceof List<?> list) {
            sb.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                writeCanon(sb, list.get(i));
            }
            sb.append(']');
            return;
        }

        Map<String, Object> asMap = MAPPER.convertValue(value, new TypeReference<>() {
        });
        writeCanon(sb, asMap);
    }

    private static String normalizeFloat(String value) {
        String v = value.replace("E", "e");
        int idx = v.indexOf('e');
        if (idx < 0) {
            return v;
        }
        String mantissa = v.substring(0, idx);
        String exp = v.substring(idx + 1).replace("+", "");
        boolean neg = exp.startsWith("-");
        if (neg) {
            exp = exp.substring(1);
        }
        exp = exp.replaceFirst("^0+", "");
        if (exp.isEmpty()) {
            exp = "0";
        }
        return mantissa + "e" + (neg ? "-" : "") + exp;
    }
}
