package io.rulia.jvm;

public enum RuliaStatus {
    OK(0),
    INVALID_ARGUMENT(1),
    PARSE_ERROR(2),
    DECODE_ERROR(3),
    VERIFY_ERROR(4),
    OUT_OF_MEMORY(5),
    INTERNAL_ERROR(6),
    FORMAT_INVALID_SYNTAX(7),
    FORMAT_NOT_CANONICAL(8),
    FRAMING_INVALID_LENGTH(9),
    FRAMING_TRUNCATED_HEADER(10),
    FRAMING_TRUNCATED_PAYLOAD(11),
    FRAMING_TOO_LARGE(12),
    FRAMING_OUTPUT_ERROR(13),
    FRAMING_NEED_MORE_DATA(14),
    UNKNOWN(-1);

    private final int code;

    RuliaStatus(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static RuliaStatus fromCode(int code) {
        for (RuliaStatus status : values()) {
            if (status.code == code) {
                return status;
            }
        }
        return UNKNOWN;
    }

    public String message() {
        return "rulia status: " + name();
    }
}
