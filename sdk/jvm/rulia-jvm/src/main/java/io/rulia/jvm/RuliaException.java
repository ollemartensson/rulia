package io.rulia.jvm;

public final class RuliaException extends RuntimeException {
    private final RuliaStatus status;

    public RuliaException(RuliaStatus status) {
        super(status.message());
        this.status = status;
    }

    public RuliaException(RuliaStatus status, String message) {
        super(message);
        this.status = status;
    }

    public RuliaStatus status() {
        return status;
    }
}
