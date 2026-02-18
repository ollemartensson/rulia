package io.rulia.jvm;

import java.util.Collections;
import java.util.List;

public final class FrameDecodeResult {
    private final List<byte[]> frames;
    private final int consumed;
    private final boolean needMore;
    private final boolean eof;

    FrameDecodeResult(List<byte[]> frames, int consumed, boolean needMore, boolean eof) {
        this.frames = Collections.unmodifiableList(frames);
        this.consumed = consumed;
        this.needMore = needMore;
        this.eof = eof;
    }

    public List<byte[]> frames() {
        return frames;
    }

    public int consumed() {
        return consumed;
    }

    public boolean needMore() {
        return needMore;
    }

    public boolean eof() {
        return eof;
    }
}
