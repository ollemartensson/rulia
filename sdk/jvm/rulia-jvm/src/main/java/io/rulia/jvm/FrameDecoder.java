package io.rulia.jvm;

import java.util.ArrayList;
import java.util.List;

import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

public final class FrameDecoder implements AutoCloseable {
    public static final int DEFAULT_MAX_LEN = 64 * 1024 * 1024;

    private final RuliaNative ffi;
    private final long handle;
    private boolean closed;

    FrameDecoder(RuliaNative ffi) {
        this(ffi, DEFAULT_MAX_LEN);
    }

    FrameDecoder(RuliaNative ffi, int maxLen) {
        this.ffi = ffi;
        NativeLong out = new NativeLong();
        int status = ffi.rulia_v1_frame_decoder_new(maxLen, out.pointer());
        RuliaStatus ruliaStatus = RuliaStatus.fromCode(status);
        if (ruliaStatus != RuliaStatus.OK) {
            throw new RuliaException(ruliaStatus);
        }
        this.handle = out.get();
        if (this.handle == 0) {
            throw new IllegalStateException("frame decoder handle is null");
        }
    }

    public FrameDecodeResult push(byte[] chunk) {
        if (closed) {
            throw new IllegalStateException("frame decoder is closed");
        }
        if (chunk == null) {
            throw new IllegalArgumentException("chunk is required");
        }
        List<byte[]> frames = new ArrayList<>();
        int offset = 0;
        boolean needMore = false;
        boolean eof = chunk.length == 0;

        while (true) {
            int remaining = chunk.length - offset;
            Pointer ptr = NativeBuffers.toPointer(chunk, offset, remaining);
            NativeLong consumedRef = new NativeLong();
            RuliaNative.RuliaBytes outFrame = new RuliaNative.RuliaBytes(Runtime.getSystemRuntime());
            int status = ffi.rulia_v1_frame_decoder_push(handle, ptr, remaining, outFrame, consumedRef.pointer());
            long consumed = consumedRef.get();
            if (consumed < 0 || consumed > remaining) {
                throw new IllegalStateException("invalid consumed value: " + consumed);
            }
            offset += (int) consumed;
            RuliaStatus ruliaStatus = RuliaStatus.fromCode(status);
            if (ruliaStatus == RuliaStatus.OK) {
                frames.add(NativeBuffers.takeBytes(ffi, outFrame));
                if (offset == chunk.length) {
                    break;
                }
                if (consumed == 0) {
                    throw new IllegalStateException("decoder returned OK without consuming input");
                }
                continue;
            }
            if (ruliaStatus == RuliaStatus.FRAMING_NEED_MORE_DATA) {
                needMore = true;
                break;
            }
            throw new RuliaException(ruliaStatus);
        }

        return new FrameDecodeResult(frames, offset, needMore, eof);
    }

    @Override
    public void close() {
        if (!closed) {
            ffi.rulia_v1_frame_decoder_free(handle);
            closed = true;
        }
    }
}
