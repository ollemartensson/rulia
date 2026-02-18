use std::ptr;

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod rulia_ffi;

use rulia_ffi::{
    rulia_v1_bytes_free, rulia_v1_format_check, rulia_v1_format_text, rulia_v1_frame_decoder_free,
    rulia_v1_frame_decoder_new, rulia_v1_frame_decoder_push, rulia_v1_frame_encode,
    rulia_v1_frame_encode_with_limit, RuliaBytes, RuliaStatus,
};

const DEFAULT_MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;

#[test]
fn v1_format_text_and_check() {
    let input = br#"(config = import  "config.rjl", id = @new( :uuid ))"#;
    let mut out = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };

    let status = unsafe { rulia_v1_format_text(input.as_ptr(), input.len(), &mut out) };
    assert_eq!(status, RuliaStatus::Ok);

    let output = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
    let output_str = std::str::from_utf8(output).expect("utf-8 output");
    assert!(output_str.contains("import \"config.rjl\""));
    assert!(output_str.contains("@new(:uuid)"));

    let status = unsafe { rulia_v1_format_check(output.as_ptr(), output.len()) };
    assert_eq!(status, RuliaStatus::Ok);

    unsafe {
        rulia_v1_bytes_free(out.ptr, out.len);
    }
}

#[test]
fn v1_frame_encode_decode_incremental() {
    let payload = b"hello frame";
    let mut framed = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };

    let status = unsafe { rulia_v1_frame_encode(payload.as_ptr(), payload.len(), &mut framed) };
    assert_eq!(status, RuliaStatus::Ok);

    let frame: &[u8] = unsafe { std::slice::from_raw_parts(framed.ptr, framed.len) };

    let mut decoder: usize = 0;
    let status = unsafe { rulia_v1_frame_decoder_new(DEFAULT_MAX_FRAME_LEN, &mut decoder) };
    assert_eq!(status, RuliaStatus::Ok);

    let split = 2usize.min(frame.len());
    let mut out_frame = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut consumed = 0usize;
    let status = unsafe {
        rulia_v1_frame_decoder_push(
            decoder,
            frame.as_ptr(),
            split,
            &mut out_frame,
            &mut consumed,
        )
    };
    assert_eq!(status, RuliaStatus::FramingNeedMoreData);
    assert_eq!(consumed, split);

    let status = unsafe {
        rulia_v1_frame_decoder_push(
            decoder,
            frame.as_ptr().add(split),
            frame.len() - split,
            &mut out_frame,
            &mut consumed,
        )
    };
    assert_eq!(status, RuliaStatus::Ok);
    assert_eq!(consumed, frame.len() - split);

    let decoded: &[u8] = unsafe { std::slice::from_raw_parts(out_frame.ptr, out_frame.len) };
    assert_eq!(decoded, payload);

    unsafe {
        rulia_v1_bytes_free(out_frame.ptr, out_frame.len);
        rulia_v1_bytes_free(framed.ptr, framed.len);
        rulia_v1_frame_decoder_free(decoder);
    }
}

#[test]
fn v1_framing_error_cases() {
    let mut out = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };

    let status = unsafe { rulia_v1_frame_encode(ptr::null(), 0, &mut out) };
    assert_eq!(status, RuliaStatus::FramingInvalidLength);

    let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55];
    let status =
        unsafe { rulia_v1_frame_encode_with_limit(payload.as_ptr(), payload.len(), 4, &mut out) };
    assert_eq!(status, RuliaStatus::FramingTooLarge);

    let mut decoder: usize = 0;
    let status = unsafe { rulia_v1_frame_decoder_new(DEFAULT_MAX_FRAME_LEN, &mut decoder) };
    assert_eq!(status, RuliaStatus::Ok);

    let header = [0x05u8, 0x00];
    let mut out_frame = RuliaBytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut consumed = 0usize;
    let status = unsafe {
        rulia_v1_frame_decoder_push(
            decoder,
            header.as_ptr(),
            header.len(),
            &mut out_frame,
            &mut consumed,
        )
    };
    assert_eq!(status, RuliaStatus::FramingNeedMoreData);
    assert_eq!(consumed, header.len());

    let status = unsafe {
        rulia_v1_frame_decoder_push(decoder, ptr::null(), 0, &mut out_frame, &mut consumed)
    };
    assert_eq!(status, RuliaStatus::FramingTruncatedHeader);

    unsafe {
        rulia_v1_frame_decoder_free(decoder);
    }
}
