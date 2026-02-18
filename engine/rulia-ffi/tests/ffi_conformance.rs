use std::ffi::CString;
use std::ptr;

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod rulia_ffi;

use rulia_ffi::{
    rulia_v1_bytes_free, rulia_v1_encode, rulia_v1_parse, rulia_v1_reader_free,
    rulia_v1_reader_new, rulia_v1_reader_root, rulia_v1_value_as_bytes, rulia_v1_value_as_string,
    rulia_v1_value_free, rulia_v1_value_kind, RuliaStatus,
};

struct FfiBytes {
    ptr: *mut u8,
    len: usize,
}

impl Drop for FfiBytes {
    fn drop(&mut self) {
        unsafe {
            rulia_v1_bytes_free(self.ptr, self.len);
        }
    }
}

fn parse_handle(input: &str) -> RuliaHandle {
    let c_str = CString::new(input).expect("cstring");
    let result = unsafe { rulia_v1_parse(c_str.as_ptr()) };
    assert_eq!(result.status, RuliaStatus::Ok);
    assert_ne!(result.handle, 0);
    result.handle
}

fn encode_handle(handle: RuliaHandle) -> FfiBytes {
    let result = unsafe { rulia_v1_encode(handle) };
    assert_eq!(result.status, RuliaStatus::Ok);
    assert!(!result.ptr.is_null());
    assert!(result.len > 0);
    FfiBytes {
        ptr: result.ptr,
        len: result.len,
    }
}

fn ptr_in_range(base_ptr: *const u8, len: usize, ptr: *const u8, slice_len: usize) -> bool {
    if base_ptr.is_null() || ptr.is_null() {
        return false;
    }
    let base = base_ptr as usize;
    let start = ptr as usize;
    let end = match base.checked_add(len) {
        Some(end) => end,
        None => return false,
    };
    let slice_end = match start.checked_add(slice_len) {
        Some(end) => end,
        None => return false,
    };
    start >= base && slice_end <= end
}

type RuliaHandle = usize;

#[test]
fn happy_path_borrowed_string() {
    let value_handle = parse_handle("\"hello\"");
    let bytes = encode_handle(value_handle);

    unsafe {
        rulia_v1_value_free(value_handle);
    }

    let mut reader_handle: RuliaHandle = 0;
    let status = unsafe { rulia_v1_reader_new(bytes.ptr, bytes.len, &mut reader_handle) };
    assert_eq!(status, RuliaStatus::Ok);
    assert_ne!(reader_handle, 0);

    let mut root_handle: RuliaHandle = 0;
    let status = unsafe { rulia_v1_reader_root(reader_handle, &mut root_handle) };
    assert_eq!(status, RuliaStatus::Ok);
    assert_ne!(root_handle, 0);

    let mut out_ptr: *const u8 = ptr::null();
    let mut out_len: usize = 0;
    let status = unsafe { rulia_v1_value_as_string(root_handle, &mut out_ptr, &mut out_len) };
    assert_eq!(status, RuliaStatus::Ok);
    assert_eq!(out_len, 5);
    assert!(ptr_in_range(bytes.ptr, bytes.len, out_ptr, out_len));

    let slice = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
    assert_eq!(slice, b"hello");

    unsafe {
        rulia_v1_value_free(root_handle);
        rulia_v1_reader_free(reader_handle);
    }
}

#[test]
fn happy_path_borrowed_bytes() {
    let value_handle = parse_handle("0x[deadbeef]");
    let bytes = encode_handle(value_handle);

    unsafe {
        rulia_v1_value_free(value_handle);
    }

    let mut reader_handle: RuliaHandle = 0;
    let status = unsafe { rulia_v1_reader_new(bytes.ptr, bytes.len, &mut reader_handle) };
    assert_eq!(status, RuliaStatus::Ok);
    assert_ne!(reader_handle, 0);

    let mut root_handle: RuliaHandle = 0;
    let status = unsafe { rulia_v1_reader_root(reader_handle, &mut root_handle) };
    assert_eq!(status, RuliaStatus::Ok);
    assert_ne!(root_handle, 0);

    let mut out_ptr: *const u8 = ptr::null();
    let mut out_len: usize = 0;
    let status = unsafe { rulia_v1_value_as_bytes(root_handle, &mut out_ptr, &mut out_len) };
    assert_eq!(status, RuliaStatus::Ok);
    assert_eq!(out_len, 4);
    assert!(ptr_in_range(bytes.ptr, bytes.len, out_ptr, out_len));

    let slice = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
    assert_eq!(slice, &[0xde, 0xad, 0xbe, 0xef]);

    unsafe {
        rulia_v1_value_free(root_handle);
        rulia_v1_reader_free(reader_handle);
    }
}

#[test]
fn double_free_is_safe() {
    let value_handle = parse_handle("\"double free\"");
    unsafe {
        rulia_v1_value_free(value_handle);
        rulia_v1_value_free(value_handle);
    }

    let reader_value_handle = parse_handle("\"reader\"");
    let bytes = encode_handle(reader_value_handle);
    unsafe {
        rulia_v1_value_free(reader_value_handle);
    }
    let mut reader_handle: RuliaHandle = 0;
    let status = unsafe { rulia_v1_reader_new(bytes.ptr, bytes.len, &mut reader_handle) };
    assert_eq!(status, RuliaStatus::Ok);

    unsafe {
        rulia_v1_reader_free(reader_handle);
        rulia_v1_reader_free(reader_handle);
    }
}

#[test]
fn use_after_reader_free_is_detected() {
    let value_handle = parse_handle("\"after-free\"");
    let bytes = encode_handle(value_handle);
    unsafe {
        rulia_v1_value_free(value_handle);
    }

    let mut reader_handle: RuliaHandle = 0;
    let status = unsafe { rulia_v1_reader_new(bytes.ptr, bytes.len, &mut reader_handle) };
    assert_eq!(status, RuliaStatus::Ok);

    let mut root_handle: RuliaHandle = 0;
    let status = unsafe { rulia_v1_reader_root(reader_handle, &mut root_handle) };
    assert_eq!(status, RuliaStatus::Ok);

    unsafe {
        rulia_v1_reader_free(reader_handle);
    }

    let mut out_ptr: *const u8 = ptr::null();
    let mut out_len: usize = 0;
    let status = unsafe { rulia_v1_value_as_string(root_handle, &mut out_ptr, &mut out_len) };
    assert_eq!(status, RuliaStatus::InvalidArgument);

    unsafe {
        rulia_v1_value_free(root_handle);
    }
}

#[test]
fn use_after_value_free_is_detected() {
    let value_handle = parse_handle("\"stale\"");
    let bytes = encode_handle(value_handle);
    unsafe {
        rulia_v1_value_free(value_handle);
    }

    let mut reader_handle: RuliaHandle = 0;
    let status = unsafe { rulia_v1_reader_new(bytes.ptr, bytes.len, &mut reader_handle) };
    assert_eq!(status, RuliaStatus::Ok);

    let mut root_handle: RuliaHandle = 0;
    let status = unsafe { rulia_v1_reader_root(reader_handle, &mut root_handle) };
    assert_eq!(status, RuliaStatus::Ok);

    unsafe {
        rulia_v1_value_free(root_handle);
    }

    let mut kind: u16 = 0;
    let status = unsafe { rulia_v1_value_kind(root_handle, &mut kind) };
    assert_eq!(status, RuliaStatus::InvalidArgument);

    let mut out_ptr: *const u8 = ptr::null();
    let mut out_len: usize = 0;
    let status = unsafe { rulia_v1_value_as_string(root_handle, &mut out_ptr, &mut out_len) };
    assert_eq!(status, RuliaStatus::InvalidArgument);

    unsafe {
        rulia_v1_reader_free(reader_handle);
    }
}
