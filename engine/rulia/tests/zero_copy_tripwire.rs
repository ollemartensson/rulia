use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use rulia::binary::{MessageReader, TypeTag};
use rulia::value::{Keyword, Value};
use rulia::RuliaResult;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        System.realloc(ptr, layout, new_size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn reset_allocations() {
    ALLOCATIONS.store(0, Ordering::SeqCst);
}

fn allocations() -> usize {
    ALLOCATIONS.load(Ordering::SeqCst)
}

fn assert_ptr_in_buffer(buffer: &[u8], ptr: *const u8) {
    let base = buffer.as_ptr() as usize;
    let end = base + buffer.len();
    let p = ptr as usize;
    assert!(base <= p && p < end, "slice pointer not in input buffer");
}

#[test]
fn value_ref_zero_copy_tripwire() -> RuliaResult<()> {
    let value = Value::Map(vec![
        (
            Value::Keyword(Keyword::simple("name")),
            Value::String("Alice".to_owned()),
        ),
        (
            Value::Keyword(Keyword::simple("blob")),
            Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
        ),
    ]);

    let bytes = rulia::encode_value(&value)?;
    let reader = MessageReader::new(&bytes)?;

    reset_allocations();

    let root = reader.root()?.as_value();
    let mut string_slice: Option<&str> = None;
    let mut bytes_slice: Option<&[u8]> = None;

    for entry in root.map_iter()? {
        let (_key, value) = entry?;
        match value.kind() {
            TypeTag::String => string_slice = Some(value.as_string()?),
            TypeTag::Bytes => bytes_slice = Some(value.as_bytes()?),
            _ => {}
        }
    }

    let string_slice = string_slice.expect("expected string entry");
    let bytes_slice = bytes_slice.expect("expected bytes entry");

    assert_ptr_in_buffer(&bytes, string_slice.as_ptr());
    assert_ptr_in_buffer(&bytes, bytes_slice.as_ptr());

    assert_eq!(
        allocations(),
        0,
        "zero-copy traversal allocated unexpectedly"
    );
    Ok(())
}
