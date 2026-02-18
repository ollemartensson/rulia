# Rulia Cheat Sheet

Quick reference for the Rulia data notation language.

---

## Primitive Types

| Type | Example | Notes |
|------|---------|-------|
| Nil | `nil` | Null value |
| Boolean | `true`, `false` | |
| Integer | `42`, `-17` | 64-bit signed |
| Unsigned | `42u` | 64-bit unsigned |
| BigInt | `99999999999999999999N` | Arbitrary precision |
| Float32 | `3.14f` | 32-bit float |
| Float64 | `3.14`, `2.5e10` | 64-bit float |
| String | `"hello"`, `"line\nbreak"` | UTF-8, escape sequences |
| Bytes | `0x[deadbeef]` | Hex-encoded binary |

---

## Collections

### Vector (ordered list)
```rulia
[1, 2, 3]
["mixed", 42, true]
[]
```

### Map (key-value pairs)
```rulia
(name = "Alice", age = 30)
(config = (nested = true))
()
```

### Set (unique values)
```rulia
Set([1, 2, 3])
Set(["a", "b", "c"])
Set([])
```

---

## Keywords

```rulia
# Simple keyword
:status

# Namespaced via underscore sugar
:user_name          # => user/name
:db_type            # => db/type

# Explicit namespace (for special characters)
Keyword("db.type/string")
Keyword("my-ns/my-key")
```

---

## Symbols

```rulia
# Simple symbol
'my_symbol

# Logic variable (Datalog)
@?entity
@?value

# Wildcard (pattern matching)
_
```

---

## Tagged Values (Constructors)

```rulia
# PascalCase constructor → snake_case tag
User(id = 1, name = "Alice")     # => #user {...}
HttpRequest(method = "GET")      # => #http_request {...}

# Common constructors
UUID("550e8400-e29b-41d4-a716-446655440000")
ULID("01ARZ3NDEKTSV4RRFFQ69G5FAV")
Instant("2025-01-01T00:00:00Z")
GeoPoint([12.5, -99.4])
#
# Instant requires canonical RFC3339 UTC with Z and minimal fractional seconds.

# Graph references
Ref(100)                         # ID reference
Ref(:email, "a@b.com")          # Lookup reference

# Explicit tagged value
Tagged("my-ns/tag", [1, 2, 3])
```

---

## String Interpolation

```rulia
let name = "Alice"
"Hello $name!"                   # => "Hello Alice!"

let x = 42
"Value: $(x)"                    # => "Value: 42"

# Escape $ with backslash
"Price: \$99"                    # => "Price: $99"
```

---

## Let Bindings

### Single binding
```rulia
let x = 10
x
```

### Multiple bindings (block)
```rulia
let {
    name = "Alice";
    age = 30
}
(name = name, age = age)
```

### Destructuring
```rulia
# Tuple destructuring
let (a, b) = [1, 2]
[b, a]                           # => [2, 1]

# Vector destructuring
let [x, y, z] = [10, 20, 30]
"$x, $y, $z"                     # => "10, 20, 30"

# In blocks
let {
    coords = [100, 200];
    (x, y) = coords
}
"Point($x, $y)"
```

---

## Functions

```rulia
# Define function
let greet = fn(name) =>
    "Hello $name!"

# Call function
greet("World")                   # => "Hello World!"

# Multi-parameter
let add = fn(a, b) =>
    let sum = a  # Note: arithmetic not built-in
    sum

# Higher-order
let apply = fn(f, x) => f(x)
apply(greet, "Rulia")
```

---

## Builtin Functions

| Function | Usage | Description |
|----------|-------|-------------|
| `merge` | `merge(map1, map2)` | Merge maps (later wins) |
| `concat` | `concat("a", "b", 42)` | Concatenate to string |
| `get` | `get(vec, 0)` | Get element by index/key |

```rulia
# merge example
merge((a = 1), (b = 2))          # => (a = 1, b = 2)

# concat example
concat("Hello ", "World")        # => "Hello World"

# get example
get([10, 20, 30], 1)            # => 20
```

---

## Value Generation

### Immediate generation (@new)
```rulia
@new(:uuid)     # Generates UUID bytes at parse time
@new(:ulid)     # Generates ULID string at parse time
@new(:now)      # Generates current Unix timestamp (milliseconds)
```

In deterministic mode, `@new(...)` requires `ParseOptions.new_provider`.

### Deferred generation (Generator)
```rulia
Generator(:uuid)    # Schema default, evaluated later
Generator(:ulid)
Generator(:now)
```

---

## Metadata & Documentation

### Docstrings
```rulia
"A user record."
User(id = 1, name = "Alice")
```

### Triple-quoted docstrings
```rulia
"""
A comprehensive user record
with multiple fields.
"""
User(id = 1)
```

### Metadata decorator
```rulia
@meta(author = "admin", version = "1.0")
User(id = 1)

# Combined with docstring
@meta(deprecated = true)
"Legacy user format."
User(id = 1)
```

---

## Namespace Macro

```rulia
@ns user begin
    (id = 101, name = "Bob", email = "bob@example.com")
end
# => (user/id = 101, user/name = "Bob", user/email = "bob@example.com")

# Nested namespaces
@ns outer begin
    (
        id = 1,
        inner = @ns inner begin
            (value = 42)
        end
    )
end
```

---

## Datalog / Logic Syntax

### Logic variables
```rulia
@?entity
@?value
@?age
```

### Wildcard
```rulia
[@?e, :user_friends, _]     # _ matches anything
```

### Infix operators (desugared to prefix)
```rulia
(@?age >= 18)               # => [>=, @?age, 18]
(@?x == 42)                 # => [==, @?x, 42]
(@?y != 0)                  # => [!=, @?y, 0]
```

### Query structure
```rulia
Query(
    find = [@?e, @?name],
    where = [
        [@?e, :user_name, @?name],
        (@?age >= 18)
    ]
)
```

---

## Imports

```rulia
# Basic import
import "path/to/file.rjl"

# Import with hash verification
import "config.rjl" sha256:abc123...
import "data.rjl" blake3:def456...
```

In deterministic/no-IO mode, filesystem import I/O is disabled; use `ParseOptions.import_resolver`.

---

## Comments

```rulia
# Single line comment

(
    name = "Alice",  # Inline comment
    age = 30
)
```

---

## Escape Sequences

| Sequence | Meaning |
|----------|---------|
| `\\` | Backslash |
| `\"` | Double quote |
| `\n` | Newline |
| `\r` | Carriage return |
| `\t` | Tab |
| `\$` | Literal $ (in interpolated strings) |

---

## File Extension

`.rjl` - Rulia files

---

## Rust API Quick Reference

```rust
use rulia::{Value, text, Keyword};

// Parse text
let value = text::parse(r#"(name = "Alice")"#)?;

// Serialize to text
let text = text::to_string(&value);

// Binary encode
let bytes = rulia::encode_value(&value)?;

// Binary decode
let decoded = rulia::decode_value(&bytes)?;

// With digest
let encoded = rulia::encode_with_digest(&value)?;
let (algorithm, digest) = rulia::verify_digest(&encoded.bytes)?;
let decoded = rulia::decode_value(&encoded.bytes)?;

// Create values programmatically
let map = Value::Map(vec![
    (Value::Keyword(Keyword::simple("name")),
     Value::String("Alice".into()))
]);
```

Deterministic/no-IO parser setup:

```rust
use std::sync::Arc;
use rulia::text::{self, ParseOptions};

let opts = ParseOptions::deterministic();
// deterministic = true, allow_import_io = false, allow_disk_cache = false

let opts = ParseOptions {
    new_provider: Some(Arc::new(MyProvider)),
    import_resolver: Some(Arc::new(MyResolver)),
    ..ParseOptions::deterministic()
};

let value = text::parse_with_options(r#"(id = @new(:uuid))"#, opts)?;
```

---

## Stream Framing (v1)

A framed stream is a concatenation of frames with no global header. Each frame is:
`LEN (u32 LE)` followed by `PAYLOAD (LEN bytes)`, where payload is a canonical Rulia binary
message. Default maximum frame length is 64 MiB; `LEN = 0` is invalid. Stream Framing v1 adds
no per-frame digest.

Example:

```
LEN     = 03 00 00 00
PAYLOAD = 01 02 03
FRAME   = 03 00 00 00 01 02 03
```

---

## Best Practices

1. **Use namespaced keywords** for domain attributes: `:user_name` not `:name`
2. **Prefer constructors** for typed data: `User(...)` not `(type = "user", ...)`
3. **Use docstrings** for schema documentation
4. **Verify imports** with hash expectations for security
5. **Use destructuring** for cleaner code when unpacking data
6. **Interpolate strings** instead of concatenation where readable

---

## See Also

- [Full Specification](SPECIFICATION.md)
- [Deterministic & Hermetic Parsing](../README.md#deterministic--hermetic-parsing)
- [Examples](../examples/)
- [API Documentation](https://docs.rs/rulia)
