# Rulia Language Specification

> Normative Rulia Core Format is docs/RULIA_CORE_FORMAT.md. This file defers to it.

Version 1.0

## Table of Contents

1. [Introduction](#introduction)
2. [Lexical Structure](#lexical-structure)
3. [Primitive Types](#primitive-types)
4. [Collection Types](#collection-types)
5. [Keywords and Symbols](#keywords-and-symbols)
6. [Tagged Values](#tagged-values)
7. [String Interpolation](#string-interpolation)
8. [Let Bindings](#let-bindings)
9. [Functions](#functions)
10. [Macros](#macros)
11. [Metadata and Documentation](#metadata-and-documentation)
12. [Imports](#imports)
13. [Binary Format](#binary-format)
14. [Grammar](#grammar)

---

## Introduction

Rulia is a data notation language designed for both human readability and machine efficiency. It provides:

- A text format with Julia-inspired syntax
- A canonical binary format with cryptographic digests
- Rich type support including tagged values and metadata
- Datalog-compatible query syntax

### Design Principles

1. **Readability**: Syntax should be immediately understandable
2. **Expressiveness**: Support complex data structures without verbosity
3. **Determinism**: Binary encoding is canonical for content addressing
4. **Safety**: Hash verification for imports and content integrity

### Authority Map

`docs/SPECIFICATION.md` is authoritative for canonical text and binary encoding. For digest/trailer layout, hashing scope, protocol/FFI container schemas, ABI surface, and governance authority, see `docs/design/SPEC_AUTHORITY_MAP.md`.

### File Extension

Rulia files use the `.rjl` extension.

---

## Lexical Structure

### Character Set

Rulia source files are UTF-8 encoded.

### Whitespace

Whitespace characters (space, tab, newline, carriage return) are used to separate tokens and are otherwise ignored. Multiple whitespace characters are treated as one.

### Comments

Line comments begin with `#` and extend to the end of the line:

```rulia
# This is a comment
(name = "Alice")  # Inline comment
```

### Identifiers

Identifiers match the pattern: `[a-zA-Z_][a-zA-Z0-9_]*`

```
Valid:    name, user_id, _private, Config2
Invalid:  2name, user-id, @special
```

### Reserved Words

```
true, false, nil, let, fn, import, begin, end
```

---

## Primitive Types

### Nil

Represents absence of value:

```rulia
nil
```

### Booleans

```rulia
true
false
```

### Integers

64-bit signed integers:

```rulia
0
42
-17
1000000
```

### Unsigned Integers

64-bit unsigned integers (suffix `u`):

```rulia
0u
42u
18446744073709551615u
```

### BigInts

Arbitrary precision integers (suffix `N`):

```rulia
99999999999999999999999999N
-12345678901234567890N
```

### Float32

32-bit floating point (suffix `f`):

```rulia
3.14f
-0.5f
1.0e10f
```

### Float64

64-bit floating point:

```rulia
3.14
-0.5
2.5e10
1.0e-5
```

### Strings

UTF-8 strings enclosed in double quotes:

```rulia
"hello world"
"with \"quotes\""
"line 1\nline 2"
```

#### Escape Sequences

| Sequence | Meaning |
|----------|---------|
| `\\` | Backslash |
| `\"` | Double quote |
| `\n` | Newline (LF) |
| `\r` | Carriage return |
| `\t` | Tab |
| `\$` | Literal dollar sign |

#### Triple-Quoted Strings

Multi-line strings with preserved formatting:

```rulia
"""
This is a
multi-line string.
"""
```

Leading/trailing newlines adjacent to the quotes are stripped.

### Bytes

Binary data as hex-encoded literals:

```rulia
0x[deadbeef]
0x[00 11 22 33]    # Whitespace allowed
0x[]               # Empty bytes
```

---

## Collection Types

### Vectors

Ordered sequences of values:

```rulia
[]                          # Empty
[1, 2, 3]                   # Integers
["a", "b", "c"]             # Strings
[1, "mixed", true, nil]     # Mixed types
[[1, 2], [3, 4]]            # Nested
```

Trailing commas are permitted:

```rulia
[
  1,
  2,
  3,
]
```

### Maps

Key-value pairs with literal keys:

```rulia
()                          # Empty
(name = "Alice")            # Identifier key (keyword sugar)
(:status = "ok")            # Keyword literal key
("content-type" = "text/plain")
```

Keys are literal forms:
- `identifier` (sugar for keyword; `user_email` becomes `:user/email`)
- `:keyword` (keyword literal)
- `"string"` (string literal; no interpolation)

Keys MUST be compile-time literals; arbitrary expressions are not allowed.
Duplicate keys are rejected deterministically at parse and encode time.
Trailing commas are permitted.

### Sets

Unordered collections of unique values:

```rulia
Set([])                     # Empty
Set([1, 2, 3])              # Integers
Set([:a, :b, :c])           # Keywords
```

---

## Keywords and Symbols

### Keywords

Named constants used as map keys and identifiers:

```rulia
# Simple keyword
:name

# Namespaced via underscore (sugar)
:user_name                  # Equivalent to user/name
:db_valueType               # Equivalent to db/valueType

# Explicit namespace (for special characters)
Keyword("db.type/string")
Keyword("my-namespace/my-key")
```

#### Namespace Sugar Rules

The first underscore splits namespace from name:
- `:user_name` → `user/name`
- `:user_home_address` → `user/home_address`
- `:name` → no namespace

### Symbols

Symbolic identifiers (not evaluated as variables):

```rulia
# Simple symbol
'my_symbol
'Symbol("ns/name")

# Logic variables (for Datalog)
@?entity
@?value

# Wildcard (matches anything)
_
```

---

## Tagged Values

Tagged values associate a type tag with data:

```rulia
# PascalCase constructor syntax
User(id = 1, name = "Alice")     # Tag: user
HttpRequest(method = "GET")      # Tag: http_request
GeoPoint([12.5, -99.4])          # Tag: geo_point

# Explicit Tagged constructor
Tagged("my-ns/tag", [1, 2, 3])
```

### PascalCase Conversion

Constructor names are converted to snake_case tags:

| Constructor | Tag |
|-------------|-----|
| `User` | `user` |
| `HttpRequest` | `http_request` |
| `GeoPoint` | `geo_point` |
| `UUID` | `uuid` |
| `API` | `api` |

### Built-in Constructors

The following constructors are **standard language features** available in all Rulia profiles. They are natively supported by the Core parser.

#### Set

```rulia
Set([1, 2, 3])
```

Creates a `Value::Set` (not a tagged value).

#### Keyword

```rulia
Keyword("ns/name")
```

Creates a keyword with explicit namespace path.

#### Symbol

```rulia
Symbol("ns/name")
```

Creates a symbol with explicit namespace path.

#### Tagged

```rulia
Tagged("tag-name", value)
```

Creates a tagged value with explicit tag string.

#### UUID

```rulia
UUID("550e8400-e29b-41d4-a716-446655440000")
```

Creates `#uuid <bytes>` with 16-byte binary representation.

#### ULID

```rulia
ULID("01ARZ3NDEKTSV4RRFFQ69G5FAV")
```

Creates `#ulid <string>` with Crockford Base32 validation.

#### Instant

```rulia
Instant("2025-01-01T00:00:00Z")
```

Creates `#instant <string>` with a canonical RFC3339 / ISO-8601 UTC timestamp payload.
The payload string MUST follow these canonical rules:

- Exact shape: `YYYY-MM-DDTHH:MM:SS[.fraction]Z`.
- Must end with `Z` and MUST NOT include timezone offsets.
- Fractional seconds are optional; if present, 1 to 9 digits only.
- Fractional seconds MUST be minimal (no trailing zeros). If the fractional value is zero,
  the fractional part MUST be omitted.
- No whitespace is permitted.
- Valid date/time ranges only: year/month/day must be a valid calendar date; hour 00-23,
  minute 00-59, second 00-59 (no leap seconds).

Encoders and validators in strict profiles MUST reject non-canonical Instant strings and MUST
NOT silently normalize or coerce them.

#### Ref

```rulia
Ref(100)                         # ID reference
Ref(:email, "alice@example.com") # Lookup reference
```

Creates `#ref <id>` or `#ref [attr, value]`.

#### Generator

```rulia
Generator(:uuid)
Generator(:ulid)
Generator(:now)
```

Creates `#generator <type>` for deferred value generation.
Generators are not permitted inside stored/transmitted Facts; see Fact Materialization.

---

## String Interpolation

Strings support variable and expression interpolation:

### Variable Interpolation

```rulia
let name = "Alice"
"Hello $name!"              # => "Hello Alice!"
```

Variables must start with letter or underscore, followed by alphanumeric or underscore.

### Expression Interpolation

```rulia
let x = 42
"Value: $(x)"               # => "Value: 42"
"Result: $(get(items, 0))"  # Complex expressions
```

### Escaping

```rulia
"Price: \$99"               # => "Price: $99"
```

### Desugaring

Interpolated strings are desugared to `concat` calls:

```rulia
"Hello $name!"
# Becomes:
concat("Hello ", name, "!")
```

---

## Let Bindings

### Single Binding

```rulia
let x = 10
x                           # => 10
```

### Block Bindings

```rulia
let {
    a = 1;
    b = 2;
    c = 3
}
[a, b, c]                   # => [1, 2, 3]
```

Separators: `;` or `,`

### Destructuring

#### Tuple Pattern

```rulia
let (a, b) = [1, 2]
[b, a]                      # => [2, 1]
```

#### Vector Pattern

```rulia
let [x, y, z] = coords
"$x, $y, $z"
```

#### Desugaring

Destructuring is desugared to `get` calls:

```rulia
let (a, b) = expr
# Becomes:
let {
    __temp = expr;
    a = get(__temp, 0);
    b = get(__temp, 1)
}
```

---

## Functions

### Anonymous Functions

```rulia
fn(x) => x
fn(a, b) => [a, b]
fn() => nil
```

### Named Functions

```rulia
let double = fn(x) =>
    concat(x, x)

double("ab")                # => "abab"
```

### Function Calls

```rulia
# Lowercase identifiers
my_function(arg1, arg2)

# Builtin functions
merge(map1, map2)
concat("a", "b")
get(vec, 0)
```

### Builtin Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `merge` | `(map, map, ...) → map` | Merge maps (later wins) |
| `concat` | `(any, any, ...) → string` | Concatenate as strings |
| `get` | `(collection, key) → value` | Get by index or key |

---

## Macros

### @new - Immediate Generation

Generates values at parse time:

```rulia
@new(:uuid)     # Generate UUID v4 bytes
@new(:ulid)     # Generate ULID string
@new(:now)      # Current Unix timestamp (milliseconds)
```

Deterministic mode requirements:

- If `ParseOptions.deterministic = true` and `ParseOptions.new_provider` is absent,
  parsing `@new(...)` MUST fail.
- If `ParseOptions.deterministic = true`, `@new(...)` MUST source values from
  `ParseOptions.new_provider` and MUST NOT read time or randomness directly.
- If `ParseOptions.deterministic = false`, `@new(...)` MAY use runtime sources.

### @ns - Namespace Block

Prefixes map keys with namespace:

```rulia
@ns user begin
    (id = 1, name = "Alice")
end
# => (user/id = 1, user/name = "Alice")
```

Nesting is supported:

```rulia
@ns outer begin
    (
        value = 1,
        inner = @ns inner begin
            (nested = true)
        end
    )
end
```

### @meta - Metadata Decorator

Attaches metadata to values:

```rulia
@meta(author = "admin", version = "1.0")
(data = true)
```

---

## Metadata and Documentation

### Docstrings

A string literal immediately before a constructor becomes documentation:

```rulia
"A user entity."
User(id = 1)
```

Triple-quoted strings work too:

```rulia
"""
A comprehensive description
spanning multiple lines.
"""
User(id = 1)
```

### Annotated Values

Values with metadata are wrapped in `Value::Annotated`:

```rulia
@meta(deprecated = true)
"Superseded format."
User(id = 1)
```

Produces:

```
Annotated {
    metadata: [(:deprecated, true), (:doc, "Superseded format.")],
    value: Tagged("user", Map(...))
}
```

### Accessing Metadata

```rust
if let Value::Annotated(ann) = value {
    if let Some(doc) = ann.doc() {
        println!("Documentation: {}", doc);
    }
    let inner = ann.inner();
}

// Unwrap all annotation layers
let core_value = value.unwrap_annotations();
```

### Fact Identity (ObjectDigest vs FactDigest)

Facts are immutable values intended for storage or transmission. Fact identity is defined
separately from object identity to ensure documentation and metadata do not alter event
identity.

- ObjectDigest = `hash(canonical(value))`
- FactDigest = `hash(canonical(unwrap_annotations(value)))`

`@meta` annotations and docstrings are non-semantic for FactDigest. Implementations MUST
strip all annotation layers via `unwrap_annotations` before computing FactDigest, but they
remain part of ObjectDigest.

### Fact Materialization (Generator Ban)

Facts MUST be fully materialized before encoding or digesting. Generator constructs are
forbidden anywhere inside a stored or transmitted Fact:

- `@new(...)`
- `Generator(...)`

Any generator usage MUST be resolved to concrete values before a Fact is formed.

---

## Imports

### Basic Import

```rulia
import "path/to/file.rjl"
```

Paths are relative to the importing file.

### Hash-Verified Import

```rulia
import "config.rjl" sha256:a1b2c3...
import "data.rjl" blake3:d4e5f6...
```

The import fails if the file's digest doesn't match.

### Supported Algorithms

- `sha256`: SHA-256 (64 hex characters)
- `blake3`: Blake3 (64 hex characters)

### Cycle Detection

Circular imports are detected and result in an error.

### Deterministic / No-IO Parse Mode

`ParseOptions::deterministic()` configures deterministic/no-IO parsing:

```rust
let opts = text::ParseOptions::deterministic();
// Equivalent fields:
// deterministic = true
// allow_import_io = false
// allow_disk_cache = false
// new_provider = None
// import_resolver = None
```

Behavioral guarantees:

- Deterministic mode MUST disable parser disk cache writes.
- With `allow_import_io = false`, imports MUST fail unless an `ImportResolver` is provided.
- Deterministic mode with imports MUST use `ParseOptions.import_resolver` for hermetic resolution.
- Deterministic mode with `@new(...)` MUST use `ParseOptions.new_provider`; otherwise parsing MUST fail.

---

## Binary Format

Authority note:
- This section is the single authoritative schema for core encoding containers:
  canonical encoding, digest trailer layout, and stream framing.

### Overview

The binary format provides:

- Canonical encoding (deterministic)
- Length-prefixed structures
- Type tags for all values
- Optional digest trailer

### Canonical Ordering

Canonical ordering defines deterministic ordering for collections when encoding.

- Map entries MUST be sorted by canonical-encoded key bytes (type tag + encoded key bytes),
  using bytewise lexicographic order.
- Set elements MUST be sorted by canonical-encoded value bytes, using bytewise lexicographic order.
- Encoders and parsers MUST reject duplicate map keys. Duplicates are defined as entries whose
  canonical-encoded key bytes are identical, regardless of literal spelling.

### Type Tags

Type tags are canonical; see ADR-0001.
Changing tag values is breaking and changes encoded bytes and digests.

| Tag | Type |
|-----|------|
| 0 | Nil |
| 1 | Bool |
| 2 | Int |
| 3 | UInt |
| 4 | BigInt |
| 5 | Float32 |
| 6 | Float64 |
| 7 | String |
| 8 | Bytes |
| 9 | Symbol |
| 10 | Keyword |
| 11 | Vector |
| 12 | Set |
| 13 | Map |
| 14 | Tagged |
| 15 | Annotated |

### Encoding

```rust
let bytes = rulia::encode_value(&value)?;
let decoded = rulia::decode_value(&bytes)?;
```

### With Digest

By default, `encode_with_digest` uses `sha256` (algorithm id `1`).
Use `encode_with_digest_using` to select a different algorithm.

```rust
let encoded = rulia::encode_with_digest(&value)?;
// encoded.bytes - the binary data
// encoded.digest - 32-byte sha256 digest

let (algorithm, digest) = rulia::verify_digest(&encoded.bytes)?;
let decoded = rulia::decode_value(&encoded.bytes)?;
```

### Digest Trailer

When the digest flag is set, a trailer is appended after the dictionary segment.
Layout: `algorithm_id:u8` followed by `digest_bytes`.
The digest is computed over the bytes before the trailer (header + value segment + dictionary).

| Algorithm ID | Algorithm | Digest Length (bytes) |
|--------------|-----------|------------------------|
| 1 | sha256 | 32 |
| 2 | blake3 | 32 |

### Verification

`verify_digest` requires the digest flag, validates the algorithm id and trailer length,
and recomputes the digest over the bytes before the trailer.

### Framing / Streaming (v1)

A framed stream is a concatenation of frames with no global header. Each frame contains exactly
one Rulia binary message.

Normative layout:

```
Frame = LEN || PAYLOAD
LEN   = u32 (4 bytes), little-endian, payload length in bytes
```

Normative requirements:
- Implementations MUST read `LEN`, then read exactly `LEN` bytes for `PAYLOAD`.
- `LEN = 0` is invalid and MUST be rejected.
- `PAYLOAD` MUST be the canonical Rulia binary message bytes as produced by `encode_value` or
  `encode_canonical`.
- `PAYLOAD` MAY include the digest trailer defined in this binary format; framing does not
  reinterpret or modify it.
- Implementations MUST enforce a configurable maximum frame length.
- The default maximum frame length is 64 MiB (67,108,864 bytes).
- Implementations MAY choose a lower default maximum.

Deterministic error codes:

| Code | Condition |
|------|-----------|
| `FRAMING_TRUNCATED_HEADER` | Fewer than 4 bytes available for `LEN`. |
| `FRAMING_TRUNCATED_PAYLOAD` | Fewer than `LEN` bytes available after reading `LEN`. |
| `FRAMING_LENGTH_EXCEEDS_LIMIT` | `LEN` exceeds the configured maximum. |
| `FRAMING_MALFORMED_PAYLOAD` | `PAYLOAD` fails Rulia binary decode. |

#### Using digests in streams

If integrity is required, encode each message with a digest trailer using
`encode_with_digest` (or equivalent) and verify after reading each frame payload.
Stream Framing v1 does not add a per-frame digest.

#### Conformance vectors (informative)

Example 1: single frame, payload length 5 bytes.

```
LEN     = 05 00 00 00
PAYLOAD = aa bb cc dd ee
FRAME   = 05 00 00 00 aa bb cc dd ee
```

Example 2: two-frame stream concatenation with offsets.

```
Frame 0:
  Offset 0  - LEN     = 03 00 00 00
  Offset 4  - PAYLOAD = 01 02 03
Frame 1:
  Offset 7  - LEN     = 04 00 00 00
  Offset 11 - PAYLOAD = 11 22 33 44
Stream bytes:
  03 00 00 00 01 02 03 04 00 00 00 11 22 33 44
```

Payload bytes in the vectors are illustrative placeholders and MUST be replaced by canonical
Rulia binary message bytes in real streams.

### Zero-Copy Access

```rust
let value_ref = rulia::decode_ref(&bytes)?;
if let Some(s) = value_ref.as_str() {
    // s borrows from bytes
}
```

---

## Grammar

### EBNF Grammar

```ebnf
value       = nil | boolean | number | string | bytes
            | keyword | symbol | vector | set | map
            | tagged | let_expr | fn_expr | import
            | annotated | macro ;

nil         = "nil" ;
boolean     = "true" | "false" ;

number      = integer | unsigned | bigint | float32 | float64 ;
integer     = ["-"] digit+ ;
unsigned    = digit+ "u" ;
bigint      = ["-"] digit+ "N" ;
float32     = ["-"] digit+ "." digit+ ["e" ["+"|"-"] digit+] "f" ;
float64     = ["-"] digit+ "." digit+ ["e" ["+"|"-"] digit+] ;

string      = '"' string_char* '"'
            | '"""' any_char* '"""' ;
string_char = escape | interpolation | any_char ;
escape      = "\\" ( "\\" | '"' | "n" | "r" | "t" | "$" ) ;
interpolation = "$" identifier | "$(" expression ")" ;

bytes       = "0x[" hex_char* "]" ;

keyword     = ":" identifier
            | "Keyword" "(" string ")" ;

symbol      = "'" identifier
            | "@?" identifier
            | "_"
            | "Symbol" "(" string ")" ;

vector      = "[" [value ("," value)*] [","] "]" ;

set         = "Set" "(" vector ")" ;

map         = "(" [map_entry ("," map_entry)*] [","] ")" ;
map_entry   = map_key "=" value ;
map_key     = identifier | keyword | string ;

tagged      = constructor "(" [args] ")"
            | "Tagged" "(" string "," value ")" ;
constructor = uppercase identifier* ;
args        = map_args | value_args ;
map_args    = map_entry ("," map_entry)* ;
value_args  = value ("," value)* ;

let_expr    = "let" (binding | block) value ;
binding     = identifier "=" value
            | pattern "=" value ;
block       = "{" (binding [";"|","])* "}" ;
pattern     = "(" identifier ("," identifier)* ")"
            | "[" identifier ("," identifier)* "]" ;

fn_expr     = "fn" "(" [params] ")" "=>" value ;
params      = identifier ("," identifier)* ;

import      = "import" string [hash_spec] ;
hash_spec   = ("sha256" | "blake3") ":" hex_string ;

annotated   = "@meta" "(" map_args ")" value
            | string value  (* docstring *)
            | annotated value ;

macro       = "@new" "(" keyword ")"
            | "@ns" identifier "begin" value "end" ;

identifier  = (letter | "_") (letter | digit | "_")* ;
letter      = "a".."z" | "A".."Z" ;
digit       = "0".."9" ;
hex_char    = digit | "a".."f" | "A".."F" ;
```

---

## Appendix A: Comparison with EDN

| Feature | Rulia | EDN |
|---------|-------|-----|
| Maps | `(k = v)` | `{:k v}` |
| Keywords | `:name` | `:name` |
| Namespaced | `:ns_name` | `:ns/name` |
| Tagged | `Type(v)` | `#type v` |
| Strings | `"..."` | `"..."` |
| Interpolation | `$var` | N/A |
| Comments | `# ...` | `; ...` |
| Sets | `Set([])` | `#{}` |
| Functions | `fn(x) => x` | N/A |
| Let | `let x = 1` | N/A |

---

## Appendix B: Reserved for Future Use

The following are reserved and may be assigned meaning in future versions:

- Infix arithmetic operators: `+`, `-`, `*`, `/`, `%`
- Pattern matching: `match`, `case`, `when`
- Conditionals: `if`, `then`, `else`
- Type annotations: `::`, `as`
