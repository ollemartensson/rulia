# Rulia Core Format

## Scope
Rulia defines the core format as the canonical data substrate.
This layer owns value representation, canonical serialization, and identity derivation.

Rulia explicitly excludes from this layer:
- Capabilities.
- Execution.
- IO.
- Side effects.

## Canonical Value Model
Rulia defines a closed value algebra with fixed semantics.
Implementations may optimize representation, but semantic meaning must remain identical.

Core value families include:
- Scalars: null, booleans, integers, decimals, text, bytes.
- Symbols and keywords where defined by core grammar.
- Collections: vectors, maps, sets.
- Structured wrappers: tagged values and annotations.

Rulia requires map keys to be literal canonical values admitted by the core grammar.
Rulia requires value equality to be semantic equality under canonical representation.

## Canonical Text Form
Rulia defines one canonical text rendering for any canonical value.

Rulia requires:
- Deterministic token spelling and escaping.
- Deterministic collection ordering where ordering is defined by canonical rules.
- No stylistic freedom that changes canonical bytes.
- Parse and print closure: `canonical_print(parse(canonical_text)) == canonical_text`.

Non-canonical text may exist for authoring ergonomics, but canonical text is the only normative textual identity surface.

## Canonical Binary Form
Rulia defines one canonical binary encoding with fixed type tags and fixed field ordering.

Rulia requires:
- A stable type-tag registry.
- Deterministic encoding for each value family.
- Canonical map ordering by canonical key bytes.
- Canonical set ordering by canonical element bytes.
- Explicit length framing for streaming contexts.

Rulia permits multiple decode strategies, including borrowed/zero-copy paths, if decoded semantics are identical.

## Hashing and Identity Rules
Rulia defines identity from canonical bytes only.

Rulia requires:
- Digest input equals canonical binary bytes of the defined identity subject.
- Digest algorithm identifiers to be explicit.
- Deterministic digest trailer layout when embedded with payload bytes.

Rulia defines two identity surfaces:
- Object digest: hash of the fully canonicalized object, including semantic wrappers that belong to object identity.
- Fact digest: hash of the canonicalized value with identity-excluded wrappers removed as defined by core rules.

Rulia guarantees that identity changes only when canonical bytes of the chosen identity surface change.

## Zero-Copy Constraints
Rulia defines zero-copy as an optimization with strict correctness limits.

Rulia requires:
- Borrowed views to reference immutable canonical byte regions.
- Lifetime and ownership boundaries to be explicit.
- No mutation of bytes that participate in canonical identity.
- A fallback copy path when borrowing cannot be proven safe.

Zero-copy must not alter parsing, equality, hashing, or verification outcomes.

## Determinism Guarantees
Rulia guarantees:
- Deterministic parse: equal input bytes produce equal value graphs.
- Deterministic encode: equal value graphs produce equal canonical bytes.
- Deterministic hash: equal canonical bytes produce equal digests.
- Deterministic decode-encode round trip on canonical artifacts.

Rulia requires all nondeterministic inputs (time, randomness, IO) to stay outside this layer.

## Conformance Expectations
A conforming core implementation must demonstrate:
- Canonical text and binary round-trip tests.
- Ordering conformance tests for maps and sets.
- Digest conformance vectors.
- Zero-copy and owned decode equivalence tests.

Rulia defines failing any of these as non-conforming core behavior.
