# Rulia JVM bindings (ABI-first)

This module provides JVM bindings to the canonical `librulia` runtime via the C ABI (v1). It installs
native artifacts deterministically from a manifest, verifies sha256, and loads the library directly
(no CLI spawning).

## Install + Load

```java
import io.rulia.jvm.Rulia;

String manifestUrl = "https://example.com/manifest.json";
String version = "0.1.0";

Rulia.installAndLoad(manifestUrl, version);

String formatted = Rulia.formatText("(b = 2, a = 1)");
boolean canonical = Rulia.formatCheck(formatted);
byte[] frame = Rulia.frameEncode("hello".getBytes(java.nio.charset.StandardCharsets.UTF_8));

byte[] canonicalBinary = Rulia.encodeCanonical("(b = 2, a = 1)");
String roundtripText = Rulia.decodeText(canonicalBinary);
byte[] recanonicalized = Rulia.canonicalizeBinary(canonicalBinary);
String canonicalValueText = Rulia.canonicalizeValueText("Tagged(\"complex_ns/tag\", \"data\")");

RuliaEncodedWithDigest digested = Rulia.encodeWithDigest(
    "(a = 1, b = 2)",
    RuliaDigestAlgorithm.SHA256
);
boolean digestValid = Rulia.hasValidDigest(digested.bytes());

RuliaValue typed = Rulia.parseTyped(
    "(user_first_name = \"Ada\", marker = Tagged(\"complex_ns/tag\", \"data\"))"
);
RuliaMapEntry first = typed.asMap().get(0);
RuliaKeyword key = first.key().asKeyword();
String keyCanonical = key.canonical(); // :user/first_name

RuliaAnnotatedValue annotated = Rulia.parseTyped(
    "@meta(author = \"ops\", :doc = \"large id\") 12345678901234567890N"
).asAnnotated();
java.math.BigInteger big = annotated.value().asBigInt();
```

## Local Manifest (offline)

```java
String manifestUrl = "file:///path/to/manifest.json";
Path libPath = Rulia.installFromManifest(manifestUrl, "0.1.0");
Rulia.load(libPath);
```

## Cache Location

Artifacts are installed under:

```
<user.home>/.rulia/tools/<version>/<target>/
```

Where `<target>` is one of:
- `x86_64-unknown-linux-gnu`
- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `x86_64-pc-windows-msvc`
