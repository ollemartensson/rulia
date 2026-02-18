use rulia::value::Symbol;
use rulia::{
    canonical_digest, verify_manifest, verify_signed, DigestAlg, HashAlgorithm, Keyword,
    RuliaError, SigAlg, Signer, TaggedValue, Value, Verifier, VerifyPolicy,
};

struct TestSigner {
    key_id: String,
}

impl TestSigner {
    fn new(key_id: &str) -> Self {
        Self {
            key_id: key_id.to_string(),
        }
    }
}

impl Signer for TestSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn alg(&self) -> SigAlg {
        SigAlg::Ed25519
    }

    fn sign_digest(&self, domain: &str, digest: &[u8]) -> rulia::RuliaResult<Vec<u8>> {
        Ok(test_signature_bytes(&self.key_id, domain, digest))
    }
}

struct TestVerifier;

impl Verifier for TestVerifier {
    fn verify_digest(
        &self,
        key_id: &str,
        alg: SigAlg,
        domain: &str,
        digest: &[u8],
        signature: &[u8],
    ) -> rulia::RuliaResult<bool> {
        if alg != SigAlg::Ed25519 {
            return Ok(false);
        }
        Ok(signature == test_signature_bytes(key_id, domain, digest))
    }
}

fn test_signature_bytes(key_id: &str, domain: &str, digest: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(domain.as_bytes());
    payload.push(0);
    payload.extend_from_slice(key_id.as_bytes());
    payload.push(0);
    payload.extend_from_slice(digest);
    HashAlgorithm::Sha256.compute(&payload)
}

fn kw(name: &str) -> Value {
    Value::Keyword(Keyword::simple(name))
}

fn tag(name: &str, value: Value) -> Value {
    Value::Tagged(TaggedValue::new(Symbol::simple(name), value))
}

fn digest_value(alg: DigestAlg, digest: [u8; 32]) -> Value {
    let alg_keyword = match alg {
        DigestAlg::Sha256 => Keyword::simple("sha256"),
        DigestAlg::Blake3 => Keyword::simple("blake3"),
    };
    tag(
        "digest",
        Value::Map(vec![
            (kw("alg"), Value::Keyword(alg_keyword)),
            (kw("hex"), Value::String(hex::encode(digest))),
        ]),
    )
}

fn signature_value(key_id: &str, digest: [u8; 32], signature: Vec<u8>) -> Value {
    signature_value_with_scope(key_id, digest, signature, "rulia_signed_v1")
}

fn signature_value_with_scope(
    key_id: &str,
    digest: [u8; 32],
    signature: Vec<u8>,
    scope: &str,
) -> Value {
    tag(
        "signature",
        Value::Map(vec![
            (kw("key_id"), Value::String(key_id.to_string())),
            (kw("alg"), Value::Keyword(Keyword::simple("ed25519"))),
            (kw("scope"), Value::Keyword(Keyword::simple(scope))),
            (
                kw("payload_digest"),
                digest_value(DigestAlg::Sha256, digest),
            ),
            (kw("sig"), Value::Bytes(signature)),
        ]),
    )
}

fn signed_value(payload: Value, signature: Value) -> Value {
    tag(
        "signed",
        Value::Map(vec![
            (kw("payload"), payload),
            (kw("signatures"), Value::Vector(vec![signature])),
        ]),
    )
}

fn policy(domain: &str, key_id: &str) -> VerifyPolicy {
    VerifyPolicy {
        digest_alg: DigestAlg::Sha256,
        allowed_sig_algs: vec![SigAlg::Ed25519],
        trusted_key_ids: vec![key_id.to_string()],
        threshold: 1,
        domain: domain.to_string(),
    }
}

fn assert_security_error(result: rulia::RuliaResult<()>, expected: &'static str) {
    match result {
        Err(RuliaError::Security(msg)) => assert_eq!(msg, expected),
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected verification failure"),
    }
}

fn manifest_entries(
    root_digest: [u8; 32],
    object_digest: [u8; 32],
    signatures: Vec<Value>,
) -> Vec<(Value, Value)> {
    vec![
        (
            kw("format"),
            Value::Keyword(Keyword::simple("rulia_manifest_v1")),
        ),
        (kw("root"), digest_value(DigestAlg::Sha256, root_digest)),
        (
            kw("objects"),
            Value::Vector(vec![Value::Map(vec![
                (kw("id"), Value::String("object-1".into())),
                (kw("digest"), digest_value(DigestAlg::Sha256, object_digest)),
            ])]),
        ),
        (kw("policy"), Value::Map(Vec::new())),
        (kw("signatures"), Value::Vector(signatures)),
    ]
}

fn manifest_value(root_digest: [u8; 32], object_digest: [u8; 32], signatures: Vec<Value>) -> Value {
    tag(
        "manifest",
        Value::Map(manifest_entries(root_digest, object_digest, signatures)),
    )
}

#[test]
fn verify_signed_succeeds_with_trusted_signature() {
    let payload = Value::Map(vec![
        (kw("name"), Value::String("example".into())),
        (kw("version"), Value::Int(1)),
    ]);
    let digest = canonical_digest(&payload, DigestAlg::Sha256).expect("digest");
    let signer = TestSigner::new("key:trusted");
    let signature = signer
        .sign_digest("rulia:signed:v1", &digest)
        .expect("sign");
    let signed = signed_value(payload, signature_value(signer.key_id(), digest, signature));
    let verifier = TestVerifier;
    let policy = policy("rulia:signed:v1", "key:trusted");
    verify_signed(&signed, &policy, &verifier).expect("verify");
}

#[test]
fn verify_signed_rejects_wrong_digest() {
    let payload = Value::Map(vec![
        (kw("name"), Value::String("example".into())),
        (kw("version"), Value::Int(1)),
    ]);
    let digest = canonical_digest(&payload, DigestAlg::Sha256).expect("digest");
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 0xFF;
    let signer = TestSigner::new("key:trusted");
    let signature = signer
        .sign_digest("rulia:signed:v1", &wrong_digest)
        .expect("sign");
    let signed = signed_value(
        payload,
        signature_value(signer.key_id(), wrong_digest, signature),
    );
    let verifier = TestVerifier;
    let policy = policy("rulia:signed:v1", "key:trusted");
    assert_security_error(
        verify_signed(&signed, &policy, &verifier),
        "signature: payload digest mismatch",
    );
}

#[test]
fn verify_signed_rejects_untrusted_key() {
    let payload = Value::Map(vec![
        (kw("name"), Value::String("example".into())),
        (kw("version"), Value::Int(1)),
    ]);
    let digest = canonical_digest(&payload, DigestAlg::Sha256).expect("digest");
    let signer = TestSigner::new("key:untrusted");
    let signature = signer
        .sign_digest("rulia:signed:v1", &digest)
        .expect("sign");
    let signed = signed_value(payload, signature_value(signer.key_id(), digest, signature));
    let verifier = TestVerifier;
    let policy = policy("rulia:signed:v1", "key:trusted");
    assert_security_error(
        verify_signed(&signed, &policy, &verifier),
        "signature: untrusted key_id",
    );
}

#[test]
fn verify_signed_rejects_scope_mismatch() {
    let payload = Value::Map(vec![
        (kw("name"), Value::String("example".into())),
        (kw("version"), Value::Int(1)),
    ]);
    let digest = canonical_digest(&payload, DigestAlg::Sha256).expect("digest");
    let signer = TestSigner::new("key:trusted");
    let signature = signer
        .sign_digest("rulia:signed:v1", &digest)
        .expect("sign");
    let signed = signed_value(
        payload,
        signature_value_with_scope(signer.key_id(), digest, signature, "rulia_manifest_v1"),
    );
    let verifier = TestVerifier;
    let policy = policy("rulia:signed:v1", "key:trusted");
    assert_security_error(
        verify_signed(&signed, &policy, &verifier),
        "signature: scope mismatch",
    );
}

#[test]
fn verify_signed_rejects_invalid_signature() {
    let payload = Value::Map(vec![
        (kw("name"), Value::String("example".into())),
        (kw("version"), Value::Int(1)),
    ]);
    let digest = canonical_digest(&payload, DigestAlg::Sha256).expect("digest");
    let signed = signed_value(
        payload,
        signature_value("key:trusted", digest, vec![0u8; 32]),
    );
    let verifier = TestVerifier;
    let policy = policy("rulia:signed:v1", "key:trusted");
    assert_security_error(
        verify_signed(&signed, &policy, &verifier),
        "signature: verification failed",
    );
}

#[test]
fn verify_manifest_succeeds_with_trusted_signature() {
    let root_payload = Value::String("root".into());
    let object_payload = Value::String("object".into());
    let root_digest = canonical_digest(&root_payload, DigestAlg::Sha256).expect("digest");
    let object_digest = canonical_digest(&object_payload, DigestAlg::Sha256).expect("digest");
    let manifest_for_signing = manifest_value(root_digest, object_digest, Vec::new());
    let manifest_digest =
        canonical_digest(&manifest_for_signing, DigestAlg::Sha256).expect("digest");
    let signer = TestSigner::new("key:trusted");
    let signature = signer
        .sign_digest("rulia:manifest:v1", &manifest_digest)
        .expect("sign");
    let manifest = manifest_value(
        root_digest,
        object_digest,
        vec![signature_value_with_scope(
            signer.key_id(),
            manifest_digest,
            signature,
            "rulia_manifest_v1",
        )],
    );
    let verifier = TestVerifier;
    let policy = policy("rulia:manifest:v1", "key:trusted");
    verify_manifest(&manifest, &policy, &verifier).expect("verify");
}

#[test]
fn verify_manifest_rejects_scope_mismatch() {
    let root_payload = Value::String("root".into());
    let object_payload = Value::String("object".into());
    let root_digest = canonical_digest(&root_payload, DigestAlg::Sha256).expect("digest");
    let object_digest = canonical_digest(&object_payload, DigestAlg::Sha256).expect("digest");
    let manifest_for_signing = manifest_value(root_digest, object_digest, Vec::new());
    let manifest_digest =
        canonical_digest(&manifest_for_signing, DigestAlg::Sha256).expect("digest");
    let signer = TestSigner::new("key:trusted");
    let signature = signer
        .sign_digest("rulia:manifest:v1", &manifest_digest)
        .expect("sign");
    let manifest = manifest_value(
        root_digest,
        object_digest,
        vec![signature_value_with_scope(
            signer.key_id(),
            manifest_digest,
            signature,
            "rulia_signed_v1",
        )],
    );
    let verifier = TestVerifier;
    let policy = policy("rulia:manifest:v1", "key:trusted");
    assert_security_error(
        verify_manifest(&manifest, &policy, &verifier),
        "signature: scope mismatch",
    );
}

#[test]
fn verify_manifest_rejects_disallowed_alg() {
    let root_payload = Value::String("root".into());
    let object_payload = Value::String("object".into());
    let root_digest = canonical_digest(&root_payload, DigestAlg::Sha256).expect("digest");
    let object_digest = canonical_digest(&object_payload, DigestAlg::Sha256).expect("digest");
    let manifest_for_signing = manifest_value(root_digest, object_digest, Vec::new());
    let manifest_digest =
        canonical_digest(&manifest_for_signing, DigestAlg::Sha256).expect("digest");
    let signer = TestSigner::new("key:trusted");
    let signature = signer
        .sign_digest("rulia:manifest:v1", &manifest_digest)
        .expect("sign");
    let manifest = manifest_value(
        root_digest,
        object_digest,
        vec![signature_value_with_scope(
            signer.key_id(),
            manifest_digest,
            signature,
            "rulia_manifest_v1",
        )],
    );
    let verifier = TestVerifier;
    let mut policy = policy("rulia:manifest:v1", "key:trusted");
    policy.allowed_sig_algs.clear();
    assert_security_error(
        verify_manifest(&manifest, &policy, &verifier),
        "signature: disallowed alg",
    );
}

#[test]
fn verify_manifest_rejects_threshold_not_met() {
    let root_payload = Value::String("root".into());
    let object_payload = Value::String("object".into());
    let root_digest = canonical_digest(&root_payload, DigestAlg::Sha256).expect("digest");
    let object_digest = canonical_digest(&object_payload, DigestAlg::Sha256).expect("digest");
    let manifest_for_signing = manifest_value(root_digest, object_digest, Vec::new());
    let manifest_digest =
        canonical_digest(&manifest_for_signing, DigestAlg::Sha256).expect("digest");
    let signer = TestSigner::new("key:trusted");
    let signature = signer
        .sign_digest("rulia:manifest:v1", &manifest_digest)
        .expect("sign");
    let manifest = manifest_value(
        root_digest,
        object_digest,
        vec![signature_value_with_scope(
            signer.key_id(),
            manifest_digest,
            signature,
            "rulia_manifest_v1",
        )],
    );
    let verifier = TestVerifier;
    let mut policy = policy("rulia:manifest:v1", "key:trusted");
    policy.threshold = 2;
    assert_security_error(
        verify_manifest(&manifest, &policy, &verifier),
        "signature: threshold not met",
    );
}

#[test]
fn verify_manifest_rejects_payload_digest_mismatch() {
    let root_payload = Value::String("root".into());
    let object_payload = Value::String("object".into());
    let root_digest = canonical_digest(&root_payload, DigestAlg::Sha256).expect("digest");
    let object_digest = canonical_digest(&object_payload, DigestAlg::Sha256).expect("digest");
    let manifest_for_signing = manifest_value(root_digest, object_digest, Vec::new());
    let manifest_digest =
        canonical_digest(&manifest_for_signing, DigestAlg::Sha256).expect("digest");
    let mut wrong_digest = manifest_digest;
    wrong_digest[0] ^= 0xFF;
    let signer = TestSigner::new("key:trusted");
    let signature = signer
        .sign_digest("rulia:manifest:v1", &wrong_digest)
        .expect("sign");
    let manifest = manifest_value(
        root_digest,
        object_digest,
        vec![signature_value_with_scope(
            signer.key_id(),
            wrong_digest,
            signature,
            "rulia_manifest_v1",
        )],
    );
    let verifier = TestVerifier;
    let policy = policy("rulia:manifest:v1", "key:trusted");
    assert_security_error(
        verify_manifest(&manifest, &policy, &verifier),
        "signature: payload digest mismatch",
    );
}

#[test]
fn verify_manifest_rejects_unknown_key() {
    let root_payload = Value::String("root".into());
    let object_payload = Value::String("object".into());
    let root_digest = canonical_digest(&root_payload, DigestAlg::Sha256).expect("digest");
    let object_digest = canonical_digest(&object_payload, DigestAlg::Sha256).expect("digest");
    let mut entries = manifest_entries(root_digest, object_digest, Vec::new());
    entries.insert(0, (kw("unexpected"), Value::Bool(true)));
    let manifest = tag("manifest", Value::Map(entries));
    let verifier = TestVerifier;
    let policy = policy("rulia:manifest:v1", "key:trusted");
    assert_security_error(
        verify_manifest(&manifest, &policy, &verifier),
        "manifest: unknown key",
    );
}
