use crate::binary::encode_canonical;
use crate::error::{RuliaError, RuliaResult};
use crate::hash::HashAlgorithm;
use crate::value::{Keyword, Symbol, TaggedValue, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DigestAlg {
    Sha256,
    Blake3,
}

impl DigestAlg {
    fn from_keyword(keyword: &Keyword) -> Option<Self> {
        if keyword.namespace().is_some() {
            return None;
        }
        match keyword.name() {
            "sha256" => Some(DigestAlg::Sha256),
            "blake3" => Some(DigestAlg::Blake3),
            _ => None,
        }
    }

    fn to_hash_algorithm(self) -> HashAlgorithm {
        match self {
            DigestAlg::Sha256 => HashAlgorithm::Sha256,
            DigestAlg::Blake3 => HashAlgorithm::Blake3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigAlg {
    Ed25519,
}

impl SigAlg {
    fn from_keyword(keyword: &Keyword) -> Option<Self> {
        if keyword.namespace().is_some() {
            return None;
        }
        match keyword.name() {
            "ed25519" => Some(SigAlg::Ed25519),
            _ => None,
        }
    }
}

pub fn canonical_digest(value: &Value, alg: DigestAlg) -> RuliaResult<[u8; 32]> {
    let bytes = encode_canonical(value)?;
    let digest = alg.to_hash_algorithm().compute(&bytes);
    if digest.len() != 32 {
        return Err(RuliaError::Security("digest: invalid length"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub fn object_digest(value: &Value, alg: DigestAlg) -> RuliaResult<[u8; 32]> {
    canonical_digest(value, alg)
}

pub fn fact_digest(value: &Value, alg: DigestAlg) -> RuliaResult<[u8; 32]> {
    let stripped = value.strip_annotations();
    canonical_digest(&stripped, alg)
}

pub fn validate_fact(value: &Value) -> RuliaResult<()> {
    if contains_generator(value) {
        return Err(RuliaError::Security("fact: generator forbidden"));
    }
    Ok(())
}

fn contains_generator(value: &Value) -> bool {
    match value {
        Value::Tagged(tagged) => is_generator_tag(&tagged.tag) || contains_generator(&tagged.value),
        Value::Vector(values) | Value::Set(values) => values.iter().any(contains_generator),
        Value::Map(entries) => entries
            .iter()
            .any(|(key, value)| contains_generator(key) || contains_generator(value)),
        Value::Annotated(ann) => {
            ann.metadata
                .iter()
                .any(|(key, value)| contains_generator(key) || contains_generator(value))
                || contains_generator(&ann.value)
        }
        _ => false,
    }
}

fn is_generator_tag(tag: &Symbol) -> bool {
    tag.namespace().is_none() && tag.name() == "generator"
}

pub trait Signer {
    fn key_id(&self) -> &str;
    fn alg(&self) -> SigAlg;
    fn sign_digest(&self, domain: &str, digest: &[u8]) -> RuliaResult<Vec<u8>>;
}

pub trait Verifier {
    fn verify_digest(
        &self,
        key_id: &str,
        alg: SigAlg,
        domain: &str,
        digest: &[u8],
        signature: &[u8],
    ) -> RuliaResult<bool>;
}

#[derive(Clone, Debug)]
pub struct VerifyPolicy {
    pub digest_alg: DigestAlg,
    pub allowed_sig_algs: Vec<SigAlg>,
    pub trusted_key_ids: Vec<String>,
    pub threshold: usize,
    pub domain: String,
}

pub fn verify_signed(
    value: &Value,
    policy: &VerifyPolicy,
    verifier: &dyn Verifier,
) -> RuliaResult<()> {
    let signed_map = tagged_map(value, "signed", "signed: expected #signed map")?;
    let entries = collect_map_entries(
        signed_map,
        &["payload", "signatures", "meta"],
        "signed: keys must be keywords",
        "signed: unknown key",
        "signed: duplicate key",
    )?;
    let payload = require_entry(&entries, "payload", "signed: missing :payload")?;
    let signatures_value = require_entry(&entries, "signatures", "signed: missing :signatures")?;
    if let Some(meta_value) = optional_entry(&entries, "meta") {
        if !matches!(meta_value, Value::Map(_)) {
            return Err(RuliaError::Security("signed: meta must be map"));
        }
    }
    let signatures = match signatures_value {
        Value::Vector(values) => values,
        _ => return Err(RuliaError::Security("signed: signatures must be vector")),
    };
    let digest = canonical_digest(payload, policy.digest_alg)?;
    verify_signatures(signatures, policy, verifier, &[digest])
}

pub fn verify_manifest(
    value: &Value,
    policy: &VerifyPolicy,
    verifier: &dyn Verifier,
) -> RuliaResult<()> {
    let (tag, manifest_map) =
        tagged_map_with_tag(value, "manifest", "manifest: expected #manifest map")?;
    let entries = collect_map_entries(
        manifest_map,
        &[
            "format",
            "root",
            "objects",
            "policy",
            "attestations",
            "signatures",
        ],
        "manifest: keys must be keywords",
        "manifest: unknown key",
        "manifest: duplicate key",
    )?;
    let format_value = require_entry(&entries, "format", "manifest: missing :format")?;
    let format_keyword = match format_value {
        Value::Keyword(keyword) if keyword.namespace().is_none() => keyword.name(),
        _ => return Err(RuliaError::Security("manifest: format must be keyword")),
    };
    if format_keyword != "rulia_manifest_v1" {
        return Err(RuliaError::Security("manifest: unsupported format"));
    }
    let root_value = require_entry(&entries, "root", "manifest: missing :root")?;
    parse_digest(root_value, Some(policy.digest_alg))?;
    let policy_value = require_entry(&entries, "policy", "manifest: missing :policy")?;
    if !matches!(policy_value, Value::Map(_)) {
        return Err(RuliaError::Security("manifest: policy must be map"));
    }
    if let Some(attestations) = optional_entry(&entries, "attestations") {
        if !matches!(attestations, Value::Vector(_)) {
            return Err(RuliaError::Security(
                "manifest: attestations must be vector",
            ));
        }
    }
    let objects_value = require_entry(&entries, "objects", "manifest: missing :objects")?;
    let objects = match objects_value {
        Value::Vector(values) => values,
        _ => return Err(RuliaError::Security("manifest: objects must be vector")),
    };
    for object in objects {
        validate_manifest_object(object, policy)?;
    }
    let signatures_value = require_entry(&entries, "signatures", "manifest: missing :signatures")?;
    let signatures = match signatures_value {
        Value::Vector(values) => values,
        _ => return Err(RuliaError::Security("manifest: signatures must be vector")),
    };
    let entries_without_signatures = manifest_entries_without_key(manifest_map, "signatures");
    let manifest_body = Value::Tagged(TaggedValue::new(
        tag.clone(),
        Value::Map(entries_without_signatures.clone()),
    ));
    let mut entries_with_empty = entries_without_signatures;
    entries_with_empty.push((
        Value::Keyword(Keyword::simple("signatures")),
        Value::Vector(Vec::new()),
    ));
    let manifest_body_with_empty =
        Value::Tagged(TaggedValue::new(tag, Value::Map(entries_with_empty)));
    let digest_without = canonical_digest(&manifest_body, policy.digest_alg)?;
    let digest_with_empty = canonical_digest(&manifest_body_with_empty, policy.digest_alg)?;
    verify_signatures(
        signatures,
        policy,
        verifier,
        &[digest_without, digest_with_empty],
    )
}

fn verify_signatures(
    signatures: &[Value],
    policy: &VerifyPolicy,
    verifier: &dyn Verifier,
    acceptable_digests: &[[u8; 32]],
) -> RuliaResult<()> {
    let mut verified = 0usize;
    let mut seen_keys: Vec<String> = Vec::new();
    for signature_value in signatures {
        let signature = parse_signature(signature_value, policy)?;
        if !acceptable_digests.contains(&signature.payload_digest) {
            return Err(RuliaError::Security("signature: payload digest mismatch"));
        }
        if seen_keys.iter().any(|key| key == &signature.key_id) {
            return Err(RuliaError::Security("signature: duplicate key_id"));
        }
        seen_keys.push(signature.key_id.clone());
        let ok = verifier.verify_digest(
            &signature.key_id,
            signature.alg,
            &policy.domain,
            &signature.payload_digest,
            &signature.signature,
        )?;
        if !ok {
            return Err(RuliaError::Security("signature: verification failed"));
        }
        verified += 1;
    }
    if verified < policy.threshold {
        return Err(RuliaError::Security("signature: threshold not met"));
    }
    Ok(())
}

struct ParsedSignature {
    key_id: String,
    alg: SigAlg,
    payload_digest: [u8; 32],
    signature: Vec<u8>,
}

fn parse_signature(value: &Value, policy: &VerifyPolicy) -> RuliaResult<ParsedSignature> {
    let signature_map = tagged_map(value, "signature", "signature: expected #signature map")?;
    let entries = collect_map_entries(
        signature_map,
        &[
            "key_id",
            "alg",
            "scope",
            "payload_digest",
            "sig",
            "created",
            "purpose",
            "claims",
        ],
        "signature: keys must be keywords",
        "signature: unknown key",
        "signature: duplicate key",
    )?;
    let key_id_value = require_entry(&entries, "key_id", "signature: missing :key_id")?;
    let key_id = parse_key_id(key_id_value)?;
    if !policy
        .trusted_key_ids
        .iter()
        .any(|trusted| trusted == &key_id)
    {
        return Err(RuliaError::Security("signature: untrusted key_id"));
    }
    let alg_value = require_entry(&entries, "alg", "signature: missing :alg")?;
    let alg = parse_sig_alg(alg_value)?;
    if !policy.allowed_sig_algs.contains(&alg) {
        return Err(RuliaError::Security("signature: disallowed alg"));
    }
    let scope_value = require_entry(&entries, "scope", "signature: missing :scope")?;
    let scope_keyword = match scope_value {
        Value::Keyword(keyword) if keyword.namespace().is_none() => keyword.name(),
        _ => return Err(RuliaError::Security("signature: scope must be keyword")),
    };
    if scope_keyword != expected_scope(&policy.domain) {
        return Err(RuliaError::Security("signature: scope mismatch"));
    }
    let digest_value = require_entry(
        &entries,
        "payload_digest",
        "signature: missing :payload_digest",
    )?;
    let (_, payload_digest) = parse_digest(digest_value, Some(policy.digest_alg))?;
    let sig_value = require_entry(&entries, "sig", "signature: missing :sig")?;
    let signature = match sig_value {
        Value::Bytes(bytes) => bytes.clone(),
        _ => return Err(RuliaError::Security("signature: sig must be bytes")),
    };
    if let Some(created) = optional_entry(&entries, "created") {
        if !matches!(created, Value::String(_)) {
            return Err(RuliaError::Security("signature: created must be string"));
        }
    }
    if let Some(purpose) = optional_entry(&entries, "purpose") {
        if !matches!(purpose, Value::Keyword(_)) {
            return Err(RuliaError::Security("signature: purpose must be keyword"));
        }
    }
    if let Some(claims) = optional_entry(&entries, "claims") {
        if !matches!(claims, Value::Map(_)) {
            return Err(RuliaError::Security("signature: claims must be map"));
        }
    }
    Ok(ParsedSignature {
        key_id,
        alg,
        payload_digest,
        signature,
    })
}

fn parse_key_id(value: &Value) -> RuliaResult<String> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Keyword(keyword) => Ok(keyword.as_symbol().as_str()),
        _ => Err(RuliaError::Security(
            "signature: key_id must be string or keyword",
        )),
    }
}

fn parse_sig_alg(value: &Value) -> RuliaResult<SigAlg> {
    let keyword = match value {
        Value::Keyword(keyword) => keyword,
        _ => return Err(RuliaError::Security("signature: alg must be keyword")),
    };
    SigAlg::from_keyword(keyword).ok_or(RuliaError::Security("signature: unsupported alg"))
}

fn parse_digest(
    value: &Value,
    expected_alg: Option<DigestAlg>,
) -> RuliaResult<(DigestAlg, [u8; 32])> {
    let digest_map = tagged_map(value, "digest", "digest: expected #digest map")?;
    let entries = collect_map_entries(
        digest_map,
        &["alg", "hex"],
        "digest: keys must be keywords",
        "digest: unknown key",
        "digest: duplicate key",
    )?;
    let alg_value = require_entry(&entries, "alg", "digest: missing :alg")?;
    let alg_keyword = match alg_value {
        Value::Keyword(keyword) => keyword,
        _ => return Err(RuliaError::Security("digest: alg must be keyword")),
    };
    let alg = DigestAlg::from_keyword(alg_keyword)
        .ok_or(RuliaError::Security("digest: unsupported alg"))?;
    if let Some(expected) = expected_alg {
        if expected != alg {
            return Err(RuliaError::Security("digest: alg mismatch"));
        }
    }
    let hex_value = require_entry(&entries, "hex", "digest: missing :hex")?;
    let hex_str = match hex_value {
        Value::String(text) => text.as_str(),
        _ => return Err(RuliaError::Security("digest: hex must be string")),
    };
    if hex_str.len() != 64 || !hex_str.bytes().all(is_lower_hex) {
        return Err(RuliaError::Security("digest: invalid hex"));
    }
    let decoded = hex::decode(hex_str).map_err(|_| RuliaError::Security("digest: invalid hex"))?;
    if decoded.len() != 32 {
        return Err(RuliaError::Security("digest: invalid hex"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok((alg, out))
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
}

fn collect_map_entries<'a>(
    entries: &'a [(Value, Value)],
    allowed: &[&'static str],
    non_keyword_err: &'static str,
    unknown_err: &'static str,
    duplicate_err: &'static str,
) -> RuliaResult<Vec<(&'a str, &'a Value)>> {
    let mut seen = Vec::new();
    for (key, value) in entries {
        let keyword = match key {
            Value::Keyword(keyword) if keyword.namespace().is_none() => keyword,
            _ => return Err(RuliaError::Security(non_keyword_err)),
        };
        let name = keyword.name();
        if !allowed.contains(&name) {
            return Err(RuliaError::Security(unknown_err));
        }
        if seen.iter().any(|(seen_name, _)| *seen_name == name) {
            return Err(RuliaError::Security(duplicate_err));
        }
        seen.push((name, value));
    }
    Ok(seen)
}

fn require_entry<'a>(
    entries: &'a [(&'a str, &'a Value)],
    name: &'static str,
    missing_err: &'static str,
) -> RuliaResult<&'a Value> {
    entries
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| *value)
        .ok_or(RuliaError::Security(missing_err))
}

fn optional_entry<'a>(
    entries: &'a [(&'a str, &'a Value)],
    name: &'static str,
) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| *value)
}

fn tagged_map<'a>(
    value: &'a Value,
    expected_tag: &str,
    err_tag: &'static str,
) -> RuliaResult<&'a [(Value, Value)]> {
    let Value::Tagged(TaggedValue { tag, value }) = value else {
        return Err(RuliaError::Security(err_tag));
    };
    if tag.as_str() != expected_tag {
        return Err(RuliaError::Security(err_tag));
    }
    match value.as_ref() {
        Value::Map(entries) => Ok(entries),
        _ => Err(RuliaError::Security(err_tag)),
    }
}

fn tagged_map_with_tag<'a>(
    value: &'a Value,
    expected_tag: &str,
    err_tag: &'static str,
) -> RuliaResult<(Symbol, &'a [(Value, Value)])> {
    let Value::Tagged(TaggedValue { tag, value }) = value else {
        return Err(RuliaError::Security(err_tag));
    };
    if tag.as_str() != expected_tag {
        return Err(RuliaError::Security(err_tag));
    }
    match value.as_ref() {
        Value::Map(entries) => Ok((tag.clone(), entries)),
        _ => Err(RuliaError::Security(err_tag)),
    }
}

fn expected_scope(domain: &str) -> String {
    domain.replace(':', "_")
}

fn manifest_entries_without_key(entries: &[(Value, Value)], skip_key: &str) -> Vec<(Value, Value)> {
    entries
        .iter()
        .filter(|(key, _)| !matches!(key, Value::Keyword(keyword) if keyword.namespace().is_none() && keyword.name() == skip_key))
        .cloned()
        .collect()
}

fn validate_manifest_object(value: &Value, policy: &VerifyPolicy) -> RuliaResult<()> {
    let Value::Map(entries) = value else {
        return Err(RuliaError::Security("manifest: object must be map"));
    };
    let collected = collect_map_entries(
        entries,
        &["id", "digest"],
        "manifest: object keys must be keywords",
        "manifest: object unknown key",
        "manifest: object duplicate key",
    )?;
    let id_value = require_entry(&collected, "id", "manifest: object missing :id")?;
    if !matches!(id_value, Value::String(_)) {
        return Err(RuliaError::Security("manifest: object id must be string"));
    }
    let digest_value = require_entry(&collected, "digest", "manifest: object missing :digest")?;
    parse_digest(digest_value, Some(policy.digest_alg))?;
    Ok(())
}
