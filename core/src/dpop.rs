use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::constants::{dpop_claims, jwk_params};
use crate::errors::validation_error;
use crate::{AuthplaneError, VerifierError};

/// Supported DPoP signing algorithms.
///
/// This slice is the source of truth for
/// `dpop_signing_alg_values_supported` in the PRM document (RFC 9728 §2).
/// JSON arrays are not order-significant by spec, but the
/// `[ES256, RS256]` order is held stable so conformance fixtures can
/// assert it byte-for-byte.
pub const SUPPORTED_DPOP_ALGORITHMS: &[Algorithm] = &[Algorithm::ES256, Algorithm::RS256];

/// Reject an algorithm that is not in [`SUPPORTED_DPOP_ALGORITHMS`].
///
/// Centralises the membership check that was hand-inlined at the
/// outbound-proof construction sites (`create_dpop_proof`,
/// `DpopProvider::with_options`). Returns
/// `AuthplaneError::Auth(validation_error)`.
///
/// The inbound-verifier path (`verify_dpop_proof`) and the per-resource
/// allowlist setter (`InboundDPoPOptions::with_allowed_proof_algorithms`)
/// use the same algorithm set but bind it into their own error types
/// (`VerifierError::InvalidClaims` and
/// `InboundDPoPOptionsError::UnsupportedAlgorithm` respectively). They
/// consult the constant directly rather than the helper because their
/// `Result` return types differ.
pub(crate) fn ensure_supported_dpop_alg(algorithm: Algorithm) -> Result<(), AuthplaneError> {
    if SUPPORTED_DPOP_ALGORITHMS.contains(&algorithm) {
        return Ok(());
    }
    Err(validation_error(&format!(
        "DPoP algorithm {algorithm:?} is not supported; use one of {SUPPORTED_DPOP_ALGORITHMS:?}"
    )))
}

#[derive(Debug, Clone)]
pub struct DpopProofOptions {
    pub private_key_pem: String,
    pub public_jwk: Value,
    pub algorithm: Algorithm,
    pub key_id: Option<String>,
    pub nonce: Option<String>,
    /// Proof lifetime in seconds. Emitted as `exp = iat + proof_ttl_seconds`.
    /// Defaults to 300 (5 minutes).
    pub proof_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct DpopVerificationOptions<'a> {
    pub expected_access_token: Option<&'a str>,
    pub expected_nonce: Option<&'a str>,
    pub allowed_algorithms: &'a [Algorithm],
    pub clock_skew_seconds: u64,
    pub max_age_seconds: u64,
}

/// Owned variant of [`DpopVerificationOptions`] for storing verification
/// options without lifetime constraints.
#[derive(Debug, Clone)]
pub struct DpopVerificationOptionsOwned {
    pub expected_access_token: Option<String>,
    pub expected_nonce: Option<String>,
    pub allowed_algorithms: Vec<Algorithm>,
    pub clock_skew_seconds: u64,
    pub max_age_seconds: u64,
}

impl DpopVerificationOptionsOwned {
    pub fn as_ref(&self) -> DpopVerificationOptions<'_> {
        DpopVerificationOptions {
            expected_access_token: self.expected_access_token.as_deref(),
            expected_nonce: self.expected_nonce.as_deref(),
            allowed_algorithms: &self.allowed_algorithms,
            clock_skew_seconds: self.clock_skew_seconds,
            max_age_seconds: self.max_age_seconds,
        }
    }
}

/// Request-level context for the unified verify path (RFC 9449 §7).
///
/// When the SDK's unified [`AuthplaneResource::verify_with_context`]
/// entrypoint receives a `DpopRequestContext`, it uses the token's
/// `cnf.jkt` claim to decide whether sender-constraint validation must
/// run:
///
/// * Token **without** `cnf.jkt`: the request context is informational —
///   verification succeeds as a bearer token and `proof` is ignored.
///   This is the catalog case
///   `rfc9449-bearer-token-with-request-context-and-no-proof-must-still-verify-as-bearer`.
/// * Token **with** `cnf.jkt` but `proof == None`: verification MUST
///   reject with [`VerifierError::DpopProofMissing`]. This is the
///   catalog case
///   `rfc9449-dpop-bound-token-with-request-context-and-no-proof-must-be-rejected-via-main-verify-path`.
/// * Token **with** `cnf.jkt` and `proof = Some(_)`: the proof is fully
///   validated, including `cnf.jkt` ↔ `jwk` thumbprint match and `ath`
///   binding against the access token.
///
/// [`AuthplaneResource::verify_with_context`]:
///     crate::resource::AuthplaneResource::verify_with_context
/// [`VerifierError::DpopProofMissing`]:
///     crate::verified_claims::VerifierError::DpopProofMissing
///
/// Carries only the request shape (RFC 9449 §4.3 inputs to `htm`/`htu`/`ath`
/// validation) plus the optional `nonce` echo. The replay store and other
/// DPoP policy knobs (`max_proof_age_seconds`, `clock_skew_seconds`,
/// `allowed_proof_algorithms`, `required`) live on the resource via
/// [`InboundDPoPOptions`] — per-resource policy, applied automatically.
///
/// All fields are private so every context carries the normalization
/// applied at construction (uppercased method; trimmed proof/nonce
/// with blanks collapsed to `None` — never `Some("")`). Read through
/// the same-named accessors.
#[derive(Clone, Debug)]
pub struct DpopRequestContext {
    pub(crate) method: String,
    pub(crate) url: String,
    pub(crate) proof: Option<String>,
    pub(crate) nonce: Option<String>,
}

impl DpopRequestContext {
    /// Build a request context from a single, already-extracted proof.
    ///
    /// Normalizes on construction: `method` is uppercased, `proof` and
    /// `nonce` are trimmed and blank values collapse to `None` — so a
    /// context can never carry `Some("")`, which downstream mode
    /// dispatch and proof verification would otherwise disagree about.
    ///
    /// When the proof comes from raw header values, use
    /// [`DpopRequestContext::from_header_values`] instead — it also
    /// enforces the RFC 9449 §4.3 #1 cardinality rule.
    pub fn new(method: &str, url: &str, proof: Option<&str>, nonce: Option<&str>) -> Self {
        Self {
            method: method.to_ascii_uppercase(),
            url: url.to_string(),
            proof: proof
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            nonce: nonce
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        }
    }

    /// The HTTP method (`htm`), uppercased at construction.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The request URL (`htu`).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The DPoP proof JWT, when the request carried exactly one.
    pub fn proof(&self) -> Option<&str> {
        self.proof.as_deref()
    }

    /// The `DPoP-Nonce` echo, when the request carried a non-blank one.
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// Build a request context from raw header values, enforcing
    /// RFC 9449 §4.3 #1: at most one `DPoP` header per request.
    ///
    /// * Zero non-blank values in `proofs` is the bearer-only path
    ///   (`proof = None`) — blank or empty header lines (as emitted by
    ///   some proxies) do not count as proofs.
    /// * Two or more reject with [`VerifierError::DpopMultipleProofs`],
    ///   surfaced as a `DPoP`-scheme challenge carrying
    ///   `error="invalid_dpop_proof"` (RFC 9449 §7.1).
    /// * RFC 9110 §5.3 lets an intermediary fold repeated field lines
    ///   into one comma-separated value, so each item is also split on
    ///   `,` before counting — a JWS compact serialization never
    ///   contains a literal comma, so the split is lossless. Two proofs
    ///   folded into one line by a proxy still reject.
    ///
    /// Framework adapters reduce to header extraction plus this call
    /// (`authplane-mcp`'s `dpop_request_context_from_axum` does exactly
    /// that); hand-rolled integrations get the same §4.3 enforcement by
    /// routing every inbound `DPoP` header value through `proofs`.
    pub fn from_header_values<I, T>(
        method: &str,
        url: &str,
        proofs: I,
        nonce: Option<&str>,
    ) -> Result<Self, VerifierError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let mut proof: Option<String> = None;
        for value in proofs {
            // Full split, not `splitn`: leading blank pieces would eat a
            // bounded split's budget and fold two trailing proofs into
            // one (",,a,b"). `split` is a lazy iterator and the loop
            // early-returns on the second non-blank piece, so the scan
            // stays O(header length) with no allocation.
            for piece in value.as_ref().split(',') {
                let piece = piece.trim();
                if piece.is_empty() {
                    continue;
                }
                if proof.is_some() {
                    return Err(VerifierError::DpopMultipleProofs);
                }
                proof = Some(piece.to_string());
            }
        }
        Ok(Self::new(method, url, proof.as_deref(), nonce))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDpopProof {
    pub jti: String,
    pub iat: i64,
    pub method: String,
    pub url: String,
    pub nonce: Option<String>,
    pub ath: Option<String>,
    pub jkt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
    /// RFC 9449 §4.2 — optional `exp` claim. When present the proof
    /// MUST be rejected if expired.
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
}

pub fn dpop_ath(access_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

pub fn create_dpop_proof(
    method: &str,
    target_url: &str,
    access_token: Option<&str>,
    options: &DpopProofOptions,
) -> Result<String, AuthplaneError> {
    ensure_supported_dpop_alg(options.algorithm)?;
    let normalized_method = method.trim().to_ascii_uppercase();
    if normalized_method.is_empty() {
        return Err(validation_error("DPoP method must not be empty"));
    }
    let normalized_url = normalize_htu(target_url).map_err(|message| validation_error(&message))?;
    let mut header = Header::new(options.algorithm);
    header.typ = Some(dpop_claims::TYP_DPOP_JWT.to_string());
    header.kid = options.key_id.clone();
    header.jwk = Some(
        serde_json::from_value::<Jwk>(options.public_jwk.clone())
            .map_err(|error| validation_error(&format!("invalid DPoP public_jwk: {error}")))?,
    );

    let iat = unix_now();
    let ttl = options.proof_ttl_seconds.unwrap_or(300);
    let claims = DpopClaims {
        htm: normalized_method,
        htu: normalized_url,
        iat,
        jti: Uuid::new_v4().to_string(),
        nonce: options.nonce.clone(),
        ath: access_token.map(dpop_ath),
        exp: Some(iat + ttl as i64),
    };

    let encoding_key = build_encoding_key(options)?;
    jsonwebtoken::encode(&header, &claims, &encoding_key)
        .map_err(|error| validation_error(&format!("failed to sign DPoP proof: {error}")))
}

pub fn verify_dpop_proof(
    proof: &str,
    expected_method: &str,
    expected_url: &str,
    options: DpopVerificationOptions<'_>,
) -> Result<VerifiedDpopProof, VerifierError> {
    let header = decode_header(proof).map_err(|error| VerifierError::InvalidClaims {
        message: format!("invalid DPoP header: {error}"),
    })?;
    let typ = header.typ.ok_or_else(|| VerifierError::InvalidClaims {
        message: "DPoP header missing typ".to_string(),
    })?;
    if typ != dpop_claims::TYP_DPOP_JWT {
        return Err(VerifierError::InvalidClaims {
            message: format!(
                "DPoP typ must be {}, got {typ:?}",
                dpop_claims::TYP_DPOP_JWT
            ),
        });
    }
    if !options.allowed_algorithms.contains(&header.alg) {
        return Err(VerifierError::InvalidClaims {
            message: format!("DPoP algorithm {:?} is not allowed", header.alg),
        });
    }
    if !SUPPORTED_DPOP_ALGORITHMS.contains(&header.alg) {
        return Err(VerifierError::InvalidClaims {
            message: format!(
                "DPoP algorithm {:?} is not in supported set {:?}",
                header.alg, SUPPORTED_DPOP_ALGORITHMS
            ),
        });
    }
    let jwk = header.jwk.ok_or_else(|| VerifierError::InvalidClaims {
        message: "DPoP header missing jwk".to_string(),
    })?;
    let decoding_key =
        DecodingKey::from_jwk(&jwk).map_err(|error| VerifierError::InvalidClaims {
            message: format!("invalid DPoP jwk: {error}"),
        })?;

    let mut validation = Validation::new(header.alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.required_spec_claims.clear();
    let decoded = decode::<DpopClaims>(proof, &decoding_key, &validation).map_err(|error| {
        VerifierError::InvalidSignature {
            message: format!("DPoP signature validation failed: {error}"),
        }
    })?;
    let claims = decoded.claims;

    let expected_method = expected_method.trim().to_ascii_uppercase();
    if claims.htm != expected_method {
        return Err(VerifierError::InvalidClaims {
            message: format!(
                "DPoP htm mismatch: expected {expected_method:?}, got {:?}",
                claims.htm
            ),
        });
    }
    let expected_url =
        normalize_htu(expected_url).map_err(|message| VerifierError::InvalidClaims { message })?;
    if claims.htu != expected_url {
        return Err(VerifierError::InvalidClaims {
            message: format!(
                "DPoP htu mismatch: expected {expected_url:?}, got {:?}",
                claims.htu
            ),
        });
    }

    let now = unix_now();
    let max_age = options.max_age_seconds as i64;
    let skew = options.clock_skew_seconds as i64;
    if claims.iat > now + skew {
        return Err(VerifierError::InvalidClaims {
            message: format!(
                "DPoP iat is in the future (iat={}, now={}, leeway={}s)",
                claims.iat, now, options.clock_skew_seconds
            ),
        });
    }
    if now - claims.iat > max_age + skew {
        return Err(VerifierError::InvalidClaims {
            message: format!(
                "DPoP proof is too old (iat={}, now={}, max_age={}s, skew={}s)",
                claims.iat, now, options.max_age_seconds, options.clock_skew_seconds
            ),
        });
    }
    // RFC 9449 §4.2 — honour `exp` when the AS includes it.
    if let Some(exp) = claims.exp
        && exp < now - skew
    {
        return Err(VerifierError::InvalidClaims {
            message: format!("DPoP proof has expired (exp={exp}, now={now}, skew={skew}s)"),
        });
    }
    if claims.jti.trim().is_empty() {
        return Err(VerifierError::InvalidClaims {
            message: "DPoP jti must not be empty".to_string(),
        });
    }

    match (options.expected_nonce, claims.nonce.as_deref()) {
        (Some(expected), Some(actual)) if expected == actual => {}
        (Some(expected), Some(actual)) => {
            return Err(VerifierError::InvalidClaims {
                message: format!("DPoP nonce mismatch: expected {expected:?}, got {actual:?}"),
            });
        }
        (Some(expected), None) => {
            return Err(VerifierError::InvalidClaims {
                message: format!("DPoP nonce {expected:?} required but missing"),
            });
        }
        (None, _) => {}
    }

    if let Some(token) = options.expected_access_token {
        let expected_ath = dpop_ath(token);
        let actual_ath = claims
            .ath
            .as_deref()
            .ok_or_else(|| VerifierError::InvalidClaims {
                message: "DPoP ath is required for token-bound verification".to_string(),
            })?;
        if expected_ath != actual_ath {
            return Err(VerifierError::InvalidClaims {
                message: "DPoP ath mismatch".to_string(),
            });
        }
    }

    let jwk_json =
        extract_jwk_header_json(proof).map_err(|message| VerifierError::InvalidClaims {
            message: format!("invalid DPoP jwk header: {message}"),
        })?;
    let jkt = jwk_thumbprint_sha256(&jwk_json).map_err(|message| VerifierError::InvalidClaims {
        message: format!("invalid DPoP jwk thumbprint: {message}"),
    })?;

    Ok(VerifiedDpopProof {
        jti: claims.jti,
        iat: claims.iat,
        method: claims.htm,
        url: claims.htu,
        nonce: claims.nonce,
        ath: claims.ath,
        jkt,
    })
}

/// Verify a DPoP proof and atomically register its `jti` with the supplied
/// replay store. Returns [`VerifierError::DpopReplayDetected`] if the
/// proof's `jti` had already been observed.
///
/// This is the async equivalent of [`verify_dpop_proof`] with
/// `replay_store` plumbed in. The proof's expiry (`iat + max_age`) is
/// passed to [`crate::DpopReplayStore::check_and_store`] as the entry's
/// expiry timestamp so stale entries can be evicted.
///
/// **For DPoP-bound access tokens** (`cnf.jkt` is set), callers MUST
/// compare the access token's `cnf.jkt` to the verified proof's `jkt` —
/// and they MUST do so BEFORE this function is called, or use the safer
/// [`verify_dpop_proof_with_jkt_and_replay`] which folds both checks
/// into one atomic operation. Doing the `cnf.jkt` check after this
/// function returns is unsafe: an attacker who knows a legitimate
/// `jti` value can submit a proof bearing that `jti` with the wrong
/// `jkt`; the `jti` will be registered in the replay store before the
/// caller's external `jkt` comparison runs, locking out the legitimate
/// proof carrying the same `jti`.
pub async fn verify_dpop_proof_with_replay(
    proof: &str,
    expected_method: &str,
    expected_url: &str,
    options: DpopVerificationOptions<'_>,
    replay_store: &dyn crate::dpop_replay::DpopReplayStore,
) -> Result<VerifiedDpopProof, VerifierError> {
    let verified = verify_dpop_proof(proof, expected_method, expected_url, options)?;
    let expires_at = verified.iat + options.max_age_seconds as i64;
    let stored = replay_store
        .check_and_store(&verified.jti, expires_at)
        .await?;
    if !stored {
        return Err(VerifierError::DpopReplayDetected);
    }
    Ok(verified)
}

/// Verify a DPoP proof, check that its `jkt` matches the expected value
/// **before** registering its `jti` in the replay store, then atomically
/// commit the `jti`. Use this when verifying a proof against a
/// DPoP-bound access token whose `cnf.jkt` claim must match.
///
/// The order of operations matters: an attacker who knows a legitimate
/// `jti` could otherwise submit a proof carrying that `jti` with the
/// wrong `jkt` and force the legitimate proof to be rejected as a
/// replay. By comparing `jkt` first, an attacker-supplied wrong-`jkt`
/// proof never reaches the replay store and the legitimate `jti` slot
/// remains available.
pub async fn verify_dpop_proof_with_jkt_and_replay(
    proof: &str,
    expected_method: &str,
    expected_url: &str,
    options: DpopVerificationOptions<'_>,
    expected_jkt: &str,
    replay_store: &dyn crate::dpop_replay::DpopReplayStore,
) -> Result<VerifiedDpopProof, VerifierError> {
    let verified = verify_dpop_proof(proof, expected_method, expected_url, options)?;
    if verified.jkt != expected_jkt {
        return Err(VerifierError::DpopBindingMismatch {
            message: format!(
                "DPoP cnf.jkt mismatch: token expects {:?}, proof has {:?}",
                expected_jkt, verified.jkt
            ),
        });
    }
    let expires_at = verified.iat + options.max_age_seconds as i64;
    let stored = replay_store
        .check_and_store(&verified.jti, expires_at)
        .await?;
    if !stored {
        return Err(VerifierError::DpopReplayDetected);
    }
    Ok(verified)
}

pub fn jwk_thumbprint_sha256(jwk: &Value) -> Result<String, String> {
    let kty = jwk
        .get(jwk_params::KTY)
        .and_then(Value::as_str)
        .ok_or_else(|| "jwk missing kty".to_string())?;
    let canonical = match kty {
        jwk_params::KTY_RSA => canonical_jwk_json(&[
            (jwk_params::E, get_required_jwk_field(jwk, jwk_params::E)?),
            (jwk_params::KTY, jwk_params::KTY_RSA),
            (jwk_params::N, get_required_jwk_field(jwk, jwk_params::N)?),
        ])?,
        jwk_params::KTY_EC => canonical_jwk_json(&[
            (
                jwk_params::CRV,
                get_required_jwk_field(jwk, jwk_params::CRV)?,
            ),
            (jwk_params::KTY, jwk_params::KTY_EC),
            (jwk_params::X, get_required_jwk_field(jwk, jwk_params::X)?),
            (jwk_params::Y, get_required_jwk_field(jwk, jwk_params::Y)?),
        ])?,
        jwk_params::KTY_OKP => canonical_jwk_json(&[
            (
                jwk_params::CRV,
                get_required_jwk_field(jwk, jwk_params::CRV)?,
            ),
            (jwk_params::KTY, jwk_params::KTY_OKP),
            (jwk_params::X, get_required_jwk_field(jwk, jwk_params::X)?),
        ])?,
        _ => return Err(format!("unsupported jwk kty {kty:?} for thumbprint")),
    };

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

fn get_required_jwk_field<'a>(jwk: &'a Value, field: &str) -> Result<&'a str, String> {
    jwk.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("jwk missing {field}"))
}

fn build_encoding_key(options: &DpopProofOptions) -> Result<EncodingKey, AuthplaneError> {
    let key = match options.algorithm {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            EncodingKey::from_rsa_pem(options.private_key_pem.as_bytes())
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            EncodingKey::from_ec_pem(options.private_key_pem.as_bytes())
        }
        Algorithm::EdDSA => EncodingKey::from_ed_pem(options.private_key_pem.as_bytes()),
        _ => {
            return Err(validation_error(&format!(
                "unsupported DPoP signing algorithm {:?}",
                options.algorithm
            )));
        }
    };
    key.map_err(|error| validation_error(&format!("invalid DPoP private key: {error}")))
}

fn canonical_jwk_json(fields: &[(&str, &str)]) -> Result<String, String> {
    let object = fields
        .iter()
        .map(|(key, value)| ((*key).to_string(), Value::String((*value).to_string())))
        .collect::<Map<String, Value>>();
    serde_json::to_string(&object).map_err(|error| error.to_string())
}

fn extract_jwk_header_json(proof: &str) -> Result<Value, String> {
    let header_segment = proof
        .split('.')
        .next()
        .ok_or_else(|| "malformed compact jwt".to_string())?;
    let decoded = URL_SAFE_NO_PAD
        .decode(header_segment)
        .map_err(|error| error.to_string())?;
    let header_json: Value = serde_json::from_slice(&decoded).map_err(|error| error.to_string())?;
    header_json
        .get("jwk")
        .cloned()
        .ok_or_else(|| "header missing jwk".to_string())
}

fn normalize_htu(raw: &str) -> Result<String, String> {
    let mut url = url::Url::parse(raw).map_err(|error| error.to_string())?;
    // RFC 9449 §4.3 step 10 expects htu to be the "URL of the resource the
    // request is targeted at", with query string and fragment stripped.
    // Userinfo (`user:pass@host`) carries credentials and is never part of
    // the resource identifier — strip it so a request that omits userinfo
    // and a request that includes it produce the same htu for matching.
    url.set_query(None);
    url.set_fragment(None);
    // `set_username` / `set_password` only return `Err(())` on cannot-be-a-base
    // URLs (e.g. `data:` / `mailto:`). DPoP `htu` is always an absolute http(s)
    // resource URL by RFC 9449 §4.2, so these always succeed for valid inputs;
    // for any pathological case the URL is left as-is (no userinfo to strip
    // means nothing to strip).
    let _ = url.set_username("");
    let _ = url.set_password(None);
    Ok(url.to_string())
}

use crate::time_utils::unix_now_secs_i64 as unix_now;

#[cfg(test)]
mod tests {
    use super::{
        DpopProofOptions, DpopRequestContext, DpopVerificationOptions, create_dpop_proof, dpop_ath,
        ensure_supported_dpop_alg, jwk_thumbprint_sha256, verify_dpop_proof,
        verify_dpop_proof_with_jkt_and_replay,
    };
    use crate::dpop_replay::{DpopReplayStore, InMemoryDpopReplayStore};
    use crate::{AuthplaneError, VerifierError};
    use jsonwebtoken::Algorithm;
    use serde_json::json;

    const TEST_PRIVATE_PEM: &str = include_str!("../tests/fixtures/test-private.pem");
    const TEST_EC_PRIVATE_PEM: &str = include_str!("../tests/fixtures/test-ec-private.pem");
    const TEST_RSA_N: &str = "pza1Jk6AXrea2P-TlgPStQO4PJ8H4mCz3qaW-PqscKygy31-_T-XNpYlH948O-hS3eN0bKLLKJetWx8bSWxBlMMW4DlV-vv32kO-phwPGE0BbQ2rMfZXfEKwKbcU_hTQv3_yfo6eugv3g_9bZR16MaNOWL0fWTmmcYoD7j8mODWoTgwGnHoriRE9wLgHOkXSJ-lnV4gR3Wa0HdI1Th91kve4mMC4DxxpzZ37xh5d0wyExHSb9bssowS70hts0JD-TX46MSpgVoCcZfBefyJ9JKoVgxVZ2aYGsdR8pwVRSRYUf2CYDvKyUZ8HfoWBv4JwBO0AVqT5Eb5F-X375fULQQ";
    const TEST_RSA_E: &str = "AQAB";
    const TEST_EC_X: &str = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";
    const TEST_EC_Y: &str = "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4";

    fn rsa_options(nonce: Option<&str>) -> DpopProofOptions {
        DpopProofOptions {
            private_key_pem: TEST_PRIVATE_PEM.to_string(),
            public_jwk: json!({
                "kty": "RSA",
                "kid": "test-kid",
                "use": "sig",
                "alg": "RS256",
                "n": TEST_RSA_N,
                "e": TEST_RSA_E
            }),
            algorithm: Algorithm::RS256,
            key_id: Some("test-kid".to_string()),
            nonce: nonce.map(ToString::to_string),
            proof_ttl_seconds: None,
        }
    }

    #[test]
    fn ath_is_base64url_sha256() {
        let ath = dpop_ath("abc123");
        assert_eq!(ath, "bKE9UspwyIPg8LsQHkJaiehiTeUdstI5JZOvaoQRgJA");
    }

    #[test]
    fn jwk_thumbprint_matches_expected_shape() {
        let jwk = json!({
            "kty": "RSA",
            "n": TEST_RSA_N,
            "e": TEST_RSA_E
        });
        let thumbprint = jwk_thumbprint_sha256(&jwk).expect("thumbprint");
        assert!(!thumbprint.is_empty());
    }

    #[test]
    fn create_dpop_proof_signs_compact_jwt() {
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            Some("token-value"),
            &rsa_options(Some("nonce-1")),
        )
        .expect("proof");
        assert_eq!(proof.split('.').count(), 3);
    }

    #[test]
    fn create_dpop_proof_supports_es256() {
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            None,
            &DpopProofOptions {
                private_key_pem: TEST_EC_PRIVATE_PEM.to_string(),
                public_jwk: json!({
                    "kty": "EC",
                    "kid": "ec-test-kid",
                    "use": "sig",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": TEST_EC_X,
                    "y": TEST_EC_Y
                }),
                algorithm: Algorithm::ES256,
                key_id: Some("ec-test-kid".to_string()),
                nonce: None,
                proof_ttl_seconds: None,
            },
        )
        .expect("proof");
        assert_eq!(proof.split('.').count(), 3);
    }

    #[test]
    fn verify_dpop_proof_accepts_valid_proof() {
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            Some("token-value"),
            &rsa_options(Some("nonce-1")),
        )
        .expect("proof");

        let verified = verify_dpop_proof(
            &proof,
            "POST",
            "https://api.example.com/mcp",
            DpopVerificationOptions {
                expected_access_token: Some("token-value"),
                expected_nonce: Some("nonce-1"),
                allowed_algorithms: &[Algorithm::RS256],
                clock_skew_seconds: 30,
                max_age_seconds: 300,
            },
        )
        .expect("valid proof");

        assert_eq!(verified.method, "POST");
        assert_eq!(verified.url, "https://api.example.com/mcp");
        assert_eq!(verified.nonce.as_deref(), Some("nonce-1"));
        assert_eq!(
            verified.ath.as_deref(),
            Some(dpop_ath("token-value").as_str())
        );
        assert!(!verified.jkt.is_empty());
    }

    #[test]
    fn verify_dpop_proof_rejects_wrong_nonce() {
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            Some("token-value"),
            &rsa_options(Some("nonce-1")),
        )
        .expect("proof");

        let err = verify_dpop_proof(
            &proof,
            "POST",
            "https://api.example.com/mcp",
            DpopVerificationOptions {
                expected_access_token: Some("token-value"),
                expected_nonce: Some("nonce-2"),
                allowed_algorithms: &[Algorithm::RS256],
                clock_skew_seconds: 30,
                max_age_seconds: 300,
            },
        )
        .expect_err("nonce mismatch should fail");
        assert!(err.to_string().contains("nonce mismatch"));
    }

    #[test]
    fn verify_dpop_proof_rejects_wrong_method() {
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            Some("token-value"),
            &rsa_options(None),
        )
        .expect("proof");

        let err = verify_dpop_proof(
            &proof,
            "GET",
            "https://api.example.com/mcp",
            DpopVerificationOptions {
                expected_access_token: Some("token-value"),
                expected_nonce: None,
                allowed_algorithms: &[Algorithm::RS256],
                clock_skew_seconds: 30,
                max_age_seconds: 300,
            },
        )
        .expect_err("method mismatch should fail");
        assert!(err.to_string().contains("htm mismatch"));
    }

    #[test]
    fn verify_dpop_proof_rejects_wrong_ath() {
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            Some("token-value"),
            &rsa_options(None),
        )
        .expect("proof");

        let err = verify_dpop_proof(
            &proof,
            "POST",
            "https://api.example.com/mcp",
            DpopVerificationOptions {
                expected_access_token: Some("other-token"),
                expected_nonce: None,
                allowed_algorithms: &[Algorithm::RS256],
                clock_skew_seconds: 30,
                max_age_seconds: 300,
            },
        )
        .expect_err("ath mismatch should fail");
        assert!(err.to_string().contains("ath mismatch"));
    }

    #[test]
    fn create_dpop_proof_rejects_empty_method() {
        let err = create_dpop_proof("", "https://api.example.com/mcp", None, &rsa_options(None))
            .expect_err("empty method should fail");
        assert!(err.to_string().contains("method must not be empty"));
    }

    #[test]
    fn verify_dpop_proof_rejects_missing_required_nonce() {
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            Some("token-value"),
            &rsa_options(None),
        )
        .expect("proof");

        let err = verify_dpop_proof(
            &proof,
            "POST",
            "https://api.example.com/mcp",
            DpopVerificationOptions {
                expected_access_token: Some("token-value"),
                expected_nonce: Some("nonce-required"),
                allowed_algorithms: &[Algorithm::RS256],
                clock_skew_seconds: 30,
                max_age_seconds: 300,
            },
        )
        .expect_err("missing nonce should fail");
        assert!(err.to_string().contains("required but missing"));
    }

    #[test]
    fn verify_dpop_proof_rejects_disallowed_algorithm() {
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            Some("token-value"),
            &rsa_options(None),
        )
        .expect("proof");

        let err = verify_dpop_proof(
            &proof,
            "POST",
            "https://api.example.com/mcp",
            DpopVerificationOptions {
                expected_access_token: Some("token-value"),
                expected_nonce: None,
                allowed_algorithms: &[Algorithm::ES256],
                clock_skew_seconds: 30,
                max_age_seconds: 300,
            },
        )
        .expect_err("disallowed alg should fail");
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn ensure_supported_dpop_alg_accepts_es256_and_rs256() {
        ensure_supported_dpop_alg(Algorithm::ES256).expect("ES256 supported");
        ensure_supported_dpop_alg(Algorithm::RS256).expect("RS256 supported");
    }

    #[test]
    fn ensure_supported_dpop_alg_rejects_other_algorithms() {
        let err = ensure_supported_dpop_alg(Algorithm::HS256)
            .expect_err("HS256 must be rejected for outbound DPoP");
        let AuthplaneError::Auth(auth_error) = err else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "validation_error");
        assert!(auth_error.message.contains("HS256"));
        assert!(auth_error.message.contains("ES256"));
        assert!(auth_error.message.contains("RS256"));
    }

    /// Regression: a wrong-jkt proof must NOT register its jti in the replay
    /// store. An attacker who knows a legitimate jti could otherwise submit
    /// a proof carrying that jti with the wrong jkt; the previous
    /// `verify_dpop_proof_with_replay` registered the jti before any jkt
    /// comparison ran, locking out the legitimate proof carrying the same
    /// jti as a "replay". The new `verify_dpop_proof_with_jkt_and_replay`
    /// compares jkt FIRST and leaves the slot free on mismatch.
    #[tokio::test]
    async fn verify_dpop_proof_with_jkt_and_replay_leaves_jti_slot_free_on_jkt_mismatch() {
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            Some("token-value"),
            &rsa_options(None),
        )
        .expect("proof");

        // Peek the proof's jti without touching the replay store.
        let peeked = verify_dpop_proof(
            &proof,
            "POST",
            "https://api.example.com/mcp",
            DpopVerificationOptions {
                expected_access_token: Some("token-value"),
                expected_nonce: None,
                allowed_algorithms: &[Algorithm::RS256],
                clock_skew_seconds: 30,
                max_age_seconds: 300,
            },
        )
        .expect("peek");

        let replay_store = InMemoryDpopReplayStore::new();

        // Submit with the WRONG jkt — must fail BEFORE the jti commit.
        let err = verify_dpop_proof_with_jkt_and_replay(
            &proof,
            "POST",
            "https://api.example.com/mcp",
            DpopVerificationOptions {
                expected_access_token: Some("token-value"),
                expected_nonce: None,
                allowed_algorithms: &[Algorithm::RS256],
                clock_skew_seconds: 30,
                max_age_seconds: 300,
            },
            "definitely-not-the-real-jkt",
            &replay_store,
        )
        .await
        .expect_err("wrong jkt must reject");

        assert!(matches!(err, VerifierError::DpopBindingMismatch { .. }));

        // The jti slot must still be free: a fresh check_and_store with the
        // peeked jti returns true (newly stored). If the buggy old order had
        // run, this would return false (slot already taken) and the
        // legitimate proof would be locked out as a replay.
        let stored = replay_store
            .check_and_store(&peeked.jti, peeked.iat + 300)
            .await
            .expect("check_and_store");
        assert!(
            stored,
            "wrong-jkt proof leaked its jti into the replay store"
        );
    }

    #[test]
    fn from_header_values_zero_proofs_is_bearer_path() {
        let ctx = DpopRequestContext::from_header_values(
            "post",
            "https://api.example.com/mcp",
            Vec::<&str>::new(),
            None,
        )
        .expect("zero proofs is valid");
        assert_eq!(ctx.method, "POST");
        assert_eq!(ctx.url, "https://api.example.com/mcp");
        assert_eq!(ctx.proof, None);
        assert_eq!(ctx.nonce, None);
    }

    #[test]
    fn from_header_values_single_proof_is_trimmed() {
        let ctx = DpopRequestContext::from_header_values(
            "POST",
            "https://api.example.com/mcp",
            ["  proof-jwt  "],
            Some(" server-nonce "),
        )
        .expect("one proof is valid");
        assert_eq!(ctx.proof.as_deref(), Some("proof-jwt"));
        assert_eq!(ctx.nonce.as_deref(), Some("server-nonce"));
    }

    #[test]
    fn from_header_values_multiple_proofs_rejected() {
        // RFC 9449 §4.3 #1 — more than one DPoP header value rejects
        // before any proof validation.
        let err = DpopRequestContext::from_header_values(
            "POST",
            "https://api.example.com/mcp",
            ["first", "second"],
            None,
        )
        .expect_err("two proofs must reject");
        assert!(matches!(err, VerifierError::DpopMultipleProofs));
    }

    #[test]
    fn from_header_values_comma_folded_proofs_rejected() {
        // RFC 9110 §5.3 — a proxy may fold two DPoP field lines into one
        // comma-separated value. Still two proofs, still §4.3 #1. The
        // ",,first,second" shape guards against a bounded split whose
        // budget is eaten by leading blank pieces.
        for folded in ["first,second", "first, second", ",,first,second"] {
            let err = DpopRequestContext::from_header_values(
                "POST",
                "https://api.example.com/mcp",
                [folded],
                None,
            )
            .expect_err("comma-folded proofs must reject");
            assert!(matches!(err, VerifierError::DpopMultipleProofs));
        }
    }

    #[test]
    fn from_header_values_blank_line_does_not_count_as_proof() {
        // An empty `DPoP:` line emitted by a proxy must not turn a
        // legitimate single-proof request into a §4.3 rejection.
        let ctx = DpopRequestContext::from_header_values(
            "POST",
            "https://api.example.com/mcp",
            ["", "proof-jwt"],
            None,
        )
        .expect("blank line plus one proof is a single-proof request");
        assert_eq!(ctx.proof(), Some("proof-jwt"));
    }

    #[test]
    fn from_header_values_whitespace_only_proof_is_bearer_path() {
        // A lone whitespace-only DPoP header normalizes to proof-absent —
        // never `Some("")`, which mode dispatch and proof verification
        // would disagree about.
        let ctx = DpopRequestContext::from_header_values(
            "POST",
            "https://api.example.com/mcp",
            ["   "],
            None,
        )
        .expect("whitespace-only header is proof-absent");
        assert_eq!(ctx.proof(), None);
    }

    #[test]
    fn new_normalizes_blank_proof_to_none() {
        let ctx = DpopRequestContext::new("post", "https://api.example.com/mcp", Some("  "), None);
        assert_eq!(ctx.proof(), None);
        assert_eq!(ctx.method, "POST");
    }
}
