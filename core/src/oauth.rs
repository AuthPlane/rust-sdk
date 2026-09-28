use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::constants::{
    auth_schemes, http_headers, http_methods, introspection_fields, jwt_claims, media_types,
};
use crate::errors::{
    AuthError, AuthplaneError, map_oauth_error, protocol_error, transport_error, validation_error,
};
use crate::fetch_settings::FetchSettings;
use crate::transport::validate_fetch_url;

pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TokenExchangeOptions {
    pub subject_token: String,
    pub subject_token_type: String,
    pub actor_token: String,
    pub actor_token_type: String,
    pub scope: String,
    pub resources: Vec<String>,
    pub audiences: Vec<String>,
}

impl TokenExchangeOptions {
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.resources.retain(|value| !value.is_empty());
        normalized.audiences.retain(|value| !value.is_empty());
        normalized
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "TokenResponseWire")]
#[non_exhaustive]
pub struct TokenResponse {
    // Field-level `#[serde(default)]` is intentionally omitted: deserialization
    // is routed through `TokenResponseWire` by `#[serde(from)]` above, and the
    // wire type carries its own per-field defaults. Re-declaring `default` here
    // would be inert (dead for deserialize, ignored for serialize).
    pub access_token: String,
    pub token_type: String,
    /// AS-supplied lifetime hint in seconds (RFC 6749 §5.1).
    ///
    /// * `None` — the AS omitted the field. The cache layer applies its
    ///   configured `default_ttl`.
    /// * `Some(0)` — the AS asked for immediate expiry (RFC 6749 §5.1
    ///   permits this for one-shot flows). The cache refuses to store.
    /// * `Some(n)` with `n > 0` — use `n` seconds, then apply the buffer.
    ///
    /// On the wire, `None` is omitted entirely (the field is absent from
    /// the JSON), matching what the AS would have sent — so serializing a
    /// cached `TokenResponse` round-trips through the same parse path
    /// that produced it.
    ///
    /// ```
    /// # use authplane_sdk::oauth::TokenResponse;
    /// # fn dispatch(resp: TokenResponse) {
    /// match resp.expires_in {
    ///     None => { /* AS gave no hint — apply default TTL */ }
    ///     Some(0) => { /* explicit immediate expiry — do not cache */ }
    ///     Some(_n) => { /* use n seconds */ }
    /// }
    /// # }
    /// ```
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    pub scope: String,
    pub refresh_token: String,
    pub issued_token_type: String,
    /// Raw `cnf` (confirmation) object from the token response when
    /// present. RFC 9449 §6.1 places `cnf.jkt` here for DPoP-bound
    /// tokens; this field preserves any extension members
    /// (`x5t#S256`, future additions) verbatim. Only `Some` when the
    /// AS sent a JSON object; non-object `cnf` values are dropped.
    pub cnf: Option<Value>,
    /// Convenience accessor for the DPoP key thumbprint at
    /// `cnf.jkt` (RFC 9449 §6.1). Empty string when the token is
    /// not DPoP-bound. Always derived from `cnf.jkt` on deserialize
    /// via `#[serde(from = "TokenResponseWire")]`, matching the
    /// imperative `parse_token_response_inner` path through
    /// `extract_cnf_and_jkt` — a top-level `cnf_jkt` on the wire is
    /// not honoured, so a poisoned blob that disagrees with its own
    /// `cnf` object cannot mint a mismatched thumbprint.
    pub cnf_jkt: String,
}

/// Private wire shape for [`TokenResponse`]: derived `Deserialize`. The
/// public type's `#[serde(from)]` runs the `cnf.jkt` → `cnf_jkt`
/// derivation in `From<TokenResponseWire>` so constructed and
/// deserialized values agree on the binding. A top-level `cnf_jkt` on
/// the wire is intentionally absent from this struct: it is ignored by
/// serde's default unknown-field policy so the thumbprint is always
/// derived from `cnf` and the two constructors stay symmetric.
#[derive(Deserialize)]
struct TokenResponseWire {
    access_token: String,
    token_type: String,
    #[serde(default, deserialize_with = "deserialize_optional_expires_in")]
    expires_in: Option<i64>,
    scope: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    issued_token_type: String,
    #[serde(default)]
    cnf: Option<Value>,
}

impl From<TokenResponseWire> for TokenResponse {
    fn from(wire: TokenResponseWire) -> Self {
        let (cnf, cnf_jkt) = normalize_cnf(wire.cnf);
        Self {
            access_token: wire.access_token,
            token_type: wire.token_type,
            expires_in: wire.expires_in,
            scope: wire.scope,
            refresh_token: wire.refresh_token,
            issued_token_type: wire.issued_token_type,
            cnf,
            cnf_jkt,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "IntrospectionResponseWire")]
#[non_exhaustive]
pub struct IntrospectionResponse {
    // Field-level `#[serde(default)]` is intentionally omitted here for the
    // same reason as on [`TokenResponse`]: deserialization is routed through
    // `IntrospectionResponseWire` by `#[serde(from)]` above.
    pub active: bool,
    pub scope: String,
    pub client_id: String,
    pub sub: String,
    pub token_type: String,
    pub iss: String,
    pub aud: Option<Value>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub jti: String,
    pub agent_id: String,
    pub agent_chain: Vec<String>,
    /// Raw `cnf` (confirmation) object from the RFC 7662 introspection
    /// response. RFC 9449 §6.2 places the DPoP key thumbprint at
    /// `cnf.jkt`; this field preserves the full object so callers can
    /// read extension members (`x5t#S256`, future additions). Only
    /// `Some` when the AS sent a JSON object; non-object `cnf` values
    /// are dropped to keep the typed shape honest.
    pub cnf: Option<Value>,
    /// Convenience accessor for the DPoP key thumbprint at
    /// `cnf.jkt` (RFC 9449 §6.2 / RFC 7662). Empty string when
    /// absent. Always derived from `cnf.jkt` on deserialize via
    /// `#[serde(from = "IntrospectionResponseWire")]` — see the
    /// matching note on [`TokenResponse::cnf_jkt`].
    pub cnf_jkt: String,
}

/// Private wire shape for [`IntrospectionResponse`]. A top-level
/// `cnf_jkt` on the wire is intentionally absent: it is ignored by
/// serde's default unknown-field policy so the thumbprint is always
/// derived from `cnf` and the imperative `introspect_token` path
/// (via `extract_cnf_and_jkt`) agrees byte-for-byte with the
/// `From<IntrospectionResponseWire>` impl.
#[derive(Deserialize)]
struct IntrospectionResponseWire {
    active: bool,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    iss: String,
    #[serde(default)]
    aud: Option<Value>,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    jti: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    agent_chain: Vec<String>,
    #[serde(default)]
    cnf: Option<Value>,
}

impl From<IntrospectionResponseWire> for IntrospectionResponse {
    fn from(wire: IntrospectionResponseWire) -> Self {
        let (cnf, cnf_jkt) = normalize_cnf(wire.cnf);
        Self {
            active: wire.active,
            scope: wire.scope,
            client_id: wire.client_id,
            sub: wire.sub,
            token_type: wire.token_type,
            iss: wire.iss,
            aud: wire.aud,
            exp: wire.exp,
            iat: wire.iat,
            jti: wire.jti,
            agent_id: wire.agent_id,
            agent_chain: wire.agent_chain,
            cnf,
            cnf_jkt,
        }
    }
}

pub fn parse_token_exchange_error(status_code: Option<u16>, body: &str) -> AuthplaneError {
    let parsed: Result<Value, _> = serde_json::from_str(body);
    match parsed {
        Ok(payload) => map_oauth_error(status_code, &payload),
        Err(_) => AuthplaneError::Auth(AuthError {
            message: "OAuth request failed".to_string(),
            code: "invalid_response".to_string(),
            status_code,
        }),
    }
}

/// Parse an OAuth 2.0 token response.
///
/// When `expect_dpop` is `true` (a DPoP proof was sent with the request),
/// the response `token_type` **must** be `"DPoP"` per RFC 9449 §5. If the
/// AS returns `"Bearer"` instead, this function returns a `ProtocolError`
/// so the caller knows the proof was silently ignored.
pub fn parse_token_response(
    data: &Value,
    allow_issued_token_type: bool,
) -> Result<TokenResponse, AuthplaneError> {
    parse_token_response_inner(data, allow_issued_token_type, false)
}

/// Same as [`parse_token_response`] with DPoP-type enforcement.
pub fn parse_token_response_dpop(
    data: &Value,
    allow_issued_token_type: bool,
) -> Result<TokenResponse, AuthplaneError> {
    parse_token_response_inner(data, allow_issued_token_type, true)
}

fn parse_token_response_inner(
    data: &Value,
    allow_issued_token_type: bool,
    expect_dpop: bool,
) -> Result<TokenResponse, AuthplaneError> {
    let access_token = required_string(data, "access_token")?;
    let token_type = required_string(data, "token_type")?;
    if !token_type.eq_ignore_ascii_case(auth_schemes::BEARER)
        && !token_type.eq_ignore_ascii_case(auth_schemes::DPOP)
    {
        return Err(protocol_error(&format!(
            "unsupported token_type {token_type:?}; only {} and {} are supported",
            auth_schemes::BEARER,
            auth_schemes::DPOP
        )));
    }
    if expect_dpop && !token_type.eq_ignore_ascii_case(auth_schemes::DPOP) {
        return Err(protocol_error(&format!(
            "DPoP proof was sent but token_type is {token_type:?}, not {:?}; \
             the authorization server may have ignored the DPoP proof (RFC 9449 §5)",
            auth_schemes::DPOP
        )));
    }

    let issued_token_type = optional_string(data, "issued_token_type");
    if allow_issued_token_type {
        if issued_token_type.is_empty() {
            return Err(protocol_error(
                "token exchange response missing required 'issued_token_type' (RFC 8693 §2.2.1)",
            ));
        }
        if issued_token_type != TOKEN_TYPE_ACCESS_TOKEN {
            return Err(protocol_error(&format!(
                "unsupported issued_token_type {issued_token_type:?}; only access_token is supported"
            )));
        }
    }

    let (cnf, cnf_jkt) = extract_cnf_and_jkt(data);

    Ok(TokenResponse {
        access_token,
        token_type,
        expires_in: optional_non_negative_i64(data, "expires_in")?,
        scope: optional_string(data, "scope"),
        refresh_token: optional_string(data, "refresh_token"),
        issued_token_type,
        cnf,
        cnf_jkt,
    })
}

pub async fn client_credentials_grant(
    http: &Client,
    token_endpoint: &str,
    auth_header: &str,
    fetch_settings: &FetchSettings,
    scopes: &[String],
    resources: &[String],
    dpop_provider: Option<&crate::dpop_provider::DpopProvider>,
) -> Result<TokenResponse, AuthplaneError> {
    let form = build_client_credentials_form(scopes, resources);

    let expect_dpop = dpop_provider.is_some();
    let (status, payload) = form_post_with_dpop(
        http,
        token_endpoint,
        "token endpoint",
        &form,
        auth_header,
        fetch_settings,
        dpop_provider,
        // No access token to bind via `ath` — this call IS the one
        // that mints it. AS endpoints don't require `ath` per
        // RFC 9449 §4.2 (ath is for resource-server requests).
        None,
    )
    .await?;

    if crate::transport::is_http_success(status) {
        return if expect_dpop {
            parse_token_response_dpop(&payload, false)
        } else {
            parse_token_response(&payload, false)
        };
    }

    Err(map_oauth_error(Some(status), &payload))
}

pub async fn exchange_token(
    http: &Client,
    token_endpoint: &str,
    options: &TokenExchangeOptions,
    auth_header: &str,
    fetch_settings: &FetchSettings,
    dpop_provider: Option<&crate::dpop_provider::DpopProvider>,
) -> Result<TokenResponse, AuthplaneError> {
    if options.subject_token.is_empty() {
        return Err(validation_error("subject_token is required"));
    }

    let normalized = options.normalized();
    let form = build_token_exchange_form(&normalized);

    let expect_dpop = dpop_provider.is_some();
    let (status, payload) = form_post_with_dpop(
        http,
        token_endpoint,
        "token endpoint",
        &form,
        auth_header,
        fetch_settings,
        dpop_provider,
        None,
    )
    .await?;

    if crate::transport::is_http_success(status) {
        return if expect_dpop {
            parse_token_response_dpop(&payload, true)
        } else {
            parse_token_response(&payload, true)
        };
    }

    Err(map_oauth_error(Some(status), &payload))
}

/// RFC 7662 §2.1 introspection call.
///
/// `auth_header` is sent verbatim; an empty string sends no credentials
/// (RFC 7662 leaves the authentication method to the deployment). Against
/// authserver >= 0.1.2 that path is not useful: only the issuing client or
/// a runtime-client of the Resource named in `aud` gets a real answer, and
/// an unauthenticated or public-client caller receives `{"active": false}`
/// for every token. Resource servers should introspect with confidential
/// credentials via [`crate::RevocationConfig`].
pub async fn introspect_token(
    http: &Client,
    introspection_endpoint: &str,
    token: &str,
    auth_header: &str,
    fetch_settings: &FetchSettings,
    dpop_provider: Option<&crate::dpop_provider::DpopProvider>,
) -> Result<IntrospectionResponse, AuthplaneError> {
    let form = [
        (
            crate::constants::oauth_params::TOKEN.to_string(),
            token.to_string(),
        ),
        (
            crate::constants::oauth_params::TOKEN_TYPE_HINT.to_string(),
            crate::constants::oauth_errors::TOKEN_TYPE_HINT_ACCESS_TOKEN.to_string(),
        ),
    ];
    let (status, payload) = form_post_with_dpop(
        http,
        introspection_endpoint,
        "introspection endpoint",
        &form,
        auth_header,
        fetch_settings,
        dpop_provider,
        None,
    )
    .await?;

    if crate::transport::is_http_success(status) {
        let (cnf, cnf_jkt) = extract_cnf_and_jkt(&payload);
        return Ok(IntrospectionResponse {
            active: payload
                .get(introspection_fields::ACTIVE)
                .and_then(Value::as_bool)
                .unwrap_or(false),
            scope: optional_string(&payload, introspection_fields::SCOPE),
            client_id: optional_string(&payload, jwt_claims::CLIENT_ID),
            sub: optional_string(&payload, jwt_claims::SUB),
            token_type: optional_string(&payload, introspection_fields::TOKEN_TYPE),
            iss: optional_string(&payload, jwt_claims::ISS),
            aud: payload.get(jwt_claims::AUD).cloned(),
            exp: payload.get(jwt_claims::EXP).and_then(Value::as_i64),
            iat: payload.get(jwt_claims::IAT).and_then(Value::as_i64),
            jti: optional_string(&payload, jwt_claims::JTI),
            agent_id: optional_string(&payload, jwt_claims::AGENT_ID),
            agent_chain: crate::json_util::string_array(&payload, jwt_claims::AGENT_CHAIN),
            cnf,
            cnf_jkt,
        });
    }

    Err(map_oauth_error(Some(status), &payload))
}

pub async fn revoke_token(
    http: &Client,
    revocation_endpoint: &str,
    token: &str,
    auth_header: &str,
    fetch_settings: &FetchSettings,
    dpop_provider: Option<&crate::dpop_provider::DpopProvider>,
) -> Result<(), AuthplaneError> {
    let form = [
        (
            crate::constants::oauth_params::TOKEN.to_string(),
            token.to_string(),
        ),
        (
            crate::constants::oauth_params::TOKEN_TYPE_HINT.to_string(),
            crate::constants::oauth_errors::TOKEN_TYPE_HINT_ACCESS_TOKEN.to_string(),
        ),
    ];
    let (status, payload) = form_post_with_dpop(
        http,
        revocation_endpoint,
        "revocation endpoint",
        &form,
        auth_header,
        fetch_settings,
        dpop_provider,
        None,
    )
    .await?;

    if crate::transport::is_http_success(status) {
        return Ok(());
    }

    Err(map_oauth_error(Some(status), &payload))
}

fn required_string(data: &Value, key: &str) -> Result<String, AuthplaneError> {
    let value = optional_string(data, key);
    if value.is_empty() {
        return Err(protocol_error(&format!(
            "token response missing required field {key:?}"
        )));
    }
    Ok(value)
}

fn optional_string(data: &Value, key: &str) -> String {
    data.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Extract the raw `cnf` confirmation object and its `jkt` thumbprint from
/// an OAuth response payload. Non-object `cnf` values are dropped so the
/// typed shape stays honest; absent `cnf.jkt` collapses to an empty string,
/// matching the `#[serde(default)]` contract on the field itself.
///
/// Convenience over [`normalize_cnf`] for the imperative `parse_*` paths
/// that already hold the full payload as a `Value`.
fn extract_cnf_and_jkt(payload: &Value) -> (Option<Value>, String) {
    normalize_cnf(payload.get("cnf").cloned())
}

/// Shared `(Option<Value>, String)` derivation for an already-extracted
/// `cnf` field. Used by both [`extract_cnf_and_jkt`] (which pulls `cnf`
/// off a full payload) and the `From<*Wire>` impls (which receive `cnf`
/// directly from serde). Non-object values are dropped; missing `jkt`
/// becomes the empty string.
fn normalize_cnf(cnf: Option<Value>) -> (Option<Value>, String) {
    let cnf = cnf.filter(Value::is_object);
    let cnf_jkt = cnf
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|map| map.get("jkt"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    (cnf, cnf_jkt)
}

/// Parse a non-negative integer field that may legitimately be absent.
///
/// Returns `None` when the field is missing or JSON `null` (the AS did not
/// supply the hint), `Some(N)` for a present value including an explicit
/// `Some(0)` (RFC 6749 §5.1 permits `expires_in: 0` for one-shot flows).
/// Negative values and non-integer / non-string types are rejected.
/// Errors the shared parse helper can emit. Stringly-typed so each caller
/// wraps the message into its own error type without leaking
/// `AuthplaneError` into the `serde` path.
enum ParseOptionalI64Error {
    NotAnInteger { got: Option<String> },
    Negative,
}

/// Parses a JSON value as an optional non-negative `i64`, accepting both
/// JSON numbers and stringly-encoded numerics. Shared by the
/// `parse_token_response` path and the `serde(deserialize_with = ...)`
/// shim so both entry points apply the same validation.
///
/// * Returns `Ok(None)` when the value is `Value::Null` (or absent).
/// * Returns `Ok(Some(n))` for `n ≥ 0`.
/// * Returns `Err` for any non-integer / non-string shape and for
///   negative values.
fn parse_optional_non_negative_i64(value: &Value) -> Result<Option<i64>, ParseOptionalI64Error> {
    if value.is_null() {
        return Ok(None);
    }
    let parsed = if let Some(number) = value.as_i64() {
        number
    } else if let Some(text) = value.as_str() {
        text.parse::<i64>()
            .map_err(|_| ParseOptionalI64Error::NotAnInteger {
                got: Some(text.to_string()),
            })?
    } else {
        return Err(ParseOptionalI64Error::NotAnInteger { got: None });
    };
    if parsed < 0 {
        return Err(ParseOptionalI64Error::Negative);
    }
    Ok(Some(parsed))
}

/// `parse_token_response`-side adapter — wraps
/// [`parse_optional_non_negative_i64`] errors as protocol errors with
/// the offending field name.
fn optional_non_negative_i64(data: &Value, key: &str) -> Result<Option<i64>, AuthplaneError> {
    let value = data.get(key).unwrap_or(&Value::Null);
    parse_optional_non_negative_i64(value).map_err(|err| match err {
        ParseOptionalI64Error::NotAnInteger { got: Some(text) } => protocol_error(&format!(
            "token response field {key:?} must be an integer, got {text:?}"
        )),
        ParseOptionalI64Error::NotAnInteger { got: None } => {
            protocol_error(&format!("token response field {key:?} must be an integer"))
        }
        ParseOptionalI64Error::Negative => protocol_error(&format!(
            "token response field {key:?} must be non-negative"
        )),
    })
}

/// `serde(deserialize_with = ...)` shim — wraps
/// [`parse_optional_non_negative_i64`] errors as serde errors so callers
/// who deserialize a `TokenResponse` directly (e.g. from a cached JSON
/// payload) get the same validation as `parse_token_response` from a
/// fresh AS response.
fn deserialize_optional_expires_in<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let raw: Option<Value> = Option::deserialize(deserializer)?;
    let value = raw.unwrap_or(Value::Null);
    parse_optional_non_negative_i64(&value).map_err(|err| match err {
        ParseOptionalI64Error::NotAnInteger { got: Some(text) } => {
            D::Error::custom(format!("expires_in must be an integer, got {text:?}"))
        }
        ParseOptionalI64Error::NotAnInteger { got: None } => {
            D::Error::custom("expires_in must be an integer")
        }
        ParseOptionalI64Error::Negative => D::Error::custom("expires_in must be non-negative"),
    })
}

/// Send a form POST with optional DPoP proof and automatic nonce retry.
///
/// If a `DpopProvider` is supplied, the function:
/// 1. Builds a DPoP proof for the endpoint (using the provider's
///    current per-origin nonce, if any),
/// 2. Sends the request,
/// 3. Extracts `DPoP-Nonce` from the response headers and stores it
///    on the provider,
/// 4. If the AS returned `use_dpop_nonce` with a fresh nonce on the
///    error response (RFC 9449 §6.1), retries the request once with
///    a proof rebuilt using the new nonce. A single retry is enough:
///    once the provider has the AS nonce, subsequent calls reuse it
///    via `current_nonce`.
///
/// Returns `(status, payload)`. The single retry is intentionally
/// not exposed as a knob; servers that send `use_dpop_nonce`
/// repeatedly are out-of-spec and we surface the error to the
/// caller rather than loop.
#[allow(clippy::too_many_arguments)] // each arg is load-bearing for the §6.1 retry contract
pub(crate) async fn form_post_with_dpop(
    http: &Client,
    url: &str,
    url_label: &str,
    form: &[(String, String)],
    auth_header: &str,
    fetch_settings: &FetchSettings,
    dpop_provider: Option<&crate::dpop_provider::DpopProvider>,
    dpop_access_token: Option<&str>,
) -> Result<(u16, Value), AuthplaneError> {
    validate_fetch_url(url, fetch_settings, url_label)?;

    let initial_dpop = match dpop_provider {
        Some(provider) => Some(provider.build_proof(http_methods::POST, url, dpop_access_token)?),
        None => None,
    };

    let (status, payload, nonce) =
        do_form_post(http, url, form, auth_header, initial_dpop.as_deref()).await?;

    // Store DPoP-Nonce from response.
    if let Some(provider) = dpop_provider {
        if !nonce.is_empty() {
            let _ = provider.note_nonce(url, &nonce);
        }

        // Retry on use_dpop_nonce error (RFC 9449 §6.1).
        let error_code = payload
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if error_code == crate::constants::oauth_errors::USE_DPOP_NONCE && !nonce.is_empty() {
            let retry_proof = provider.build_proof(http_methods::POST, url, dpop_access_token)?;
            let (status2, payload2, nonce2) =
                do_form_post(http, url, form, auth_header, Some(&retry_proof)).await?;
            // Also refresh the stored nonce from the retry response so the
            // next outbound call starts with the freshest server-issued value.
            // RFC 9449 §6.1 permits the AS to rotate nonces on every response;
            // absorbing the retry's `DPoP-Nonce` here avoids a second
            // guaranteed-stale request when the AS rotates aggressively.
            if !nonce2.is_empty() {
                let _ = provider.note_nonce(url, &nonce2);
            }
            return Ok((status2, payload2));
        }
    }

    Ok((status, payload))
}

/// Low-level form POST. Returns (status, body, dpop_nonce_header).
async fn do_form_post(
    http: &Client,
    url: &str,
    form: &[(String, String)],
    auth_header: &str,
    dpop_proof: Option<&str>,
) -> Result<(u16, Value, String), AuthplaneError> {
    let mut request = http
        .post(url)
        .header(http_headers::AUTHORIZATION, auth_header)
        .header(http_headers::ACCEPT, media_types::APPLICATION_JSON);
    if let Some(proof) = dpop_proof {
        request = request.header(http_headers::DPOP, proof);
    }
    let response = request
        .form(form)
        .send()
        .await
        .map_err(|error| transport_error(&error.to_string()))?;
    let status = response.status().as_u16();
    let nonce = response
        .headers()
        .get(http_headers::DPOP_NONCE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    // RFC 7009 §2.2 revocation responses are typically 200 with no body, and a
    // server can send an empty success body on any of these form-POST endpoints.
    // Treat an empty body as `{}` rather than erroring on `serde_json::from_slice`
    // so a spec-conformant revoke doesn't surface as `Err(transport_error)`.
    let bytes = response
        .bytes()
        .await
        .map_err(|error| transport_error(&error.to_string()))?;
    let payload: Value = if bytes.is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_slice(&bytes).map_err(|error| transport_error(&error.to_string()))?
    };
    Ok((status, payload, nonce))
}

#[doc(hidden)]
pub fn build_client_credentials_form(
    scopes: &[String],
    resources: &[String],
) -> Vec<(String, String)> {
    use crate::constants::oauth_params::*;
    let mut form = vec![(
        GRANT_TYPE.to_string(),
        GRANT_TYPE_CLIENT_CREDENTIALS.to_string(),
    )];
    if !scopes.is_empty() {
        form.push((SCOPE.to_string(), scopes.join(" ")));
    }
    for resource in resources.iter().filter(|value| !value.is_empty()) {
        form.push((RESOURCE.to_string(), resource.clone()));
    }
    form
}

#[doc(hidden)]
pub fn build_token_exchange_form(options: &TokenExchangeOptions) -> Vec<(String, String)> {
    use crate::constants::oauth_params::*;
    let mut form = vec![
        (
            GRANT_TYPE.to_string(),
            GRANT_TYPE_TOKEN_EXCHANGE.to_string(),
        ),
        (SUBJECT_TOKEN.to_string(), options.subject_token.clone()),
        (
            SUBJECT_TOKEN_TYPE.to_string(),
            if options.subject_token_type.is_empty() {
                TOKEN_TYPE_ACCESS_TOKEN.to_string()
            } else {
                options.subject_token_type.clone()
            },
        ),
    ];

    if !options.actor_token.is_empty() {
        form.push((ACTOR_TOKEN.to_string(), options.actor_token.clone()));
        form.push((
            ACTOR_TOKEN_TYPE.to_string(),
            if options.actor_token_type.is_empty() {
                TOKEN_TYPE_ACCESS_TOKEN.to_string()
            } else {
                options.actor_token_type.clone()
            },
        ));
    }
    if !options.scope.is_empty() {
        form.push((SCOPE.to_string(), options.scope.clone()));
    }
    for resource in &options.resources {
        form.push((RESOURCE.to_string(), resource.clone()));
    }
    for audience in &options.audiences {
        form.push((AUDIENCE.to_string(), audience.clone()));
    }
    form
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{AuthplaneError, parse_token_exchange_error};

    use super::{
        GRANT_TYPE_TOKEN_EXCHANGE, IntrospectionResponse, TOKEN_TYPE_ACCESS_TOKEN,
        TokenExchangeOptions, TokenResponse, build_client_credentials_form,
        build_token_exchange_form, parse_token_response,
    };

    #[test]
    fn maps_consent_required_to_typed_error() {
        let body = r#"{
            "error":"consent_required",
            "error_description":"Consent needed",
            "service_id":"drive",
            "cause":"approval_needed",
            "consent_url":"https://consent.example.com/start"
        }"#;

        let error = parse_token_exchange_error(Some(400), body);
        let AuthplaneError::ConsentRequired(consent) = error else {
            panic!("expected consent required");
        };

        assert_eq!(consent.code, "consent_required");
        assert_eq!(consent.service_id, "drive");
        assert_eq!(consent.cause_detail, "approval_needed");
        assert_eq!(
            consent.consent_url.as_deref(),
            Some("https://consent.example.com/start")
        );
    }

    #[test]
    fn maps_interaction_required_to_typed_error() {
        let body = r#"{
            "error":"interaction_required",
            "error_description":"User interaction required",
            "service":"calendar"
        }"#;

        let error = parse_token_exchange_error(Some(400), body);
        let AuthplaneError::ConsentRequired(consent) = error else {
            panic!("expected consent required");
        };

        assert_eq!(consent.code, "interaction_required");
        assert_eq!(consent.service_id, "calendar");
        assert_eq!(consent.cause_detail, "User interaction required");
        assert_eq!(consent.consent_url, None);
    }

    #[test]
    fn maps_invalid_json_to_invalid_response_auth_error() {
        let error = parse_token_exchange_error(Some(500), "{invalid-json");
        let AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };

        assert_eq!(auth_error.code, "invalid_response");
        assert_eq!(auth_error.message, "OAuth request failed");
        assert_eq!(auth_error.status_code, Some(500));
    }

    #[test]
    fn maps_non_consent_error_to_auth_error() {
        let body = r#"{
            "error":"invalid_target",
            "error_description":"target missing"
        }"#;
        let error = parse_token_exchange_error(Some(400), body);
        let AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };

        assert_eq!(auth_error.code, "invalid_target");
        assert_eq!(auth_error.message, "target missing");
        assert!(auth_error.is_invalid_target());
        assert!(!auth_error.is_access_denied());
        assert!(!crate::should_open_circuit_for_oauth_error(
            &auth_error.code
        ));
    }

    /// authserver 0.2.0 answers a cross-client exchange whose client is
    /// not allowlisted on the target Resource with `access_denied` and
    /// HTTP 403. It is a plain `AuthError` — not `ConsentRequired`, since
    /// no user interaction can clear it — and must not trip the breaker.
    #[test]
    fn maps_access_denied_to_auth_error_outside_the_breaker() {
        let body = r#"{
            "error":"access_denied",
            "error_description":"client is not allowed to exchange for this resource"
        }"#;
        let error = parse_token_exchange_error(Some(403), body);
        let AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };

        assert_eq!(auth_error.code, "access_denied");
        assert_eq!(auth_error.status_code, Some(403));
        assert!(auth_error.is_access_denied());
        assert!(!auth_error.is_invalid_target());
        assert!(!crate::should_open_circuit_for_oauth_error(
            &auth_error.code
        ));
    }

    #[test]
    fn token_exchange_options_filter_empty_resource_and_audience_values() {
        let options = TokenExchangeOptions {
            subject_token: "subject".to_string(),
            resources: vec!["".to_string(), "https://api.example.com".to_string()],
            audiences: vec!["".to_string(), "api://billing".to_string()],
            ..TokenExchangeOptions::default()
        }
        .normalized();

        assert_eq!(
            options.resources,
            vec!["https://api.example.com".to_string()]
        );
        assert_eq!(options.audiences, vec!["api://billing".to_string()]);
    }

    #[test]
    fn client_credentials_form_includes_scope_and_resource() {
        let form = build_client_credentials_form(
            &["tools/read".to_string()],
            &["https://api.example.com".to_string()],
        );
        assert!(form.contains(&("grant_type".to_string(), "client_credentials".to_string())));
        assert!(form.contains(&("scope".to_string(), "tools/read".to_string())));
        assert!(form.contains(&(
            "resource".to_string(),
            "https://api.example.com".to_string()
        )));
    }

    #[test]
    fn token_exchange_form_applies_defaults_and_repeated_values() {
        let form = build_token_exchange_form(&TokenExchangeOptions {
            subject_token: "subject-token".to_string(),
            resources: vec![
                "https://api-one.example.com".to_string(),
                "https://api-two.example.com".to_string(),
            ],
            audiences: vec!["api://inventory".to_string()],
            ..TokenExchangeOptions::default()
        });

        assert!(form.contains(&(
            "grant_type".to_string(),
            GRANT_TYPE_TOKEN_EXCHANGE.to_string()
        )));
        assert!(form.contains(&(
            "subject_token_type".to_string(),
            TOKEN_TYPE_ACCESS_TOKEN.to_string()
        )));
        assert!(form.contains(&(
            "resource".to_string(),
            "https://api-one.example.com".to_string()
        )));
        assert!(form.contains(&(
            "resource".to_string(),
            "https://api-two.example.com".to_string()
        )));
        assert!(form.contains(&("audience".to_string(), "api://inventory".to_string())));
    }

    #[test]
    fn parse_token_response_requires_issued_token_type_for_exchange() {
        let payload = json!({
            "access_token": "new-token",
            "token_type": "Bearer"
        });

        let error = parse_token_response(&payload, true).expect_err("missing issued token type");
        let AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "protocol_error");
    }

    #[test]
    fn parse_token_response_preserves_issued_token_type() {
        let payload = json!({
            "access_token": "new-token",
            "token_type": "Bearer",
            "issued_token_type": TOKEN_TYPE_ACCESS_TOKEN
        });

        let response = parse_token_response(&payload, true).expect("valid token response");
        assert_eq!(response.issued_token_type, TOKEN_TYPE_ACCESS_TOKEN);
    }

    #[test]
    fn parse_token_response_rejects_unsupported_token_type() {
        let payload = json!({
            "access_token": "new-token",
            "token_type": "mac"
        });
        let error = parse_token_response(&payload, false).expect_err("must reject token type");
        let AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "protocol_error");
        assert!(auth_error.message.contains("unsupported token_type"));
    }

    #[test]
    fn parse_token_response_rejects_unsupported_issued_token_type() {
        let payload = json!({
            "access_token": "new-token",
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token"
        });
        let error =
            parse_token_response(&payload, true).expect_err("must reject issued token type");
        let AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "protocol_error");
        assert!(auth_error.message.contains("unsupported issued_token_type"));
    }

    #[test]
    fn parse_token_response_rejects_negative_expires_in() {
        let payload = json!({
            "access_token": "new-token",
            "token_type": "Bearer",
            "expires_in": -1
        });
        let error =
            parse_token_response(&payload, false).expect_err("must reject negative expires_in");
        let AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "protocol_error");
        assert!(auth_error.message.contains("must be non-negative"));
    }

    #[test]
    fn parse_token_response_rejects_non_integer_expires_in() {
        let payload = json!({
            "access_token": "new-token",
            "token_type": "Bearer",
            "expires_in": "abc"
        });
        let error =
            parse_token_response(&payload, false).expect_err("must reject non-integer expires_in");
        let AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "protocol_error");
        assert!(auth_error.message.contains("must be an integer"));
    }

    #[test]
    fn parse_token_response_missing_expires_in_becomes_none() {
        // A missing `expires_in` is a *signal*: the AS did not commit to a
        // lifetime hint. The cache layer uses this to apply its configured
        // `default_ttl`. Previously this field was defaulted to `0`, which
        // collided with the RFC 6749 §5.1 explicit-zero shape and silently
        // extended a deliberately-immediate-expiry token to one hour.
        let payload = json!({
            "access_token": "new-token",
            "token_type": "Bearer"
        });
        let response = parse_token_response(&payload, false).expect("valid response");
        assert_eq!(response.expires_in, None);
    }

    #[test]
    fn parse_token_response_explicit_zero_expires_in_becomes_some_zero() {
        // RFC 6749 §5.1 permits `expires_in: 0` for one-shot flows.
        // Distinguished from a missing hint via `Some(0)` vs `None`.
        let payload = json!({
            "access_token": "new-token",
            "token_type": "Bearer",
            "expires_in": 0
        });
        let response = parse_token_response(&payload, false).expect("valid response");
        assert_eq!(response.expires_in, Some(0));
    }

    #[test]
    fn client_credentials_form_emits_one_resource_per_value() {
        // RFC 8707 §2 — a client that needs multiple resources MUST emit
        // one `resource=` parameter per value, not a joined single string.
        let form = build_client_credentials_form(
            &["tools/read".to_string()],
            &[
                "https://api-one.example.com".to_string(),
                "https://api-two.example.com".to_string(),
            ],
        );
        let resource_entries: Vec<_> = form.iter().filter(|(k, _)| k == "resource").collect();
        assert_eq!(resource_entries.len(), 2);
        assert!(
            resource_entries
                .iter()
                .any(|(_, v)| v == "https://api-one.example.com")
        );
        assert!(
            resource_entries
                .iter()
                .any(|(_, v)| v == "https://api-two.example.com")
        );
    }

    #[test]
    fn client_credentials_form_space_joins_multiple_scopes() {
        // RFC 6749 §3.3 — multiple scope values MUST be space-delimited
        // (URL-encoding is handled by the HTTP client).
        let form = build_client_credentials_form(
            &["tools/read".to_string(), "tools/write".to_string()],
            &[],
        );
        let scope = form
            .iter()
            .find(|(k, _)| k == "scope")
            .map(|(_, v)| v.clone())
            .expect("scope must be present");
        assert_eq!(scope, "tools/read tools/write");
    }

    #[test]
    fn client_credentials_form_omits_empty_scope() {
        let form = build_client_credentials_form(&[], &[]);
        assert!(
            !form.iter().any(|(k, _)| k == "scope"),
            "scope must be omitted when empty"
        );
    }

    #[test]
    fn token_exchange_form_uses_token_exchange_grant_type() {
        let options = TokenExchangeOptions {
            subject_token: "subject-1".to_string(),
            ..TokenExchangeOptions::default()
        };
        let form = build_token_exchange_form(&options);
        assert!(form.contains(&(
            "grant_type".to_string(),
            GRANT_TYPE_TOKEN_EXCHANGE.to_string()
        )));
    }

    #[test]
    fn token_exchange_form_defaults_subject_token_type_when_missing() {
        // RFC 8693 §2.1 — when subject_token_type is not set by the
        // caller, the SDK MUST default to access-token.
        let options = TokenExchangeOptions {
            subject_token: "subject-1".to_string(),
            ..TokenExchangeOptions::default()
        };
        let form = build_token_exchange_form(&options);
        let subject_type = form
            .iter()
            .find(|(k, _)| k == "subject_token_type")
            .map(|(_, v)| v.clone())
            .expect("subject_token_type must be present");
        assert_eq!(subject_type, TOKEN_TYPE_ACCESS_TOKEN);
    }

    #[test]
    fn token_exchange_form_defaults_actor_token_type_only_when_actor_token_present() {
        // Actor token type default only applies when actor_token is set —
        // otherwise we must not emit a spurious actor_token_type.
        let with_actor = TokenExchangeOptions {
            subject_token: "subject-1".to_string(),
            actor_token: "actor-1".to_string(),
            ..TokenExchangeOptions::default()
        };
        let form = build_token_exchange_form(&with_actor);
        assert!(
            form.iter()
                .any(|(k, v)| k == "actor_token_type" && v == TOKEN_TYPE_ACCESS_TOKEN)
        );

        let without_actor = TokenExchangeOptions {
            subject_token: "subject-1".to_string(),
            ..TokenExchangeOptions::default()
        };
        let form = build_token_exchange_form(&without_actor);
        assert!(
            !form.iter().any(|(k, _)| k == "actor_token_type"),
            "actor_token_type must be omitted when actor_token is missing"
        );
    }

    #[test]
    fn token_exchange_form_normalizes_empty_resource_and_audience() {
        // Empty-string entries in resources/audiences must not reach the wire.
        let options = TokenExchangeOptions {
            subject_token: "subject-1".to_string(),
            resources: vec!["".to_string(), "https://api.example.com".to_string()],
            audiences: vec!["api://billing".to_string(), "".to_string()],
            ..TokenExchangeOptions::default()
        }
        .normalized();
        let form = build_token_exchange_form(&options);
        let resources: Vec<_> = form.iter().filter(|(k, _)| k == "resource").collect();
        let audiences: Vec<_> = form.iter().filter(|(k, _)| k == "audience").collect();
        assert_eq!(resources.len(), 1);
        assert_eq!(audiences.len(), 1);
    }

    #[test]
    fn parse_token_exchange_error_without_status_code_still_maps_to_auth_error() {
        let error = parse_token_exchange_error(None, "not json at all");
        let AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "invalid_response");
        assert_eq!(auth_error.status_code, None);
    }

    #[test]
    fn parse_token_exchange_error_401_maps_to_authentication_failure() {
        let body = r#"{"error":"invalid_client","error_description":"bad creds"}"#;
        let error = parse_token_exchange_error(Some(401), body);
        let AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "invalid_client");
        assert_eq!(auth_error.status_code, Some(401));
    }

    #[test]
    fn introspection_response_deserialize_derives_cnf_jkt_from_cnf_object() {
        // RFC 9449 §6.2 places the DPoP thumbprint at `cnf.jkt`.
        // Direct `serde_json::from_value` must surface it as
        // `cnf_jkt` so the typed shape matches what `introspect_token`
        // builds on the construction path. Previous behaviour left
        // `cnf_jkt` empty on direct deserialize — a footgun for any
        // cache/proxy that round-tripped the struct through JSON.
        let payload = json!({
            "active": true,
            "token_type": "DPoP",
            "cnf": {"jkt": "abc"},
        });
        let response: IntrospectionResponse = serde_json::from_value(payload).unwrap();
        assert!(response.active);
        assert_eq!(response.cnf_jkt, "abc");
        assert_eq!(
            response.cnf.and_then(|v| v.get("jkt").cloned()),
            Some(json!("abc"))
        );
    }

    #[test]
    fn introspection_response_deserializes_with_absent_cnf_defaults_to_empty() {
        let payload = json!({"active": true, "token_type": "Bearer"});
        let response: IntrospectionResponse = serde_json::from_value(payload).unwrap();
        assert!(response.active);
        assert_eq!(response.cnf, None);
        assert_eq!(response.cnf_jkt, "");
    }

    #[test]
    fn introspection_response_round_trips_cnf_binding_through_serde() {
        // to_value → from_value must preserve both `cnf` and
        // `cnf_jkt`. The two were asymmetric before the
        // `#[serde(from = "IntrospectionResponseWire")]` fix: a
        // caller building the struct via constructor saw `cnf_jkt`
        // populated, but the same struct after a JSON round-trip
        // through a cache layer had `cnf_jkt = ""` while `cnf` was
        // preserved — two shapes for the same wire payload.
        let payload = json!({
            "active": true,
            "token_type": "DPoP",
            "cnf": {"jkt": "thumbprint-abc"},
        });
        let first: IntrospectionResponse = serde_json::from_value(payload).unwrap();
        let serialized = serde_json::to_value(&first).unwrap();
        let second: IntrospectionResponse = serde_json::from_value(serialized).unwrap();
        assert_eq!(first, second);
        assert_eq!(second.cnf_jkt, "thumbprint-abc");
    }

    #[test]
    fn introspection_response_deserialize_drops_non_object_cnf() {
        // Defensive parity with `extract_cnf_and_jkt`: a malformed AS
        // sending `cnf` as a non-object scalar should not pollute the
        // typed shape; we drop the `cnf` and leave `cnf_jkt` empty.
        let payload = json!({"active": true, "cnf": "not-an-object"});
        let response: IntrospectionResponse = serde_json::from_value(payload).unwrap();
        assert_eq!(response.cnf, None);
        assert_eq!(response.cnf_jkt, "");
    }

    #[test]
    fn token_response_deserialize_derives_cnf_jkt_from_cnf_object() {
        // Same symmetric-deserialize fix as the introspection peer
        // above, applied to RFC 9449 §6.1 token responses.
        let payload = json!({
            "access_token": "at",
            "token_type": "DPoP",
            "expires_in": 3600,
            "scope": "tools/echo",
            "cnf": {"jkt": "thumbprint-token"},
        });
        let response: TokenResponse = serde_json::from_value(payload).unwrap();
        assert_eq!(response.cnf_jkt, "thumbprint-token");
        assert_eq!(
            response.cnf.and_then(|v| v.get("jkt").cloned()),
            Some(json!("thumbprint-token"))
        );
    }

    #[test]
    fn token_response_round_trips_cnf_binding_through_serde() {
        let payload = json!({
            "access_token": "at",
            "token_type": "DPoP",
            "expires_in": 3600,
            "scope": "tools/echo",
            "cnf": {"jkt": "thumbprint-token"},
        });
        let first: TokenResponse = serde_json::from_value(payload).unwrap();
        let serialized = serde_json::to_value(&first).unwrap();
        let second: TokenResponse = serde_json::from_value(serialized).unwrap();
        assert_eq!(first, second);
        assert_eq!(second.cnf_jkt, "thumbprint-token");
    }

    #[test]
    fn token_response_deserialize_ignores_wire_cnf_jkt_when_it_disagrees_with_cnf() {
        // A poisoned cache/persistence blob that carries both a `cnf.jkt`
        // and a mismatched top-level `cnf_jkt` must resolve to the
        // `cnf.jkt` thumbprint — the imperative `parse_token_response_inner`
        // path through `extract_cnf_and_jkt` always derives from `cnf`,
        // and the serde path is required to agree.
        let payload = json!({
            "access_token": "at",
            "token_type": "DPoP",
            "expires_in": 3600,
            "scope": "tools/echo",
            "cnf": {"jkt": "from-cnf"},
            "cnf_jkt": "poisoned-top-level",
        });
        let response: TokenResponse = serde_json::from_value(payload).unwrap();
        assert_eq!(response.cnf_jkt, "from-cnf");
    }

    #[test]
    fn introspection_response_deserialize_ignores_wire_cnf_jkt_when_it_disagrees_with_cnf() {
        let payload = json!({
            "active": true,
            "token_type": "DPoP",
            "cnf": {"jkt": "from-cnf"},
            "cnf_jkt": "poisoned-top-level",
        });
        let response: IntrospectionResponse = serde_json::from_value(payload).unwrap();
        assert_eq!(response.cnf_jkt, "from-cnf");
    }
}
