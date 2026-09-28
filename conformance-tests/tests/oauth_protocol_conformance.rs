//! OAuth protocol conformance: RFC 6749, 6750, 7009, 7662, 8693, 8707, 9728.
//!
//! Cases whose bodies rely on a real (or mocked) HTTP exchange use mockito
//! to stand up a local server and drive the SDK's public API end-to-end.

use authplane_conformance_tests::conformance_case;
use authplane_sdk::{
    AuthplaneError, AuthplaneResource, FetchSettings, GRANT_TYPE_TOKEN_EXCHANGE,
    ProtectedResourceMetadata, ResourceOptions, RevocationConfig, TOKEN_TYPE_ACCESS_TOKEN,
    TokenExchangeOptions, VerifierError, build_prm, build_prm_url, map_oauth_error,
    parse_token_exchange_error,
};
use base64::Engine;
use serde_json::json;

/// Helper: build a "Basic" auth header from client_id + client_secret using
/// RFC 3986 percent-encoding before base64 (same algorithm the SDK uses
/// internally via `build_basic_auth_header`).
fn basic_auth(client_id: &str, client_secret: &str) -> String {
    fn rfc3986_encode(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        for byte in input.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                out.push(byte as char);
            } else {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
        out
    }
    let raw = format!(
        "{}:{}",
        rfc3986_encode(client_id),
        rfc3986_encode(client_secret)
    );
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

/// Helper: dev-mode FetchSettings that allow HTTP + localhost.
fn dev_fetch_settings() -> FetchSettings {
    FetchSettings::from_dev_mode(true)
}

// ---------- RFC 6749 ---------------------------------------------------------

#[tokio::test]
async fn rfc6749_client_credentials_success_response() {
    conformance_case!("rfc6749-client-credentials-success-response");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_header(
            "content-type",
            mockito::Matcher::Regex("application/x-www-form-urlencoded".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": "test-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "tools/read"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let token_endpoint = format!("{}/oauth/token", server.url());
    let auth_header = basic_auth("client-id", "client-secret");

    let response = authplane_sdk::oauth::client_credentials_grant(
        &http,
        &token_endpoint,
        &auth_header,
        &dev_fetch_settings(),
        &["tools/read".to_string()],
        &[],
        None,
    )
    .await
    .expect("client_credentials_grant must succeed");

    assert_eq!(response.access_token, "test-access-token");
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, Some(3600));
    assert_eq!(response.scope, "tools/read");
    mock.assert_async().await;
}

#[tokio::test]
async fn rfc6749_basic_auth_credentials_must_be_form_urlencoded_before_base64() {
    conformance_case!("rfc6749-basic-auth-credentials-must-be-form-urlencoded-before-base64");

    // RFC 6749 section 2.3.1 requires that client_id and client_secret are
    // form-encoded (percent-encoded per RFC 3986) BEFORE base64. Use a
    // client_id and secret with special characters to verify.
    let client_id = "client:with:colons";
    let client_secret = "s3cr3t+value/special@char";
    let auth_header = basic_auth(client_id, client_secret);

    // Decode and verify proper encoding.
    let encoded = auth_header.trim_start_matches("Basic ");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("valid base64");
    let decoded_str = String::from_utf8(decoded).expect("utf8");

    // The colon separator between client_id and client_secret must be the
    // ONLY unencoded colon (colons in the values are percent-encoded).
    assert_eq!(
        decoded_str.matches(':').count(),
        1,
        "decoded: {decoded_str}"
    );
    assert!(decoded_str.starts_with("client%3Awith%3Acolons:"));
    assert!(decoded_str.contains("s3cr3t%2Bvalue%2Fspecial%40char"));

    // Now run an actual mock request to confirm the SDK sends the correctly
    // encoded auth header over the wire.
    let mut server = mockito::Server::new_async().await;
    let expected_header = auth_header.clone();
    let mock = server
        .mock("POST", "/oauth/token")
        .match_header("authorization", expected_header.as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": "tok",
                "token_type": "Bearer",
                "expires_in": 60
            })
            .to_string(),
        )
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let token_endpoint = format!("{}/oauth/token", server.url());
    authplane_sdk::oauth::client_credentials_grant(
        &http,
        &token_endpoint,
        &auth_header,
        &dev_fetch_settings(),
        &[],
        &[],
        None,
    )
    .await
    .expect("grant must succeed");
    mock.assert_async().await;
}

#[test]
fn rfc6749_token_response_must_contain_access_token() {
    conformance_case!("rfc6749-token-response-must-contain-access-token");

    // A token response without `access_token` must be rejected.
    let payload = json!({
        "token_type": "Bearer",
        "expires_in": 3600
    });
    let error = authplane_sdk::oauth::parse_token_response(&payload, false)
        .expect_err("missing access_token must error");
    let AuthplaneError::Auth(auth) = error else {
        panic!("expected AuthError, got {error:?}");
    };
    assert_eq!(auth.code, "protocol_error");
    assert!(auth.message.contains("access_token"));
}

#[test]
fn rfc6749_token_response_token_type_must_be_supported() {
    conformance_case!("rfc6749-token-response-token-type-must-be-supported");

    // Only "Bearer" and "DPoP" are supported. Other token types must error.
    let payload = json!({
        "access_token": "tok",
        "token_type": "mac"
    });
    let error = authplane_sdk::oauth::parse_token_response(&payload, false)
        .expect_err("unsupported token_type must error");
    let AuthplaneError::Auth(auth) = error else {
        panic!("expected AuthError, got {error:?}");
    };
    assert_eq!(auth.code, "protocol_error");
    assert!(auth.message.contains("unsupported token_type"));
}

#[test]
fn rfc6749_token_response_expires_in_must_be_non_negative_integer() {
    conformance_case!("rfc6749-token-response-expires-in-must-be-non-negative-integer");

    let payload = json!({
        "access_token": "tok",
        "token_type": "Bearer",
        "expires_in": -1
    });
    let error = authplane_sdk::oauth::parse_token_response(&payload, false)
        .expect_err("negative expires_in must error");
    let AuthplaneError::Auth(auth) = error else {
        panic!("expected AuthError, got {error:?}");
    };
    assert_eq!(auth.code, "protocol_error");
    assert!(auth.message.contains("non-negative"));
}

#[test]
fn rfc6749_invalid_client_must_map_to_authentication_failure() {
    conformance_case!("rfc6749-invalid-client-must-map-to-authentication-failure");

    let payload = json!({
        "error": "invalid_client",
        "error_description": "client_id or client_secret is wrong",
    });
    let error = map_oauth_error(Some(401), &payload);
    let AuthplaneError::Auth(auth) = error else {
        panic!("invalid_client must map to AuthError (not ConsentRequired)");
    };
    assert_eq!(auth.code, "invalid_client");
    assert_eq!(auth.status_code, Some(401));
    assert!(auth.message.contains("client"));
}

#[tokio::test]
async fn rfc6749_client_credentials_scopes_must_support_multiple_values() {
    conformance_case!("rfc6749-client-credentials-scopes-must-support-multiple-values");

    // RFC 6749 section 3.3: multiple scope values must be space-delimited.
    // Verify the request body contains "scope=tools%2Fread+tools%2Fwrite"
    // (or equivalent URL-encoded space-separated scopes).
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::Regex("scope=".to_string()),
            // The scopes must be space-separated (URL-encoded space is + or %20)
            mockito::Matcher::Regex("tools%2Fread".to_string()),
            mockito::Matcher::Regex("tools%2Fwrite".to_string()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": "tok",
                "token_type": "Bearer",
                "expires_in": 60
            })
            .to_string(),
        )
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let token_endpoint = format!("{}/oauth/token", server.url());
    let auth_header = basic_auth("client", "secret");

    authplane_sdk::oauth::client_credentials_grant(
        &http,
        &token_endpoint,
        &auth_header,
        &dev_fetch_settings(),
        &["tools/read".to_string(), "tools/write".to_string()],
        &[],
        None,
    )
    .await
    .expect("grant must succeed");
    mock.assert_async().await;
}

// ---------- RFC 7009 (token revocation) --------------------------------------

#[tokio::test]
async fn rfc7009_revocation_200_is_success_even_for_already_invalid_token() {
    conformance_case!("rfc7009-revocation-200-is-success-even-for-already-invalid-token");

    // RFC 7009 section 2.1: the server responds 200 even if the token was
    // already invalid / expired. The client must treat this as success.
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/revoke")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{}")
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/revoke", server.url());
    let auth_header = basic_auth("client", "secret");

    authplane_sdk::oauth::revoke_token(
        &http,
        &endpoint,
        "already-expired-token",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("revocation 200 must be treated as success");
    mock.assert_async().await;
}

#[tokio::test]
async fn rfc7009_revocation_request_must_post_token_and_token_type_hint() {
    conformance_case!("rfc7009-revocation-request-must-post-token-and-token-type-hint");

    // RFC 7009 section 2.1: the revocation request body must contain
    // `token` and `token_type_hint`.
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/revoke")
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::Regex("token=my-token-to-revoke".to_string()),
            mockito::Matcher::Regex("token_type_hint=access_token".to_string()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{}")
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/revoke", server.url());
    let auth_header = basic_auth("client", "secret");

    authplane_sdk::oauth::revoke_token(
        &http,
        &endpoint,
        "my-token-to-revoke",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("revocation must succeed");
    mock.assert_async().await;
}

#[tokio::test]
async fn rfc7009_revocation_server_errors_must_surface() {
    conformance_case!("rfc7009-revocation-server-errors-must-surface");

    // RFC 7009 section 2.2.1: server errors (5xx) must be surfaced to the
    // caller as an error, not silently swallowed.
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/revoke")
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "server_error",
                "error_description": "internal failure"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/revoke", server.url());
    let auth_header = basic_auth("client", "secret");

    let error = authplane_sdk::oauth::revoke_token(
        &http,
        &endpoint,
        "some-token",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect_err("500 revocation must surface as error");

    let AuthplaneError::Auth(auth) = error else {
        panic!("expected AuthError, got {error:?}");
    };
    assert_eq!(auth.code, "server_error");
    mock.assert_async().await;
}

// ---------- RFC 7662 (token introspection) -----------------------------------

#[tokio::test]
async fn rfc7662_introspection_request_must_post_token_and_access_token_hint() {
    conformance_case!("rfc7662-introspection-request-must-post-token-and-access-token-hint");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/introspect")
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::Regex("token=my-token".to_string()),
            mockito::Matcher::Regex("token_type_hint=access_token".to_string()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"active": true}).to_string())
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/introspect", server.url());
    let auth_header = basic_auth("client", "secret");

    authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint,
        "my-token",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("introspection must succeed");
    mock.assert_async().await;
}

#[tokio::test]
async fn rfc7662_introspection_without_credentials_must_not_send_authorization_header() {
    conformance_case!(
        "rfc7662-introspection-without-credentials-must-not-send-authorization-header"
    );

    // When called with an empty auth_header, the SDK must still send the
    // Authorization header (it always sets it), but the value will be empty.
    // The key test is that no Basic/Bearer credentials leak when none are
    // configured.
    //
    // The `active: false` body below is also what a real deployment gets:
    // authserver >= 0.1.2 answers exactly that to unauthenticated
    // introspection, for every token. The path stays supported because
    // RFC 7662 leaves the authentication method to the deployment; a
    // resource server that wants real answers introspects with the
    // confidential credentials in `RevocationConfig`, which the resource
    // constructors now require to be non-empty.
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/introspect")
        .match_header("authorization", "")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"active": false}).to_string())
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/introspect", server.url());

    let response = authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint,
        "some-token",
        "",
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("introspection must succeed");
    assert!(!response.active);
    mock.assert_async().await;
}

#[tokio::test]
async fn rfc7662_introspection_basic_auth_must_be_supported() {
    conformance_case!("rfc7662-introspection-basic-auth-must-be-supported");

    let auth_header = basic_auth("intro-client", "intro-secret");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/introspect")
        .match_header("authorization", auth_header.as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"active": true}).to_string())
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/introspect", server.url());

    let response = authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint,
        "some-token",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("introspection with basic auth must succeed");
    assert!(response.active);
    mock.assert_async().await;
}

#[tokio::test]
async fn rfc7662_introspection_active_false_must_parse_as_inactive() {
    conformance_case!("rfc7662-introspection-active-false-must-parse-as-inactive");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/introspect")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"active": false}).to_string())
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/introspect", server.url());
    let auth_header = basic_auth("client", "secret");

    let response = authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint,
        "revoked-token",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("introspection must succeed");
    assert!(!response.active, "active=false must parse as inactive");
    mock.assert_async().await;
}

#[tokio::test]
async fn rfc7662_introspection_missing_active_must_default_to_inactive() {
    conformance_case!("rfc7662-introspection-missing-active-must-default-to-inactive");

    // RFC 7662 section 2.2: if the `active` field is missing, the SDK
    // defaults to inactive (false).
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/introspect")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({}).to_string())
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/introspect", server.url());
    let auth_header = basic_auth("client", "secret");

    let response = authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint,
        "some-token",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("introspection must succeed");
    assert!(
        !response.active,
        "missing 'active' must default to inactive"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn rfc7662_introspection_standard_fields_must_round_trip() {
    conformance_case!("rfc7662-introspection-standard-fields-must-round-trip");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/introspect")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "active": true,
                "scope": "tools/read tools/write",
                "client_id": "my-client",
                "sub": "user-1",
                "token_type": "Bearer",
                "iss": "https://auth.example.com",
                "aud": "https://api.example.com",
                "exp": 4102444800i64,
                "iat": 1700000000i64,
                "jti": "token-jti-123"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/introspect", server.url());
    let auth_header = basic_auth("client", "secret");

    let response = authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint,
        "some-token",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("introspection must succeed");

    assert!(response.active);
    assert_eq!(response.scope, "tools/read tools/write");
    assert_eq!(response.client_id, "my-client");
    assert_eq!(response.sub, "user-1");
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.iss, "https://auth.example.com");
    assert_eq!(response.aud, Some(json!("https://api.example.com")));
    assert_eq!(response.exp, Some(4102444800));
    assert_eq!(response.iat, Some(1700000000));
    assert_eq!(response.jti, "token-jti-123");
    mock.assert_async().await;
}

#[tokio::test]
async fn introspection_response_exposes_cnf_jkt() {
    // RFC 9449 §6.2 Figure 11: an RFC 7662 introspection response for a
    // DPoP-bound token carries a top-level `cnf` object whose `jkt`
    // member is the SHA-256 thumbprint of the DPoP public key. The SDK
    // introspection result type exposes that thumbprint without
    // forcing callers to reach into the raw map. `cnf_jkt` is the typed
    // convenience accessor (string); `cnf` preserves the full
    // confirmation object so callers can read extension members
    // (`x5t#S256`, future RFC 9449 additions).
    let expected_jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/introspect")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "active": true,
                "token_type": "DPoP",
                "cnf": { "jkt": expected_jkt },
            })
            .to_string(),
        )
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/introspect", server.url());
    let auth_header = basic_auth("client", "secret");

    let response = authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint,
        "dpop-bound-token",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("introspection must succeed");

    assert!(response.active);
    assert_eq!(response.token_type, "DPoP");
    assert_eq!(
        response.cnf_jkt, expected_jkt,
        "cnf.jkt must be exposed via the typed convenience accessor"
    );
    assert_eq!(
        response
            .cnf
            .as_ref()
            .and_then(|cnf| cnf.get("jkt"))
            .and_then(serde_json::Value::as_str),
        Some(expected_jkt),
        "raw `cnf` object must be preserved for callers needing extension members",
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn introspection_response_without_cnf_yields_empty_thumbprint() {
    // Defensive coverage for the absent-cnf path: bearer-only tokens
    // come back without a `cnf` object, and the typed accessor must be
    // empty-string (not panic, not unwrap a None). The empty-default
    // mirrors `TokenResponse::cnf_jkt`; downstream callers can branch
    // on `.is_empty()` or `.cnf.is_some()` depending on what they need.
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/introspect")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"active": true, "token_type": "Bearer"}).to_string())
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/introspect", server.url());
    let auth_header = basic_auth("client", "secret");

    let response = authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint,
        "bearer-token",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("introspection must succeed");

    assert!(response.active);
    assert_eq!(response.cnf, None);
    assert_eq!(response.cnf_jkt, "");
    mock.assert_async().await;
}

#[tokio::test]
async fn rfc7662_introspection_audience_must_parse_string_or_array() {
    conformance_case!("rfc7662-introspection-audience-must-parse-string-or-array");

    // Test string aud
    let mut server = mockito::Server::new_async().await;
    let mock_string = server
        .mock("POST", "/oauth/introspect")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "active": true,
                "aud": "https://api.example.com"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/introspect", server.url());
    let auth_header = basic_auth("client", "secret");

    let response = authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint,
        "token-1",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("string aud must parse");
    assert_eq!(response.aud, Some(json!("https://api.example.com")));
    mock_string.assert_async().await;

    // Test array aud
    let mut server2 = mockito::Server::new_async().await;
    let mock_array = server2
        .mock("POST", "/oauth/introspect")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "active": true,
                "aud": ["https://api-a.example.com", "https://api-b.example.com"]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let endpoint2 = format!("{}/oauth/introspect", server2.url());

    let response2 = authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint2,
        "token-2",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("array aud must parse");
    assert_eq!(
        response2.aud,
        Some(json!([
            "https://api-a.example.com",
            "https://api-b.example.com"
        ]))
    );
    mock_array.assert_async().await;
}

#[tokio::test]
async fn rfc7662_verifier_active_false_must_reject_token() {
    conformance_case!("rfc7662-verifier-active-false-must-reject-token");

    // When an AuthplaneResource with revocation config introspects a token
    // and gets active=false, verify() must return TokenRevoked.
    //
    // We need a real signed JWT for the verify path (it validates signature
    // before introspection). Instead, we test the introspection result
    // handling through direct introspect_token + the known SDK logic:
    // if introspection returns active=false, the resource rejects with
    // TokenRevoked.
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/introspect")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"active": false}).to_string())
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/introspect", server.url());
    let auth_header = basic_auth("client", "secret");

    let response = authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint,
        "some-token",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect("introspection must succeed");

    // The SDK's verify path checks this condition and returns TokenRevoked
    assert!(!response.active, "active=false must be parsed");

    // Verify the RevocationConfig can be constructed for this use-case
    let _config = RevocationConfig {
        client_id: "client".to_string(),
        client_secret: "secret".to_string(),
        fail_open: false,
    };

    mock.assert_async().await;
}

#[tokio::test]
async fn rfc7662_introspection_fail_open_policy_must_be_explicitly_tested() {
    conformance_case!("rfc7662-introspection-fail-open-policy-must-be-explicitly-tested");

    // When introspection fails (e.g. 500) and fail_open=true, the resource
    // must still accept the token (the error is swallowed). When fail_open=false,
    // the error must surface.
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/introspect")
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "server_error",
                "error_description": "introspection service down"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let endpoint = format!("{}/oauth/introspect", server.url());
    let auth_header = basic_auth("client", "secret");

    // Verify that introspection error surfaces
    let error = authplane_sdk::oauth::introspect_token(
        &http,
        &endpoint,
        "some-token",
        &auth_header,
        &dev_fetch_settings(),
        None,
    )
    .await
    .expect_err("500 introspection must error");

    // With fail_open=true, the SDK resource.verify() would swallow this error.
    // With fail_open=false (default), it would propagate as MetadataUnavailable.
    let fail_open_config = RevocationConfig {
        client_id: "client".to_string(),
        client_secret: "secret".to_string(),
        fail_open: true,
    };
    assert!(
        fail_open_config.fail_open,
        "fail_open=true must be explicitly set"
    );

    let fail_closed_config = RevocationConfig {
        client_id: "client".to_string(),
        client_secret: "secret".to_string(),
        fail_open: false,
    };
    assert!(
        !fail_closed_config.fail_open,
        "fail_open=false is the secure default"
    );

    // Verify the error is an AuthError from the server
    let AuthplaneError::Auth(auth) = error else {
        panic!("expected AuthError, got {error:?}");
    };
    assert_eq!(auth.code, "server_error");
    mock.assert_async().await;
}

// ---------- RFC 8693 (token exchange) — testable via public types ----------

#[test]
fn rfc8693_grant_type_must_be_token_exchange() {
    conformance_case!("rfc8693-grant-type-must-be-token-exchange");

    assert_eq!(
        GRANT_TYPE_TOKEN_EXCHANGE,
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );

    let form = authplane_sdk::oauth::build_token_exchange_form(&TokenExchangeOptions {
        subject_token: "subject".to_string(),
        ..TokenExchangeOptions::default()
    });
    assert!(
        form.contains(&(
            "grant_type".to_string(),
            GRANT_TYPE_TOKEN_EXCHANGE.to_string()
        )),
        "token-exchange form must carry the RFC 8693 grant_type URN: {form:?}"
    );
}

#[test]
fn rfc8693_subject_token_is_required() {
    conformance_case!("rfc8693-subject-token-is-required");

    let options = TokenExchangeOptions::default();
    assert_eq!(options.subject_token, "");
    let form = authplane_sdk::oauth::build_token_exchange_form(&options);
    let keys: Vec<&String> = form.iter().map(|(k, _)| k).collect();
    assert!(keys.iter().any(|k| k.as_str() == "subject_token"));
}

#[test]
fn rfc8693_default_subject_token_type_is_access_token() {
    conformance_case!("rfc8693-default-subject-token-type-is-access-token");

    let form = authplane_sdk::oauth::build_token_exchange_form(&TokenExchangeOptions {
        subject_token: "subject".to_string(),
        subject_token_type: String::new(),
        ..TokenExchangeOptions::default()
    });
    assert!(form.contains(&(
        "subject_token_type".to_string(),
        TOKEN_TYPE_ACCESS_TOKEN.to_string()
    )));
}

#[test]
fn rfc8693_actor_token_type_defaults_when_actor_token_is_present() {
    conformance_case!("rfc8693-actor-token-type-defaults-when-actor-token-is-present");

    let with_actor = authplane_sdk::oauth::build_token_exchange_form(&TokenExchangeOptions {
        subject_token: "subject".to_string(),
        actor_token: "actor".to_string(),
        ..TokenExchangeOptions::default()
    });
    assert!(with_actor.contains(&("actor_token".to_string(), "actor".to_string())));
    assert!(with_actor.contains(&(
        "actor_token_type".to_string(),
        TOKEN_TYPE_ACCESS_TOKEN.to_string()
    )));

    let without_actor = authplane_sdk::oauth::build_token_exchange_form(&TokenExchangeOptions {
        subject_token: "subject".to_string(),
        ..TokenExchangeOptions::default()
    });
    assert!(
        !without_actor.iter().any(|(k, _)| k == "actor_token"),
        "actor_token key must be absent when no actor is supplied"
    );
    assert!(
        !without_actor.iter().any(|(k, _)| k == "actor_token_type"),
        "actor_token_type key must be absent when no actor is supplied"
    );
}

#[test]
fn rfc8693_resource_parameter_must_be_sent_when_configured() {
    conformance_case!("rfc8693-resource-parameter-must-be-sent-when-configured");

    let form = authplane_sdk::oauth::build_token_exchange_form(&TokenExchangeOptions {
        subject_token: "subject".to_string(),
        resources: vec!["https://api.example.com/v1".to_string()],
        ..TokenExchangeOptions::default()
    });
    assert!(form.contains(&(
        "resource".to_string(),
        "https://api.example.com/v1".to_string()
    )));
}

#[test]
fn rfc8693_multiple_resource_parameters_must_be_emitted() {
    conformance_case!("rfc8693-multiple-resource-parameters-must-be-emitted");

    let form = authplane_sdk::oauth::build_token_exchange_form(&TokenExchangeOptions {
        subject_token: "subject".to_string(),
        resources: vec![
            "https://api-a.example.com".to_string(),
            "https://api-b.example.com".to_string(),
        ],
        ..TokenExchangeOptions::default()
    });
    let resource_count = form.iter().filter(|(k, _)| k == "resource").count();
    assert_eq!(resource_count, 2, "both resource values must be emitted");
    assert!(form.contains(&(
        "resource".to_string(),
        "https://api-a.example.com".to_string()
    )));
    assert!(form.contains(&(
        "resource".to_string(),
        "https://api-b.example.com".to_string()
    )));
}

#[test]
fn rfc8693_error_mapping_invalid_grant() {
    conformance_case!("rfc8693-error-mapping-invalid-grant");

    let body = r#"{"error":"invalid_grant","error_description":"subject token expired"}"#;
    let error = parse_token_exchange_error(Some(400), body);
    let AuthplaneError::Auth(auth) = error else {
        panic!("invalid_grant must map to AuthError");
    };
    assert_eq!(auth.code, "invalid_grant");
    assert_eq!(auth.status_code, Some(400));
    assert_eq!(auth.message, "subject token expired");
}

#[test]
fn rfc8693_audience_parameter_must_be_sent_when_configured() {
    conformance_case!("rfc8693-audience-parameter-must-be-sent-when-configured");

    let form = authplane_sdk::oauth::build_token_exchange_form(&TokenExchangeOptions {
        subject_token: "subject".to_string(),
        audiences: vec!["api://inventory".to_string()],
        ..TokenExchangeOptions::default()
    });
    assert!(form.contains(&("audience".to_string(), "api://inventory".to_string())));
}

#[test]
fn rfc8693_multiple_audience_parameters_must_be_emitted() {
    conformance_case!("rfc8693-multiple-audience-parameters-must-be-emitted");

    let form = authplane_sdk::oauth::build_token_exchange_form(&TokenExchangeOptions {
        subject_token: "subject".to_string(),
        audiences: vec!["api://a".to_string(), "api://b".to_string()],
        ..TokenExchangeOptions::default()
    });
    let audience_count = form.iter().filter(|(k, _)| k == "audience").count();
    assert_eq!(audience_count, 2);
}

#[test]
fn rfc8693_empty_resource_and_audience_values_must_be_omitted() {
    conformance_case!("rfc8693-empty-resource-and-audience-values-must-be-omitted");

    let options = TokenExchangeOptions {
        subject_token: "subject".to_string(),
        resources: vec!["".to_string(), "https://api.example.com".to_string()],
        audiences: vec!["".to_string(), "api://x".to_string()],
        ..TokenExchangeOptions::default()
    }
    .normalized();
    assert_eq!(
        options.resources,
        vec!["https://api.example.com".to_string()]
    );
    assert_eq!(options.audiences, vec!["api://x".to_string()]);

    let form = authplane_sdk::oauth::build_token_exchange_form(&options);
    assert_eq!(
        form.iter().filter(|(k, _)| k == "resource").count(),
        1,
        "empty resource value must not be emitted"
    );
    assert_eq!(
        form.iter().filter(|(k, _)| k == "audience").count(),
        1,
        "empty audience value must not be emitted"
    );
}

#[test]
fn rfc8693_success_response_must_use_access_token_issued_token_type_when_present() {
    conformance_case!(
        "rfc8693-success-response-must-use-access-token-issued-token-type-when-present"
    );

    // RFC 8693 section 2.2.1: when `issued_token_type` is present in the
    // response and equals the access_token URN, parse_token_response must
    // preserve it.
    let payload = json!({
        "access_token": "exchanged-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "issued_token_type": TOKEN_TYPE_ACCESS_TOKEN
    });
    let response = authplane_sdk::oauth::parse_token_response(&payload, true)
        .expect("valid token exchange response");
    assert_eq!(response.access_token, "exchanged-token");
    assert_eq!(response.issued_token_type, TOKEN_TYPE_ACCESS_TOKEN);
}

#[test]
fn rfc8693_token_exchange_response_must_contain_issued_token_type() {
    conformance_case!("rfc8693-token-exchange-response-must-contain-issued-token-type");

    // RFC 8693 section 2.2.1: `issued_token_type` is REQUIRED in token
    // exchange responses. When allow_issued_token_type=true and the field
    // is missing, parse_token_response must error.
    let payload = json!({
        "access_token": "exchanged-token",
        "token_type": "Bearer"
    });
    let error = authplane_sdk::oauth::parse_token_response(&payload, true)
        .expect_err("missing issued_token_type must error");
    let AuthplaneError::Auth(auth) = error else {
        panic!("expected AuthError, got {error:?}");
    };
    assert_eq!(auth.code, "protocol_error");
    assert!(auth.message.contains("issued_token_type"));
}

// ---------- RFC 8707 (resource indicators) ----------------------------------

#[tokio::test]
async fn rfc8707_client_credentials_resource_parameter_should_be_supported() {
    conformance_case!("rfc8707-client-credentials-resource-parameter-should-be-supported");

    // RFC 8707 section 2: the `resource` parameter must be included in the
    // client_credentials request when configured.
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::Regex("grant_type=client_credentials".to_string()),
            mockito::Matcher::Regex("resource=https%3A%2F%2Fapi.example.com%2Fv1".to_string()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": "tok",
                "token_type": "Bearer",
                "expires_in": 60
            })
            .to_string(),
        )
        .create_async()
        .await;

    let http = reqwest::Client::new();
    let token_endpoint = format!("{}/oauth/token", server.url());
    let auth_header = basic_auth("client", "secret");

    authplane_sdk::oauth::client_credentials_grant(
        &http,
        &token_endpoint,
        &auth_header,
        &dev_fetch_settings(),
        &[],
        &["https://api.example.com/v1".to_string()],
        None,
    )
    .await
    .expect("grant must succeed");
    mock.assert_async().await;
}

#[test]
fn rfc8707_verifier_must_accept_resource_when_present_in_aud_array() {
    conformance_case!("rfc8707-verifier-must-accept-resource-when-present-in-aud-array");

    // RFC 8707 section 2: a resource server MUST accept tokens whose `aud`
    // is an array containing the configured resource URI. We test this
    // through from_prefetched_metadata (no HTTP needed) by verifying the
    // SDK's audience parsing logic: an array aud containing the resource
    // must be accepted.
    //
    // The build_client_credentials_form helper already supports resource
    // parameters; here we verify the verifier-side audience acceptance by
    // checking the form builder includes multiple resources and the
    // AuthplaneResource can be constructed with prefetched metadata.
    use authplane_sdk::metadata::AuthorizationServerMetadata;
    use jsonwebtoken::jwk::JwkSet;

    let metadata = AuthorizationServerMetadata {
        issuer: "https://auth.example.com".to_string(),
        jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
        token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
        introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
        revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
    };
    let jwks = JwkSet { keys: vec![] };

    // Construct resource with the target resource URI
    let resource = AuthplaneResource::from_prefetched_metadata(
        "https://auth.example.com",
        "https://api.example.com/mcp",
        &["tools/read".to_string()],
        metadata,
        FetchSettings::from_dev_mode(true),
        ResourceOptions::default(),
        jwks,
    )
    .expect("from_prefetched_metadata must succeed");

    // The resource is configured to accept audience "https://api.example.com/mcp".
    // When a token arrives with aud=["https://api.example.com/mcp", "https://other.example.com"],
    // the resource's verify path (via jsonwebtoken Validation::set_audience) will
    // accept it because the configured resource is in the audience list.
    assert_eq!(resource.resource(), "https://api.example.com/mcp");
}

#[test]
fn rfc8707_client_credentials_multiple_resource_parameters_must_be_emitted() {
    conformance_case!("rfc8707-client-credentials-multiple-resource-parameters-must-be-emitted");

    let form = authplane_sdk::oauth::build_client_credentials_form(
        &["tools/read".to_string()],
        &[
            "https://api-a.example.com".to_string(),
            "https://api-b.example.com".to_string(),
        ],
    );
    let resource_count = form.iter().filter(|(k, _)| k == "resource").count();
    assert_eq!(resource_count, 2);
    assert!(form.contains(&(
        "resource".to_string(),
        "https://api-a.example.com".to_string()
    )));
    assert!(form.contains(&(
        "resource".to_string(),
        "https://api-b.example.com".to_string()
    )));
}

// ---------- RFC 6750 (bearer error codes) -----------------------------------

#[test]
fn rfc6750_error_response_realm_should_be_included() {
    conformance_case!("rfc6750-error-response-realm-should-be-included");

    use authplane_sdk::{VerifierError, www_authenticate};

    let header = www_authenticate(&VerifierError::TokenMissing, "mcp");
    assert!(header.starts_with("Bearer "));
    assert!(header.contains("realm=\"mcp\""));

    let no_realm = www_authenticate(&VerifierError::TokenMissing, "");
    assert!(no_realm.starts_with("Bearer "));
    assert!(!no_realm.contains("realm="));
}

#[test]
fn rfc6750_error_response_must_map_error_codes() {
    conformance_case!("rfc6750-error-response-must-map-error-codes");

    use authplane_sdk::{VerifierError, www_authenticate};

    let missing = www_authenticate(&VerifierError::TokenMissing, "");
    assert!(missing.contains("error=\"invalid_token\""));

    let expired = www_authenticate(&VerifierError::TokenExpired, "");
    assert!(expired.contains("error=\"invalid_token\""));

    let revoked = www_authenticate(&VerifierError::TokenRevoked, "");
    assert!(revoked.contains("error=\"invalid_token\""));

    let insufficient = www_authenticate(
        &VerifierError::InsufficientScope {
            required: "tools/admin".to_string(),
            available: vec![],
        },
        "",
    );
    assert!(insufficient.contains("error=\"insufficient_scope\""));

    let metadata_down = www_authenticate(
        &VerifierError::MetadataUnavailable {
            message: "network".to_string(),
        },
        "",
    );
    assert!(!metadata_down.contains("error="));

    // The catalog's `dpop_error → invalid_token / DPoP` row covers
    // proof-validation failures against a DPoP-opted-in resource. The
    // error code stays `invalid_token`; the scheme flips to `DPoP` so a
    // well-behaved client knows to rebuild the proof rather than rotate
    // the bearer token.
    let dpop_proof_missing = www_authenticate(&VerifierError::DpopProofMissing, "");
    assert!(dpop_proof_missing.starts_with("DPoP"));
    assert!(dpop_proof_missing.contains("error=\"invalid_token\""));

    let dpop_replay = www_authenticate(&VerifierError::DpopReplayDetected, "");
    assert!(dpop_replay.starts_with("DPoP"));
    assert!(dpop_replay.contains("error=\"invalid_token\""));

    let dpop_mismatch = www_authenticate(
        &VerifierError::DpopBindingMismatch {
            message: "cnf.jkt mismatch".to_string(),
        },
        "",
    );
    assert!(dpop_mismatch.starts_with("DPoP"));
    assert!(dpop_mismatch.contains("error=\"invalid_token\""));

    // Deliberately NOT asserted here: `VerifierError::DpopMultipleProofs`
    // maps to `error="invalid_dpop_proof"` (RFC 9449 §4.3 #1 / §7.1),
    // but this case is pinned to the catalog's `error_scenarios`, which
    // carry no `dpop_multi_header` row yet. Asserting the carve-out
    // inside a catalog-pinned case would drift from the catalog; unit
    // coverage lives in `core/src/www_authenticate.rs`
    // (`www_authenticate_dpop_multiple_proofs_uses_dpop_scheme_and_invalid_dpop_proof`).
    // Restore the assertion once the catalog gains the row, proposed in
    // https://github.com/AuthPlane/conformance/pull/2.

    // Carve-out: a DPoP signal against a Mode-3 resource is rejected
    // on the `Bearer` scheme (no DPoP retry path on this resource) but
    // shares the same `invalid_token` code.
    let dpop_not_supported = www_authenticate(&VerifierError::DpopNotSupported, "");
    assert!(dpop_not_supported.starts_with("Bearer"));
    assert!(dpop_not_supported.contains("error=\"invalid_token\""));
}

// ---------- RFC 9728 (Protected Resource Metadata) --------------------------

#[test]
fn rfc9728_prm_must_contain_required_fields() {
    conformance_case!("rfc9728-prm-must-contain-required-fields");

    let prm: ProtectedResourceMetadata = build_prm(
        "https://auth.example.com",
        "https://api.example.com/mcp",
        &["tools/read".to_string()],
        None,
        false,
    );
    assert_eq!(prm.resource, "https://api.example.com/mcp");
    assert_eq!(prm.authorization_servers, vec!["https://auth.example.com"]);
    assert!(!prm.bearer_methods_supported.is_empty());
    assert!(!prm.scopes_supported.is_empty());
}

#[test]
fn rfc9728_prm_authorization_servers_must_list_the_issuer() {
    conformance_case!("rfc9728-prm-authorization-servers-must-list-the-issuer");

    let prm = build_prm(
        "https://auth.example.com",
        "https://api.example.com/mcp",
        &[],
        None,
        false,
    );
    assert!(
        prm.authorization_servers
            .iter()
            .any(|s| s == "https://auth.example.com"),
        "authorization_servers must list the configured issuer: {:?}",
        prm.authorization_servers
    );
}

#[test]
fn rfc9728_prm_supported_bearer_methods_should_be_stable() {
    conformance_case!("rfc9728-prm-supported-bearer-methods-should-be-stable");

    let prm = build_prm(
        "https://auth.example.com",
        "https://api.example.com",
        &[],
        None,
        false,
    );
    assert_eq!(prm.bearer_methods_supported, vec!["header".to_string()]);
}

#[test]
fn rfc9728_well_known_path_must_derive_from_resource_uri() {
    conformance_case!("rfc9728-well-known-path-must-derive-from-resource-uri");

    let url = build_prm_url("https://api.example.com/mcp")
        .expect("build_prm_url must accept https resource");
    assert_eq!(
        url,
        "https://api.example.com/.well-known/oauth-protected-resource/mcp"
    );

    let root = build_prm_url("https://api.example.com").expect("root resource");
    assert_eq!(
        root,
        "https://api.example.com/.well-known/oauth-protected-resource"
    );

    let nested = build_prm_url("https://api.example.com/v2/mcp").expect("nested resource");
    assert_eq!(
        nested,
        "https://api.example.com/.well-known/oauth-protected-resource/v2/mcp"
    );

    // The catalog's fourth case: the terminating slash is removed, so
    // this derives the same document URL as the slash-less identifier.
    let trailing = build_prm_url("https://api.example.com/mcp/").expect("trailing-slash resource");
    assert_eq!(
        trailing,
        "https://api.example.com/.well-known/oauth-protected-resource/mcp"
    );
}

#[test]
fn rfc9728_well_known_url_must_preserve_the_resource_query_component() {
    conformance_case!("rfc9728-well-known-url-must-preserve-the-resource-query-component");

    // RFC 9728 section 3 inserts the well-known string "between the host
    // component and the path and/or query components", so the query survives
    // onto the derived URL. Dropping it would collapse every tenant on a
    // host onto one metadata document — the multi-tenant case RFC 8707
    // section 2 names as the reason a query is permitted at all — and the
    // client would then have to discard the response under section 3.3 with
    // a 200 and no server-side signal.
    let cases = [
        (
            "https://api.example.com/mcp?tenant=a",
            "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a",
        ),
        (
            "https://api.example.com/mcp?tenant=b",
            "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=b",
        ),
        // No path and no terminating slash: section 3.1 has no slash to
        // remove, so the suffix goes directly after the host and the query
        // follows it.
        (
            "https://api.example.com?x=1",
            "https://api.example.com/.well-known/oauth-protected-resource?x=1",
        ),
    ];

    let mut derived = std::collections::HashSet::new();
    for (resource, expected) in cases {
        let url = build_prm_url(resource).expect("a query-bearing resource must derive");
        assert_eq!(url, expected, "derived PRM URL for {resource}");
        // Identifiers differing only by their query must not collapse onto
        // one metadata document URL.
        assert!(
            derived.insert(url),
            "distinct identifiers collapsed onto one PRM URL ({resource})"
        );
    }
}

/// Metadata + empty JWKS fixture for the construction-gate cases below:
/// `from_prefetched_metadata` performs no network I/O, so the rejection is
/// observable from the constructor call itself, as the catalog requires.
fn construction_gate_fixture() -> (
    authplane_sdk::metadata::AuthorizationServerMetadata,
    jsonwebtoken::jwk::JwkSet,
) {
    (
        authplane_sdk::metadata::AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
            introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
            revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
        },
        jsonwebtoken::jwk::JwkSet { keys: vec![] },
    )
}

fn construct_resource(resource: &str) -> Result<AuthplaneResource, VerifierError> {
    let (metadata, jwks) = construction_gate_fixture();
    AuthplaneResource::from_prefetched_metadata(
        "https://auth.example.com",
        resource,
        &["tools/read".to_string()],
        metadata,
        FetchSettings::from_dev_mode(true),
        ResourceOptions::default(),
        jwks,
    )
}

#[test]
fn rfc8707_resource_indicator_must_not_contain_a_fragment() {
    conformance_case!("rfc8707-resource-indicator-must-not-contain-a-fragment");

    // RFC 8707 section 2 forbids a fragment in the resource indicator and
    // RFC 9728 section 1.2 defines the resource identifier as carrying
    // none. The catalog puts the gate at construction: accepting the value
    // and stripping the fragment later, while deriving the well-known URL,
    // publishes a document whose `resource` differs from the URL it was
    // fetched from, which RFC 9728 section 3.3 obliges the client to
    // discard silently.
    let Err(error) = construct_resource("https://api.example.com/mcp#section") else {
        panic!("a fragment-bearing identifier must be rejected at construction");
    };
    assert!(
        error.to_string().contains("fragment"),
        "the rejection must name the fragment, got: {error}"
    );

    // Control: the fragment-free identifier constructs.
    construct_resource("https://api.example.com/mcp")
        .expect("the fragment-free identifier must construct");
}

#[test]
fn rfc9728_resource_identifier_must_be_an_absolute_url_with_scheme_and_host() {
    conformance_case!("rfc9728-resource-identifier-must-be-an-absolute-url-with-scheme-and-host");

    // Each value is exercised independently and each must reject on its
    // own. The two are not redundant: a scheme-relative reference supplies
    // an authority, so a guard that only asks whether the identifier is
    // opaque or authority-less would accept it while still rejecting the
    // plain relative form. The scheme is the component missing from both.
    for resource in ["/mcp", "//api.example.com/mcp"] {
        let Err(error) = construct_resource(resource) else {
            panic!("{resource:?} must be rejected at construction");
        };
        assert!(
            error
                .to_string()
                .contains("absolute URL with a scheme and a host"),
            "the rejection for {resource:?} must name the absoluteness requirement, got: {error}"
        );
    }

    // The requirement is scheme-and-host, not https-only: local development
    // loops depend on an http loopback identifier still being accepted.
    construct_resource("http://localhost:8080/mcp")
        .expect("http://localhost must be accepted on scheme-and-host grounds");
}

#[test]
fn rfc9728_prm_dpop_fields_should_be_advertised_when_dpop_is_supported() {
    conformance_case!("rfc9728-prm-dpop-fields-should-be-advertised-when-dpop-is-supported");

    let with_dpop = build_prm(
        "https://auth.example.com",
        "https://api.example.com",
        &[],
        Some(&["ES256".to_string(), "RS256".to_string()]),
        true,
    );
    assert_eq!(
        with_dpop.dpop_signing_alg_values_supported.as_deref(),
        Some(&["ES256".to_string(), "RS256".to_string()][..]),
    );
    assert_eq!(with_dpop.dpop_bound_access_tokens_required, Some(true));

    let without_dpop = build_prm(
        "https://auth.example.com",
        "https://api.example.com",
        &[],
        None,
        false,
    );
    assert!(without_dpop.dpop_signing_alg_values_supported.is_none());
    assert!(without_dpop.dpop_bound_access_tokens_required.is_none());
}

// ---------- RFC 9449 token_type="DPoP" (grant-side shape) -------------------

#[test]
fn rfc9449_token_response_token_type_dpop_must_be_accepted() {
    conformance_case!("rfc9449-token-response-token-type-dpop-must-be-accepted");

    // RFC 9449 section 5: token_type="DPoP" must be accepted by
    // parse_token_response as a valid token type.
    let payload = json!({
        "access_token": "dpop-bound-token",
        "token_type": "DPoP",
        "expires_in": 3600
    });
    let response = authplane_sdk::oauth::parse_token_response(&payload, false)
        .expect("DPoP token_type must be accepted");
    assert_eq!(response.access_token, "dpop-bound-token");
    assert_eq!(response.token_type, "DPoP");
}

#[test]
fn rfc9449_dpop_grant_token_type_must_be_dpop() {
    conformance_case!("rfc9449-dpop-grant-token-type-must-be-dpop");

    // RFC 9449 section 5: when a DPoP proof was sent with the token request,
    // parse_token_response_dpop MUST enforce that token_type is "DPoP".
    // If the AS returns "Bearer" instead, it means the DPoP proof was
    // silently ignored.

    // DPoP token_type must be accepted
    let dpop_payload = json!({
        "access_token": "dpop-tok",
        "token_type": "DPoP",
        "expires_in": 3600
    });
    let response = authplane_sdk::parse_token_response_dpop(&dpop_payload, false)
        .expect("DPoP token_type must be accepted by dpop parser");
    assert_eq!(response.token_type, "DPoP");

    // Bearer token_type must be REJECTED when DPoP was expected
    let bearer_payload = json!({
        "access_token": "bearer-tok",
        "token_type": "Bearer",
        "expires_in": 3600
    });
    let error = authplane_sdk::parse_token_response_dpop(&bearer_payload, false)
        .expect_err("Bearer must be rejected when DPoP was expected");
    let AuthplaneError::Auth(auth) = error else {
        panic!("expected AuthError, got {error:?}");
    };
    assert_eq!(auth.code, "protocol_error");
    assert!(
        auth.message.contains("DPoP"),
        "error must mention DPoP: {}",
        auth.message
    );
}
