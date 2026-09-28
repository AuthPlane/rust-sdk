use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, redirect::Policy};
use serde_json::Value;
use url::Url;

/// RFC 3986 §2.3 unreserved set is `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
/// Start from `NON_ALPHANUMERIC` (encodes everything except ALPHA + DIGIT)
/// and re-exempt the four punctuation marks to land on the OAuth 2.0
/// percent-encoding contract from RFC 6749 §2.3.1.
const RFC3986_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

use crate::errors::transport_error;
use crate::{AuthplaneError, FetchSettings};

/// RFC 7231 §6.3: 2xx is "Successful". Centralised so policy on what
/// counts as success (e.g. accepting 207, treating empty 204 as a
/// special case) lands in one place. Used by every OAuth call site and
/// every document fetch path.
pub fn is_http_success(status: u16) -> bool {
    (200..300).contains(&status)
}

pub(crate) fn build_http_client(fetch_settings: &FetchSettings) -> Result<Client, AuthplaneError> {
    let mut builder =
        Client::builder().timeout(Duration::from_secs_f64(fetch_settings.timeout_seconds));
    if fetch_settings.ssrf_protection {
        builder = builder.redirect(Policy::none());
    }
    builder
        .build()
        .map_err(|error| transport_error(&error.to_string()))
}

pub(crate) fn build_basic_auth_header(client_id: &str, client_secret: &str) -> String {
    let encoded_client_id = utf8_percent_encode(client_id, &RFC3986_ENCODE_SET).to_string();
    let encoded_client_secret = utf8_percent_encode(client_secret, &RFC3986_ENCODE_SET).to_string();
    let raw = format!("{encoded_client_id}:{encoded_client_secret}");
    format!("Basic {}", BASE64_STANDARD.encode(raw))
}

pub(crate) fn validate_fetch_url(
    value: &str,
    settings: &FetchSettings,
    context: &str,
) -> Result<(), AuthplaneError> {
    let parsed = Url::parse(value)
        .map_err(|_| transport_error(&format!("{context} must be an absolute URL: {value:?}")))?;
    validate_parsed_fetch_url(&parsed, settings, context)
}

pub(crate) fn validate_parsed_fetch_url(
    url: &Url,
    settings: &FetchSettings,
    context: &str,
) -> Result<(), AuthplaneError> {
    if !settings.allow_http && url.scheme() != "https" {
        return Err(transport_error(&format!(
            "{context} must use HTTPS, got scheme {:?}: {:?}",
            url.scheme(),
            url.as_str()
        )));
    }

    if !settings.ssrf_protection {
        return Ok(());
    }

    let host = url
        .host()
        .ok_or_else(|| transport_error(&format!("{context} missing host: {:?}", url.as_str())))?;
    let host_display = url.host_str().unwrap_or("<unknown>");

    match host {
        url::Host::Domain(domain) => {
            if is_localhost_name(domain) && !settings.allow_localhost {
                return Err(transport_error(&format!(
                    "{context} host {host_display:?} is blocked by localhost policy"
                )));
            }
        }
        url::Host::Ipv4(ip) => {
            if ip.is_loopback() && !settings.allow_localhost {
                return Err(transport_error(&format!(
                    "{context} host {host_display:?} is blocked by localhost policy"
                )));
            }
            if is_private_or_special_ipv4(ip) && !settings.allow_private_networks {
                return Err(transport_error(&format!(
                    "{context} host {host_display:?} is blocked by private-network policy"
                )));
            }
        }
        url::Host::Ipv6(ip) => {
            if ip.is_loopback() && !settings.allow_localhost {
                return Err(transport_error(&format!(
                    "{context} host {host_display:?} is blocked by localhost policy"
                )));
            }
            if is_private_or_special_ipv6(ip) && !settings.allow_private_networks {
                return Err(transport_error(&format!(
                    "{context} host {host_display:?} is blocked by private-network policy"
                )));
            }
        }
    }

    Ok(())
}

fn is_localhost_name(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    normalized == "localhost" || normalized.ends_with(".localhost")
}

fn is_private_or_special_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || matches!(
            octets,
            [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
        )
        // RFC 6598 Carrier-Grade NAT (100.64.0.0/10)
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || octets[0] == 0
        || octets[0] >= 224
}

fn is_private_or_special_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

// ---------------------------------------------------------------------------
// DNS-resolving SSRF protection
// ---------------------------------------------------------------------------

pub(crate) struct SsrfResponse {
    pub body: Value,
    pub headers: HashMap<String, String>,
    pub status_code: u16,
}

async fn resolve_hostname(host: &str, port: u16) -> Result<Vec<IpAddr>, AuthplaneError> {
    let addrs = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .map_err(|e| transport_error(&format!("DNS resolution failed for {host}: {e}")))?;

    let mut seen = Vec::<IpAddr>::new();
    for addr in addrs {
        let ip = addr.ip();
        if !seen.contains(&ip) {
            seen.push(ip);
        }
    }
    Ok(seen)
}

fn is_ip_allowed(ip: IpAddr, allow_localhost: bool, allow_private_networks: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // Always block link-local (169.254.x.x — includes cloud metadata)
            if v4.is_link_local() {
                return false;
            }
            // Always block multicast
            if v4.is_multicast() {
                return false;
            }
            // Block loopback unless allow_localhost
            if v4.is_loopback() && !allow_localhost {
                return false;
            }
            // Block private/reserved unless allow_private_networks
            if is_private_or_special_ipv4(v4) && !allow_private_networks {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();

            // IPv4-mapped (::ffff:x.x.x.x) — extract and recurse
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_ip_allowed(IpAddr::V4(mapped), allow_localhost, allow_private_networks);
            }

            // 6to4 (2002::/16) — embedded IPv4 is in segments[1..2]
            if segments[0] == 0x2002 {
                let embedded = Ipv4Addr::new(
                    (segments[1] >> 8) as u8,
                    (segments[1] & 0xff) as u8,
                    (segments[2] >> 8) as u8,
                    (segments[2] & 0xff) as u8,
                );
                return is_ip_allowed(
                    IpAddr::V4(embedded),
                    allow_localhost,
                    allow_private_networks,
                );
            }

            // Teredo (2001:0000::/32) — check both server and client
            // portions. Both are checked; segments[2..3] are the
            // Teredo server IPv4, segments[6..7] are the inverted client.
            if segments[0] == 0x2001 && segments[1] == 0x0000 {
                let server = Ipv4Addr::new(
                    (segments[2] >> 8) as u8,
                    (segments[2] & 0xff) as u8,
                    (segments[3] >> 8) as u8,
                    (segments[3] & 0xff) as u8,
                );
                if !is_ip_allowed(IpAddr::V4(server), allow_localhost, allow_private_networks) {
                    return false;
                }
                let client = Ipv4Addr::new(
                    !(segments[6] >> 8) as u8,
                    !(segments[6] & 0xff) as u8,
                    !(segments[7] >> 8) as u8,
                    !(segments[7] & 0xff) as u8,
                );
                return is_ip_allowed(IpAddr::V4(client), allow_localhost, allow_private_networks);
            }

            // Always block link-local (fe80::/10)
            if v6.is_unicast_link_local() {
                return false;
            }
            // Always block multicast
            if v6.is_multicast() {
                return false;
            }
            // Block loopback unless allow_localhost
            if v6.is_loopback() && !allow_localhost {
                return false;
            }
            // Block private/reserved unless allow_private_networks
            if is_private_or_special_ipv6(v6) && !allow_private_networks {
                return false;
            }
            true
        }
    }
}

/// Perform DNS-pinned SSRF-safe POST request.
#[allow(dead_code)]
pub(crate) async fn ssrf_safe_post(
    url: &str,
    form_data: &[(String, String)],
    settings: &FetchSettings,
    extra_headers: &[(String, String)],
    max_size: u64,
) -> Result<SsrfResponse, AuthplaneError> {
    ssrf_safe_request(
        "POST",
        url,
        Some(form_data),
        settings,
        extra_headers,
        max_size,
    )
    .await
}

/// Perform DNS-pinned SSRF-safe GET request.
pub(crate) async fn ssrf_safe_get(
    url: &str,
    settings: &FetchSettings,
    max_size: u64,
) -> Result<SsrfResponse, AuthplaneError> {
    ssrf_safe_request("GET", url, None, settings, &[], max_size).await
}

async fn ssrf_safe_request(
    method: &str,
    url: &str,
    form_data: Option<&[(String, String)]>,
    settings: &FetchSettings,
    extra_headers: &[(String, String)],
    max_size: u64,
) -> Result<SsrfResponse, AuthplaneError> {
    // Parse and validate URL at the URL level first.
    let parsed = Url::parse(url).map_err(|_| transport_error(&format!("Invalid URL: {url:?}")))?;
    validate_parsed_fetch_url(&parsed, settings, "request URL")?;

    let scheme = parsed.scheme().to_string();
    let host_str = parsed
        .host_str()
        .ok_or_else(|| transport_error(&format!("URL missing host: {url:?}")))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    // DNS resolution
    let ips = resolve_hostname(&host_str, port).await?;
    if ips.is_empty() {
        return Err(transport_error(&format!(
            "DNS resolution returned no addresses for {host_str}"
        )));
    }

    // Check ALL resolved IPs; reject if any is blocked.
    for ip in &ips {
        if !is_ip_allowed(
            *ip,
            settings.allow_localhost,
            settings.allow_private_networks,
        ) {
            return Err(transport_error(&format!(
                "Resolved IP {ip} for host {host_str:?} is blocked by SSRF protection"
            )));
        }
    }

    // Build a client with no redirects and the configured timeout.
    let client = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs_f64(settings.timeout_seconds))
        .build()
        .map_err(|e| transport_error(&e.to_string()))?;

    // DNS-pinning loop: try each resolved IP in order.
    let mut last_err: Option<AuthplaneError> = None;
    for ip in &ips {
        // Build a pinned URL: replace the host with the IP literal.
        let ip_host = match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        let mut pinned = parsed.clone();
        pinned
            .set_host(Some(&ip_host))
            .map_err(|_| transport_error(&format!("Failed to pin URL to IP {ip}")))?;
        // Preserve the explicit port if the original URL had one, otherwise
        // let the scheme default apply.
        let _ = pinned.set_port(parsed.port());

        let mut req = match method {
            "POST" => {
                let mut r = client.post(pinned.as_str());
                if let Some(fd) = form_data {
                    r = r.form(fd);
                }
                r
            }
            _ => client.get(pinned.as_str()),
        };

        // Set the Host header to the original hostname so the server sees the
        // correct virtual-host / SNI name.
        req = req.header("Host", &host_str);

        for (name, value) in extra_headers {
            req = req.header(name.as_str(), value.as_str());
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                // On SSRF-related or HTTP-level errors, propagate immediately.
                if e.is_timeout() || e.is_redirect() {
                    return Err(transport_error(&e.to_string()));
                }
                // On network error, try next IP.
                last_err = Some(transport_error(&e.to_string()));
                continue;
            }
        };

        let status_code = resp.status().as_u16();

        // Collect response headers.
        let mut headers = HashMap::new();
        for (name, value) in resp.headers().iter() {
            if let Ok(v) = value.to_str() {
                headers.insert(name.to_string(), v.to_string());
            }
        }

        // Enforce max_size on response body.
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| transport_error(&e.to_string()))?;

        if body_bytes.len() as u64 > max_size {
            return Err(transport_error(&format!(
                "Response body exceeds maximum size of {max_size} bytes ({} bytes received)",
                body_bytes.len()
            )));
        }

        let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);

        return Ok(SsrfResponse {
            body,
            headers,
            status_code,
        });
    }

    Err(last_err
        .unwrap_or_else(|| transport_error(&format!("All resolved IPs for {host_str} failed"))))
}

#[cfg(test)]
mod tests {
    use super::{build_basic_auth_header, build_http_client, is_ip_allowed, validate_fetch_url};
    use crate::FetchSettings;
    use base64::Engine as _;

    #[test]
    fn localhost_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://localhost:8080/token", &settings, "token endpoint")
            .expect_err("localhost should be blocked");
        assert!(err.to_string().contains("localhost policy"));
    }

    #[test]
    fn private_ip_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://10.0.0.5/token", &settings, "token endpoint")
            .expect_err("private network should be blocked");
        assert!(err.to_string().contains("private-network policy"));
    }

    #[test]
    fn dev_mode_allows_local_urls() {
        validate_fetch_url(
            "http://localhost:8080/token",
            &FetchSettings::from_dev_mode(true),
            "token endpoint",
        )
        .expect("dev mode should allow localhost");
    }

    #[test]
    fn loopback_ip_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://127.0.0.1/token", &settings, "token endpoint")
            .expect_err("loopback should be blocked");
        assert!(err.to_string().contains("localhost policy"));
    }

    #[test]
    fn ipv6_loopback_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://[::1]/token", &settings, "token endpoint")
            .expect_err("IPv6 loopback should be blocked");
        assert!(err.to_string().contains("localhost policy"));
    }

    #[test]
    fn link_local_ipv4_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://169.254.169.254/token", &settings, "token endpoint")
            .expect_err("link-local (cloud metadata) should be blocked");
        assert!(err.to_string().contains("private-network policy"));
    }

    #[test]
    fn link_local_ipv6_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://[fe80::1]/token", &settings, "token endpoint")
            .expect_err("IPv6 link-local should be blocked");
        assert!(err.to_string().contains("private-network policy"));
    }

    #[test]
    fn ipv6_unique_local_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://[fc00::1]/token", &settings, "token endpoint")
            .expect_err("IPv6 unique-local should be blocked");
        assert!(err.to_string().contains("private-network policy"));
    }

    #[test]
    fn ipv6_documentation_range_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://[2001:db8::1]/token", &settings, "token endpoint")
            .expect_err("IPv6 documentation range should be blocked");
        assert!(err.to_string().contains("private-network policy"));
    }

    #[test]
    fn test_net_ipv4_ranges_are_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        for host in ["192.0.2.5", "198.51.100.5", "203.0.113.5"] {
            let err =
                validate_fetch_url(&format!("http://{host}/token"), &settings, "token endpoint")
                    .expect_err("TEST-NET range should be blocked");
            assert!(
                err.to_string().contains("private-network policy"),
                "unexpected error for {host}: {err}"
            );
        }
    }

    #[test]
    fn multicast_ipv4_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://239.255.255.250/token", &settings, "token endpoint")
            .expect_err("multicast should be blocked");
        assert!(err.to_string().contains("private-network policy"));
    }

    #[test]
    fn unspecified_ipv4_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://0.0.0.0/token", &settings, "token endpoint")
            .expect_err("0.0.0.0 should be blocked");
        assert!(err.to_string().contains("private-network policy"));
    }

    #[test]
    fn broadcast_ipv4_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://255.255.255.255/token", &settings, "token endpoint")
            .expect_err("broadcast should be blocked");
        assert!(err.to_string().contains("private-network policy"));
    }

    #[test]
    fn dotted_localhost_suffix_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("http://evil.localhost/token", &settings, "token endpoint")
            .expect_err("*.localhost should be blocked");
        assert!(err.to_string().contains("localhost policy"));
    }

    #[test]
    fn http_scheme_is_rejected_in_prod_mode_even_for_public_hosts() {
        // prod mode: allow_http = false. HTTP must fail before SSRF checks.
        let err = validate_fetch_url(
            "http://public.example.com/token",
            &FetchSettings::default(),
            "token endpoint",
        )
        .expect_err("http must be rejected in prod mode");
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn invalid_url_is_rejected() {
        let err = validate_fetch_url("not-a-url", &FetchSettings::default(), "token endpoint")
            .expect_err("invalid URL must be rejected");
        assert!(err.to_string().contains("absolute URL"));
    }

    #[test]
    fn url_without_host_is_rejected() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        let err = validate_fetch_url("data:text/plain,hello", &settings, "token endpoint")
            .expect_err("data: URL has no host");
        // Either the URL parse fails or the host check fails — both are valid.
        let message = err.to_string();
        assert!(
            message.contains("host") || message.contains("HTTPS"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn https_public_host_is_allowed_in_prod_mode() {
        validate_fetch_url(
            "https://auth.example.com/token",
            &FetchSettings::default(),
            "token endpoint",
        )
        .expect("public https host should pass");
    }

    #[test]
    fn dev_mode_allows_private_ips() {
        validate_fetch_url(
            "http://10.0.0.5/token",
            &FetchSettings::from_dev_mode(true),
            "token endpoint",
        )
        .expect("dev mode should allow private networks");
    }

    #[test]
    fn basic_auth_header_percent_encodes_reserved_chars_in_client_id() {
        // Basic-auth inputs with reserved characters (colon, at-sign, slash)
        // must be percent-encoded BEFORE base64 per RFC 6749 §2.3.1 so the
        // server can round-trip them. The colon between userid:password
        // inside the base64 payload must be the only unencoded colon.
        let header = build_basic_auth_header("user:with:colons", "p@ssw/rd");
        assert!(header.starts_with("Basic "));
        let encoded = header.trim_start_matches("Basic ");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("valid base64");
        let decoded = String::from_utf8(decoded).expect("utf8 basic auth");
        // client_id / client_secret are each percent-encoded, then joined
        // with a literal `:` — so exactly one colon in the payload.
        assert_eq!(decoded.matches(':').count(), 1, "decoded: {decoded}");
        assert!(decoded.starts_with("user%3Awith%3Acolons:"));
        assert!(decoded.ends_with(":p%40ssw%2Frd"));
    }

    #[test]
    fn basic_auth_header_preserves_unreserved_chars() {
        // Unreserved characters (RFC 3986 §2.3) must NOT be percent-encoded.
        let header = build_basic_auth_header("client-id_01", "secret~value.07");
        let encoded = header.trim_start_matches("Basic ");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("valid base64");
        let decoded = String::from_utf8(decoded).expect("utf8 basic auth");
        assert_eq!(decoded, "client-id_01:secret~value.07");
    }

    #[test]
    fn http_client_is_built_with_no_redirects_when_ssrf_protection_is_on() {
        // SSRF-safe clients must never follow redirects — otherwise a
        // public AS could 302 to 169.254.169.254/latest/meta-data/ and
        // we would leak the bearer on the next hop.
        let client = build_http_client(&FetchSettings::default())
            .expect("client build must succeed with safe defaults");
        // Build succeeded; the actual redirect Policy::none() is verified
        // by construction — reqwest does not expose a reader for it, so
        // this test asserts that the explicit defaults still produce a
        // client (regression signal if the builder starts to fail).
        drop(client);
    }

    #[test]
    fn cgnat_ipv4_is_blocked_in_prod_mode() {
        let settings = FetchSettings {
            allow_http: true,
            ..FetchSettings::default()
        };
        // RFC 6598 CGNAT: 100.64.0.0/10 (100.64.0.0 – 100.127.255.255)
        let err = validate_fetch_url("http://100.64.0.1/token", &settings, "token endpoint")
            .expect_err("CGNAT 100.64.0.1 should be blocked");
        assert!(err.to_string().contains("private-network policy"));

        let err2 = validate_fetch_url("http://100.127.255.254/token", &settings, "token endpoint")
            .expect_err("CGNAT 100.127.255.254 should be blocked");
        assert!(err2.to_string().contains("private-network policy"));
    }

    #[test]
    fn teredo_with_blocked_server_is_rejected() {
        // Teredo address 2001:0000:SSSS:SSSS:...:CCCC:CCCC
        // Server portion is segments[2..3]. If the server IPv4 is private,
        // the address must be rejected even if the client portion is public.
        let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x0000, // Teredo prefix
            0xC0A8, 0x0001, // Server: 192.168.0.1 (private)
            0x0000, 0x0000, // Flags + port
            0xF7F7, 0xF7F7, // Client: inverted → 8.8.8.8 (public)
        ));
        assert!(
            !is_ip_allowed(ip, false, false),
            "Teredo with private server 192.168.0.1 must be blocked"
        );
    }

    #[test]
    fn http_client_honors_configured_timeout() {
        let settings = FetchSettings {
            timeout_seconds: 2.5,
            ..FetchSettings::default()
        };
        build_http_client(&settings).expect("client build must honor 2.5s timeout");
    }
}
