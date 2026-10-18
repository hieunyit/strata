//! Challenge action: JS challenge token generation, validation, and HTML page.
//!
//! RV-R-04:
//! 1. Cookie signed with HMAC-SHA256, carrying expiration timestamp and client binding.
//! 2. Token format: `v1.<issued_ts>.<expiry_ts>.<nonce_hex>.<signature_hex>`
//! 3. Lightweight JS challenge page to verify browser and automatically solve/set cookie.
//! 4. Non-JS clients fail the challenge (status 403 / HTML response).
//! 5. Expired or forged cookies are strictly rejected.
#![forbid(unsafe_code)]

use crate::privacy::hmac_sha256;

/// Default cookie name for Strata challenge clearance.
pub const CHALLENGE_COOKIE_NAME: &str = "__strata_challenge";

/// Default clearance validity period (30 minutes = 1800s).
pub const DEFAULT_CHALLENGE_TTL_SECS: u64 = 1800;


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ChallengeError {
    Malformed,
    Expired,
    InvalidSignature,
    ClockSkew,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallengeError::Malformed => write!(f, "malformed challenge token"),
            ChallengeError::Expired => write!(f, "challenge token expired"),
            ChallengeError::InvalidSignature => write!(f, "invalid challenge signature"),
            ChallengeError::ClockSkew => write!(f, "challenge token issued in the future"),
        }
    }
}

impl std::error::Error for ChallengeError {}

/// Generates a signed challenge clearance token.
/// Format: `v1.<issued_ts>.<expiry_ts>.<nonce_hex>.<signature_hex>`
pub fn generate_token(
    key: &[u8; 32],
    client_ip: &str,
    identity: &str,
    issued_ts: u64,
    validity_secs: u64,
    nonce: u64,
) -> String {
    let expiry_ts = issued_ts.saturating_add(validity_secs);
    let nonce_hex = format!("{:016x}", nonce);
    let payload = format!("{issued_ts}:{expiry_ts}:{nonce_hex}:{client_ip}:{identity}");
    let sig = hmac_sha256(key, payload.as_bytes());
    let sig_hex = to_hex(&sig);
    format!("v1.{issued_ts}.{expiry_ts}.{nonce_hex}.{sig_hex}")
}

/// Verifies a challenge clearance token.
pub fn verify_token(
    token: &str,
    key: &[u8; 32],
    client_ip: &str,
    identity: &str,
    now_ts: u64,
) -> Result<(), ChallengeError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 || parts[0] != "v1" {
        return Err(ChallengeError::Malformed);
    }

    let issued_ts: u64 = parts[1].parse().map_err(|_| ChallengeError::Malformed)?;
    let expiry_ts: u64 = parts[2].parse().map_err(|_| ChallengeError::Malformed)?;
    let nonce_hex = parts[3];
    let sig_hex = parts[4];

    // Check expiration
    if now_ts > expiry_ts {
        return Err(ChallengeError::Expired);
    }

    // Allow up to 60s future clock skew
    if issued_ts > now_ts.saturating_add(60) {
        return Err(ChallengeError::ClockSkew);
    }

    // Recompute signature and compare in constant time
    let payload = format!("{issued_ts}:{expiry_ts}:{nonce_hex}:{client_ip}:{identity}");
    let expected_sig = hmac_sha256(key, payload.as_bytes());
    let expected_sig_hex = to_hex(&expected_sig);

    if !constant_time_eq_str(sig_hex, &expected_sig_hex) {
        return Err(ChallengeError::InvalidSignature);
    }

    Ok(())
}

/// Renders a lightweight HTML page with JavaScript challenge solver.
pub fn render_challenge_page(token: &str, block_id: &str) -> String {
    format!(
        "<!DOCTYPE html>\n\
<html>\n\
<head>\n\
  <meta charset=\"utf-8\">\n\
  <title>Security Check - Strata WAF</title>\n\
  <script>\n\
    (function() {{\n\
      var c = \"{name}=\" + \"{token}\" + \"; path=/; max-age={ttl}; SameSite=Lax\";\n\
      document.cookie = c;\n\
      setTimeout(function() {{ window.location.reload(); }}, 100);\n\
    }})();\n\
  </script>\n\
</head>\n\
<body>\n\
  <h1>Security Check</h1>\n\
  <p>Please wait while we verify your browser before accessing the site...</p>\n\
  <p>Block ID: <code>{block_id}</code></p>\n\
  <noscript><p>JavaScript is required to pass this security check.</p></noscript>\n\
</body>\n\
</html>\n",
        name = CHALLENGE_COOKIE_NAME,
        token = token,
        ttl = DEFAULT_CHALLENGE_TTL_SECS,
        block_id = block_id,
    )
}

/// Constant-time comparison for hex strings.
fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn test_challenge_valid_token() {
        let now = 1700000000;
        let token = generate_token(&KEY, "192.0.2.1", "alice", now, 1800, 12345);
        assert!(verify_token(&token, &KEY, "192.0.2.1", "alice", now + 100).is_ok());
    }

    #[test]
    fn test_challenge_expired_token() {
        let now = 1700000000;
        let token = generate_token(&KEY, "192.0.2.1", "alice", now, 1800, 12345);
        assert_eq!(
            verify_token(&token, &KEY, "192.0.2.1", "alice", now + 1801),
            Err(ChallengeError::Expired)
        );
    }

    #[test]
    fn test_challenge_forged_signature() {
        let now = 1700000000;
        let mut token = generate_token(&KEY, "192.0.2.1", "alice", now, 1800, 12345);
        // Tamper with signature
        token.pop();
        token.push('0');
        assert_eq!(
            verify_token(&token, &KEY, "192.0.2.1", "alice", now + 100),
            Err(ChallengeError::InvalidSignature)
        );
    }

    #[test]
    fn test_challenge_client_ip_mismatch() {
        let now = 1700000000;
        let token = generate_token(&KEY, "192.0.2.1", "alice", now, 1800, 12345);
        assert_eq!(
            verify_token(&token, &KEY, "198.51.100.1", "alice", now + 100),
            Err(ChallengeError::InvalidSignature)
        );
    }

    #[test]
    fn test_challenge_identity_mismatch() {
        let now = 1700000000;
        let token = generate_token(&KEY, "192.0.2.1", "alice", now, 1800, 12345);
        assert_eq!(
            verify_token(&token, &KEY, "192.0.2.1", "bob", now + 100),
            Err(ChallengeError::InvalidSignature)
        );
    }

    #[test]
    fn test_challenge_malformed() {
        assert_eq!(
            verify_token("invalid.token", &KEY, "127.0.0.1", "", 1700000000),
            Err(ChallengeError::Malformed)
        );
    }

    #[test]
    fn test_challenge_page_rendering() {
        let html = render_challenge_page("v1.test.token", "STR-TEST-1234");
        assert!(html.contains("__strata_challenge"));
        assert!(html.contains("v1.test.token"));
        assert!(html.contains("STR-TEST-1234"));
        assert!(html.contains("window.location.reload()"));
    }
}
