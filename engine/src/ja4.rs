//! TLS Client Fingerprinting (JA4) implementation (RV-N-02).
//!
//! Calculates FoxIO JA4 TLS Client Fingerprint from raw ClientHello bytes.
//! Format: `[t|q][version][d|i][ciphers][exts][alpn]_[hash12_ciphers]_[hash12_exts]`
//! Safe Rust with zero unnecessary allocation.
#![forbid(unsafe_code)]

use std::fmt::Write as FmtWrite;
use sha2::{Digest, Sha256};

/// Maximum JA4 string length: 10 + 1 + 12 + 1 + 12 = 36 characters.
pub const JA4_STRING_LEN: usize = 36;

/// Checks if a 16-bit integer is a GREASE value according to RFC 8701.
#[inline]
pub fn is_grease(val: u16) -> bool {
    matches!(
        val,
        0x0a0a
            | 0x1a1a
            | 0x2a2a
            | 0x3a3a
            | 0x4a4a
            | 0x5a5a
            | 0x6a6a
            | 0x7a7a
            | 0x8a8a
            | 0x9a9a
            | 0xaaaa
            | 0xbaba
            | 0xcaca
            | 0xdada
            | 0xeaea
            | 0xfafa
    )
}

/// Parsed TLS ClientHello components for JA4 computation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientHelloInfo {
    pub is_quic: bool,
    pub legacy_version: u16,
    pub highest_version: u16,
    pub has_sni_domain: bool,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub sig_algs: Vec<u16>,
    pub alpn: Option<String>,
}

/// Parses raw TLS bytes (either wrapped in TLS Record Layer or pure Handshake ClientHello).
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn parse_client_hello(data: &[u8], is_quic: bool) -> Option<ClientHelloInfo> {
    if data.len() < 4 {
        return None;
    }

    let mut cursor = 0;

    // Check if wrapped in TLS Record Layer (ContentType 0x16 Handshake)
    if data[0] == 0x16 && data.len() >= 5 {
        // Skip Record Layer header: ContentType (1) + Version (2) + Length (2)
        cursor = 5;
    }

    if cursor >= data.len() || data[cursor] != 0x01 {
        // Handshake type must be 1 (ClientHello)
        return None;
    }

    // Skip Handshake Type (1) + Length (3)
    cursor += 4;
    if cursor + 34 > data.len() {
        return None;
    }

    // Client Version (2 bytes)
    let legacy_version = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
    cursor += 2;

    // Random (32 bytes)
    cursor += 32;

    // Session ID
    if cursor >= data.len() {
        return None;
    }
    let session_id_len = data[cursor] as usize;
    cursor += 1 + session_id_len;

    // Cipher Suites
    if cursor + 2 > data.len() {
        return None;
    }
    let ciphers_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
    cursor += 2;
    if cursor + ciphers_len > data.len() {
        return None;
    }

    let mut ciphers = Vec::with_capacity(ciphers_len / 2);
    for chunk in data[cursor..cursor + ciphers_len].chunks_exact(2) {
        let cipher = u16::from_be_bytes([chunk[0], chunk[1]]);
        if !is_grease(cipher) {
            ciphers.push(cipher);
        }
    }
    cursor += ciphers_len;

    // Compression Methods
    if cursor >= data.len() {
        return None;
    }
    let compression_len = data[cursor] as usize;
    cursor += 1 + compression_len;

    let mut highest_version = legacy_version;
    let mut has_sni_domain = false;
    let mut extensions = Vec::new();
    let mut sig_algs = Vec::new();
    let mut alpn = None;

    // Extensions
    if cursor + 2 <= data.len() {
        let extensions_total_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
        cursor += 2;
        let ext_end = (cursor + extensions_total_len).min(data.len());

        while cursor + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
            let ext_len = u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
            cursor += 4;
            if cursor + ext_len > ext_end {
                break;
            }
            let ext_data = &data[cursor..cursor + ext_len];
            cursor += ext_len;

            if is_grease(ext_type) {
                continue;
            }

            // SNI (0x0000)
            if ext_type == 0x0000 {
                if ext_data.len() >= 5 {
                    let mut p = 2; // skip server_name_list length
                    while p + 3 <= ext_data.len() {
                        let name_type = ext_data[p];
                        let name_len = u16::from_be_bytes([ext_data[p + 1], ext_data[p + 2]]) as usize;
                        p += 3;
                        if p + name_len <= ext_data.len() {
                            if name_type == 0 {
                                // host_name
                                if let Ok(host) = std::str::from_utf8(&ext_data[p..p + name_len]) {
                                    // Must be a domain, not an IP literal
                                    if !host.is_empty() && host.parse::<std::net::IpAddr>().is_err() {
                                        has_sni_domain = true;
                                    }
                                }
                            }
                            p += name_len;
                        } else {
                            break;
                        }
                    }
                }
            } else if ext_type == 0x0010 {
                // ALPN (0x0010)
                if ext_data.len() >= 3 {
                    // skip 2 bytes alpn_extension_length
                    let first_proto_len = ext_data[2] as usize;
                    if 3 + first_proto_len <= ext_data.len()
                        && let Ok(proto) = std::str::from_utf8(&ext_data[3..3 + first_proto_len])
                    {
                        alpn = Some(proto.to_string());
                    }
                }
            } else if ext_type == 0x000d {
                // signature_algorithms (0x000d)
                if ext_data.len() >= 2 {
                    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    for chunk in ext_data[2..2 + list_len.min(ext_data.len() - 2)].chunks_exact(2) {
                        let sig_alg = u16::from_be_bytes([chunk[0], chunk[1]]);
                        if !is_grease(sig_alg) {
                            sig_algs.push(sig_alg);
                        }
                    }
                }
                extensions.push(ext_type);
            } else if ext_type == 0x002b {
                // Supported Versions (0x002b)
                if !ext_data.is_empty() {
                    let list_len = ext_data[0] as usize;
                    for chunk in ext_data[1..1 + list_len.min(ext_data.len() - 1)].chunks_exact(2) {
                        let ver = u16::from_be_bytes([chunk[0], chunk[1]]);
                        if !is_grease(ver) && ver > highest_version {
                            highest_version = ver;
                        }
                    }
                }
                extensions.push(ext_type);
            } else {
                extensions.push(ext_type);
            }
        }
    }

    Some(ClientHelloInfo {
        is_quic,
        legacy_version,
        highest_version,
        has_sni_domain,
        ciphers,
        extensions,
        sig_algs,
        alpn,
    })
}

/// Calculates the JA4 TLS client fingerprint string.
pub fn calculate_ja4(info: &ClientHelloInfo) -> String {
    let mut out = String::with_capacity(JA4_STRING_LEN);

    // 1. Protocol: t or q
    out.push(if info.is_quic { 'q' } else { 't' });

    // 2. TLS Version (2 chars)
    let ver_str = match info.highest_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };
    out.push_str(ver_str);

    // 3. SNI indicator (1 char): d (domain) or i (ip or none)
    out.push(if info.has_sni_domain { 'd' } else { 'i' });

    // 4. Number of ciphers (2 digits)
    let num_ciphers = info.ciphers.len().min(99);
    let _ = write!(out, "{:02}", num_ciphers);

    // 5. Number of extensions (2 digits, excluding SNI, ALPN, GREASE)
    let num_exts = info.extensions.len().min(99);
    let _ = write!(out, "{:02}", num_exts);

    // 6. ALPN (2 chars): first and last char of first ALPN protocol, or 00
    if let Some(ref alpn) = info.alpn {
        if !alpn.is_empty() {
            let first = alpn.chars().next().unwrap_or('0');
            let last = alpn.chars().last().unwrap_or('0');
            out.push(if first.is_ascii_alphanumeric() { first } else { '0' });
            out.push(if last.is_ascii_alphanumeric() { last } else { '0' });
        } else {
            out.push_str("00");
        }
    } else {
        out.push_str("00");
    }

    out.push('_');

    // 7. Hash of sorted cipher suites (first 12 hex chars)
    if !info.ciphers.is_empty() {
        let mut sorted_ciphers = info.ciphers.clone();
        sorted_ciphers.sort_unstable();
        let mut cipher_str = String::with_capacity(sorted_ciphers.len() * 5);
        for (idx, c) in sorted_ciphers.iter().enumerate() {
            if idx > 0 {
                cipher_str.push(',');
            }
            let _ = write!(cipher_str, "{:04x}", c);
        }
        let hash = Sha256::digest(cipher_str.as_bytes());
        let hex_hash = format!("{:x}", hash);
        out.push_str(&hex_hash[..12]);
    } else {
        out.push_str("000000000000");
    }

    out.push('_');

    // 8. Hash of sorted extensions + signature algorithms (first 12 hex chars)
    if !info.extensions.is_empty() {
        let mut sorted_exts = info.extensions.clone();
        sorted_exts.sort_unstable();
        let mut ext_str = String::with_capacity(sorted_exts.len() * 5 + info.sig_algs.len() * 5 + 1);
        for (idx, e) in sorted_exts.iter().enumerate() {
            if idx > 0 {
                ext_str.push(',');
            }
            let _ = write!(ext_str, "{:04x}", e);
        }
        if !info.sig_algs.is_empty() {
            ext_str.push('_');
            for (idx, s) in info.sig_algs.iter().enumerate() {
                if idx > 0 {
                    ext_str.push(',');
                }
                let _ = write!(ext_str, "{:04x}", s);
            }
        }
        let hash = Sha256::digest(ext_str.as_bytes());
        let hex_hash = format!("{:x}", hash);
        out.push_str(&hex_hash[..12]);
    } else {
        out.push_str("000000000000");
    }

    out
}

/// Convenience function calculating JA4 directly from raw bytes.
pub fn calculate_ja4_from_raw(raw: &[u8], is_quic: bool) -> Option<String> {
    let info = parse_client_hello(raw, is_quic)?;
    Some(calculate_ja4(&info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja4_format_structure() {
        let info = ClientHelloInfo {
            is_quic: false,
            legacy_version: 0x0303,
            highest_version: 0x0304, // TLS 1.3
            has_sni_domain: true,
            ciphers: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            extensions: vec![0x002b, 0x000d, 0x0023, 0x002d],
            sig_algs: vec![0x0403, 0x0804],
            alpn: Some("h2".into()),
        };

        let ja4 = calculate_ja4(&info);
        assert_eq!(ja4.len(), 36);
        assert!(ja4.starts_with("t13d0504h2_"), "got {}", ja4);
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "t13d0504h2");
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
    }

    #[test]
    fn test_grease_exclusion() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x002b));
    }

    #[test]
    fn test_alpn_variations() {
        let mut info = ClientHelloInfo {
            is_quic: false,
            legacy_version: 0x0303,
            highest_version: 0x0303,
            has_sni_domain: false,
            ciphers: vec![0x002f],
            extensions: vec![0x000d],
            sig_algs: vec![0x0403],
            alpn: Some("http/1.1".into()),
        };
        assert!(calculate_ja4(&info).starts_with("t12i0101h1_"));

        info.alpn = None;
        assert!(calculate_ja4(&info).starts_with("t12i010100_"));
    }

    #[test]
    fn test_foxio_chrome_reference_vector() {
        // FoxIO Chromium reference vector:
        // Cipher hash: 8daaf6152771
        // 15 Chromium cipher suites (excluding GREASE):
        // 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
        // 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
        let info = ClientHelloInfo {
            is_quic: false,
            legacy_version: 0x0303,
            highest_version: 0x0304,
            has_sni_domain: true,
            ciphers: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            // 16 extensions
            extensions: vec![
                0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0017, 0x001b, 0x0023,
                0x002b, 0x002d, 0x0033, 0x44cd, 0xff01, 0x0015, 0x001c, 0x0029,
            ],
            sig_algs: vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
            alpn: Some("h2".into()),
        };

        let ja4 = calculate_ja4(&info);
        assert_eq!(ja4.len(), 36);
        assert!(ja4.starts_with("t13d1516h2_8daaf6152771_"), "got {}", ja4);
    }

    #[test]
    fn test_foxio_python_and_curl_vectors() {
        // Python requests reference vector prefix
        let py_info = ClientHelloInfo {
            is_quic: false,
            legacy_version: 0x0303,
            highest_version: 0x0304,
            has_sni_domain: true,
            ciphers: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x00ff,
            ],
            extensions: vec![
                0x000b, 0x000a, 0x0023, 0x0016, 0x000d, 0x002b, 0x002d, 0x001c, 0x0015, 0x0033,
            ],
            sig_algs: vec![0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806],
            alpn: None,
        };
        let py_ja4 = calculate_ja4(&py_info);
        assert!(py_ja4.starts_with("t13d181000_"), "got {}", py_ja4);

        // Curl / OpenSSL CLI reference vector
        let curl_info = ClientHelloInfo {
            is_quic: false,
            legacy_version: 0x0303,
            highest_version: 0x0304,
            has_sni_domain: true,
            ciphers: vec![
                0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0xcca9, 0xc0ad, 0xc02b, 0xc02f,
                0xcca8, 0xc0ac, 0xc00a, 0xc014, 0xc009, 0xc013, 0x009d, 0x009c, 0x0035,
                0x002f,
            ],
            extensions: vec![
                0x000b, 0x000a, 0x0023, 0x0016, 0x000d, 0x002b, 0x002d, 0x0033,
            ],
            sig_algs: vec![0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501],
            alpn: Some("h2".into()),
        };
        let curl_ja4 = calculate_ja4(&curl_info);
        assert!(curl_ja4.starts_with("t13d1908h2_"), "got {}", curl_ja4);
    }

    #[test]
    fn test_raw_client_hello_parsing() {
        // Construct raw TLS ClientHello bytes (record layer + handshake)
        let mut raw = Vec::new();
        // Record layer header: Handshake (0x16), TLS 1.0 (0x0301), length (placeholder)
        raw.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x00]);
        let handshake_start = raw.len();

        // Handshake: ClientHello (0x01), length (placeholder 3 bytes)
        raw.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let body_start = raw.len();

        // Version: 0x0303
        raw.extend_from_slice(&[0x03, 0x03]);
        // Random: 32 bytes
        raw.extend_from_slice(&[0x42; 32]);
        // Session ID length: 0
        raw.push(0x00);
        // Cipher suites: 2 ciphers (0x1301, 0x1302) + 1 GREASE (0x0a0a) = 6 bytes
        raw.extend_from_slice(&[0x00, 0x06, 0x13, 0x01, 0x0a, 0x0a, 0x13, 0x02]);
        // Compression methods: 1 byte (0x00)
        raw.extend_from_slice(&[0x01, 0x00]);

        // Extensions
        let ext_len_offset = raw.len();
        raw.extend_from_slice(&[0x00, 0x00]); // placeholder for total ext length
        let exts_start = raw.len();

        // Ext 1: SNI (0x0000) with domain "example.com"
        let host = b"example.com";
        let sni_data_len = 2 + 1 + 2 + host.len();
        raw.extend_from_slice(&[0x00, 0x00]);
        raw.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
        raw.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        raw.push(0x00); // host_name
        raw.extend_from_slice(&(host.len() as u16).to_be_bytes());
        raw.extend_from_slice(host);

        // Ext 2: ALPN (0x0010) with "h2"
        raw.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']);

        // Ext 3: Supported Versions (0x002b) with 0x0304 (TLS 1.3)
        raw.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        // Patch extensions length
        let exts_len = (raw.len() - exts_start) as u16;
        raw[ext_len_offset..ext_len_offset + 2].copy_from_slice(&exts_len.to_be_bytes());

        // Patch handshake length
        let hs_len = (raw.len() - body_start) as u32;
        raw[handshake_start + 1] = (hs_len >> 16) as u8;
        raw[handshake_start + 2] = (hs_len >> 8) as u8;
        raw[handshake_start + 3] = hs_len as u8;

        // Patch record layer length
        let rec_len = (raw.len() - handshake_start) as u16;
        raw[3..5].copy_from_slice(&rec_len.to_be_bytes());

        let ja4 = calculate_ja4_from_raw(&raw, false).expect("should parse raw TLS record");
        assert_eq!(ja4.len(), 36);
        // t13 (TLS 1.3 from supported_versions) d (SNI domain) 02 (2 non-GREASE ciphers) 01 (supported_versions only; SNI and ALPN excluded) h2
        assert!(ja4.starts_with("t13d0201h2_"), "got {}", ja4);
    }
}

