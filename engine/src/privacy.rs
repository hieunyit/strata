//! Privacy settings of a policy (P-01 §1): field names whose snippets are
//! never kept, added to the built-in list, and patterns masked in event
//! snippets and context, after the built-in masks (CCCD, JWT, card
//! numbers); and `identity: hmac`, which replaces the identity of an event
//! by `hmac:` and the hex of the first 16 bytes of HMAC-SHA256(key,
//! identity): the same client keeps the same value (lookups and counts
//! still work), the value itself never leaves the node. The key is the
//! installation's, the same in every bundle (control plane), so values stay
//! comparable across deploys; another key gives other values. Section
//! PRIVACY (kind 9):
//!
//! ```text
//! n_entries u32 | n_strings u32 | identity_key [u8; 32] (zeros: none)
//! n_entries x { policy_index u32 | fields_first u32 | fields_count u32
//!              | patterns_first u32 | patterns_count u32
//!              | flags u32 (bit 0: identity hmac, others 0) }
//! n_strings x { off u32 | len u32 }      into the blob that follows
//! blob
//! ```
//!
//! A policy with settings also has bit 2 of byte 62 of its policy entry set, so an
//! engine that does not know the section refuses the bundle instead of
//! logging what the policy asked to mask.
#![forbid(unsafe_code)]

use crate::bundle::Error;

/// Limits the compiler checks and the engine enforces again.
pub const MAX_FIELDS: usize = 64;
pub const MAX_FIELD_LEN: usize = 64;
pub const MAX_PATTERNS: usize = 16;
pub const MAX_PATTERN_LEN: usize = 256;
/// Compiled size limit of one pattern (regex crate, linear time).
const REGEX_SIZE_LIMIT: usize = 1 << 20;

const ENTRY_LEN: usize = 24;
const HEADER_LEN: usize = 8 + KEY_LEN;
/// Length of the identity key.
pub const KEY_LEN: usize = 32;
const FLAG_IDENTITY_HMAC: u32 = 1;
/// Prefix of a pseudonymized identity.
pub const HMAC_PREFIX: &str = "hmac:";

/// Settings of one policy, to write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrivacySpec {
    pub policy_index: u32,
    pub sensitive_fields: Vec<String>,
    pub mask_patterns: Vec<String>,
    /// replace the identity by its HMAC (needs the installation's key)
    pub identity_hmac: bool,
}

impl PrivacySpec {
    fn is_empty(&self) -> bool {
        self.sensitive_fields.is_empty() && self.mask_patterns.is_empty() && !self.identity_hmac
    }
}

/// Settings of one policy, ready to use.
pub struct Privacy {
    /// lowercase
    fields: Vec<String>,
    patterns: Vec<regex::bytes::Regex>,
    identity_key: Option<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for Privacy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // never the key
        f.debug_struct("Privacy")
            .field("fields", &self.fields)
            .field("patterns", &self.patterns.len())
            .field("identity_hmac", &self.identity_key.is_some())
            .finish()
    }
}

/// HMAC-SHA256 (RFC 2104) of `msg` with a 32-byte key.
pub fn hmac_sha256(key: &[u8; KEY_LEN], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

/// Compiles a mask pattern as the engine runs it: bytes, linear time,
/// bounded size; a pattern that matches the empty string would mask
/// nothing useful and is refused.
pub fn compile_pattern(p: &str) -> Result<regex::bytes::Regex, String> {
    if p.is_empty() || p.len() > MAX_PATTERN_LEN {
        return Err(format!("mask pattern must be 1 to {MAX_PATTERN_LEN} bytes"));
    }
    let re = regex::bytes::RegexBuilder::new(p)
        .unicode(false)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| format!("mask pattern {p:?}: {e}"))?;
    if re.is_match(b"") {
        return Err(format!("mask pattern {p:?} matches the empty string"));
    }
    Ok(re)
}

/// Checks a field name: printable ASCII without spaces, 1 to MAX_FIELD_LEN.
pub fn check_field(f: &str) -> Result<(), String> {
    if f.is_empty() || f.len() > MAX_FIELD_LEN || !f.bytes().all(|c| c.is_ascii_graphic()) {
        return Err(format!(
            "sensitive field {f:?}: 1 to {MAX_FIELD_LEN} printable characters, no space"
        ));
    }
    Ok(())
}

impl Privacy {
    /// Whether the key of `field` (`ARGS:name`, `REQUEST_HEADERS:X-Id`,
    /// the last part of a JSON path) is one of the policy's names.
    pub fn sensitive(&self, field: &str) -> bool {
        let key = field.split_once(':').map_or(field, |(_, k)| k).trim();
        // a value inspected decoded (b64.rs) keeps the name it came with
        let key = key.strip_suffix(crate::b64::SUFFIX_STR).unwrap_or(key);
        let last = key.rsplit_once('.').map_or(key, |(_, l)| l);
        self.fields
            .iter()
            .any(|f| f.eq_ignore_ascii_case(key) || f.eq_ignore_ascii_case(last))
    }

    /// The extra field names, lowercase (replay samples, #75).
    pub fn fields(&self) -> &[String] {
        &self.fields
    }

    /// The compiled mask patterns (replay samples, #75).
    pub fn patterns(&self) -> &[regex::bytes::Regex] {
        &self.patterns
    }

    /// The identity as events carry it: `hmac:` and 32 hex digits when the
    /// policy pseudonymizes it, else None (kept as it is). Empty stays empty.
    pub fn identity(&self, identity: &[u8]) -> Option<String> {
        let key = self.identity_key.as_ref()?;
        if identity.is_empty() {
            return Some(String::new());
        }
        let mac = hmac_sha256(key, identity);
        let mut s = String::with_capacity(HMAC_PREFIX.len() + 32);
        s.push_str(HMAC_PREFIX);
        for b in &mac[..16] {
            s.push_str(&format!("{b:02x}"));
        }
        Some(s)
    }

    /// Masks the policy's patterns in `b` with '*' (same length).
    pub fn mask(&self, b: &mut [u8]) {
        for re in &self.patterns {
            let hits: Vec<(usize, usize)> = re.find_iter(b).map(|m| (m.start(), m.end())).collect();
            for (s, e) in hits {
                b[s..e].fill(b'*');
            }
        }
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// The PRIVACY section of `specs` (empty when no policy has settings).
/// `identity_key` is required when a policy asks for `identity: hmac`.
pub fn encode(
    specs: &[PrivacySpec],
    identity_key: Option<&[u8; KEY_LEN]>,
) -> Result<Vec<u8>, String> {
    let specs: Vec<&PrivacySpec> = specs.iter().filter(|s| !s.is_empty()).collect();
    if specs.is_empty() {
        return Ok(Vec::new());
    }
    let key = match (specs.iter().any(|s| s.identity_hmac), identity_key) {
        (true, None) => return Err("identity: hmac needs the installation's identity key".into()),
        (true, Some(k)) if k.iter().all(|&b| b == 0) => {
            return Err("the identity key must not be all zeros".into());
        }
        (true, Some(k)) => *k,
        (false, _) => [0; KEY_LEN],
    };
    let mut strings: Vec<&[u8]> = vec![];
    let mut entries = vec![];
    for s in &specs {
        let ff = strings.len() as u32;
        strings.extend(s.sensitive_fields.iter().map(|f| f.as_bytes()));
        let pf = strings.len() as u32;
        strings.extend(s.mask_patterns.iter().map(|p| p.as_bytes()));
        entries.push((
            s.policy_index,
            ff,
            s.sensitive_fields.len() as u32,
            pf,
            s.mask_patterns.len() as u32,
            if s.identity_hmac {
                FLAG_IDENTITY_HMAC
            } else {
                0
            },
        ));
    }
    let mut out = vec![];
    put_u32(&mut out, entries.len() as u32);
    put_u32(&mut out, strings.len() as u32);
    out.extend_from_slice(&key);
    for (pi, ff, fc, pf, pc, flags) in entries {
        for v in [pi, ff, fc, pf, pc, flags] {
            put_u32(&mut out, v);
        }
    }
    let mut off = 0u32;
    for s in &strings {
        put_u32(&mut out, off);
        put_u32(&mut out, s.len() as u32);
        off += s.len() as u32;
    }
    for s in strings {
        out.extend_from_slice(s);
    }
    Ok(out)
}

/// Parses and compiles the PRIVACY section: per policy index, its
/// settings. Every bound is checked; `flagged` are the policies whose
/// entry announces settings, which must be exactly those of the section.
pub fn parse(sec: &[u8], n_policies: u32, flagged: &[u32]) -> Result<Vec<Option<Privacy>>, Error> {
    let bad = |_| Error::BadLayout("bad privacy section");
    let mut out: Vec<Option<Privacy>> = (0..n_policies).map(|_| None).collect();
    if sec.is_empty() {
        return if flagged.is_empty() {
            Ok(out)
        } else {
            Err(Error::BadLayout("policy privacy settings missing"))
        };
    }
    if sec.len() < HEADER_LEN {
        return Err(bad(()));
    }
    let (n, ns) = (u32_at(sec, 0) as usize, u32_at(sec, 4) as usize);
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&sec[8..HEADER_LEN]);
    let key = (key != [0; KEY_LEN]).then_some(key);
    let rec_end = n
        .checked_mul(ENTRY_LEN)
        .and_then(|e| e.checked_add(HEADER_LEN))
        .ok_or(Error::BadLayout("bad privacy section"))?;
    let blob_at = ns
        .checked_mul(8)
        .and_then(|s| s.checked_add(rec_end))
        .filter(|&b| b <= sec.len())
        .ok_or(Error::BadLayout("bad privacy section"))?;
    let blob = &sec[blob_at..];
    let string = |i: usize| -> Result<&str, Error> {
        if i >= ns {
            return Err(Error::BadLayout("bad privacy section"));
        }
        let r = rec_end + i * 8;
        let (o, l) = (u32_at(sec, r) as usize, u32_at(sec, r + 4) as usize);
        let s = o
            .checked_add(l)
            .filter(|&e| e <= blob.len())
            .map(|e| &blob[o..e])
            .ok_or(Error::BadLayout("bad privacy section"))?;
        std::str::from_utf8(s).map_err(|_| Error::BadLayout("bad privacy section"))
    };
    let mut seen = vec![];
    for i in 0..n {
        let e = HEADER_LEN + i * ENTRY_LEN;
        let v = |k: usize| u32_at(sec, e + k * 4) as usize;
        let (pi, ff, fc, pf, pc) = (v(0), v(1), v(2), v(3), v(4));
        let flags = v(5) as u32;
        if flags & !FLAG_IDENTITY_HMAC != 0
            || (flags & FLAG_IDENTITY_HMAC != 0 && key.is_none())
            || pi >= n_policies as usize
            || out[pi].is_some()
            || fc > MAX_FIELDS
            || pc > MAX_PATTERNS
        {
            return Err(Error::BadLayout("bad privacy entry"));
        }
        let mut fields = Vec::with_capacity(fc);
        for k in 0..fc {
            let f = string(
                ff.checked_add(k)
                    .ok_or(Error::BadLayout("bad privacy entry"))?,
            )?;
            check_field(f).map_err(|_| Error::BadLayout("bad privacy field"))?;
            fields.push(f.to_ascii_lowercase());
        }
        let mut patterns = Vec::with_capacity(pc);
        for k in 0..pc {
            let p = string(
                pf.checked_add(k)
                    .ok_or(Error::BadLayout("bad privacy entry"))?,
            )?;
            // the compiler checked it: a refusal is a bundle for another build
            patterns.push(
                compile_pattern(p)
                    .map_err(|_| Error::BadLayout("privacy pattern this build cannot compile"))?,
            );
        }
        out[pi] = Some(Privacy {
            fields,
            patterns,
            identity_key: if flags & FLAG_IDENTITY_HMAC != 0 {
                key
            } else {
                None
            },
        });
        seen.push(pi as u32);
    }
    seen.sort_unstable();
    let mut want = flagged.to_vec();
    want.sort_unstable();
    if seen != want {
        return Err(Error::BadLayout(
            "policy privacy flag does not match the privacy section",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = {
        let mut k = [0u8; KEY_LEN];
        let mut i = 0;
        while i < KEY_LEN {
            k[i] = i as u8 + 1;
            i += 1;
        }
        k
    };

    fn spec(pi: u32, f: &[&str], p: &[&str]) -> PrivacySpec {
        PrivacySpec {
            policy_index: pi,
            sensitive_fields: f.iter().map(|s| s.to_string()).collect(),
            mask_patterns: p.iter().map(|s| s.to_string()).collect(),
            identity_hmac: false,
        }
    }

    #[test]
    fn round_trip_and_use() {
        let sec = encode(
            &[
                spec(1, &["Ma_Khach_Hang", "so_hop_dong"], &["KH[0-9]{8}"]),
                spec(0, &[], &[]),
            ],
            None,
        )
        .unwrap();
        let got = parse(&sec, 3, &[1]).unwrap();
        assert!(got[0].is_none() && got[2].is_none());
        let p = got[1].as_ref().unwrap();
        assert!(p.sensitive("ARGS:ma_khach_hang"));
        assert!(p.sensitive("ARGS:order.SO_HOP_DONG"));
        assert!(!p.sensitive("ARGS:ma_khach"));
        let mut b = b"id KH12345678 and KH1234".to_vec();
        p.mask(&mut b);
        assert_eq!(b, b"id ********** and KH1234");
        assert_eq!(p.identity(b"user@example.test"), None, "identity kept");
        assert!(encode(&[spec(0, &[], &[])], None).unwrap().is_empty());
    }

    /// HMAC-SHA256 as RFC 2104 defines it (values from Python's hmac).
    #[test]
    fn hmac_known_answers() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&hmac_sha256(&KEY, b"user@example.test")),
            "19a5a732d32ba3001eb251e854f4be4c76e66377abf1379119981df25c6f77c8"
        );
        assert_eq!(
            hex(&hmac_sha256(&KEY, b"")),
            "462476a897ddfdbd40d1420e08a5bcfeeb25c3e2ade6a0a9083b327b9ef9fca1"
        );
    }

    #[test]
    fn identity_hmac() {
        let only = PrivacySpec {
            policy_index: 0,
            identity_hmac: true,
            ..Default::default()
        };
        assert!(encode(std::slice::from_ref(&only), None).is_err(), "no key");
        assert!(
            encode(std::slice::from_ref(&only), Some(&[0; KEY_LEN])).is_err(),
            "zero key"
        );
        let sec = encode(&[only, spec(1, &["a"], &[])], Some(&KEY)).unwrap();
        let got = parse(&sec, 2, &[0, 1]).unwrap();
        let p = got[0].as_ref().unwrap();
        assert_eq!(
            p.identity(b"user@example.test").unwrap(),
            "hmac:19a5a732d32ba3001eb251e854f4be4c"
        );
        assert_eq!(p.identity(b"").unwrap(), "", "no identity, nothing to hide");
        assert_eq!(
            got[1].as_ref().unwrap().identity(b"x"),
            None,
            "the other policy keeps it"
        );
        assert!(
            !format!("{p:?}").contains("19a5"),
            "Debug never shows the key"
        );
        // a flag without the key, or an unknown flag, is refused
        let mut bad = sec.clone();
        bad[8..8 + KEY_LEN].fill(0);
        assert!(parse(&bad, 2, &[0, 1]).is_err());
        let mut bad = sec;
        bad[HEADER_LEN + 20] = 2;
        assert!(parse(&bad, 2, &[0, 1]).is_err());
    }

    #[test]
    fn patterns_are_checked() {
        assert!(compile_pattern("a*").is_err(), "matches empty");
        assert!(compile_pattern("").is_err());
        assert!(compile_pattern(&"a".repeat(257)).is_err());
        assert!(compile_pattern("(a)\\1").is_err(), "backreference");
        assert!(compile_pattern("[0-9]{4}-[0-9]{4}").is_ok());
        assert!(check_field("has space").is_err() && check_field("").is_err());
    }

    #[test]
    fn layout_errors() {
        let sec = encode(&[spec(1, &["a"], &["b+"])], None).unwrap();
        assert!(parse(&sec, 1, &[1]).is_err(), "policy index out of range");
        assert!(parse(&sec, 2, &[]).is_err(), "settings without the flag");
        assert!(parse(&[], 2, &[1]).is_err(), "flag without settings");
        assert!(parse(&sec[..sec.len() - 1], 2, &[1]).is_err(), "cut");
        assert!(
            parse(&sec[..HEADER_LEN - 1], 2, &[1]).is_err(),
            "header cut"
        );
        let mut bad = sec.clone();
        bad[HEADER_LEN + 20] = 4; // unknown flag
        assert!(parse(&bad, 2, &[1]).is_err());
        let mut bad = sec;
        let n = bad.len();
        bad[n - 2] = b'('; // the pattern no longer compiles
        assert!(parse(&bad, 2, &[1]).is_err());
    }
}
