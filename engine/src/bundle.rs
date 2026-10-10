//! Bundle file format, version 1 (docs/design/control-file.md).
//!
//! ```text
//! 0      header (64 bytes, little-endian)
//!          magic "STRBNDL\0" | format u16 | flags u16 | n_policies u32
//!          version u64 | created_at_ms u64 | sections_off u64 | sections_len u64
//!          reserved [u8; 16] (zero)
//! 64     policy table: n_policies x 64 bytes:
//!          name [u8; 56] (1..55 chars [a-z0-9._-], NUL-padded) | mode u8
//!          (0 shadow, 1 enforce) | reserved [u8; 7] (zero)
//! ...    zero padding up to sections_off (multiple of 4096)
//! off    section directory: count u32 | reserved u32 |
//!          count x { kind u32 | reserved u32 | offset u64 | len u64 }
//!        then every section at a multiple of 4096, in offset order
//!        (layouts of the rule sections: `crate::rules`)
//! len-64 Ed25519 signature over bytes [0, len - 64)
//! ```
//!
//! Everything is read in place from the mapping; nothing is copied.
#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub const MAGIC: &[u8; 8] = b"STRBNDL\0";
pub const FORMAT: u16 = 1;
pub const HEADER_LEN: usize = 64;
pub const POLICY_ENTRY_LEN: usize = 64;
/// Bytes of the NUL-padded name inside a policy entry.
pub const POLICY_NAME_LEN: usize = 56;
pub const SIG_LEN: usize = 64;
pub const SECTION_ALIGN: usize = 4096;
pub const MAX_POLICIES: u32 = 4096;
pub const MAX_SECTIONS: usize = 64;
const DIR_ENTRY_LEN: usize = 24;

/// Section kinds. Unknown kinds are skipped (bounds still checked), so newer
/// compilers can add sections that older engines ignore.
pub mod kind {
    pub const RULES: u32 = 1;
    pub const CONDITIONS: u32 = 2;
    pub const TARGETS: u32 = 3;
    pub const LISTS: u32 = 4;
    pub const STRINGS: u32 = 5;
    pub const BLOCK_PAGE: u32 = 6;
    /// Highest kind this engine reads.
    pub const KNOWN: u32 = 6;
}

/// (offset, len) of a section inside the bundle; (0, 0) when absent.
pub type Range = (usize, usize);
/// Header flag: this bundle may replace a newer one (signed rollback).
pub const FLAG_ROLLBACK: u16 = 1 << 0;

/// Policy mode signed into the bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Shadow = 0,
    Enforce = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub version: u64,
    pub created_at_ms: u64,
    pub flags: u16,
    pub n_policies: u32,
    /// Known sections, indexed by kind.
    pub sections: [Range; kind::KNOWN as usize + 1],
}

impl Info {
    pub fn section<'a>(&self, bundle: &'a [u8], kind: u32) -> &'a [u8] {
        let (off, len) = self.sections.get(kind as usize).copied().unwrap_or((0, 0));
        &bundle[off..off + len]
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadKey,
    TooShort,
    BadMagic,
    BadFormat,
    BadSignature,
    BadLayout(&'static str),
}

impl Error {
    pub fn message(&self) -> &'static str {
        match self {
            Error::BadKey => "invalid public key",
            Error::TooShort => "bundle too short",
            Error::BadMagic => "bad bundle magic",
            Error::BadFormat => "unsupported bundle format version",
            Error::BadSignature => "bad bundle signature",
            Error::BadLayout(m) => m,
        }
    }
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[off..off + 4]);
    u32::from_le_bytes(a)
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

fn valid_policy_name(name: &[u8]) -> bool {
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    len > 0
        && len < POLICY_NAME_LEN
        && name[len..].iter().all(|&c| c == 0)
        && name[..len]
            .iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
}

fn valid_policy_entry(entry: &[u8]) -> bool {
    valid_policy_name(&entry[..POLICY_NAME_LEN])
        && entry[POLICY_NAME_LEN] <= Mode::Enforce as u8
        && entry[POLICY_NAME_LEN + 1..].iter().all(|&c| c == 0)
}

fn entry_name(e: &[u8]) -> &[u8] {
    let len = e[..POLICY_NAME_LEN]
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(POLICY_NAME_LEN);
    &e[..len]
}

fn entry_mode(e: &[u8]) -> Mode {
    if e[POLICY_NAME_LEN] == Mode::Enforce as u8 {
        Mode::Enforce
    } else {
        Mode::Shadow
    }
}

/// Verifies the signature first, then the layout; returns the header info.
pub fn verify(bundle: &[u8], pubkey: &[u8]) -> Result<Info, Error> {
    let key: [u8; 32] = pubkey.try_into().map_err(|_| Error::BadKey)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| Error::BadKey)?;

    if bundle.len() < HEADER_LEN + SIG_LEN {
        return Err(Error::TooShort);
    }
    if &bundle[..8] != MAGIC {
        return Err(Error::BadMagic);
    }

    let (signed, sig) = bundle.split_at(bundle.len() - SIG_LEN);
    let sig: [u8; SIG_LEN] = sig.try_into().map_err(|_| Error::TooShort)?;
    key.verify_strict(signed, &Signature::from_bytes(&sig))
        .map_err(|_| Error::BadSignature)?;

    if u16_at(bundle, 8) != FORMAT {
        return Err(Error::BadFormat);
    }
    let mut info = Info {
        flags: u16_at(bundle, 10),
        n_policies: u32_at(bundle, 12),
        version: u64_at(bundle, 16),
        created_at_ms: u64_at(bundle, 24),
        sections: [(0, 0); kind::KNOWN as usize + 1],
    };
    let sections_off = u64_at(bundle, 32);
    let sections_len = u64_at(bundle, 40);

    if bundle[48..64].iter().any(|&c| c != 0) {
        return Err(Error::BadLayout("reserved header bytes are not zero"));
    }
    if info.n_policies > MAX_POLICIES {
        return Err(Error::BadLayout("too many policies"));
    }
    let table_end = HEADER_LEN + info.n_policies as usize * POLICY_ENTRY_LEN;
    let body_end = (signed.len()) as u64;
    if !sections_off.is_multiple_of(SECTION_ALIGN as u64)
        || sections_off < table_end as u64
        || sections_off
            .checked_add(sections_len)
            .is_none_or(|end| end > body_end)
    {
        return Err(Error::BadLayout("bad section bounds"));
    }
    if !bundle[HEADER_LEN..table_end]
        .chunks(POLICY_ENTRY_LEN)
        .all(valid_policy_entry)
    {
        return Err(Error::BadLayout("bad policy entry"));
    }
    if sections_len > 0 {
        read_directory(
            bundle,
            sections_off as usize,
            sections_len as usize,
            &mut info,
        )?;
    }
    Ok(info)
}

/// Validates the section directory: aligned, inside the section region,
/// sorted, non-overlapping, each known kind at most once.
fn read_directory(bundle: &[u8], off: usize, len: usize, info: &mut Info) -> Result<(), Error> {
    let end = off + len;
    if len < 8 {
        return Err(Error::BadLayout("section directory too short"));
    }
    let n = u32_at(bundle, off) as usize;
    if n > MAX_SECTIONS || u32_at(bundle, off + 4) != 0 {
        return Err(Error::BadLayout("bad section directory"));
    }
    let dir_end = off + 8 + n * DIR_ENTRY_LEN;
    if dir_end > end {
        return Err(Error::BadLayout("section directory too short"));
    }
    let mut next = dir_end;
    for i in 0..n {
        let e = off + 8 + i * DIR_ENTRY_LEN;
        let k = u32_at(bundle, e);
        let s_off = u64_at(bundle, e + 8);
        let s_len = u64_at(bundle, e + 16);
        let s_end = s_off.saturating_add(s_len);
        if u32_at(bundle, e + 4) != 0
            || !s_off.is_multiple_of(SECTION_ALIGN as u64)
            || s_off < next as u64
            || s_end > end as u64
        {
            return Err(Error::BadLayout("bad section bounds"));
        }
        if (1..=kind::KNOWN).contains(&k) {
            let slot = &mut info.sections[k as usize];
            if *slot != (0, 0) {
                return Err(Error::BadLayout("duplicate section"));
            }
            *slot = (s_off as usize, s_len as usize);
        }
        next = s_end as usize;
    }
    Ok(())
}

/// Iterates the policy names of a bundle that passed `verify`.
pub fn policies<'a>(
    bundle: &'a [u8],
    info: &Info,
) -> impl Iterator<Item = (&'a [u8], Mode)> + use<'a> {
    let end = HEADER_LEN + info.n_policies as usize * POLICY_ENTRY_LEN;
    bundle[HEADER_LEN..end]
        .chunks(POLICY_ENTRY_LEN)
        .map(|e| (entry_name(e), entry_mode(e)))
}

/// Index and mode of the policy `name` in a bundle that passed `verify`.
pub fn find_policy(bundle: &[u8], info: &Info, name: &[u8]) -> Option<(u32, Mode)> {
    policies(bundle, info)
        .position(|(n, _)| n == name)
        .map(|i| {
            (
                i as u32,
                policies(bundle, info).nth(i).map_or(Mode::Shadow, |p| p.1),
            )
        })
}

/// Parameters for `build` (bundle compiler, tools and tests).
pub struct Spec<'a> {
    pub version: u64,
    pub created_at_ms: u64,
    pub flags: u16,
    pub policies: &'a [(&'a str, Mode)],
    /// (kind, bytes), written in this order, each 4 KB-aligned.
    pub sections: &'a [(u32, &'a [u8])],
}

/// Builds and signs a bundle with an Ed25519 seed (32 bytes).
pub fn build(spec: &Spec<'_>, seed: &[u8; 32]) -> Result<Vec<u8>, Error> {
    if spec.policies.len() > MAX_POLICIES as usize
        || !spec.policies.iter().all(|(p, _)| {
            let mut e = [0u8; POLICY_NAME_LEN];
            let n = p.len().min(POLICY_NAME_LEN);
            e[..n].copy_from_slice(&p.as_bytes()[..n]);
            p.len() < POLICY_NAME_LEN && valid_policy_name(&e)
        })
    {
        return Err(Error::BadLayout("bad policy name"));
    }

    let table_end = HEADER_LEN + spec.policies.len() * POLICY_ENTRY_LEN;
    let sections_off = table_end.div_ceil(SECTION_ALIGN) * SECTION_ALIGN;
    let mut out = vec![0u8; sections_off];

    out[..8].copy_from_slice(MAGIC);
    out[8..10].copy_from_slice(&FORMAT.to_le_bytes());
    out[10..12].copy_from_slice(&spec.flags.to_le_bytes());
    out[12..16].copy_from_slice(&(spec.policies.len() as u32).to_le_bytes());
    out[16..24].copy_from_slice(&spec.version.to_le_bytes());
    out[24..32].copy_from_slice(&spec.created_at_ms.to_le_bytes());
    for (i, (p, mode)) in spec.policies.iter().enumerate() {
        let at = HEADER_LEN + i * POLICY_ENTRY_LEN;
        out[at..at + p.len()].copy_from_slice(p.as_bytes());
        out[at + POLICY_NAME_LEN] = *mode as u8;
    }

    if spec.sections.len() > MAX_SECTIONS {
        return Err(Error::BadLayout("too many sections"));
    }
    if !spec.sections.is_empty() {
        // directory, then each section on the next 4 KB boundary
        let dir_len = 8 + spec.sections.len() * DIR_ENTRY_LEN;
        let mut dir = vec![0u8; dir_len];
        dir[..4].copy_from_slice(&(spec.sections.len() as u32).to_le_bytes());
        let mut at = (sections_off + dir_len).div_ceil(SECTION_ALIGN) * SECTION_ALIGN;
        let mut placed = Vec::with_capacity(spec.sections.len());
        for (i, (k, bytes)) in spec.sections.iter().enumerate() {
            let e = 8 + i * DIR_ENTRY_LEN;
            dir[e..e + 4].copy_from_slice(&k.to_le_bytes());
            dir[e + 8..e + 16].copy_from_slice(&(at as u64).to_le_bytes());
            dir[e + 16..e + 24].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
            placed.push(at);
            at = (at + bytes.len()).div_ceil(SECTION_ALIGN) * SECTION_ALIGN;
        }
        out.extend_from_slice(&dir);
        for ((_, bytes), at) in spec.sections.iter().zip(placed) {
            out.resize(at, 0);
            out.extend_from_slice(bytes);
        }
    }
    let sections_len = out.len() - sections_off;
    out[32..40].copy_from_slice(&(sections_off as u64).to_le_bytes());
    out[40..48].copy_from_slice(&(sections_len as u64).to_le_bytes());

    let sig = SigningKey::from_bytes(seed).sign(&out);
    out.extend_from_slice(&sig.to_bytes());
    Ok(out)
}

/// Public key for an Ed25519 seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7; 32];

    fn spec<'a>(policies: &'a [(&'a str, Mode)]) -> Spec<'a> {
        Spec {
            version: 42,
            created_at_ms: 1_700_000_000_000,
            flags: 0,
            policies,
            sections: &[
                (kind::STRINGS, b"strings"),
                (0x7fff, b"unknown kind, skipped"),
            ],
        }
    }

    #[test]
    fn round_trip() {
        let b = build(
            &spec(&[
                ("example-api", Mode::Enforce),
                ("example-web", Mode::Shadow),
            ]),
            &SEED,
        )
        .unwrap();
        let info = verify(&b, &public_key(&SEED)).unwrap();
        assert_eq!(info.version, 42);
        assert_eq!(info.n_policies, 2);
        assert_eq!(info.flags, 0);
        let names: Vec<_> = policies(&b, &info).collect();
        assert_eq!(
            names,
            [
                (&b"example-api"[..], Mode::Enforce),
                (b"example-web", Mode::Shadow)
            ]
        );
        assert_eq!(
            find_policy(&b, &info, b"example-web"),
            Some((1, Mode::Shadow))
        );
        assert_eq!(
            find_policy(&b, &info, b"example-api"),
            Some((0, Mode::Enforce))
        );
        assert_eq!(find_policy(&b, &info, b"example"), None);
        // sections start on a 4 KB boundary
        assert_eq!(u64_at(&b, 32) % 4096, 0);
    }

    #[test]
    fn rollback_flag() {
        let mut s = spec(&[]);
        s.flags = FLAG_ROLLBACK;
        let b = build(&s, &SEED).unwrap();
        assert_eq!(verify(&b, &public_key(&SEED)).unwrap().flags, FLAG_ROLLBACK);
    }

    #[test]
    fn any_modified_byte_breaks_the_signature() {
        let b = build(&spec(&[("example-api", Mode::Shadow)]), &SEED).unwrap();
        let key = public_key(&SEED);
        for i in (8..b.len()).step_by(97) {
            let mut t = b.clone();
            t[i] ^= 1;
            assert!(verify(&t, &key).is_err(), "byte {i}");
        }
    }

    #[test]
    fn wrong_key_is_rejected() {
        let b = build(&spec(&[]), &SEED).unwrap();
        assert_eq!(verify(&b, &public_key(&[8; 32])), Err(Error::BadSignature));
        assert_eq!(verify(&b, &[0; 31]), Err(Error::BadKey));
    }

    #[test]
    fn short_and_foreign_input() {
        let key = public_key(&SEED);
        assert_eq!(verify(b"", &key), Err(Error::TooShort));
        assert_eq!(verify(&[0u8; 200], &key), Err(Error::BadMagic));
    }

    #[test]
    fn signed_but_malformed_layout_is_rejected() {
        // a signer bug must not turn into out-of-bounds reads
        let mut b = build(&spec(&[("example-api", Mode::Shadow)]), &SEED).unwrap();
        b.truncate(b.len() - SIG_LEN);
        b[12..16].copy_from_slice(&5000u32.to_le_bytes());
        let sig = SigningKey::from_bytes(&SEED).sign(&b);
        b.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            verify(&b, &public_key(&SEED)),
            Err(Error::BadLayout("too many policies"))
        );
    }

    #[test]
    fn invalid_policy_names() {
        for bad in ["", "Upper", "a/b", "x".repeat(56).as_str()] {
            assert!(
                build(&spec(&[(bad, Mode::Shadow)]), &SEED).is_err(),
                "{bad:?}"
            );
        }
        assert!(build(&spec(&[("x".repeat(55).as_str(), Mode::Shadow)]), &SEED).is_ok());
    }

    #[test]
    fn signed_bad_policy_mode_is_rejected() {
        let mut b = build(&spec(&[("example-api", Mode::Shadow)]), &SEED).unwrap();
        b.truncate(b.len() - SIG_LEN);
        b[HEADER_LEN + POLICY_NAME_LEN] = 2;
        let sig = SigningKey::from_bytes(&SEED).sign(&b);
        b.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            verify(&b, &public_key(&SEED)),
            Err(Error::BadLayout("bad policy entry"))
        );
    }
}
