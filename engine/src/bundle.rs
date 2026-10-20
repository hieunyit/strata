//! Bundle file format, version 1 (docs/design/control-file.md).
//!
//! ```text
//! 0      header (64 bytes, little-endian)
//!          magic "STRBNDL\0" | format u16 | flags u16 | n_policies u32
//!          version u64 | created_at_ms u64 | sections_off u64 | sections_len u64
//!          reserved [u8; 16] (zero)
//! 64     policy table: n_policies x 64 bytes:
//!          name [u8; 56] (1..55 chars [a-z0-9._-], NUL-padded) | mode u8
//!          (0 shadow, 1 enforce) | oversize u8 (0 pass, 1 block: request
//!          bodies larger than the connector inspects) | response u8 (flags,
//!          `Response`) | canary u16 (enforce share in basis points, 0 = no
//!          canary; only with mode enforce, < 10000) | signatures u8
//!          (`Signatures`: 0 shadow, 1 off, 2 enforce) | reserved [u8; 2]
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
    pub const HYPERSCAN: u32 = 7;
    /// The patterns of HYPERSCAN again, compiled in block mode, for short
    /// values (#27). Engines before it skip the section and scan with
    /// HYPERSCAN alone.
    pub const HYPERSCAN_BLOCK: u32 = 8;
    /// Privacy settings of the policies (P-01 §1, `crate::privacy`).
    pub const PRIVACY: u32 = 9;
    pub const EXCEPTIONS: u32 = 10;
    /// Signed per-policy managed-rule log-only overlay.
    pub const STAGING: u32 = 11;
    /// Published IP ranges of the big crawlers (W18-R-02,
    /// `crate::goodbots`). Optional: engines before it skip the section,
    /// and their rules on bot_verified cannot exist (unknown target).
    pub const GOOD_BOTS: u32 = 12;
    /// CRS paranoia levels of the policies with bit 6 of byte 62
    /// (W17-S-01, `crate::paranoia`).
    pub const PARANOIA: u32 = 13;
    /// Removals of the exclusion rules (rule flag bit 3) and the policies
    /// that run them (W17-S-01, `crate::rule_exclusions`).
    pub const EXCLUSIONS: u32 = 14;
    /// Networks of the countries and ASNs rules name (W19-R-01,
    /// `crate::geo`). Optional: engines before it skip the section, and
    /// refuse rules on geo_country / geo_asn (unknown targets).
    pub const GEO: u32 = 15;
    /// The policies each policy-scoped rule (rule flag bit 4) runs for,
    /// and its mode (W19-G2-01, `crate::scope`).
    pub const SCOPE: u32 = 16;
    /// Highest kind this engine reads.
    pub const KNOWN: u32 = 16;
}

/// (offset, len) of a section inside the bundle; (0, 0) when absent.
pub type Range = (usize, usize);
/// Header flag: this bundle may replace a newer one (signed rollback).
pub const FLAG_ROLLBACK: u16 = 1 << 0;

/// What to do with a request body larger than the connector inspects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Oversize {
    Pass = 0,
    Block = 1,
}

/// Response layer of a policy: one flag per check (0 = all off, which is
/// what bundles written before the flags carry).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Response(pub u8);

impl Response {
    /// Response status against the allowed codes (rule 600001).
    pub const STATUS: u8 = 1 << 0;
    /// Database error signatures in the body (rules 600101-600107).
    pub const DB_ERRORS: u8 = 1 << 1;
    /// Data guard: Vietnamese citizen ID numbers (rule 600201).
    pub const GUARD_CCCD: u8 = 1 << 2;
    /// Data guard: JSON Web Tokens (rule 600202).
    pub const GUARD_JWT: u8 = 1 << 3;
    /// Data guard: payment card numbers (rule 600203, P-01 §1). Engines
    /// before it refuse a bundle with this bit.
    pub const GUARD_PAN: u8 = 1 << 4;
    pub const ALL: u8 = 0x1f;

    pub fn has(self, flag: u8) -> bool {
        self.0 & flag != 0
    }
}

/// Byte of the policy entry for its events (RV-G2-01): bits 0-1 the snippet
/// size, bit 2 the privacy flag, other bits 0. Bytes 59-61 belong to the
/// canary (u16) and the signature pack (W11-R-01, RV-S-01). Engines from
/// before it refuse a bundle with this byte set.
const EVENT_BYTE: usize = POLICY_NAME_LEN + 6;
const SNIPPET_MASK: u8 = 0b11;
const PRIVACY_BIT: u8 = 1 << 2;
/// bit 3 of EVENT_BYTE (#98): when the CPU budget runs out on a request
/// that already has findings (score above 0), the connector answers as in
/// fail mode closed (503) instead of following its fail mode. Engines
/// from before it refuse a bundle with this bit set.
const FAIL_ON_FINDINGS_BIT: u8 = 1 << 3;
// Mandatory compatibility bit: old engines reject exception-bearing policies.
const EXCEPTIONS_BIT: u8 = 1 << 4;
// Old engines reject policies requiring per-rule log-only staging.
const STAGING_BIT: u8 = 1 << 5;
// W17-S-01: the policy's CRS paranoia levels are in section PARANOIA.
const PARANOIA_BIT: u8 = 1 << 6;

/// Last byte of the policy entry (#28): the arguments the policy inspects,
/// in fours; 0 (bundles written before it) is the engine's limit,
/// `MAX_ARGS_DEFAULT`. Engines from before it refuse a bundle with this
/// byte set rather than inspect more arguments than the policy asks.
const ARGS_BYTE: usize = POLICY_NAME_LEN + 7;
/// The engine's limit when the policy sets none (eval::MAX_ARGS).
pub const MAX_ARGS_DEFAULT: usize = 1024;
/// Highest `max_args` a policy sets (255 fours).
pub const MAX_ARGS_POLICY: usize = 255 * 4;

/// The byte for `max_args` (0 = the default), rounded up to four.
pub fn args_byte(max_args: usize) -> Option<u8> {
    match max_args {
        0 => Some(0),
        n if n <= MAX_ARGS_POLICY => Some(n.div_ceil(4) as u8),
        _ => None,
    }
}

/// Longest snippet of a match in the policy's events (P-01 §1b, set by
/// admins with `max_snippet_size`): bits 0-1 of EVENT_BYTE, 0 in bundles
/// written before it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SnippetSize {
    /// 128 bytes
    #[default]
    Small = 0,
    /// 2 KB, for investigation
    Kb2 = 1,
    /// 4 KB
    Kb4 = 2,
}

impl SnippetSize {
    pub fn bytes(self) -> usize {
        match self {
            SnippetSize::Small => 128,
            SnippetSize::Kb2 => 2048,
            SnippetSize::Kb4 => 4096,
        }
    }

    fn of(b: u8) -> SnippetSize {
        match b {
            1 => SnippetSize::Kb2,
            2 => SnippetSize::Kb4,
            _ => SnippetSize::Small,
        }
    }
}

/// A policy of the bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy<'a> {
    pub index: u32,
    pub name: &'a [u8],
    pub mode: Mode,
    pub oversize: Oversize,
    pub response: Response,
    /// Enforce canary (`crate::canary`): share of clients, in basis points,
    /// whose requests an enforce policy blocks; the others run in shadow.
    /// 0 = no canary (every request follows `mode`).
    pub canary: u16,
    /// What the rules of the signature pack do for this policy.
    pub signatures: Signatures,
    pub snippet: SnippetSize,
    /// the policy has privacy settings (section PRIVACY)
    pub privacy: bool,
    /// Requires section EXCEPTIONS and field-scoped runtime exclusion support.
    pub exceptions: bool,
    /// Requires the signed STAGING section and log-only rule support.
    pub staging: bool,
    /// Its CRS paranoia levels are in section PARANOIA (W17-S-01).
    pub paranoia: bool,
    /// arguments inspected (query and body fields): see ARGS_BYTE
    pub max_args: usize,
    /// #98: budget exhausted with findings: fail closed (FAIL_ON_FINDINGS_BIT)
    pub fail_on_findings: bool,
}

/// Rules of the signature pack for a policy (RV-S-01). The default (0 in
/// the bundle, so every bundle from before it) is shadow: they run and are
/// reported, but never block, even in an enforce policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Signatures {
    #[default]
    Shadow = 0,
    Off = 1,
    Enforce = 2,
}

impl Signatures {
    fn from_byte(b: u8) -> Option<Signatures> {
        match b {
            0 => Some(Signatures::Shadow),
            1 => Some(Signatures::Off),
            2 => Some(Signatures::Enforce),
            _ => None,
        }
    }
}

/// Highest canary share: 100% is a plain enforce policy (canary 0).
pub const MAX_CANARY: u16 = 9999;

/// A policy to write (`build`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicySpec<'a> {
    pub name: &'a str,
    pub mode: Mode,
    pub oversize: Oversize,
    pub response: Response,
    /// See `Policy::canary`.
    pub canary: u16,
    /// See `Policy::signatures`.
    pub signatures: Signatures,
    pub snippet: SnippetSize,
    /// bit 2 of EVENT_BYTE: the policy has privacy settings; engines that do not
    /// read section PRIVACY refuse the bundle rather than ignore them
    pub privacy: bool,
    /// Requires section EXCEPTIONS and field-scoped runtime exclusion support.
    pub exceptions: bool,
    /// Requires the signed STAGING section and log-only rule support.
    pub staging: bool,
    /// See `Policy::paranoia`.
    pub paranoia: bool,
    /// See `Policy::max_args`; 0 = the default. Rounded up to four.
    pub max_args: usize,
    /// See `Policy::fail_on_findings`.
    pub fail_on_findings: bool,
}

impl<'a> PolicySpec<'a> {
    /// A policy with the response layer off.
    pub fn new(name: &'a str, mode: Mode, oversize: Oversize) -> PolicySpec<'a> {
        PolicySpec {
            name,
            mode,
            oversize,
            response: Response::default(),
            canary: 0,
            signatures: Signatures::Shadow,
            snippet: SnippetSize::Small,
            privacy: false,
            exceptions: false,
            staging: false,
            paranoia: false,
            max_args: 0,
            fail_on_findings: false,
        }
    }
}

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
        && entry[POLICY_NAME_LEN + 1] <= Oversize::Block as u8
        && entry[POLICY_NAME_LEN + 2] & !Response::ALL == 0
        && valid_canary(entry_mode(entry), entry_canary(entry))
        && Signatures::from_byte(entry[POLICY_NAME_LEN + 5]).is_some()
        && entry[EVENT_BYTE]
            & !(SNIPPET_MASK
                | PRIVACY_BIT
                | FAIL_ON_FINDINGS_BIT
                | EXCEPTIONS_BIT
                | STAGING_BIT
                | PARANOIA_BIT)
            == 0
        && entry[EVENT_BYTE] & SNIPPET_MASK <= SnippetSize::Kb4 as u8
        && entry[ARGS_BYTE + 1..].iter().all(|&c| c == 0)
}

/// A canary share only makes sense on an enforce policy.
fn valid_canary(mode: Mode, canary: u16) -> bool {
    canary == 0 || (mode == Mode::Enforce && canary <= MAX_CANARY)
}

fn entry_canary(e: &[u8]) -> u16 {
    u16_at(e, POLICY_NAME_LEN + 3)
}

fn entry_name(e: &[u8]) -> &[u8] {
    let len = e[..POLICY_NAME_LEN]
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(POLICY_NAME_LEN);
    &e[..len]
}

fn entry_oversize(e: &[u8]) -> Oversize {
    if e[POLICY_NAME_LEN + 1] == Oversize::Block as u8 {
        Oversize::Block
    } else {
        Oversize::Pass
    }
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
pub fn policies<'a>(bundle: &'a [u8], info: &Info) -> impl Iterator<Item = Policy<'a>> + use<'a> {
    let end = HEADER_LEN + info.n_policies as usize * POLICY_ENTRY_LEN;
    bundle[HEADER_LEN..end]
        .chunks(POLICY_ENTRY_LEN)
        .enumerate()
        .map(|(i, e)| Policy {
            index: i as u32,
            name: entry_name(e),
            mode: entry_mode(e),
            oversize: entry_oversize(e),
            response: Response(e[POLICY_NAME_LEN + 2]),
            canary: entry_canary(e),
            signatures: Signatures::from_byte(e[POLICY_NAME_LEN + 5]).unwrap_or_default(),
            snippet: SnippetSize::of(e[EVENT_BYTE] & SNIPPET_MASK),
            privacy: e[EVENT_BYTE] & PRIVACY_BIT != 0,
            exceptions: e[EVENT_BYTE] & EXCEPTIONS_BIT != 0,
            staging: e[EVENT_BYTE] & STAGING_BIT != 0,
            paranoia: e[EVENT_BYTE] & PARANOIA_BIT != 0,
            fail_on_findings: e[EVENT_BYTE] & FAIL_ON_FINDINGS_BIT != 0,
            max_args: match e[ARGS_BYTE] {
                0 => MAX_ARGS_DEFAULT,
                n => n as usize * 4,
            },
        })
}

/// The policy `name` of a bundle that passed `verify`.
pub fn find_policy<'a>(bundle: &'a [u8], info: &Info, name: &[u8]) -> Option<Policy<'a>> {
    policies(bundle, info).find(|p| p.name == name)
}

/// The policy at `index` of a bundle that passed `verify`.
pub fn policy_by_index<'a>(bundle: &'a [u8], info: &Info, index: u32) -> Option<Policy<'a>> {
    policies(bundle, info).find(|p| p.index == index)
}

/// Parameters for `build` (bundle compiler, tools and tests).
pub struct Spec<'a> {
    pub version: u64,
    pub created_at_ms: u64,
    pub flags: u16,
    pub policies: &'a [PolicySpec<'a>],
    /// (kind, bytes), written in this order, each 4 KB-aligned.
    pub sections: &'a [(u32, &'a [u8])],
}

/// Builds and signs a bundle with an Ed25519 seed (32 bytes).
pub fn build(spec: &Spec<'_>, seed: &[u8; 32]) -> Result<Vec<u8>, Error> {
    Ok(sign(build_unsigned(spec)?, seed))
}

/// Appends the Ed25519 signature of `unsigned` with `seed`.
pub fn sign(mut unsigned: Vec<u8>, seed: &[u8; 32]) -> Vec<u8> {
    let sig = SigningKey::from_bytes(seed).sign(&unsigned);
    unsigned.extend_from_slice(&sig.to_bytes());
    unsigned
}

/// The bundle without its signature: the bytes an external signer (KMS)
/// signs; the bundle is these bytes followed by the 64-byte Ed25519
/// signature over them.
pub fn build_unsigned(spec: &Spec<'_>) -> Result<Vec<u8>, Error> {
    if spec.policies.len() > MAX_POLICIES as usize
        || !spec.policies.iter().all(|PolicySpec { name: p, .. }| {
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
    for (i, p) in spec.policies.iter().enumerate() {
        let Some(args) = args_byte(p.max_args) else {
            return Err(Error::BadLayout("bad policy entry"));
        };
        if p.response.0 & !Response::ALL != 0 || !valid_canary(p.mode, p.canary) {
            return Err(Error::BadLayout("bad policy entry"));
        }
        let at = HEADER_LEN + i * POLICY_ENTRY_LEN;
        out[at..at + p.name.len()].copy_from_slice(p.name.as_bytes());
        out[at + POLICY_NAME_LEN] = p.mode as u8;
        out[at + POLICY_NAME_LEN + 1] = p.oversize as u8;
        out[at + POLICY_NAME_LEN + 2] = p.response.0;
        out[at + POLICY_NAME_LEN + 3..at + POLICY_NAME_LEN + 5]
            .copy_from_slice(&p.canary.to_le_bytes());
        out[at + POLICY_NAME_LEN + 5] = p.signatures as u8;
        out[at + EVENT_BYTE] = p.snippet as u8
            | if p.privacy { PRIVACY_BIT } else { 0 }
            | if p.exceptions { EXCEPTIONS_BIT } else { 0 }
            | if p.staging { STAGING_BIT } else { 0 }
            | if p.paranoia { PARANOIA_BIT } else { 0 }
            | if p.fail_on_findings {
                FAIL_ON_FINDINGS_BIT
            } else {
                0
            };
        out[at + ARGS_BYTE] = args;
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

    fn spec<'a>(policies: &'a [PolicySpec<'a>]) -> Spec<'a> {
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
                PolicySpec::new("example-api", Mode::Enforce, Oversize::Block),
                PolicySpec::new("example-web", Mode::Shadow, Oversize::Pass),
            ]),
            &SEED,
        )
        .unwrap();
        let info = verify(&b, &public_key(&SEED)).unwrap();
        assert_eq!(info.version, 42);
        assert_eq!(info.n_policies, 2);
        assert_eq!(info.flags, 0);
        let got: Vec<_> = policies(&b, &info)
            .map(|p| (p.index, p.name, p.mode, p.oversize))
            .collect();
        assert_eq!(
            got,
            [
                (0, &b"example-api"[..], Mode::Enforce, Oversize::Block),
                (1, b"example-web", Mode::Shadow, Oversize::Pass)
            ]
        );
        let web = find_policy(&b, &info, b"example-web").unwrap();
        assert_eq!(
            (web.index, web.mode, web.oversize),
            (1, Mode::Shadow, Oversize::Pass)
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
        let b = build(
            &spec(&[PolicySpec::new("example-api", Mode::Shadow, Oversize::Pass)]),
            &SEED,
        )
        .unwrap();
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
        let mut b = build(
            &spec(&[PolicySpec::new("example-api", Mode::Shadow, Oversize::Pass)]),
            &SEED,
        )
        .unwrap();
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
                build(
                    &spec(&[PolicySpec::new(bad, Mode::Shadow, Oversize::Pass)]),
                    &SEED
                )
                .is_err(),
                "{bad:?}"
            );
        }
        assert!(
            build(
                &spec(&[PolicySpec::new(
                    "x".repeat(55).as_str(),
                    Mode::Shadow,
                    Oversize::Pass
                )]),
                &SEED
            )
            .is_ok()
        );
    }

    #[test]
    fn response_flags_round_trip_and_unknown_flags_are_rejected() {
        let p = PolicySpec {
            response: Response(Response::STATUS | Response::GUARD_JWT),
            ..PolicySpec::new("example-api", Mode::Enforce, Oversize::Pass)
        };
        let b = build(&spec(&[p]), &SEED).unwrap();
        let info = verify(&b, &public_key(&SEED)).unwrap();
        let got = find_policy(&b, &info, b"example-api").unwrap().response;
        assert!(got.has(Response::STATUS) && got.has(Response::GUARD_JWT));
        assert!(!got.has(Response::DB_ERRORS) && !got.has(Response::GUARD_CCCD));

        // max_snippet_size: bits 0-1 of byte 62, 0..=2 (P-01 §1b)
        let big = PolicySpec {
            snippet: SnippetSize::Kb4,
            ..p
        };
        let bb = build(&spec(&[big]), &SEED).unwrap();
        let info = verify(&bb, &public_key(&SEED)).unwrap();
        assert_eq!(
            find_policy(&bb, &info, b"example-api").unwrap().snippet,
            SnippetSize::Kb4
        );
        assert_eq!(SnippetSize::Kb2.bytes(), 2048);
        let mut bad3 = bb.clone();
        bad3.truncate(bad3.len() - SIG_LEN);
        bad3[HEADER_LEN + EVENT_BYTE] = 3;
        let sig = SigningKey::from_bytes(&SEED).sign(&bad3);
        bad3.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            verify(&bad3, &public_key(&SEED)),
            Err(Error::BadLayout("bad policy entry"))
        );

        // fail_on_findings (#98): bit 3 of byte 62; bit 7 remains unknown (M4 uses bit 5, W17-S-01 bit 6)
        let ff = PolicySpec {
            fail_on_findings: true,
            ..p
        };
        let fb = build(&spec(&[ff]), &SEED).unwrap();
        assert_eq!(
            fb[HEADER_LEN + EVENT_BYTE] & FAIL_ON_FINDINGS_BIT,
            FAIL_ON_FINDINGS_BIT
        );
        let info = verify(&fb, &public_key(&SEED)).unwrap();
        assert!(
            find_policy(&fb, &info, b"example-api")
                .unwrap()
                .fail_on_findings
        );
        let mut bad5 = fb.clone();
        bad5.truncate(bad5.len() - SIG_LEN);
        bad5[HEADER_LEN + EVENT_BYTE] |= 1 << 7;
        let sig = SigningKey::from_bytes(&SEED).sign(&bad5);
        bad5.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            verify(&bad5, &public_key(&SEED)),
            Err(Error::BadLayout("bad policy entry"))
        );

        // max_args (#28): byte 63 in fours; 0 is the engine's 1024
        assert_eq!(
            find_policy(&b, &verify(&b, &public_key(&SEED)).unwrap(), b"example-api")
                .unwrap()
                .max_args,
            MAX_ARGS_DEFAULT
        );
        for (set, got, byte) in [(1, 4, 1u8), (5, 8, 2), (100, 100, 25), (1020, 1020, 255)] {
            let pa = PolicySpec { max_args: set, ..p };
            let ab = build(&spec(&[pa]), &SEED).unwrap();
            assert_eq!(ab[HEADER_LEN + ARGS_BYTE], byte);
            let info = verify(&ab, &public_key(&SEED)).unwrap();
            assert_eq!(
                find_policy(&ab, &info, b"example-api").unwrap().max_args,
                got
            );
        }
        assert_eq!(
            build(
                &spec(&[PolicySpec {
                    max_args: 1021,
                    ..p
                }]),
                &SEED
            ),
            Err(Error::BadLayout("bad policy entry"))
        );

        // privacy flag: bit 2 of byte 62 (P-01 §1); bit 7 is not known
        // (bit 3 is fail_on_findings; bit 5 is staging since M4)
        let pv = PolicySpec { privacy: true, ..p };
        let pb = build(&spec(&[pv]), &SEED).unwrap();
        let info = verify(&pb, &public_key(&SEED)).unwrap();
        assert!(find_policy(&pb, &info, b"example-api").unwrap().privacy);
        let mut bad4 = pb;
        bad4.truncate(bad4.len() - SIG_LEN);
        bad4[HEADER_LEN + EVENT_BYTE] = 1 << 7;
        let sig = SigningKey::from_bytes(&SEED).sign(&bad4);
        bad4.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            verify(&bad4, &public_key(&SEED)),
            Err(Error::BadLayout("bad policy entry"))
        );

        // bit 4 (PAN) is known since P-01 §1; bit 5 is not
        let pan = PolicySpec {
            response: Response(Response::GUARD_PAN),
            ..p
        };
        assert!(build(&spec(&[pan]), &SEED).is_ok());
        let bad = PolicySpec {
            response: Response(0x20),
            ..p
        };
        assert!(build(&spec(&[bad]), &SEED).is_err());

        let mut b = b;
        b.truncate(b.len() - SIG_LEN);
        b[HEADER_LEN + POLICY_NAME_LEN + 2] = 0x80;
        let sig = SigningKey::from_bytes(&SEED).sign(&b);
        b.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            verify(&b, &public_key(&SEED)),
            Err(Error::BadLayout("bad policy entry"))
        );
    }

    #[test]
    fn signed_bad_policy_mode_is_rejected() {
        let mut b = build(
            &spec(&[PolicySpec::new("example-api", Mode::Shadow, Oversize::Pass)]),
            &SEED,
        )
        .unwrap();
        b.truncate(b.len() - SIG_LEN);
        b[HEADER_LEN + POLICY_NAME_LEN] = 2;
        let sig = SigningKey::from_bytes(&SEED).sign(&b);
        b.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            verify(&b, &public_key(&SEED)),
            Err(Error::BadLayout("bad policy entry"))
        );
    }

    #[test]
    fn canary_round_trip_and_bounds() {
        let p = PolicySpec {
            canary: 100,
            ..PolicySpec::new("example-api", Mode::Enforce, Oversize::Pass)
        };
        let b = build(&spec(&[p]), &SEED).unwrap();
        let info = verify(&b, &public_key(&SEED)).unwrap();
        assert_eq!(find_policy(&b, &info, b"example-api").unwrap().canary, 100);
        assert_eq!(
            u16_at(&b, HEADER_LEN + POLICY_NAME_LEN + 3),
            100,
            "canary is u16 LE at entry offset 59"
        );

        // a shadow policy has no canary, and 100% is not a canary
        for bad in [
            PolicySpec {
                canary: 100,
                ..PolicySpec::new("example-api", Mode::Shadow, Oversize::Pass)
            },
            PolicySpec {
                canary: MAX_CANARY + 1,
                ..p
            },
        ] {
            assert!(build(&spec(&[bad]), &SEED).is_err(), "{bad:?}");
        }

        // the same checks on signed bytes
        for (mode, canary) in [(Mode::Shadow as u8, 100u16), (Mode::Enforce as u8, 10000)] {
            let mut t = b.clone();
            t.truncate(t.len() - SIG_LEN);
            t[HEADER_LEN + POLICY_NAME_LEN] = mode;
            t[HEADER_LEN + POLICY_NAME_LEN + 3..HEADER_LEN + POLICY_NAME_LEN + 5]
                .copy_from_slice(&canary.to_le_bytes());
            let sig = SigningKey::from_bytes(&SEED).sign(&t);
            t.extend_from_slice(&sig.to_bytes());
            assert_eq!(
                verify(&t, &public_key(&SEED)),
                Err(Error::BadLayout("bad policy entry")),
                "mode {mode} canary {canary}"
            );
        }
    }

    #[test]
    fn signatures_round_trip_and_bad_values_are_rejected() {
        for sig in [Signatures::Shadow, Signatures::Off, Signatures::Enforce] {
            let p = PolicySpec {
                signatures: sig,
                ..PolicySpec::new("example-api", Mode::Enforce, Oversize::Pass)
            };
            let b = build(&spec(&[p]), &SEED).unwrap();
            let info = verify(&b, &public_key(&SEED)).unwrap();
            assert_eq!(
                find_policy(&b, &info, b"example-api").unwrap().signatures,
                sig
            );
            assert_eq!(b[HEADER_LEN + POLICY_NAME_LEN + 5], sig as u8);
        }
        let mut b = build(
            &spec(&[PolicySpec::new(
                "example-api",
                Mode::Enforce,
                Oversize::Pass,
            )]),
            &SEED,
        )
        .unwrap();
        b.truncate(b.len() - SIG_LEN);
        b[HEADER_LEN + POLICY_NAME_LEN + 5] = 3;
        let sig = SigningKey::from_bytes(&SEED).sign(&b);
        b.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            verify(&b, &public_key(&SEED)),
            Err(Error::BadLayout("bad policy entry"))
        );
    }
}
