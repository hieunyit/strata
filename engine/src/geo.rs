//! Country and ASN of the client address at the node (W19-R-01).
//!
//! The bundle does not carry a GeoIP database: the compiler takes, from
//! the control plane's databases, only the networks of the countries and
//! ASNs that rules name (`strata-compile --geo`). Targets `geo_country`
//! and `geo_asn` are, for the client address:
//!
//! - the country (ISO code, `VN`) or ASN (decimal, `7552`) whose networks
//!   hold it, among those of the bundle;
//! - `private` for a loopback, private, link-local, unique-local or
//!   unspecified address (no database places them);
//! - `other` for any other address;
//! - no value when the address is not an IP address, or the bundle has no
//!   network of that kind.
//!
//! Section GEO, codec `SGE1` (little-endian): magic, `u32` number of
//! entries (1..=MAX_ENTRIES), then each entry: `u8` kind (1 country,
//! 2 ASN), `u8` key length, key (`[A-Z]{2}` or a decimal ASN 1..=u32::MAX
//! without leading zero), `u32` IPv4 range count, `u32` IPv6 range count,
//! the IPv4 ranges `(u32 first, u32 last)` then the IPv6 ranges
//! `(u128 first, u128 last)`. Entries by increasing (kind, key); in an
//! entry, ranges increasing, neither overlapping nor adjacent; across the
//! entries of a kind, no range overlaps another (an address has one
//! country, one ASN). Anything else refuses the bundle.
#![forbid(unsafe_code)]

use crate::bundle::Error;
use std::net::IpAddr;

const MAGIC: &[u8; 4] = b"SGE1";
/// Most countries and ASNs one bundle carries.
pub const MAX_ENTRIES: usize = 1024;
/// Most ranges of one family in one entry.
pub const MAX_RANGES: usize = 1 << 20;

/// What an entry places.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Country = 1,
    Asn = 2,
}

/// The networks of one country or ASN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: Kind,
    pub key: String,
    pub v4: Vec<(u32, u32)>,
    pub v6: Vec<(u128, u128)>,
}

/// Section GEO, decoded, with an index per kind and family.
#[derive(Clone, Debug, Default)]
pub struct Geo {
    entries: Vec<Entry>,
    /// per kind (country, ASN): (first, last, entry index), by first
    v4: [Vec<(u32, u32, u32)>; 2],
    v6: [Vec<(u128, u128, u32)>; 2],
}

fn bad() -> Error {
    Error::BadLayout("invalid geo section")
}

/// A valid key of `kind`.
pub fn valid_key(kind: Kind, key: &str) -> bool {
    match kind {
        Kind::Country => key.len() == 2 && key.bytes().all(|b| b.is_ascii_uppercase()),
        Kind::Asn => {
            !key.is_empty()
                && !key.starts_with('0')
                && key.len() <= 10
                && key.bytes().all(|b| b.is_ascii_digit())
                && key.parse::<u32>().is_ok()
        }
    }
}

/// An entry from CIDR prefixes (`192.0.2.0/24`, `2001:db8::/32`), merged.
/// Host bits set in a prefix are an error.
pub fn entry(kind: Kind, key: &str, prefixes: &[&str]) -> Result<Entry, String> {
    if !valid_key(kind, key) {
        return Err(format!("{kind:?} {key:?}: not a valid key"));
    }
    let (mut v4, mut v6) = (vec![], vec![]);
    for p in prefixes {
        let bad = || format!("{key}: {p:?} is not a prefix");
        let (addr, len) = p.split_once('/').ok_or_else(bad)?;
        let len: u32 = len.parse().map_err(|_| bad())?;
        match addr.parse::<IpAddr>().map_err(|_| bad())? {
            IpAddr::V4(a) if len <= 32 => {
                let a = u32::from(a);
                let host = u32::MAX.checked_shr(len).unwrap_or(0);
                if a & host != 0 {
                    return Err(format!("{key}: {p:?} has host bits set"));
                }
                v4.push((a, a | host));
            }
            IpAddr::V6(a) if len <= 128 => {
                let a = u128::from(a);
                let host = u128::MAX.checked_shr(len).unwrap_or(0);
                if a & host != 0 {
                    return Err(format!("{key}: {p:?} has host bits set"));
                }
                v6.push((a, a | host));
            }
            _ => return Err(bad()),
        }
    }
    let e = Entry {
        kind,
        key: key.to_string(),
        v4: merge(v4),
        v6: merge(v6),
    };
    if e.v4.len() > MAX_RANGES || e.v6.len() > MAX_RANGES {
        return Err(format!("{key}: more than {MAX_RANGES} ranges"));
    }
    Ok(e)
}

trait Succ: Sized + Copy + Ord {
    fn succ(self) -> Option<Self>;
}
impl Succ for u32 {
    fn succ(self) -> Option<u32> {
        self.checked_add(1)
    }
}
impl Succ for u128 {
    fn succ(self) -> Option<u128> {
        self.checked_add(1)
    }
}

fn merge<T: Succ>(mut r: Vec<(T, T)>) -> Vec<(T, T)> {
    r.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(r.len());
    for (a, b) in r {
        match out.last_mut() {
            Some(last) if last.1.succ().is_none_or(|n| a <= n) => {
                if b > last.1 {
                    last.1 = b;
                }
            }
            _ => out.push((a, b)),
        }
    }
    out
}

/// Section bytes; empty without entries.
pub fn encode(entries: &[Entry]) -> Result<Vec<u8>, String> {
    if entries.is_empty() {
        return Ok(vec![]);
    }
    if entries.len() > MAX_ENTRIES {
        return Err(format!("more than {MAX_ENTRIES} countries and ASNs"));
    }
    let mut sorted: Vec<Entry> = entries
        .iter()
        .map(|e| Entry {
            kind: e.kind,
            key: e.key.clone(),
            v4: merge(e.v4.clone()),
            v6: merge(e.v6.clone()),
        })
        .collect();
    sorted.sort_by(|a, b| (a.kind, &a.key).cmp(&(b.kind, &b.key)));
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for (i, e) in sorted.iter().enumerate() {
        if !valid_key(e.kind, &e.key)
            || (i > 0 && (sorted[i - 1].kind, &sorted[i - 1].key) == (e.kind, &e.key))
        {
            return Err(format!("{:?} {:?}: invalid or repeated", e.kind, e.key));
        }
        if e.v4.len() > MAX_RANGES || e.v6.len() > MAX_RANGES {
            return Err(format!("{}: more than {MAX_RANGES} ranges", e.key));
        }
        out.push(e.kind as u8);
        out.push(e.key.len() as u8);
        out.extend_from_slice(e.key.as_bytes());
        out.extend_from_slice(&(e.v4.len() as u32).to_le_bytes());
        out.extend_from_slice(&(e.v6.len() as u32).to_le_bytes());
        for &(a, b) in &e.v4 {
            out.extend_from_slice(&a.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
        }
        for &(a, b) in &e.v6 {
            out.extend_from_slice(&a.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
        }
    }
    // the engine refuses overlaps across entries: say it here first
    parse(&out).map_err(|_| "two countries or two ASNs share an address".to_string())?;
    Ok(out)
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        if self.0.len() < N {
            return Err(bad());
        }
        let (h, t) = self.0.split_at(N);
        self.0 = t;
        h.try_into().map_err(|_| bad())
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take()?))
    }
    fn u128(&mut self) -> Result<u128, Error> {
        Ok(u128::from_le_bytes(self.take()?))
    }
}

/// Ranges increasing, neither overlapping nor adjacent.
fn ordered<T: Succ>(r: &[(T, T)]) -> bool {
    r.iter().all(|&(a, b)| a <= b)
        && r.windows(2)
            .all(|w| w[0].1.succ().is_some_and(|n| n < w[1].0))
}

/// No two ranges of the index overlap (entries of one kind).
fn disjoint<T: Copy + Ord>(index: &[(T, T, u32)]) -> bool {
    index.windows(2).all(|w| w[0].1 < w[1].0)
}

/// Reads section GEO (empty: none), checking every invariant.
pub fn parse(section: &[u8]) -> Result<Geo, Error> {
    if section.is_empty() {
        return Ok(Geo::default());
    }
    let mut r = Reader(section);
    if &r.take::<4>()? != MAGIC {
        return Err(bad());
    }
    let n = r.u32()? as usize;
    if n == 0 || n > MAX_ENTRIES {
        return Err(bad());
    }
    let mut g = Geo::default();
    for _ in 0..n {
        let kind = match r.take::<1>()?[0] {
            1 => Kind::Country,
            2 => Kind::Asn,
            _ => return Err(bad()),
        };
        let len = r.take::<1>()?[0] as usize;
        if len > r.0.len() {
            return Err(bad());
        }
        let (key, rest) = r.0.split_at(len);
        r.0 = rest;
        let key = std::str::from_utf8(key).map_err(|_| bad())?;
        if !valid_key(kind, key)
            || g.entries
                .last()
                .is_some_and(|p| (p.kind, p.key.as_str()) >= (kind, key))
        {
            return Err(bad());
        }
        let (n4, n6) = (r.u32()? as usize, r.u32()? as usize);
        if n4 > MAX_RANGES || n6 > MAX_RANGES || n4 * 8 + n6 * 32 > r.0.len() {
            return Err(bad());
        }
        let mut v4 = Vec::with_capacity(n4);
        for _ in 0..n4 {
            v4.push((r.u32()?, r.u32()?));
        }
        let mut v6 = Vec::with_capacity(n6);
        for _ in 0..n6 {
            v6.push((r.u128()?, r.u128()?));
        }
        if !ordered(&v4) || !ordered(&v6) {
            return Err(bad());
        }
        let (i, k) = (g.entries.len() as u32, kind as usize - 1);
        g.v4[k].extend(v4.iter().map(|&(a, b)| (a, b, i)));
        g.v6[k].extend(v6.iter().map(|&(a, b)| (a, b, i)));
        g.entries.push(Entry {
            kind,
            key: key.to_string(),
            v4,
            v6,
        });
    }
    if !r.0.is_empty() {
        return Err(bad());
    }
    for k in 0..2 {
        g.v4[k].sort_unstable();
        g.v6[k].sort_unstable();
        if !disjoint(&g.v4[k]) || !disjoint(&g.v6[k]) {
            return Err(bad());
        }
    }
    Ok(g)
}

fn find<T: Copy + Ord>(index: &[(T, T, u32)], x: T) -> Option<u32> {
    // last range starting at or before x
    let i = index.partition_point(|&(a, _, _)| a <= x);
    (i > 0 && x <= index[i - 1].1).then(|| index[i - 1].2)
}

/// Addresses no GeoIP database places: loopback, private (RFC 1918),
/// link-local, unique-local (fc00::/7), unspecified, and IPv4 0.0.0.0/8.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_loopback() || a.is_private() || a.is_link_local() || a.octets()[0] == 0
        }
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => is_private(IpAddr::V4(v4)),
            None => {
                a.is_loopback()
                    || a.is_unspecified()
                    || (a.segments()[0] & 0xffc0) == 0xfe80
                    || (a.segments()[0] & 0xfe00) == 0xfc00
            }
        },
    }
}

impl Geo {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the section has an entry of `kind`, `key`.
    pub fn has(&self, kind: Kind, key: &str) -> bool {
        self.entries.iter().any(|e| e.kind == kind && e.key == key)
    }

    /// `geo_country` / `geo_asn` of a client address (see the module
    /// documentation); None: no value.
    pub fn lookup(&self, kind: Kind, client_addr: &[u8]) -> Option<&[u8]> {
        let k = kind as usize - 1;
        if self.v4[k].is_empty() && self.v6[k].is_empty() {
            return None;
        }
        let ip = std::str::from_utf8(client_addr)
            .ok()?
            .parse::<IpAddr>()
            .ok()?;
        if is_private(ip) {
            return Some(b"private");
        }
        let found = match ip {
            IpAddr::V4(a) => find(&self.v4[k], u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => find(&self.v4[k], u32::from(v4)),
                None => find(&self.v6[k], u128::from(a)),
            },
        };
        Some(match found {
            Some(i) => self.entries[i as usize].key.as_bytes(),
            None => b"other",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geo() -> Geo {
        let b = encode(&[
            entry(Kind::Country, "VN", &["14.160.0.0/11", "2402:800::/32"]).unwrap(),
            entry(Kind::Country, "US", &["8.8.8.0/24"]).unwrap(),
            entry(Kind::Asn, "7552", &["14.160.0.0/12"]).unwrap(),
        ])
        .unwrap();
        parse(&b).unwrap()
    }

    #[test]
    fn lookups() {
        let g = geo();
        let c = |a: &str| g.lookup(Kind::Country, a.as_bytes());
        let n = |a: &str| g.lookup(Kind::Asn, a.as_bytes());
        assert_eq!(c("14.161.2.3"), Some(&b"VN"[..]));
        assert_eq!(c("::ffff:14.161.2.3"), Some(&b"VN"[..]));
        assert_eq!(c("2402:800::1"), Some(&b"VN"[..]));
        assert_eq!(c("8.8.8.8"), Some(&b"US"[..]));
        assert_eq!(c("1.1.1.1"), Some(&b"other"[..]));
        assert_eq!(n("14.161.2.3"), Some(&b"7552"[..]));
        assert_eq!(n("14.180.0.1"), Some(&b"other"[..]));
        for p in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
            "::",
        ] {
            assert_eq!(c(p), Some(&b"private"[..]), "{p}");
        }
        assert_eq!(c("not an address"), None);
        assert_eq!(c("14.161.2.3:443"), None);
        // no entry of a kind: no value
        let only =
            parse(&encode(&[entry(Kind::Country, "VN", &["14.160.0.0/11"]).unwrap()]).unwrap())
                .unwrap();
        assert_eq!(only.lookup(Kind::Asn, b"14.161.2.3"), None);
        assert!(
            Geo::default()
                .lookup(Kind::Country, b"14.161.2.3")
                .is_none()
        );
        assert!(g.has(Kind::Asn, "7552") && !g.has(Kind::Asn, "1"));
    }

    #[test]
    fn keys_and_prefixes() {
        for (k, key, ok) in [
            (Kind::Country, "VN", true),
            (Kind::Country, "vn", false),
            (Kind::Country, "VNM", false),
            (Kind::Asn, "7552", true),
            (Kind::Asn, "07552", false),
            (Kind::Asn, "4294967295", true),
            (Kind::Asn, "4294967296", false),
            (Kind::Asn, "", false),
        ] {
            assert_eq!(valid_key(k, key), ok, "{key}");
        }
        assert!(entry(Kind::Country, "VN", &["14.160.0.1/11"]).is_err());
        assert!(entry(Kind::Country, "VN", &["14.160.0.0"]).is_err());
        assert!(entry(Kind::Country, "VN", &["14.160.0.0/33"]).is_err());
        // adjacent prefixes merge; /0 is allowed
        let e = entry(Kind::Country, "VN", &["10.0.0.0/9", "10.128.0.0/9", "::/0"]).unwrap();
        assert_eq!(e.v4, vec![(0x0a00_0000, 0x0aff_ffff)]);
        assert_eq!(e.v6, vec![(0, u128::MAX)]);
    }

    #[test]
    fn refuses_bad_sections() {
        // overlapping entries of one kind
        assert!(
            encode(&[
                entry(Kind::Country, "VN", &["14.160.0.0/11"]).unwrap(),
                entry(Kind::Country, "US", &["14.161.0.0/16"]).unwrap(),
            ])
            .is_err()
        );
        // a country and an ASN may share addresses
        assert!(
            encode(&[
                entry(Kind::Country, "VN", &["14.160.0.0/11"]).unwrap(),
                entry(Kind::Asn, "7552", &["14.161.0.0/16"]).unwrap(),
            ])
            .is_ok()
        );
        let b = encode(&[entry(Kind::Country, "VN", &["14.160.0.0/11", "2402:800::/32"]).unwrap()])
            .unwrap();
        for cut in 0..b.len() {
            assert!(parse(&b[..cut]).is_err() || cut == 0, "cut {cut}");
        }
        let mut kind = b.clone();
        kind[8] = 3;
        assert!(parse(&kind).is_err());
        let mut key = b.clone();
        key[10] = b'n';
        assert!(parse(&key).is_err());
        let mut range = b.clone();
        range[23] ^= 0xff; // first > last
        assert!(parse(&range).is_err());
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(parse(&trailing).is_err());
    }
}
