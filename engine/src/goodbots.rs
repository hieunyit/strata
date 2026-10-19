//! Published IP ranges of the big crawlers (W18-R-02, W18-G2-02): a request
//! whose User-Agent claims to be one of them is checked against the ranges
//! the crawler's owner publishes, which the control plane fetches and the
//! compiler packs into section GOOD_BOTS. Rules read the result through
//! the targets `bot_claim` (the crawler claimed) and `bot_verified`
//! (`true`, `false`, or `unknown` when the bundle has no ranges for it).
//!
//! Section codec `SGB1` (little-endian): magic, `u32` crawler count, then
//! per crawler a `u8` name length, the name (`[a-z0-9_-]`, at most 32), a
//! `u32` count of IPv4 ranges, a `u32` count of IPv6 ranges, the IPv4
//! ranges as `(u32 first, u32 last)` and the IPv6 ranges as
//! `(u128 first, u128 last)`, each list sorted, not overlapping nor
//! adjacent, crawlers sorted by name. No section: no crawler is verified.
#![forbid(unsafe_code)]

use crate::bundle::Error;
use std::net::IpAddr;

const MAGIC: &[u8; 4] = b"SGB1";
pub const MAX_CRAWLERS: usize = 16;
pub const MAX_RANGES: usize = 65_536;
const NAME_MAX: usize = 32;
/// Broadest prefixes accepted: a poisoned feed cannot make a large part of
/// the Internet a verified crawler.
pub const MIN_V4_PREFIX: u32 = 8;
pub const MIN_V6_PREFIX: u32 = 16;

/// Crawlers a User-Agent may claim, with the (lowercase) tokens that claim
/// them. The ranges come from the bundle; a claimed crawler the bundle has
/// no ranges for is `unknown`, never `false`.
pub const CLAIMS: &[(&str, &[&[u8]])] = &[
    ("applebot", &[b"applebot"]),
    ("bingbot", &[b"bingbot", b"adidxbot", b"bingpreview"]),
    (
        "googlebot",
        &[b"googlebot", b"google-inspectiontool", b"googleother"],
    ),
];

fn bad() -> Error {
    Error::BadLayout("invalid good bots section")
}

/// One crawler's ranges, merged and sorted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Crawler {
    pub name: String,
    pub v4: Vec<(u32, u32)>,
    pub v6: Vec<(u128, u128)>,
}

/// The ranges of a bundle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GoodBots {
    crawlers: Vec<Crawler>,
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= NAME_MAX
        && n.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

/// Ranges of CIDR prefixes (`192.0.2.0/24`, `2001:db8::/32`), merged.
/// Host bits set in a prefix are an error (as in the published lists).
pub fn crawler(name: &str, prefixes: &[&str]) -> Result<Crawler, String> {
    if !valid_name(name) {
        return Err(format!("crawler name {name:?}: [a-z0-9_-], 1 to 32"));
    }
    let mut v4 = vec![];
    let mut v6 = vec![];
    for p in prefixes {
        let (addr, len) = p
            .split_once('/')
            .ok_or_else(|| format!("{name}: {p:?} is not a prefix"))?;
        let len: u32 = len
            .parse()
            .map_err(|_| format!("{name}: {p:?} is not a prefix"))?;
        match addr.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) if len < MIN_V4_PREFIX => {
                return Err(format!("{name}: {p:?} is broader than /{MIN_V4_PREFIX}"));
            }
            Ok(IpAddr::V6(_)) if len < MIN_V6_PREFIX => {
                return Err(format!("{name}: {p:?} is broader than /{MIN_V6_PREFIX}"));
            }
            Ok(IpAddr::V4(a)) if len <= 32 => {
                let a = u32::from(a);
                let host = if len == 32 { 0 } else { u32::MAX >> len };
                if a & host != 0 {
                    return Err(format!("{name}: {p:?} has host bits set"));
                }
                v4.push((a, a | host));
            }
            Ok(IpAddr::V6(a)) if len <= 128 => {
                let a = u128::from(a);
                let host = if len == 128 { 0 } else { u128::MAX >> len };
                if a & host != 0 {
                    return Err(format!("{name}: {p:?} has host bits set"));
                }
                v6.push((a, a | host));
            }
            _ => return Err(format!("{name}: {p:?} is not a prefix")),
        }
    }
    let c = Crawler {
        name: name.to_string(),
        v4: merge(v4),
        v6: merge(v6),
    };
    if c.v4.len() > MAX_RANGES || c.v6.len() > MAX_RANGES {
        return Err(format!("{name}: more than {MAX_RANGES} ranges"));
    }
    Ok(c)
}

fn merge<T: Copy + Ord + num_like::Succ>(mut r: Vec<(T, T)>) -> Vec<(T, T)> {
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

mod num_like {
    pub trait Succ: Sized {
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
}

/// Section bytes; empty without crawlers (no section).
pub fn encode(crawlers: &[Crawler]) -> Result<Vec<u8>, String> {
    if crawlers.is_empty() {
        return Ok(vec![]);
    }
    if crawlers.len() > MAX_CRAWLERS {
        return Err(format!("more than {MAX_CRAWLERS} crawlers"));
    }
    let mut sorted: Vec<&Crawler> = crawlers.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    let mut prev = "";
    for c in sorted {
        if !valid_name(&c.name) || c.name == prev {
            return Err(format!("crawler name {:?} invalid or repeated", c.name));
        }
        prev = &c.name;
        let (v4, v6) = (merge(c.v4.clone()), merge(c.v6.clone()));
        if v4.len() > MAX_RANGES || v6.len() > MAX_RANGES {
            return Err(format!("{}: more than {MAX_RANGES} ranges", c.name));
        }
        out.push(c.name.len() as u8);
        out.extend_from_slice(c.name.as_bytes());
        out.extend_from_slice(&(v4.len() as u32).to_le_bytes());
        out.extend_from_slice(&(v6.len() as u32).to_le_bytes());
        for (a, b) in v4 {
            out.extend_from_slice(&a.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
        }
        for (a, b) in v6 {
            out.extend_from_slice(&a.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
        }
    }
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

/// Reads section GOOD_BOTS (empty: none), checking every invariant: an
/// engine never trusts ranges it would search wrongly.
pub fn parse(section: &[u8]) -> Result<GoodBots, Error> {
    if section.is_empty() {
        return Ok(GoodBots::default());
    }
    let mut r = Reader(section);
    if &r.take::<4>()? != MAGIC {
        return Err(bad());
    }
    let n = r.u32()? as usize;
    if n == 0 || n > MAX_CRAWLERS {
        return Err(bad());
    }
    let mut crawlers: Vec<Crawler> = Vec::with_capacity(n);
    for _ in 0..n {
        let len = r.take::<1>()?[0] as usize;
        if len > r.0.len() {
            return Err(bad());
        }
        let (name, rest) = r.0.split_at(len);
        r.0 = rest;
        let name = std::str::from_utf8(name).map_err(|_| bad())?;
        if !valid_name(name) || crawlers.last().is_some_and(|p| p.name.as_str() >= name) {
            return Err(bad());
        }
        let (n4, n6) = (r.u32()? as usize, r.u32()? as usize);
        if n4 > MAX_RANGES || n6 > MAX_RANGES || n4 * 8 + n6 * 32 > r.0.len() {
            return Err(bad());
        }
        let mut c = Crawler {
            name: name.to_string(),
            v4: Vec::with_capacity(n4),
            v6: Vec::with_capacity(n6),
        };
        for _ in 0..n4 {
            let (a, b) = (r.u32()?, r.u32()?);
            if a > b
                || c.v4
                    .last()
                    .is_some_and(|&(_, l)| l.checked_add(1).is_none_or(|n| a <= n))
            {
                return Err(bad());
            }
            c.v4.push((a, b));
        }
        for _ in 0..n6 {
            let (a, b) = (r.u128()?, r.u128()?);
            if a > b
                || c.v6
                    .last()
                    .is_some_and(|&(_, l)| l.checked_add(1).is_none_or(|n| a <= n))
            {
                return Err(bad());
            }
            c.v6.push((a, b));
        }
        crawlers.push(c);
    }
    if !r.0.is_empty() {
        return Err(bad());
    }
    Ok(GoodBots { crawlers })
}

fn find<T: Copy + Ord>(ranges: &[(T, T)], x: T) -> bool {
    // last range starting at or before x
    let i = ranges.partition_point(|&(a, _)| a <= x);
    i > 0 && x <= ranges[i - 1].1
}

impl GoodBots {
    pub fn is_empty(&self) -> bool {
        self.crawlers.is_empty()
    }

    /// Whether ip is in the ranges of crawler `name`; None when the bundle
    /// has none for it.
    pub fn contains(&self, name: &str, ip: IpAddr) -> Option<bool> {
        let c = self.crawlers.iter().find(|c| c.name == name)?;
        Some(match ip {
            IpAddr::V4(a) => find(&c.v4, u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => find(&c.v4, u32::from(v4)),
                None => find(&c.v6, u128::from(a)),
            },
        })
    }
}

/// The crawler a User-Agent claims (case-insensitive token anywhere in it).
pub fn claim(user_agent: &[u8]) -> Option<&'static str> {
    CLAIMS.iter().find_map(|&(name, tokens)| {
        tokens
            .iter()
            .any(|t| {
                user_agent
                    .windows(t.len())
                    .any(|w| w.eq_ignore_ascii_case(t))
            })
            .then_some(name)
    })
}

/// `bot_verified` of a request: None without a claim; else `true`,
/// `false`, or `unknown` (no ranges for the crawler, or the client
/// address is not an IP address).
pub fn verify(
    bots: &GoodBots,
    user_agent: &[u8],
    client_addr: &[u8],
) -> Option<(&'static str, &'static [u8])> {
    let name = claim(user_agent)?;
    let ip = std::str::from_utf8(client_addr)
        .ok()
        .and_then(|s| s.parse::<IpAddr>().ok());
    let verdict: &'static [u8] = match ip.and_then(|ip| bots.contains(name, ip)) {
        Some(true) => b"true",
        Some(false) => b"false",
        None => b"unknown",
    };
    Some((name, verdict))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bots() -> GoodBots {
        let g = crawler(
            "googlebot",
            &[
                "66.249.64.0/27",
                "66.249.64.32/27",
                "2001:4860:4801:10::/64",
            ],
        )
        .unwrap();
        let b = crawler("bingbot", &["157.55.39.0/24"]).unwrap();
        parse(&encode(&[g, b]).unwrap()).unwrap()
    }

    #[test]
    fn ranges_merge_and_match() {
        let g = crawler("googlebot", &["66.249.64.0/27", "66.249.64.32/27"]).unwrap();
        assert_eq!(g.v4, [(0x42f9_4000, 0x42f9_403f)]); // adjacent: one range
        let b = bots();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(b.contains("googlebot", ip("66.249.64.63")), Some(true));
        assert_eq!(b.contains("googlebot", ip("66.249.64.64")), Some(false));
        assert_eq!(b.contains("googlebot", ip("66.249.63.255")), Some(false));
        assert_eq!(
            b.contains("googlebot", ip("::ffff:66.249.64.1")),
            Some(true)
        );
        assert_eq!(
            b.contains("googlebot", ip("2001:4860:4801:10::abcd")),
            Some(true)
        );
        assert_eq!(
            b.contains("googlebot", ip("2001:4860:4801:11::1")),
            Some(false)
        );
        assert_eq!(b.contains("applebot", ip("17.0.0.1")), None);
        assert_eq!(b.contains("bingbot", ip("157.55.39.200")), Some(true));
    }

    #[test]
    fn claims_and_verdicts() {
        let b = bots();
        let ua = b"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        assert_eq!(
            verify(&b, ua, b"66.249.64.1"),
            Some(("googlebot", &b"true"[..]))
        );
        assert_eq!(
            verify(&b, ua, b"203.0.113.9"),
            Some(("googlebot", &b"false"[..]))
        );
        assert_eq!(
            verify(&b, ua, b"unix:"),
            Some(("googlebot", &b"unknown"[..]))
        );
        assert_eq!(
            verify(&b, b"Mozilla/5.0 (compatible; bingbot/2.0)", b"157.55.39.1"),
            Some(("bingbot", &b"true"[..]))
        );
        assert_eq!(
            verify(&b, b"Mozilla/5.0 (Applebot/0.1)", b"203.0.113.9"),
            Some(("applebot", &b"unknown"[..]))
        );
        assert_eq!(
            verify(&b, b"Mozilla/5.0 Firefox/130.0", b"66.249.64.1"),
            None
        );
        assert_eq!(
            verify(&GoodBots::default(), ua, b"203.0.113.9"),
            Some(("googlebot", &b"unknown"[..]))
        );
        assert_eq!(claim(b"GOOGLE-INSPECTIONTOOL/1.0"), Some("googlebot"));
    }

    #[test]
    fn bad_input_is_refused() {
        for p in [
            "66.249.64.1/27",
            "66.249.64.0",
            "66.249.64.0/33",
            "x/8",
            "2001:db8::1/64",
            "0.0.0.0/0",
            "64.0.0.0/7",
            "2000::/3",
            "::/0",
        ] {
            assert!(crawler("googlebot", &[p]).is_err(), "{p}");
        }
        assert!(crawler("Googlebot", &[]).is_err());
        assert!(crawler(&"a".repeat(33), &[]).is_err());
        assert!(encode(&[crawler("x", &[]).unwrap(), crawler("x", &[]).unwrap()]).is_err());
        assert_eq!(encode(&[]).unwrap(), Vec::<u8>::new());
        assert_eq!(parse(&[]).unwrap(), GoodBots::default());

        let good =
            encode(&[crawler("googlebot", &["66.249.64.0/27", "2001:4860:4801:10::/64"]).unwrap()])
                .unwrap();
        assert!(parse(&good).is_ok());
        for cut in 1..good.len() {
            assert!(parse(&good[..cut]).is_err(), "cut {cut}");
        }
        let mut extra = good.clone();
        extra.push(0);
        assert!(parse(&extra).is_err());
        let mut magic = good.clone();
        magic[3] = b'2';
        assert!(parse(&magic).is_err());
        // overlapping or unsorted ranges are refused
        let mut c = crawler("googlebot", &["10.0.0.0/8"]).unwrap();
        c.v4 = vec![(10, 20), (15, 30)];
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.push(9);
        b.extend_from_slice(b"googlebot");
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        for (x, y) in c.v4 {
            b.extend_from_slice(&x.to_le_bytes());
            b.extend_from_slice(&y.to_le_bytes());
        }
        assert!(parse(&b).is_err());
    }
}
