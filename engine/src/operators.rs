//! Operators phase 2 (W07-R-02): `validate_byte_range`,
//! `validate_url_encoding`, `validate_utf8_encoding`, `ip_match`.
//!
//! Semantics match Coraza v3.8.1 (corazawaf/coraza 9f8521398d1ff023b958fad0b944cac265763866).
//!
//! - `validate_byte_range`: validates that byte values fall into specified range(s).
//!   Matches (violation) when any byte is outside the allowed ranges.
//! - `validate_url_encoding`: validates `%XX` percent-encoding.
//!   Matches when `%` is not followed by 2 hex digits, or `%` is at the end.
//! - `validate_utf8_encoding`: validates UTF-8 byte sequences.
//!   Matches on invalid UTF-8 (overlong, surrogates, > U+10FFFF, truncated).
//! - `ip_match`: fast IPv4 and IPv6 CIDR / single IP matching using binary search
//!   over pre-sorted and merged disjoint ranges. Non-IP inputs do not match.
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::rules::{Tables, ValueView, code};

/// Allowed byte set for `validate_byte_range`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteRangeSet {
    valid_bytes: [bool; 256],
    unconditional: bool,
}

impl Default for ByteRangeSet {
    fn default() -> Self {
        Self {
            valid_bytes: [false; 256],
            unconditional: false,
        }
    }
}

impl ByteRangeSet {
    /// Parses a comma-separated range specification, e.g. `"10, 13, 32-126"`.
    ///
    /// Empty string corresponds to Coraza's unconditional match (matches any non-empty input).
    pub fn parse(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(Self {
                valid_bytes: [false; 256],
                unconditional: true,
            });
        }
        let mut valid_bytes = [false; 256];
        for part in trimmed.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((start_s, end_s)) = part.split_once('-') {
                let start: u16 = start_s
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid byte range start: {start_s:?}"))?;
                let end: u16 = end_s
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid byte range end: {end_s:?}"))?;
                if start > 255 || end > 255 {
                    return Err(format!("byte out of range 0..255 in {part:?}"));
                }
                if start > end {
                    return Err(format!("byte range inverted {start}-{end}"));
                }
                for b in start..=end {
                    valid_bytes[b as usize] = true;
                }
            } else {
                let b: u16 = part
                    .parse()
                    .map_err(|_| format!("invalid byte value: {part:?}"))?;
                if b > 255 {
                    return Err(format!("byte out of range 0..255: {b}"));
                }
                valid_bytes[b as usize] = true;
            }
        }
        Ok(Self {
            valid_bytes,
            unconditional: false,
        })
    }

    /// Evaluates `data`. Returns `true` if any byte is outside the allowed ranges
    /// (violation detected), or `false` if all bytes are valid. Empty data returns `false`.
    pub fn is_match(&self, data: &[u8]) -> bool {
        if self.unconditional {
            return !data.is_empty();
        }
        if data.is_empty() {
            return false;
        }
        for &b in data {
            if !self.valid_bytes[b as usize] {
                return true;
            }
        }
        false
    }
}

/// Validates syntax of a `validate_byte_range` parameter.
pub fn validate_byte_range_syntax(s: &str) -> Result<(), String> {
    ByteRangeSet::parse(s).map(|_| ())
}

/// Validates URL-encoded characters in `data`.
/// Returns `true` if invalid percent-encoding is detected (violation).
pub fn validate_url_encoding(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'%' {
            if i + 2 >= data.len() {
                return true;
            }
            if !data[i + 1].is_ascii_hexdigit() || !data[i + 2].is_ascii_hexdigit() {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

/// Validates UTF-8 encoding of `data`.
/// Returns `true` if invalid UTF-8 encoding is detected (violation).
pub fn validate_utf8_encoding(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_err()
}

/// Sorted, disjoint IPv4 and IPv6 address ranges for $O(\log N)$ binary search lookup.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpMatchSet {
    v4_ranges: Vec<(u32, u32)>,
    v6_ranges: Vec<(u128, u128)>,
}

fn merge_ranges_u32(ranges: &mut Vec<(u32, u32)>) {
    if ranges.is_empty() {
        return;
    }
    ranges.sort_unstable_by_key(|r| r.0);
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges.drain(..) {
        if let Some(last) = merged.last_mut() {
            if start <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        } else {
            merged.push((start, end));
        }
    }
    *ranges = merged;
}

fn merge_ranges_u128(ranges: &mut Vec<(u128, u128)>) {
    if ranges.is_empty() {
        return;
    }
    ranges.sort_unstable_by_key(|r| r.0);
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges.drain(..) {
        if let Some(last) = merged.last_mut() {
            if start <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        } else {
            merged.push((start, end));
        }
    }
    *ranges = merged;
}

enum SingleIpRange {
    V4(u32, u32),
    V6(u128, u128),
}

fn parse_single_range(sb: &str) -> Result<SingleIpRange, String> {
    let (ip_str, mask_str) = if let Some((ip, mask)) = sb.split_once('/') {
        (ip.trim(), Some(mask.trim()))
    } else {
        (sb, None)
    };

    // Check IPv6 first (covers IPv4-in-IPv6 syntax like 1:2:3:4:5:6:1.2.3.4 as well)
    if ip_str.contains(':') {
        let v6 = ip_str
            .parse::<Ipv6Addr>()
            .map_err(|e| format!("invalid IPv6 address {ip_str:?}: {e}"))?;
        let prefix: u8 = match mask_str {
            Some(m) => m
                .parse()
                .map_err(|_| format!("invalid IPv6 CIDR mask {m:?} in {sb:?}"))?,
            None => 128,
        };
        if prefix > 128 {
            return Err(format!("IPv6 CIDR mask out of range: {prefix} in {sb:?}"));
        }
        if let Some(v4) = v6.to_ipv4_mapped() {
            let v4_prefix = prefix.saturating_sub(96);
            let num = u32::from(v4);
            let mask = if v4_prefix == 0 {
                0
            } else {
                !0u32 << (32 - v4_prefix)
            };
            let start = num & mask;
            let end = start | !mask;
            Ok(SingleIpRange::V4(start, end))
        } else {
            let num = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                !0u128 << (128 - prefix)
            };
            let start = num & mask;
            let end = start | !mask;
            Ok(SingleIpRange::V6(start, end))
        }
    } else {
        let v4 = ip_str
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("invalid IPv4 address {ip_str:?}: {e}"))?;
        let prefix: u8 = match mask_str {
            Some(m) => m
                .parse()
                .map_err(|_| format!("invalid IPv4 CIDR mask {m:?} in {sb:?}"))?,
            None => 32,
        };
        if prefix > 32 {
            return Err(format!("IPv4 CIDR mask out of range: {prefix} in {sb:?}"));
        }
        let num = u32::from(v4);
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        let start = num & mask;
        let end = start | !mask;
        Ok(SingleIpRange::V4(start, end))
    }
}

impl IpMatchSet {
    /// Parses an iterator of IP or CIDR strings (each may contain comma-separated entries).
    ///
    /// Following Coraza semantics, individual invalid subnets in the list are ignored.
    pub fn parse_entries<I, S>(entries: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut v4_ranges = Vec::new();
        let mut v6_ranges = Vec::new();

        for entry in entries {
            for item in entry.as_ref().split(',') {
                let sb = item.trim();
                if sb.is_empty() {
                    continue;
                }
                match parse_single_range(sb) {
                    Ok(SingleIpRange::V4(start, end)) => v4_ranges.push((start, end)),
                    Ok(SingleIpRange::V6(start, end)) => v6_ranges.push((start, end)),
                    Err(_) => {
                        // Coraza semantics: if err != nil { continue }
                    }
                }
            }
        }

        merge_ranges_u32(&mut v4_ranges);
        merge_ranges_u128(&mut v6_ranges);

        Ok(Self {
            v4_ranges,
            v6_ranges,
        })
    }

    /// Evaluates whether `data` represents an IP address matching any configured range.
    /// Non-IP inputs return `false`.
    pub fn is_match(&self, data: &[u8]) -> bool {
        let Ok(s) = std::str::from_utf8(data) else {
            return false;
        };
        let s = s.trim();
        if s.is_empty() {
            return false;
        }

        match s.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => {
                let x = u32::from(v4);
                self.v4_ranges
                    .binary_search_by(|&(start, end)| {
                        if x < start {
                            std::cmp::Ordering::Greater
                        } else if x > end {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Equal
                        }
                    })
                    .is_ok()
            }
            Ok(IpAddr::V6(v6)) => {
                // In Go net.IPNet, if ip.To4() != nil (IPv4 or IPv4-mapped IPv6),
                // IPv6 subnets never match, only IPv4 subnets are checked.
                if let Some(v4) = v6.to_ipv4_mapped() {
                    let x = u32::from(v4);
                    return self
                        .v4_ranges
                        .binary_search_by(|&(start, end)| {
                            if x < start {
                                std::cmp::Ordering::Greater
                            } else if x > end {
                                std::cmp::Ordering::Less
                            } else {
                                std::cmp::Ordering::Equal
                            }
                        })
                        .is_ok();
                }
                let x = u128::from(v6);
                self.v6_ranges
                    .binary_search_by(|&(start, end)| {
                        if x < start {
                            std::cmp::Ordering::Greater
                        } else if x > end {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Equal
                        }
                    })
                    .is_ok()
            }
            Err(_) => false,
        }
    }
}

/// Validates syntax of an `ip_match` list of IP/CIDR entries.
pub fn validate_ip_match_syntax<I, S>(entries: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut any = false;
    for entry in entries {
        for item in entry.as_ref().split(',') {
            let sb = item.trim();
            if sb.is_empty() {
                continue;
            }
            parse_single_range(sb)?;
            any = true;
        }
    }
    if !any {
        return Err("empty ip_match entry list".to_string());
    }
    Ok(())
}

/// Validates syntax of a `geo_match` list of ISO country codes (2-letter uppercase).
pub fn validate_geo_match_syntax<I, S>(entries: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut any = false;
    for entry in entries {
        for item in entry.as_ref().split(',') {
            let s = item.trim();
            if s.is_empty() {
                continue;
            }
            if s.len() != 2 || !s.chars().all(|c| c.is_ascii_uppercase()) {
                return Err(format!("invalid country ISO code {s:?}, must be 2 uppercase ASCII letters"));
            }
            any = true;
        }
    }
    if !any {
        return Err("empty geo_match entry list".to_string());
    }
    Ok(())
}

/// Validates syntax of an `asn_match` list of AS numbers (e.g. 13335, AS15169).
pub fn validate_asn_match_syntax<I, S>(entries: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut any = false;
    for entry in entries {
        for item in entry.as_ref().split(',') {
            let s = item.trim().trim_start_matches(|c| c == 'A' || c == 'S' || c == 'a' || c == 's');
            if s.is_empty() {
                continue;
            }
            s.parse::<u32>()
                .map_err(|_| format!("invalid ASN number in {item:?}"))?;
            any = true;
        }
    }
    if !any {
        return Err("empty asn_match entry list".to_string());
    }
    Ok(())
}

/// Pre-compiled operator lookup tables built once at bundle map time.
#[derive(Clone, Debug, Default)]
pub struct CompiledOperators {
    byte_ranges: Vec<(u32, ByteRangeSet)>,
    ip_matches: Vec<(u32, IpMatchSet)>,
    geo_matches: Vec<(u32, Vec<[u8; 2]>)>,
    asn_matches: Vec<(u32, Vec<u32>)>,
}

impl CompiledOperators {
    /// Builds lookup structures for all `validate_byte_range`, `ip_match`,
    /// `geo_match`, and `asn_match` conditions in `tables`.
    pub fn build(tables: &Tables<'_>) -> Result<Self, &'static str> {
        let vbr_code = code(crate::rules::OPERATORS, "validate_byte_range").unwrap_or(u8::MAX);
        let ipm_code = code(crate::rules::OPERATORS, "ip_match").unwrap_or(u8::MAX);
        let geo_code = code(crate::rules::OPERATORS, "geo_match").unwrap_or(u8::MAX);
        let asn_code = code(crate::rules::OPERATORS, "asn_match").unwrap_or(u8::MAX);

        let mut byte_ranges = Vec::new();
        let mut ip_matches = Vec::new();
        let mut geo_matches = Vec::new();
        let mut asn_matches = Vec::new();

        for ri in 0..tables.n_rules() {
            let Some(r) = tables.rule(ri) else { continue };
            for ci in r.cond_first..r.cond_first + r.cond_count {
                let Some(c) = tables.cond(ci) else { continue };
                if c.op == vbr_code {
                    let range_str = match c.value {
                        ValueView::Str(bytes) => std::str::from_utf8(bytes)
                            .map_err(|_| "bundle has non-UTF8 validate_byte_range value")?,
                        _ => return Err("bundle has non-string validate_byte_range value"),
                    };
                    let set = ByteRangeSet::parse(range_str)
                        .map_err(|_| "bundle has invalid validate_byte_range syntax")?;
                    byte_ranges.push((ci, set));
                } else if c.op == ipm_code {
                    let (first, count) = match c.value {
                        ValueView::List(first, count) => (first, count),
                        _ => return Err("bundle has non-list ip_match value"),
                    };
                    let mut entries = Vec::with_capacity(count as usize);
                    for li in first..first + count {
                        let item_bytes =
                            tables.list(li).ok_or("bundle has missing ip_match item")?;
                        let item_str = std::str::from_utf8(item_bytes)
                            .map_err(|_| "bundle has non-UTF8 ip_match entry")?;
                        entries.push(item_str);
                    }
                    let set = IpMatchSet::parse_entries(&entries)
                        .map_err(|_| "bundle has invalid ip_match entry")?;
                    ip_matches.push((ci, set));
                } else if c.op == geo_code {
                    let mut countries = Vec::new();
                    match c.value {
                        ValueView::List(first, count) => {
                            for li in first..first + count {
                                let item_bytes = tables.list(li).ok_or("bundle has missing geo_match item")?;
                                if item_bytes.len() == 2 {
                                    countries.push([item_bytes[0].to_ascii_uppercase(), item_bytes[1].to_ascii_uppercase()]);
                                }
                            }
                        }
                        ValueView::Str(bytes) => {
                            if let Ok(s) = std::str::from_utf8(bytes) {
                                for item in s.split(',') {
                                    let b = item.trim().as_bytes();
                                    if b.len() == 2 {
                                        countries.push([b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()]);
                                    }
                                }
                            }
                        }
                        _ => return Err("bundle has invalid geo_match value"),
                    }
                    countries.sort_unstable();
                    countries.dedup();
                    geo_matches.push((ci, countries));
                } else if c.op == asn_code {
                    let mut asns = Vec::new();
                    match c.value {
                        ValueView::List(first, count) => {
                            for li in first..first + count {
                                let item_bytes = tables.list(li).ok_or("bundle has missing asn_match item")?;
                                if let Ok(s) = std::str::from_utf8(item_bytes) {
                                    let clean = s.trim().trim_start_matches(|c| c == 'A' || c == 'S' || c == 'a' || c == 's');
                                    if let Ok(num) = clean.parse::<u32>() {
                                        asns.push(num);
                                    }
                                }
                            }
                        }
                        ValueView::Int(n) => {
                            if n > 0 {
                                asns.push(n as u32);
                            }
                        }
                        ValueView::Str(bytes) => {
                            if let Ok(s) = std::str::from_utf8(bytes) {
                                for item in s.split(',') {
                                    let clean = item.trim().trim_start_matches(|c| c == 'A' || c == 'S' || c == 'a' || c == 's');
                                    if let Ok(num) = clean.parse::<u32>() {
                                        asns.push(num);
                                    }
                                }
                            }
                        }
                        _ => return Err("bundle has invalid asn_match value"),
                    }
                    asns.sort_unstable();
                    asns.dedup();
                    asn_matches.push((ci, asns));
                }
            }
        }

        byte_ranges.sort_unstable_by_key(|(ci, _)| *ci);
        ip_matches.sort_unstable_by_key(|(ci, _)| *ci);
        geo_matches.sort_unstable_by_key(|(ci, _)| *ci);
        asn_matches.sort_unstable_by_key(|(ci, _)| *ci);

        Ok(Self {
            byte_ranges,
            ip_matches,
            geo_matches,
            asn_matches,
        })
    }

    /// Evaluates condition `ci` with `validate_byte_range`.
    pub fn check_byte_range(&self, ci: u32, val: &[u8]) -> bool {
        match self.byte_ranges.binary_search_by_key(&ci, |(c, _)| *c) {
            Ok(idx) => self.byte_ranges[idx].1.is_match(val),
            Err(_) => false,
        }
    }

    /// Evaluates condition `ci` with `ip_match`.
    pub fn check_ip_match(&self, ci: u32, val: &[u8]) -> bool {
        match self.ip_matches.binary_search_by_key(&ci, |(c, _)| *c) {
            Ok(idx) => self.ip_matches[idx].1.is_match(val),
            Err(_) => false,
        }
    }

    /// Evaluates condition `ci` with `geo_match`.
    pub fn check_geo_match(&self, ci: u32, country_iso: &[u8]) -> bool {
        if country_iso.len() != 2 {
            return false;
        }
        let needle = [country_iso[0].to_ascii_uppercase(), country_iso[1].to_ascii_uppercase()];
        match self.geo_matches.binary_search_by_key(&ci, |(c, _)| *c) {
            Ok(idx) => self.geo_matches[idx].1.binary_search(&needle).is_ok(),
            Err(_) => false,
        }
    }

    /// Evaluates condition `ci` with `asn_match`.
    pub fn check_asn_match(&self, ci: u32, asn: u32) -> bool {
        if asn == 0 {
            return false;
        }
        match self.asn_matches.binary_search_by_key(&ci, |(c, _)| *c) {
            Ok(idx) => self.asn_matches[idx].1.binary_search(&asn).is_ok(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_range_parse_and_eval() {
        let set = ByteRangeSet::parse("9,10,13,32-126").unwrap();
        assert!(!set.is_match(b"")); // empty input does not match
        assert!(!set.is_match(b"Hello World\t\n\r")); // all valid
        assert!(set.is_match(b"Hello\x00World")); // null byte is outside range
        assert!(set.is_match(b"\xff")); // 255 is outside range

        // Unconditional match when param is empty
        let unconn = ByteRangeSet::parse("").unwrap();
        assert!(!unconn.is_match(b""));
        assert!(unconn.is_match(b"abc"));

        // Single range
        let ascii = ByteRangeSet::parse("0-127").unwrap();
        assert!(!ascii.is_match(b"ASCII string!"));
        assert!(ascii.is_match("Tiếng Việt".as_bytes()));
    }

    #[test]
    fn test_byte_range_syntax_errors() {
        assert!(validate_byte_range_syntax("256").is_err());
        assert!(validate_byte_range_syntax("100-50").is_err());
        assert!(validate_byte_range_syntax("abc").is_err());
        assert!(validate_byte_range_syntax("10-").is_err());
    }

    #[test]
    fn test_url_encoding() {
        assert!(!validate_url_encoding(b""));
        assert!(!validate_url_encoding(b"Hello%20World!"));
        assert!(!validate_url_encoding(b"%00%ff%AA"));
        assert!(!validate_url_encoding(b"normal string"));

        // Truncated percent
        assert!(validate_url_encoding(b"%"));
        assert!(validate_url_encoding(b"%a"));
        assert!(validate_url_encoding(b"abc%"));
        assert!(validate_url_encoding(b"abc%1"));

        // Non-hex characters
        assert!(validate_url_encoding(b"%0z"));
        assert!(validate_url_encoding(b"%z0"));
        assert!(validate_url_encoding(b"%0%"));
        assert!(validate_url_encoding(b"x=new %w20$"));
    }

    #[test]
    fn test_utf8_encoding() {
        assert!(!validate_utf8_encoding(b""));
        assert!(!validate_utf8_encoding(b"Hello, world!"));
        assert!(!validate_utf8_encoding("Xin chào Việt Nam, 🦀!".as_bytes()));

        // Overlong encoding of ASCII (e.g. 0xC0 0x80 for NUL)
        assert!(validate_utf8_encoding(b"\xc0\x80"));
        // Isolated continuation byte
        assert!(validate_utf8_encoding(b"\x80"));
        // Truncated 2-byte sequence
        assert!(validate_utf8_encoding(b"\xc2"));
        // Truncated 3-byte sequence
        assert!(validate_utf8_encoding(b"\xe0\xa0"));
        // Invalid byte 0xFF
        assert!(validate_utf8_encoding(b"\xff"));
        // UTF-16 surrogate
        assert!(validate_utf8_encoding(b"\xed\xa0\x80"));
    }

    #[test]
    fn test_ip_match_v4_and_v6() {
        let set = IpMatchSet::parse_entries([
            "10.0.0.0/8, 192.168.1.0/24",
            "172.16.5.10",
            "2001:db8::/32",
            "::1",
        ])
        .unwrap();

        // Valid IPv4 matches
        assert!(set.is_match(b"10.1.2.3"));
        assert!(set.is_match(b"10.255.255.255"));
        assert!(set.is_match(b"192.168.1.100"));
        assert!(set.is_match(b"172.16.5.10"));

        // Non-matching IPv4
        assert!(!set.is_match(b"192.168.2.1"));
        assert!(!set.is_match(b"172.16.5.11"));
        assert!(!set.is_match(b"8.8.8.8"));

        // Valid IPv6 matches
        assert!(set.is_match(b"2001:db8::1"));
        assert!(set.is_match(b"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert!(set.is_match(b"::1"));
        assert!(set.is_match(b"0:0:0:0:0:0:0:1"));

        // Non-matching IPv6
        assert!(!set.is_match(b"2001:db9::1"));
        assert!(!set.is_match(b"::2"));

        // Non-IP inputs
        assert!(!set.is_match(b""));
        assert!(!set.is_match(b"not-an-ip"));
        assert!(!set.is_match(b"localhost"));
        assert!(!set.is_match(b"10.0.0.999"));
    }

    #[test]
    fn test_ip_match_interval_merging() {
        let set = IpMatchSet::parse_entries([
            "192.168.1.0/25",   // 192.168.1.0 - 192.168.1.127
            "192.168.1.128/25", // 192.168.1.128 - 192.168.1.255 (adjacent!)
        ])
        .unwrap();
        // After merging, there should be exactly 1 range spanning 192.168.1.0/24
        assert_eq!(set.v4_ranges.len(), 1);
        assert!(set.is_match(b"192.168.1.50"));
        assert!(set.is_match(b"192.168.1.200"));
    }
}
