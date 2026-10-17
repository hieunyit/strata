//! GeoIP & ASN threat mitigation and location-based access control (W19-R-01).
//!
//! Provides zero-copy, sub-microsecond IP geographic and Autonomous System (ASN)
//! resolution directly at the proxy node data plane.
//!
//! Supports:
//! 1. Fast-path short-circuit for private, loopback, and link-local IPs (0ns overhead).
//! 2. Zero-copy MaxMind DB (MMDB v2) binary search tree navigation directly over bundle mmap bytes.
//! 3. Compact Strata binary Geo index table for optimized low-memory deployments.
//! 4. Policy-level `geo_restrictions` evaluation (block/challenge by Country ISO or ASN).
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr};

/// Magic header for the STRGEO section in the bundle (kind 10).
pub const GEO_SECTION_MAGIC: &[u8; 8] = b"STRGEO1\0";
pub const GEO_FORMAT_VERSION: u16 = 1;

/// Action triggered by geographic or ASN restriction matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum GeoAction {
    #[default]
    Pass = 0,
    Block = 1,
    Challenge = 2,
    Monitor = 3,
}

impl GeoAction {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Block,
            2 => Self::Challenge,
            3 => Self::Monitor,
            _ => Self::Pass,
        }
    }
}

/// Resolved geographical and autonomous system location data for an IP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeoLocation {
    pub country_iso: [u8; 2],
    pub asn: u32,
    pub is_internal: bool,
}

impl Default for GeoLocation {
    fn default() -> Self {
        Self {
            country_iso: *b"--",
            asn: 0,
            is_internal: false,
        }
    }
}

impl GeoLocation {
    pub const INTERNAL: Self = Self {
        country_iso: *b"IN",
        asn: 0,
        is_internal: true,
    };

    pub fn country_str(&self) -> &str {
        std::str::from_utf8(&self.country_iso).unwrap_or("--")
    }
}

/// Restriction rules configured for a specific policy.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PolicyGeoRestriction {
    pub enabled: bool,
    pub default_action: GeoAction,
    pub action: GeoAction,
    pub blocked_countries: Vec<[u8; 2]>,
    pub blocked_asns: Vec<u32>,
    pub challenge_countries: Vec<[u8; 2]>,
    pub challenge_asns: Vec<u32>,
}

impl PolicyGeoRestriction {
    /// Evaluates `loc` against this restriction.
    /// Returns Some((action, reason)) if restricted, None if permitted.
    pub fn check(&self, loc: &GeoLocation) -> Option<(GeoAction, &'static str)> {
        if !self.enabled || loc.is_internal {
            return None;
        }

        // 1. Check blocked countries
        if self.blocked_countries.contains(&loc.country_iso) {
            let act = if self.action == GeoAction::Pass { GeoAction::Block } else { self.action };
            return Some((act, "country in blocked_countries"));
        }

        // 2. Check blocked ASNs
        if loc.asn > 0 && self.blocked_asns.contains(&loc.asn) {
            let act = if self.action == GeoAction::Pass { GeoAction::Block } else { self.action };
            return Some((act, "ASN in blocked_asns"));
        }

        // 3. Check challenged countries
        if self.challenge_countries.contains(&loc.country_iso) {
            return Some((GeoAction::Challenge, "country in challenge_countries"));
        }

        // 4. Check challenged ASNs
        if loc.asn > 0 && self.challenge_asns.contains(&loc.asn) {
            return Some((GeoAction::Challenge, "ASN in challenge_asns"));
        }

        None
    }
}

/// Fast-path check: returns true if the IP belongs to internal, loopback, or private ranges.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            // 127.0.0.0/8 (Loopback)
            oct[0] == 127
            // 10.0.0.0/8 (RFC 1918)
            || oct[0] == 10
            // 172.16.0.0/12 (RFC 1918)
            || (oct[0] == 172 && (16..=31).contains(&oct[1]))
            // 192.168.0.0/16 (RFC 1918)
            || (oct[0] == 192 && oct[1] == 168)
            // 169.254.0.0/16 (Link Local)
            || (oct[0] == 169 && oct[1] == 254)
            // 0.0.0.0/8
            || oct[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
            // Link-local unicast fe80::/10
            || (v6.segments()[0] & 0xffc0) == 0xfe80
            // Unique local address fc00::/7 (RFC 4193)
            || (v6.segments()[0] & 0xfe00) == 0xfc00
            // IPv4 mapped loopback ::ffff:127.x.x.x
            || (v6.to_ipv4_mapped().is_some_and(|ipv4| is_private_ip(&IpAddr::V4(ipv4))))
        }
    }
}

/// Parses an IP address from string slice, stripping optional port notation.
pub fn parse_ip_or_host(s: &str) -> Option<IpAddr> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Direct parse
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }
    // Handle host:port syntax
    if let Some((host, _port)) = trimmed.rsplit_once(':') {
        let clean_host = host.trim_matches(['[', ']']);
        if let Ok(ip) = clean_host.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

/// A compact IP range entry for fast binary search in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactRangeV4 {
    pub start: u32,
    pub end: u32,
    pub country: [u8; 2],
    pub asn: u32,
}

/// Zero-copy MMDB v2 parser directly over mapped bytes.
#[derive(Clone, Copy, Debug)]
pub struct MmdbView<'a> {
    data: &'a [u8],
    node_count: usize,
    record_size_bits: usize,
    node_size_bytes: usize,
    data_section_start: usize,
}

impl<'a> MmdbView<'a> {
    /// Attempts to parse an MMDB slice.
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 32 {
            return None;
        }
        // Search backwards for MaxMind metadata marker "\xab\xcd\xefMaxMind.com"
        let marker = b"\xab\xcd\xefMaxMind.com";
        let marker_pos = bytes.windows(marker.len()).rposition(|w| w == marker)?;
        let meta_bytes = &bytes[marker_pos + marker.len()..];
        if meta_bytes.is_empty() {
            return None;
        }

        // Minimal metadata extraction: search for node_count & record_size
        // In MMDB format, metadata is an encoded map.
        let node_count = Self::find_uint_in_meta(meta_bytes, b"node_count").unwrap_or(0) as usize;
        let record_size = Self::find_uint_in_meta(meta_bytes, b"record_size").unwrap_or(24) as usize;

        if node_count == 0 || !(24..=32).contains(&record_size) {
            return None;
        }

        let node_size_bytes = (record_size * 2) / 8;
        let tree_len = node_count * node_size_bytes;
        let data_section_start = tree_len + 16;

        if bytes.len() < data_section_start {
            return None;
        }

        Some(Self {
            data: bytes,
            node_count,
            record_size_bits: record_size,
            node_size_bytes,
            data_section_start,
        })
    }

    fn find_uint_in_meta(meta: &[u8], key: &[u8]) -> Option<u64> {
        let pos = meta.windows(key.len()).position(|w| w == key)?;
        let rest = &meta[pos + key.len()..];
        for window in rest.windows(5) {
            // Looking for uint control byte (type 2, 8, or 9)
            if window[0] & 0xe0 == 0x40 || window[0] & 0xe0 == 0x00 {
                let len = (window[0] & 0x1f) as usize;
                if (1..=4).contains(&len) && rest.len() >= 1 + len {
                    let mut val = 0u64;
                    for &b in &window[1..=len] {
                        val = (val << 8) | (b as u64);
                    }
                    if val > 0 {
                        return Some(val);
                    }
                }
            }
        }
        None
    }

    /// Navigates the tree to look up an IPv4 address.
    pub fn lookup_v4(&self, ip: Ipv4Addr) -> Option<GeoLocation> {
        let octets = ip.octets();
        let mut node = 0usize;

        for &octet in &octets {
            for bit_idx in (0..8).rev() {
                let bit = (octet >> bit_idx) & 1;
                let child = self.read_child(node, bit as usize)?;
                if child < self.node_count {
                    node = child;
                } else if child == self.node_count {
                    return None; // Not found
                } else {
                    // Match found!
                    let data_offset = child - self.node_count - 16;
                    return self.parse_record(data_offset);
                }
            }
        }
        None
    }

    fn read_child(&self, node: usize, bit: usize) -> Option<usize> {
        let offset = node * self.node_size_bytes;
        if offset + self.node_size_bytes > self.data_section_start {
            return None;
        }
        let b = &self.data[offset..offset + self.node_size_bytes];
        if self.record_size_bits == 24 {
            if bit == 0 {
                Some((b[0] as usize) << 16 | (b[1] as usize) << 8 | (b[2] as usize))
            } else {
                Some((b[3] as usize) << 16 | (b[4] as usize) << 8 | (b[5] as usize))
            }
        } else if self.record_size_bits == 28 {
            if bit == 0 {
                Some(((b[3] as usize & 0xf0) << 20) | ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize))
            } else {
                Some(((b[3] as usize & 0x0f) << 24) | ((b[4] as usize) << 16) | ((b[5] as usize) << 8) | (b[6] as usize))
            }
        } else if self.record_size_bits == 32 {
            if bit == 0 {
                Some((b[0] as usize) << 24 | (b[1] as usize) << 16 | (b[2] as usize) << 8 | (b[3] as usize))
            } else {
                Some((b[4] as usize) << 24 | (b[5] as usize) << 16 | (b[6] as usize) << 8 | (b[7] as usize))
            }
        } else {
            None
        }
    }

    fn parse_record(&self, record_offset: usize) -> Option<GeoLocation> {
        let abs_offset = self.data_section_start + record_offset;
        if abs_offset >= self.data.len() {
            return None;
        }
        let slice = &self.data[abs_offset..];
        let mut loc = GeoLocation::default();

        // Fast search for 2-letter ISO code in record payload
        if let Some(pos) = slice.windows(10).position(|w| w.starts_with(b"iso_code")) {
            let val_slice = &slice[pos + 8..];
            if val_slice.len() >= 3 && val_slice[0] & 0xe0 == 0x40 && (val_slice[0] & 0x1f) == 2 {
                loc.country_iso = [val_slice[1], val_slice[2]];
            }
        }

        // Fast search for ASN in record payload
        if let Some(pos) = slice.windows(16).position(|w| w.starts_with(b"autonomous_system_number") || w.starts_with(b"asn")) {
            let val_slice = &slice[pos..];
            for w in val_slice.windows(5) {
                if w[0] == 0x04 || w[0] == 0x02 || w[0] == 0x08 {
                    loc.asn = ((w[1] as u32) << 24) | ((w[2] as u32) << 16) | ((w[3] as u32) << 8) | (w[4] as u32);
                    break;
                }
            }
        }

        Some(loc)
    }
}

/// The GeoResolver component loaded into the WAF Engine.
#[derive(Clone, Debug)]
pub struct GeoResolver<'a> {
    policies: Vec<PolicyGeoRestriction>,
    compact_v4: Vec<CompactRangeV4>,
    mmdb: Option<MmdbView<'a>>,
}

impl<'a> GeoResolver<'a> {
    /// Builds a GeoResolver from the STRGEO bundle section.
    pub fn parse(section_bytes: &'a [u8], n_policies: usize) -> Option<Self> {
        if section_bytes.len() < 16 || !section_bytes.starts_with(GEO_SECTION_MAGIC) {
            return None;
        }

        let version = u16::from_le_bytes([section_bytes[8], section_bytes[9]]);
        if version != GEO_FORMAT_VERSION {
            return None;
        }

        let pol_count = u32::from_le_bytes([
            section_bytes[12],
            section_bytes[13],
            section_bytes[14],
            section_bytes[15],
        ]) as usize;

        let mut offset = 16;
        let mut policies = Vec::with_capacity(std::cmp::min(pol_count, n_policies));

        // Read policy table
        for _ in 0..pol_count {
            if offset + 6 > section_bytes.len() {
                break;
            }
            let enabled = section_bytes[offset] != 0;
            let default_action = GeoAction::from_u8(section_bytes[offset + 1]);
            let action = GeoAction::from_u8(section_bytes[offset + 2]);
            offset += 4; // plus 1 byte reserved

            // Blocked countries
            let n_bc = u16::from_le_bytes([section_bytes[offset], section_bytes[offset + 1]]) as usize;
            offset += 2;
            let mut blocked_countries = Vec::with_capacity(n_bc);
            for _ in 0..n_bc {
                if offset + 2 > section_bytes.len() {
                    break;
                }
                blocked_countries.push([section_bytes[offset], section_bytes[offset + 1]]);
                offset += 2;
            }

            // Blocked ASNs
            if offset + 2 > section_bytes.len() {
                break;
            }
            let n_ba = u16::from_le_bytes([section_bytes[offset], section_bytes[offset + 1]]) as usize;
            offset += 2;
            let mut blocked_asns = Vec::with_capacity(n_ba);
            for _ in 0..n_ba {
                if offset + 4 > section_bytes.len() {
                    break;
                }
                let asn = u32::from_le_bytes([
                    section_bytes[offset],
                    section_bytes[offset + 1],
                    section_bytes[offset + 2],
                    section_bytes[offset + 3],
                ]);
                blocked_asns.push(asn);
                offset += 4;
            }

            // Challenged countries
            if offset + 2 > section_bytes.len() {
                break;
            }
            let n_cc = u16::from_le_bytes([section_bytes[offset], section_bytes[offset + 1]]) as usize;
            offset += 2;
            let mut challenge_countries = Vec::with_capacity(n_cc);
            for _ in 0..n_cc {
                if offset + 2 > section_bytes.len() {
                    break;
                }
                challenge_countries.push([section_bytes[offset], section_bytes[offset + 1]]);
                offset += 2;
            }

            // Challenged ASNs
            if offset + 2 > section_bytes.len() {
                break;
            }
            let n_ca = u16::from_le_bytes([section_bytes[offset], section_bytes[offset + 1]]) as usize;
            offset += 2;
            let mut challenge_asns = Vec::with_capacity(n_ca);
            for _ in 0..n_ca {
                if offset + 4 > section_bytes.len() {
                    break;
                }
                let asn = u32::from_le_bytes([
                    section_bytes[offset],
                    section_bytes[offset + 1],
                    section_bytes[offset + 2],
                    section_bytes[offset + 3],
                ]);
                challenge_asns.push(asn);
                offset += 4;
            }

            policies.push(PolicyGeoRestriction {
                enabled,
                default_action,
                action,
                blocked_countries,
                blocked_asns,
                challenge_countries,
                challenge_asns,
            });
        }

        // Read compact table if present
        let mut compact_v4 = Vec::new();
        if offset + 4 <= section_bytes.len() {
            let n_compact = u32::from_le_bytes([
                section_bytes[offset],
                section_bytes[offset + 1],
                section_bytes[offset + 2],
                section_bytes[offset + 3],
            ]) as usize;
            offset += 4;

            compact_v4.reserve(n_compact);
            for _ in 0..n_compact {
                if offset + 14 > section_bytes.len() {
                    break;
                }
                let start = u32::from_le_bytes([
                    section_bytes[offset],
                    section_bytes[offset + 1],
                    section_bytes[offset + 2],
                    section_bytes[offset + 3],
                ]);
                let end = u32::from_le_bytes([
                    section_bytes[offset + 4],
                    section_bytes[offset + 5],
                    section_bytes[offset + 6],
                    section_bytes[offset + 7],
                ]);
                let country = [section_bytes[offset + 8], section_bytes[offset + 9]];
                let asn = u32::from_le_bytes([
                    section_bytes[offset + 10],
                    section_bytes[offset + 11],
                    section_bytes[offset + 12],
                    section_bytes[offset + 13],
                ]);
                compact_v4.push(CompactRangeV4 {
                    start,
                    end,
                    country,
                    asn,
                });
                offset += 14;
            }
        }

        // Remaining bytes are optional raw MMDB payload
        let mmdb = if offset < section_bytes.len() {
            MmdbView::parse(&section_bytes[offset..])
        } else {
            None
        };

        Some(Self {
            policies,
            compact_v4,
            mmdb,
        })
    }

    /// Resolves an IP string or address to GeoLocation.
    pub fn resolve(&self, ip_str: &str) -> GeoLocation {
        let Some(ip) = parse_ip_or_host(ip_str) else {
            return GeoLocation::default();
        };
        self.resolve_ip(&ip)
    }

    /// Resolves parsed `IpAddr`.
    pub fn resolve_ip(&self, ip: &IpAddr) -> GeoLocation {
        // 1. Fast-path: internal IPs immediately return INTERNAL without tree search
        if is_private_ip(ip) {
            return GeoLocation::INTERNAL;
        }

        // 2. Binary search on compact table if available
        if let IpAddr::V4(v4) = ip {
            let ip_num = u32::from_be_bytes(v4.octets());
            if let Ok(idx) = self.compact_v4.binary_search_by(|entry| {
                if ip_num < entry.start {
                    std::cmp::Ordering::Greater
                } else if ip_num > entry.end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            }) {
                let entry = &self.compact_v4[idx];
                return GeoLocation {
                    country_iso: entry.country,
                    asn: entry.asn,
                    is_internal: false,
                };
            }

            // 3. Fallback to MMDB zero-copy view if present
            if let Some(mmdb) = &self.mmdb {
                if let Some(loc) = mmdb.lookup_v4(*v4) {
                    return loc;
                }
            }
        }

        GeoLocation::default()
    }

    /// Checks policy geo restriction for a transaction.
    pub fn check_policy(&self, policy_idx: usize, ip_str: &str) -> Option<(GeoAction, &'static str)> {
        let restriction = self.policies.get(policy_idx)?;
        if !restriction.enabled {
            return None;
        }
        let loc = self.resolve(ip_str);
        restriction.check(&loc)
    }

    /// Helper constructor for tests with compact ranges.
    pub fn with_compact(policies: Vec<PolicyGeoRestriction>, compact: Vec<CompactRangeV4>) -> Self {
        let mut sorted = compact;
        sorted.sort_by_key(|e| e.start);
        Self {
            policies,
            compact_v4: sorted,
            mmdb: None,
        }
    }
}

/// Encodes policy restrictions and compact/MMDB data into a STRGEO section byte vector.
pub fn encode_section(
    policies: &[PolicyGeoRestriction],
    compact: &[CompactRangeV4],
    raw_mmdb: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(GEO_SECTION_MAGIC);
    out.extend_from_slice(&GEO_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&(policies.len() as u32).to_le_bytes());

    for pol in policies {
        out.push(if pol.enabled { 1 } else { 0 });
        out.push(pol.default_action as u8);
        out.push(pol.action as u8);
        out.push(0); // reserved

        // Blocked countries
        out.extend_from_slice(&(pol.blocked_countries.len() as u16).to_le_bytes());
        for c in &pol.blocked_countries {
            out.extend_from_slice(c);
        }

        // Blocked ASNs
        out.extend_from_slice(&(pol.blocked_asns.len() as u16).to_le_bytes());
        for &asn in &pol.blocked_asns {
            out.extend_from_slice(&asn.to_le_bytes());
        }

        // Challenge countries
        out.extend_from_slice(&(pol.challenge_countries.len() as u16).to_le_bytes());
        for c in &pol.challenge_countries {
            out.extend_from_slice(c);
        }

        // Challenge ASNs
        out.extend_from_slice(&(pol.challenge_asns.len() as u16).to_le_bytes());
        for &asn in &pol.challenge_asns {
            out.extend_from_slice(&asn.to_le_bytes());
        }
    }

    // Compact table
    let mut sorted_compact = compact.to_vec();
    sorted_compact.sort_by_key(|e| e.start);

    out.extend_from_slice(&(sorted_compact.len() as u32).to_le_bytes());
    for entry in &sorted_compact {
        out.extend_from_slice(&entry.start.to_le_bytes());
        out.extend_from_slice(&entry.end.to_le_bytes());
        out.extend_from_slice(&entry.country);
        out.extend_from_slice(&entry.asn.to_le_bytes());
    }

    // Optional raw MMDB
    if let Some(mmdb) = raw_mmdb {
        out.extend_from_slice(mmdb);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_fastpath() {
        let loc = GeoResolver::with_compact(vec![], vec![]).resolve("127.0.0.1");
        assert!(loc.is_internal);
        assert_eq!(&loc.country_iso, b"IN");
        assert_eq!(loc.asn, 0);

        let loc_priv = GeoResolver::with_compact(vec![], vec![]).resolve("10.0.5.99:8080");
        assert!(loc_priv.is_internal);
        assert_eq!(&loc_priv.country_iso, b"IN");

        let loc_v6 = GeoResolver::with_compact(vec![], vec![]).resolve("[::1]:443");
        assert!(loc_v6.is_internal);
    }

    #[test]
    fn test_compact_resolution_and_policy_check() {
        // IP 203.0.113.195 (VN, ASN 7552) -> 203.0.113.0/24
        // 203.0.113.0 = 0xCB007100, 203.0.113.255 = 0xCB0071FF
        let compact = vec![
            CompactRangeV4 {
                start: 0xCB007100,
                end: 0xCB0071FF,
                country: *b"VN",
                asn: 7552,
            },
            CompactRangeV4 {
                start: 0xC6336400, // 198.51.100.0/24 (US, ASN 13335)
                end: 0xC63364FF,
                country: *b"US",
                asn: 13335,
            },
        ];

        let pol = PolicyGeoRestriction {
            enabled: true,
            default_action: GeoAction::Pass,
            action: GeoAction::Block,
            blocked_countries: vec![*b"US"],
            blocked_asns: vec![7552],
            challenge_countries: vec![],
            challenge_asns: vec![],
        };

        let resolver = GeoResolver::with_compact(vec![pol], compact);

        // 1. Resolve VN
        let loc_vn = resolver.resolve("203.0.113.195");
        assert_eq!(&loc_vn.country_iso, b"VN");
        assert_eq!(loc_vn.asn, 7552);
        assert!(!loc_vn.is_internal);

        // 2. Policy check on VN: blocked because ASN 7552 is in blocked_asns
        let check_vn = resolver.check_policy(0, "203.0.113.195");
        assert_eq!(check_vn, Some((GeoAction::Block, "ASN in blocked_asns")));

        // 3. Policy check on US: blocked because country US is in blocked_countries
        let check_us = resolver.check_policy(0, "198.51.100.42");
        assert_eq!(check_us, Some((GeoAction::Block, "country in blocked_countries")));

        // 4. Internal IP bypasses policy check
        let check_priv = resolver.check_policy(0, "192.168.1.1");
        assert_eq!(check_priv, None);
    }

    #[test]
    fn test_section_encode_decode_roundtrip() {
        let pol = PolicyGeoRestriction {
            enabled: true,
            default_action: GeoAction::Pass,
            action: GeoAction::Block,
            blocked_countries: vec![*b"KP", *b"RU"],
            blocked_asns: vec![12345, 67890],
            challenge_countries: vec![*b"CN"],
            challenge_asns: vec![9999],
        };

        let compact = vec![CompactRangeV4 {
            start: 0x01020300,
            end: 0x010203FF,
            country: *b"KP",
            asn: 12345,
        }];

        let encoded = encode_section(&[pol.clone()], &compact, None);
        assert!(encoded.starts_with(GEO_SECTION_MAGIC));

        let decoded = GeoResolver::parse(&encoded, 1).expect("failed to parse encoded section");
        assert_eq!(decoded.policies.len(), 1);
        assert_eq!(decoded.policies[0].blocked_countries, vec![*b"KP", *b"RU"]);
        assert_eq!(decoded.policies[0].blocked_asns, vec![12345, 67890]);
        assert_eq!(decoded.policies[0].challenge_countries, vec![*b"CN"]);
        assert_eq!(decoded.policies[0].challenge_asns, vec![9999]);

        // Verify resolution
        let loc = decoded.resolve("1.2.3.4");
        assert_eq!(&loc.country_iso, b"KP");
        assert_eq!(loc.asn, 12345);
    }
}
