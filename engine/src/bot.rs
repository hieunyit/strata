//! Good bot verification and search crawler validation (W18-R-02).
//!
//! Validates requests claiming to originate from reputable search engine crawlers
//! (Googlebot, Bingbot, Applebot, etc.) against official published IP CIDR ranges.
//! Detects and flags spoofed crawlers (user-agent spoofing) with sub-microsecond binary search.
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Magic header for the STRBOT section in the bundle (kind 11).
pub const BOT_SECTION_MAGIC: &[u8; 8] = b"STRBOT1\0";
pub const BOT_FORMAT_VERSION: u16 = 1;

/// Recognized search engine crawler family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownBot {
    Googlebot,
    Bingbot,
    Applebot,
    Cloudflare,
    Yandex,
    DuckDuckGo,
}

impl KnownBot {
    pub fn as_str(&self) -> &'static str {
        match self {
            KnownBot::Googlebot => "googlebot",
            KnownBot::Bingbot => "bingbot",
            KnownBot::Applebot => "applebot",
            KnownBot::Cloudflare => "cloudflare",
            KnownBot::Yandex => "yandex",
            KnownBot::DuckDuckGo => "duckduckgo",
        }
    }
}

/// Identifies whether a User-Agent string claims to be a recognized search engine crawler.
pub fn identify_crawler_user_agent(ua: &[u8]) -> Option<KnownBot> {
    if ua.is_empty() {
        return None;
    }

    // Fast ASCII lowercase scan without heap allocation
    let mut buf = [0u8; 256];
    let len = ua.len().min(buf.len());
    for i in 0..len {
        buf[i] = ua[i].to_ascii_lowercase();
    }
    let s = match std::str::from_utf8(&buf[..len]) {
        Ok(v) => v,
        Err(_) => return None,
    };

    // Googlebot variants
    if s.contains("googlebot")
        || s.contains("google-inspectiontool")
        || s.contains("storebot-google")
        || s.contains("google-extended")
        || s.contains("mediapartners-google")
        || s.contains("adsbot-google")
        || s.contains("feedfetcher-google")
    {
        return Some(KnownBot::Googlebot);
    }

    // Bingbot variants
    if s.contains("bingbot")
        || s.contains("msnbot")
        || s.contains("adidxbot")
        || s.contains("bingpreview")
    {
        return Some(KnownBot::Bingbot);
    }

    // Applebot
    if s.contains("applebot") {
        return Some(KnownBot::Applebot);
    }

    // Cloudflare crawler
    if s.contains("cloudflare-alwaysonline") {
        return Some(KnownBot::Cloudflare);
    }

    // Yandex
    if s.contains("yandexbot") || s.contains("yandeximages") || s.contains("yandexmobilebot") {
        return Some(KnownBot::Yandex);
    }

    // DuckDuckGo
    if s.contains("duckduckbot") {
        return Some(KnownBot::DuckDuckGo);
    }

    None
}

/// Bot verification state for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BotVerificationResult {
    /// Crawler identity if User-Agent claims to be a recognized crawler.
    pub bot: Option<KnownBot>,
    /// Whether the client IP matches the verified ranges for this crawler.
    /// None if User-Agent is not a crawler.
    /// Some(true) if IP matches official crawler CIDRs.
    /// Some(false) if IP is spoofed/unverified.
    pub verified: Option<bool>,
}

impl BotVerificationResult {
    /// Returns the verified state as string bytes: b"true", b"false", or b"".
    pub fn verified_bytes(&self) -> &'static [u8] {
        match self.verified {
            Some(true) => b"true",
            Some(false) => b"false",
            None => b"",
        }
    }

    /// Returns the bot name as string bytes, or empty if none.
    pub fn bot_name_bytes(&self) -> &'static [u8] {
        match self.bot {
            Some(b) => b.as_str().as_bytes(),
            None => b"",
        }
    }
}

/// CIDR Range intervals for binary search lookup.
#[derive(Clone, Debug, Default)]
pub struct BotIpRanges {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl BotIpRanges {
    pub fn is_match(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let x = u32::from(*v4);
                self.v4
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
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    let x = u32::from(v4);
                    return self
                        .v4
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
                let x = u128::from(*v6);
                self.v6
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
        }
    }

    pub fn add_v4_cidr(&mut self, base: Ipv4Addr, prefix: u8) {
        if prefix > 32 {
            return;
        }
        let num = u32::from(base);
        let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
        let start = num & mask;
        let end = start | !mask;
        self.v4.push((start, end));
    }

    pub fn add_v6_cidr(&mut self, base: Ipv6Addr, prefix: u8) {
        if prefix > 128 {
            return;
        }
        let num = u128::from(base);
        let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
        let start = num & mask;
        let end = start | !mask;
        self.v6.push((start, end));
    }

    pub fn sort_and_merge(&mut self) {
        if !self.v4.is_empty() {
            self.v4.sort_unstable_by_key(|&(s, _)| s);
            let mut merged = Vec::with_capacity(self.v4.len());
            let (mut cur_start, mut cur_end) = self.v4[0];
            for &(s, e) in &self.v4[1..] {
                if s <= cur_end.saturating_add(1) {
                    cur_end = cur_end.max(e);
                } else {
                    merged.push((cur_start, cur_end));
                    cur_start = s;
                    cur_end = e;
                }
            }
            merged.push((cur_start, cur_end));
            self.v4 = merged;
        }

        if !self.v6.is_empty() {
            self.v6.sort_unstable_by_key(|&(s, _)| s);
            let mut merged = Vec::with_capacity(self.v6.len());
            let (mut cur_start, mut cur_end) = self.v6[0];
            for &(s, e) in &self.v6[1..] {
                if s <= cur_end.saturating_add(1) {
                    cur_end = cur_end.max(e);
                } else {
                    merged.push((cur_start, cur_end));
                    cur_start = s;
                    cur_end = e;
                }
            }
            merged.push((cur_start, cur_end));
            self.v6 = merged;
        }
    }
}

/// Complete verified bot lookup table for all major crawlers.
#[derive(Clone, Debug)]
pub struct BotVerifier {
    google: BotIpRanges,
    bing: BotIpRanges,
    apple: BotIpRanges,
    cloudflare: BotIpRanges,
    yandex: BotIpRanges,
    duckduckgo: BotIpRanges,
}

impl Default for BotVerifier {
    fn default() -> Self {
        let mut google = BotIpRanges::default();
        // Official Googlebot CIDRs
        google.add_v4_cidr(Ipv4Addr::new(66, 249, 64, 0), 19);
        google.add_v4_cidr(Ipv4Addr::new(64, 233, 160, 0), 19);
        google.add_v4_cidr(Ipv4Addr::new(66, 102, 0, 0), 20);
        google.add_v4_cidr(Ipv4Addr::new(72, 14, 192, 0), 18);
        google.add_v4_cidr(Ipv4Addr::new(74, 125, 0, 0), 16);
        google.add_v4_cidr(Ipv4Addr::new(209, 85, 128, 0), 17);
        google.add_v4_cidr(Ipv4Addr::new(216, 239, 32, 0), 19);
        google.add_v4_cidr(Ipv4Addr::new(173, 194, 0, 0), 16);
        google.add_v4_cidr(Ipv4Addr::new(172, 217, 0, 0), 16);
        google.add_v4_cidr(Ipv4Addr::new(142, 250, 0, 0), 15);
        google.add_v6_cidr("2001:4860:4801::".parse().unwrap(), 48);
        google.add_v6_cidr("2001:4860:4802::".parse().unwrap(), 48);
        google.add_v6_cidr("2607:f8b0:4000::".parse().unwrap(), 36);
        google.sort_and_merge();

        let mut bing = BotIpRanges::default();
        // Official Bingbot CIDRs
        bing.add_v4_cidr(Ipv4Addr::new(157, 55, 39, 0), 24);
        bing.add_v4_cidr(Ipv4Addr::new(207, 46, 13, 0), 24);
        bing.add_v4_cidr(Ipv4Addr::new(40, 77, 167, 0), 24);
        bing.add_v4_cidr(Ipv4Addr::new(13, 66, 139, 0), 24);
        bing.add_v4_cidr(Ipv4Addr::new(13, 66, 144, 0), 24);
        bing.add_v4_cidr(Ipv4Addr::new(52, 167, 144, 0), 24);
        bing.add_v4_cidr(Ipv4Addr::new(157, 55, 16, 0), 20);
        bing.add_v4_cidr(Ipv4Addr::new(157, 55, 32, 0), 20);
        bing.add_v4_cidr(Ipv4Addr::new(157, 55, 48, 0), 20);
        bing.add_v4_cidr(Ipv4Addr::new(157, 55, 64, 0), 20);
        bing.add_v4_cidr(Ipv4Addr::new(40, 76, 0, 0), 14);
        bing.add_v4_cidr(Ipv4Addr::new(40, 80, 0, 0), 12);
        bing.add_v6_cidr("2a01:111:f400::".parse().unwrap(), 48);
        bing.add_v6_cidr("2603:1030::".parse().unwrap(), 32);
        bing.add_v6_cidr("2603:1040::".parse().unwrap(), 32);
        bing.sort_and_merge();

        let mut apple = BotIpRanges::default();
        apple.add_v4_cidr(Ipv4Addr::new(17, 0, 0, 0), 8);
        apple.sort_and_merge();

        let mut cloudflare = BotIpRanges::default();
        cloudflare.add_v4_cidr(Ipv4Addr::new(173, 245, 48, 0), 20);
        cloudflare.add_v4_cidr(Ipv4Addr::new(103, 21, 244, 0), 22);
        cloudflare.add_v4_cidr(Ipv4Addr::new(103, 22, 200, 0), 22);
        cloudflare.add_v4_cidr(Ipv4Addr::new(103, 31, 4, 0), 22);
        cloudflare.add_v4_cidr(Ipv4Addr::new(141, 101, 64, 0), 18);
        cloudflare.add_v4_cidr(Ipv4Addr::new(108, 162, 192, 0), 18);
        cloudflare.add_v4_cidr(Ipv4Addr::new(190, 93, 240, 0), 20);
        cloudflare.add_v4_cidr(Ipv4Addr::new(188, 114, 96, 0), 20);
        cloudflare.add_v4_cidr(Ipv4Addr::new(197, 234, 240, 0), 22);
        cloudflare.add_v4_cidr(Ipv4Addr::new(198, 41, 128, 0), 17);
        cloudflare.add_v4_cidr(Ipv4Addr::new(162, 158, 0, 0), 15);
        cloudflare.add_v4_cidr(Ipv4Addr::new(104, 16, 0, 0), 12);
        cloudflare.add_v4_cidr(Ipv4Addr::new(172, 64, 0, 0), 13);
        cloudflare.add_v4_cidr(Ipv4Addr::new(131, 0, 72, 0), 22);
        cloudflare.add_v6_cidr("2400:cb00::".parse().unwrap(), 32);
        cloudflare.add_v6_cidr("2606:4700::".parse().unwrap(), 32);
        cloudflare.add_v6_cidr("2803:f800::".parse().unwrap(), 32);
        cloudflare.sort_and_merge();

        let mut yandex = BotIpRanges::default();
        yandex.add_v4_cidr(Ipv4Addr::new(77, 88, 0, 0), 18);
        yandex.add_v4_cidr(Ipv4Addr::new(87, 250, 224, 0), 19);
        yandex.add_v4_cidr(Ipv4Addr::new(93, 158, 128, 0), 18);
        yandex.add_v4_cidr(Ipv4Addr::new(178, 154, 128, 0), 18);
        yandex.add_v4_cidr(Ipv4Addr::new(213, 180, 192, 0), 19);
        yandex.sort_and_merge();

        let mut duckduckgo = BotIpRanges::default();
        duckduckgo.add_v4_cidr(Ipv4Addr::new(50, 16, 241, 113), 32);
        duckduckgo.add_v4_cidr(Ipv4Addr::new(50, 16, 241, 114), 32);
        duckduckgo.add_v4_cidr(Ipv4Addr::new(50, 16, 241, 117), 32);
        duckduckgo.add_v4_cidr(Ipv4Addr::new(54, 208, 100, 253), 32);
        duckduckgo.add_v4_cidr(Ipv4Addr::new(54, 208, 102, 37), 32);
        duckduckgo.add_v4_cidr(Ipv4Addr::new(107, 21, 1, 8), 32);
        duckduckgo.sort_and_merge();

        Self {
            google,
            bing,
            apple,
            cloudflare,
            yandex,
            duckduckgo,
        }
    }
}

impl BotVerifier {
    /// Verifies whether a request from `client_ip` with `user_agent` is an authentic crawler.
    pub fn verify(&self, user_agent: &[u8], client_ip: &str) -> BotVerificationResult {
        let Some(bot) = identify_crawler_user_agent(user_agent) else {
            return BotVerificationResult {
                bot: None,
                verified: None,
            };
        };

        let Ok(ip) = client_ip.trim().parse::<IpAddr>() else {
            return BotVerificationResult {
                bot: Some(bot),
                verified: Some(false),
            };
        };

        let is_match = match bot {
            KnownBot::Googlebot => self.google.is_match(&ip),
            KnownBot::Bingbot => self.bing.is_match(&ip),
            KnownBot::Applebot => self.apple.is_match(&ip),
            KnownBot::Cloudflare => self.cloudflare.is_match(&ip),
            KnownBot::Yandex => self.yandex.is_match(&ip),
            KnownBot::DuckDuckGo => self.duckduckgo.is_match(&ip),
        };

        BotVerificationResult {
            bot: Some(bot),
            verified: Some(is_match),
        }
    }

    /// Loads additional/updated bot CIDRs from a bundle section `STRBOT1\0` (kind 11).
    pub fn parse_section(sec: &[u8]) -> Option<Self> {
        if sec.len() < 16 || &sec[..8] != BOT_SECTION_MAGIC {
            return None;
        }
        let version = u16::from_le_bytes([sec[8], sec[9]]);
        if version != BOT_FORMAT_VERSION {
            return None;
        }

        let mut verifier = Self::default();
        // Format: [magic 8B][version 2B][flags 2B][entry_count 4B]...
        let count = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
        let mut off = 16;
        for _ in 0..count {
            if off + 20 > sec.len() {
                break;
            }
            let bot_id = sec[off];
            let is_v6 = sec[off + 1] == 1;
            let prefix = sec[off + 2];
            let _reserved = sec[off + 3];
            off += 4;

            if is_v6 {
                if off + 16 > sec.len() {
                    break;
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&sec[off..off + 16]);
                off += 16;
                let v6 = Ipv6Addr::from(ip_bytes);
                match bot_id {
                    1 => verifier.google.add_v6_cidr(v6, prefix),
                    2 => verifier.bing.add_v6_cidr(v6, prefix),
                    3 => verifier.apple.add_v6_cidr(v6, prefix),
                    4 => verifier.cloudflare.add_v6_cidr(v6, prefix),
                    _ => {}
                }
            } else {
                if off + 4 > sec.len() {
                    break;
                }
                let mut ip_bytes = [0u8; 4];
                ip_bytes.copy_from_slice(&sec[off..off + 4]);
                off += 4;
                let v4 = Ipv4Addr::from(ip_bytes);
                match bot_id {
                    1 => verifier.google.add_v4_cidr(v4, prefix),
                    2 => verifier.bing.add_v4_cidr(v4, prefix),
                    3 => verifier.apple.add_v4_cidr(v4, prefix),
                    4 => verifier.cloudflare.add_v4_cidr(v4, prefix),
                    _ => {}
                }
            }
        }

        verifier.google.sort_and_merge();
        verifier.bing.sort_and_merge();
        verifier.apple.sort_and_merge();
        verifier.cloudflare.sort_and_merge();
        Some(verifier)
    }
}
