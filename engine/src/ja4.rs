//! JA4 TLS client fingerprint (RV-N-02), after the FoxIO specification
//! (`technical_details/JA4.md` of github.com/FoxIO-LLC/ja4):
//!
//! `<t|q><version><d|i><ciphers:02><extensions:02><alpn:2>_<b>_<c>`, where
//! `b` is the first 12 hex digits of SHA-256 over the sorted cipher suites
//! and `c` over the sorted extensions without SNI and ALPN, then `_` and the
//! signature algorithms in their original order. GREASE values (RFC 8701)
//! are ignored everywhere; the counts include SNI and ALPN.
//!
//! Input: one ClientHello handshake message (type byte, 24-bit length,
//! body), as OpenSSL's message callback gives it. Bounded parsing, no heap
//! allocation: lists longer than the fixed storage give no fingerprint.
#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// Length of a JA4 fingerprint.
pub const LEN: usize = 36;

const MAX_CIPHERS: usize = 256;
const MAX_EXTENSIONS: usize = 128;
const MAX_SIG_ALGS: usize = 128;

const EXT_SNI: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIG_ALGS: u16 = 0x000d;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// RFC 8701 GREASE: 0x0a0a, 0x1a1a ... 0xfafa.
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

/// Big-endian reader over a slice; every read is bounds checked.
struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.b.len() {
            return None;
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Fixed-capacity list of 16-bit values.
struct List<const N: usize> {
    v: [u16; N],
    n: usize,
}

impl<const N: usize> List<N> {
    fn new() -> Self {
        List { v: [0; N], n: 0 }
    }
    fn push(&mut self, x: u16) -> Option<()> {
        *self.v.get_mut(self.n)? = x;
        self.n += 1;
        Some(())
    }
    fn as_mut(&mut self) -> &mut [u16] {
        &mut self.v[..self.n]
    }
    fn as_ref(&self) -> &[u16] {
        &self.v[..self.n]
    }
}

/// Non-GREASE 16-bit values of `b` (an even number of bytes).
fn values<const N: usize>(b: &[u8], out: &mut List<N>) -> Option<()> {
    let (pairs, rest) = b.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    for &pair in pairs {
        let v = u16::from_be_bytes(pair);
        if !is_grease(v) {
            out.push(v)?;
        }
    }
    Some(())
}

/// Writes the JA4 fingerprint of ClientHello `hello` into `out`; `quic`
/// selects the `q` prefix. `None` if `hello` is not a well-formed
/// ClientHello or exceeds the fixed storage.
pub fn fingerprint(hello: &[u8], quic: bool, out: &mut [u8; LEN]) -> Option<()> {
    let mut r = Reader { b: hello };
    if r.u8()? != 1 {
        return None;
    }
    let len = r.take(3)?;
    let len = (len[0] as usize) << 16 | (len[1] as usize) << 8 | len[2] as usize;
    let mut r = Reader { b: r.take(len)? };
    let legacy_version = r.u16()?;
    r.take(32)?; // random
    r.vec8()?; // session id
    let mut ciphers = List::<MAX_CIPHERS>::new();
    values(r.vec16()?, &mut ciphers)?;
    r.vec8()?; // compression methods

    let mut extensions = List::<MAX_EXTENSIONS>::new();
    let mut sig_algs = List::<MAX_SIG_ALGS>::new();
    let mut version = legacy_version;
    let mut sni = false;
    let mut alpn: &[u8] = &[];
    if !r.b.is_empty() {
        let mut ext = Reader { b: r.vec16()? };
        while !ext.b.is_empty() {
            let kind = ext.u16()?;
            let data = ext.vec16()?;
            if is_grease(kind) {
                continue;
            }
            extensions.push(kind)?;
            let mut d = Reader { b: data };
            match kind {
                EXT_SNI => sni = true,
                EXT_ALPN => {
                    // first protocol of the list
                    let mut list = Reader { b: d.vec16()? };
                    alpn = list.vec8()?;
                }
                EXT_SIG_ALGS => values(d.vec16()?, &mut sig_algs)?,
                EXT_SUPPORTED_VERSIONS => {
                    let mut versions = List::<128>::new();
                    values(d.vec8()?, &mut versions)?;
                    if let Some(&v) = versions.as_ref().iter().max() {
                        version = v;
                    }
                }
                _ => {}
            }
        }
    }

    // section a
    out[0] = if quic { b'q' } else { b't' };
    out[1..3].copy_from_slice(match version {
        0x0304 => b"13",
        0x0303 => b"12",
        0x0302 => b"11",
        0x0301 => b"10",
        0x0300 => b"s3",
        0x0002 => b"s2",
        0xfeff => b"d1",
        0xfefd => b"d2",
        0xfefc => b"d3",
        _ => b"00",
    });
    out[3] = if sni { b'd' } else { b'i' };
    two_digits(ciphers.n, &mut out[4..6]);
    two_digits(extensions.n, &mut out[6..8]);
    alpn_chars(alpn, &mut out[8..10]);
    out[10] = b'_';

    // section b: sorted cipher suites
    let ciphers = ciphers.as_mut();
    ciphers.sort_unstable();
    hash12(&[ciphers], &mut out[11..23]);
    out[23] = b'_';

    // section c: sorted extensions without SNI and ALPN, then the signature
    // algorithms as sent
    let ext = extensions.as_mut();
    ext.sort_unstable();
    let mut kept = List::<MAX_EXTENSIONS>::new();
    for &e in ext.iter() {
        if e != EXT_SNI && e != EXT_ALPN {
            kept.push(e)?;
        }
    }
    hash12(&[kept.as_ref(), sig_algs.as_ref()], &mut out[24..36]);
    Some(())
}

fn two_digits(n: usize, out: &mut [u8]) {
    let n = n.min(99) as u8;
    out[0] = b'0' + n / 10;
    out[1] = b'0' + n % 10;
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// First and last character of the first ALPN value, or of its hex form
/// when one of them is not alphanumeric; "00" without ALPN.
fn alpn_chars(alpn: &[u8], out: &mut [u8]) {
    match (alpn.first(), alpn.last()) {
        (Some(&f), Some(&l)) if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() => {
            out[0] = f;
            out[1] = l;
        }
        (Some(&f), Some(&l)) => {
            out[0] = HEX[(f >> 4) as usize];
            out[1] = HEX[(l & 0x0f) as usize];
        }
        _ => out.copy_from_slice(b"00"),
    }
}

/// First 12 hex digits of SHA-256 over the lists, each value as 4 hex
/// digits joined by ',' and lists joined by '_' (an empty later list adds
/// nothing); "000000000000" when the first list is empty.
fn hash12(lists: &[&[u16]], out: &mut [u8]) {
    if lists[0].is_empty() {
        out.copy_from_slice(b"000000000000");
        return;
    }
    let mut h = Sha256::new();
    for (i, list) in lists.iter().enumerate() {
        if list.is_empty() {
            continue;
        }
        if i > 0 {
            h.update(b"_");
        }
        for (j, v) in list.iter().enumerate() {
            if j > 0 {
                h.update(b",");
            }
            let b = v.to_be_bytes();
            h.update([
                HEX[(b[0] >> 4) as usize],
                HEX[(b[0] & 15) as usize],
                HEX[(b[1] >> 4) as usize],
                HEX[(b[1] & 15) as usize],
            ]);
        }
    }
    let d = h.finalize();
    for (i, o) in out.iter_mut().enumerate() {
        let byte = d[i / 2];
        *o = HEX[if i % 2 == 0 { byte >> 4 } else { byte & 15 } as usize];
    }
}

/// A JA4 value as stored and matched: 36 bytes of `[0-9a-z_]`.
pub fn is_valid(b: &[u8]) -> bool {
    b.len() == LEN
        && b.iter()
            .all(|&c| c.is_ascii_digit() || c.is_ascii_lowercase() || c == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello from parts (extensions as (type, data)).
    fn hello(version: u16, ciphers: &[u16], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = version.to_be_bytes().to_vec();
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]);
        let mut e = vec![];
        for (t, d) in exts {
            e.extend_from_slice(&t.to_be_bytes());
            e.extend_from_slice(&(d.len() as u16).to_be_bytes());
            e.extend_from_slice(d);
        }
        body.extend_from_slice(&(e.len() as u16).to_be_bytes());
        body.extend_from_slice(&e);
        let mut h = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        h.extend_from_slice(&body);
        h
    }

    fn alpn(p: &[u8]) -> Vec<u8> {
        let mut v = ((p.len() + 1) as u16).to_be_bytes().to_vec();
        v.push(p.len() as u8);
        v.extend_from_slice(p);
        v
    }

    fn ja4(h: &[u8]) -> Option<String> {
        let mut out = [0; LEN];
        fingerprint(h, false, &mut out)?;
        Some(String::from_utf8(out.to_vec()).unwrap())
    }

    #[test]
    fn grease_values() {
        for v in [0x0a0a, 0x1a1a, 0x4a4a, 0xaaaa, 0xfafa] {
            assert!(is_grease(v), "{v:04x}");
        }
        for v in [0x0a1a, 0x1301, 0x002b, 0x0a0b, 0xaa0a] {
            assert!(!is_grease(v), "{v:04x}");
        }
    }

    #[test]
    fn counts_include_sni_and_alpn_and_skip_grease() {
        let h = hello(
            0x0303,
            &[0x0a0a, 0x1301, 0x1302],
            &[
                (0x2a2a, vec![]),
                (EXT_SNI, vec![0, 4, 0, 0, 1, b'x']),
                (EXT_ALPN, alpn(b"h2")),
                (EXT_SUPPORTED_VERSIONS, vec![4, 0x3a, 0x3a, 3, 4]),
                (EXT_SIG_ALGS, vec![0, 4, 0x5a, 0x5a, 4, 3]),
            ],
        );
        let s = ja4(&h).unwrap();
        assert!(s.starts_with("t13d0204h2_"), "{s}");
        // section c: extensions 000d,002b then the non-GREASE signature
        // algorithm
        let mut want = [0; 12];
        hash12(&[&[0x000d, 0x002b], &[0x0403]], &mut want);
        assert_eq!(&s.as_bytes()[24..], &want);
    }

    #[test]
    fn alpn_and_version_edge_cases() {
        let none = hello(0x0303, &[0x002f], &[]);
        assert_eq!(&ja4(&none).unwrap()[..11], "t12i010000_");
        let odd = hello(0x0303, &[0x002f], &[(EXT_ALPN, alpn(&[0xab, b'x', 0x01]))]);
        assert_eq!(&ja4(&odd).unwrap()[8..10], "a1");
        let old = hello(0x0301, &[], &[]);
        assert_eq!(ja4(&old).unwrap(), "t10i000000_000000000000_000000000000");
        let mut out = [0; LEN];
        fingerprint(&none, true, &mut out).unwrap();
        assert_eq!(out[0], b'q');
    }

    #[test]
    fn malformed_input_gives_no_fingerprint() {
        let good = hello(0x0303, &[0x1301], &[(EXT_ALPN, alpn(b"h2"))]);
        assert!(ja4(&good).is_some());
        for cut in 0..good.len() {
            assert!(ja4(&good[..cut]).is_none(), "cut {cut}");
        }
        let mut wrong = good.clone();
        wrong[0] = 2;
        assert!(ja4(&wrong).is_none());
        // odd cipher list length
        let mut odd = good.clone();
        odd[4 + 2 + 32 + 1 + 1] = 3;
        assert!(ja4(&odd).is_none());
        // more ciphers than the fixed storage
        let many: Vec<u16> = (1..=MAX_CIPHERS as u16 + 1).collect();
        assert!(ja4(&hello(0x0303, &many, &[])).is_none());
        let grease_only = hello(0x0303, &[0x0a0a; 300], &[]);
        assert!(ja4(&grease_only).is_some());
    }

    #[test]
    fn valid_values() {
        assert!(is_valid(b"t13d1516h2_8daaf6152771_02713d6af862"));
        assert!(!is_valid(b"t13d1516h2_8daaf6152771_02713d6af86"));
        assert!(!is_valid(b"T13d1516h2_8daaf6152771_02713d6af862"));
        assert!(!is_valid(b"t13d1516h2 8daaf6152771_02713d6af862"));
    }
}
