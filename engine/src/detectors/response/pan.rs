//! Payment card numbers (PAN, P-01 §1): 13 to 19 digits, groups separated
//! by at most one space or dash, not part of a longer digit run, the first
//! digit 2-6 (the issuer ranges of the card networks: a 13-digit Unix time
//! in milliseconds starts with 1), and a valid Luhn check digit. Rule
//! 600203, masked. Always masked in event snippets (PCI DSS: a stored PAN
//! must be unreadable); in response bodies with `data_guard: [pan]`.
#![forbid(unsafe_code)]

use super::digit;
use crate::guard::{Ctx, Hit, Matcher};

pub const RULE: u32 = 600_203;
const MIN: usize = 13;
const MAX: usize = 19;

fn separator(c: u8) -> bool {
    c == b' ' || c == b'-'
}

/// Luhn check over the digits of `run` (separators skipped).
fn luhn(run: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, c) in run.iter().rev().filter(|c| digit(**c)).enumerate() {
        let mut d = (c - b'0') as u32;
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum.is_multiple_of(10)
}

pub struct Pan;

impl Matcher for Pan {
    /// the longest number with a separator between every two digits, and
    /// one byte of context on each side
    fn max_len(&self) -> usize {
        MAX * 2 - 1 + 2
    }

    fn masks(&self) -> bool {
        true
    }

    fn find(&mut self, hay: &[u8], ctx: Ctx, out: &mut Vec<Hit>) {
        let mut i = 0;
        while i < hay.len() {
            if !digit(hay[i]) {
                i += 1;
                continue;
            }
            // a run: digits, with single separators between digits
            let start = i;
            let mut digits = 0;
            loop {
                while i < hay.len() && digit(hay[i]) {
                    i += 1;
                    digits += 1;
                }
                if i + 1 < hay.len() && separator(hay[i]) && digit(hay[i + 1]) {
                    i += 1;
                    continue;
                }
                break;
            }
            // complete: something follows that cannot continue it, or the
            // scan ends here (a trailing separator may be followed by digits
            // in the next chunk)
            let after_ok = if i < hay.len() {
                !(separator(hay[i]) && i + 1 == hay.len() && !ctx.end)
            } else {
                ctx.end
            };
            let before_ok = start > 0 || !ctx.before.is_some_and(digit);
            if (MIN..=MAX).contains(&digits)
                && after_ok
                && before_ok
                && (b'2'..=b'6').contains(&hay[start])
                && luhn(&hay[start..i])
            {
                out.push(Hit {
                    start,
                    end: i,
                    rule: RULE,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::{Guard, tests::run};

    fn mask(chunks: &[&[u8]]) -> (Vec<u8>, Vec<u32>) {
        let mut g = Guard::new(vec![Box::new(Pan)], true);
        let out = run(&mut g, chunks);
        (out, g.found().to_vec())
    }

    #[test]
    fn luhn_check() {
        assert!(luhn(b"4111111111111111"));
        assert!(luhn(b"4111 1111 1111 1111"));
        assert!(!luhn(b"4111111111111112"));
        assert!(luhn(b"378282246310005")); // Amex test number
        assert!(luhn(b"6011111111111117")); // Discover test number
    }

    #[test]
    fn masks_card_numbers() {
        for (body, want) in [
            (
                &br#"{"pan":"4111111111111111"}"#[..],
                &br#"{"pan":"****************"}"#[..],
            ),
            (
                b"card 4111 1111 1111 1111 ok",
                b"card ******************* ok",
            ),
            (b"card 5500-0000-0000-0004.", b"card *******************."),
            (b"amex 378282246310005", b"amex ***************"),
            (b"unionpay 6250941006528599", b"unionpay ****************"),
        ] {
            let (out, found) = mask(&[body]);
            assert_eq!(String::from_utf8_lossy(&out), String::from_utf8_lossy(want));
            assert_eq!(found, [RULE]);
        }
    }

    #[test]
    fn not_masked() {
        for body in [
            &b"4111111111111112"[..],  // Luhn fails
            b"1791907725413",          // a Unix time in ms, Luhn-valid: first digit 1
            b"41111111111111110",      // 17 digits, Luhn fails
            b"x41111111111111111111y", // 20 digits: longer than a PAN
            b"4111  1111 1111 1111",   // two separators: two runs
            b"411111111111",           // 12 digits
            b"order 9111111111111110", // Luhn-valid, first digit 9
            b"4111111111111111 22",    // the run goes on: 18 digits, Luhn fails
        ] {
            let (out, found) = mask(&[body]);
            assert_eq!(out, body, "{}", String::from_utf8_lossy(body));
            assert!(found.is_empty(), "{}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn every_split_point() {
        let body = b"pay 4111 1111 1111 1111 and 5500000000000004.";
        let want = b"pay ******************* and ****************.";
        for at in 0..=body.len() {
            let (out, found) = mask(&[&body[..at], &body[at..]]);
            assert_eq!(out, want, "split at {at}");
            assert_eq!(found, [RULE], "split at {at}");
        }
    }
}
