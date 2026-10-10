//! Vietnamese citizen ID numbers (CCCD): exactly 12 digits, not part of a
//! longer digit run, the first three a province code and the fourth the
//! century/sex digit (0-3: born 1900-2099). Rule 600201, masked.
#![forbid(unsafe_code)]

use super::digit;
use crate::guard::{Ctx, Hit, Matcher};

pub const RULE: u32 = 600_201;
const LEN: usize = 12;

/// Province codes of the citizen ID (Circular 07/2016/TT-BCA).
const PROVINCES: &[u16] = &[
    1, 2, 4, 6, 8, 10, 11, 12, 14, 15, 17, 19, 20, 22, 24, 25, 26, 27, 30, 31, 33, 34, 35, 36, 37,
    38, 40, 42, 44, 45, 46, 48, 49, 51, 52, 54, 56, 58, 60, 62, 64, 66, 67, 68, 70, 72, 74, 75, 77,
    79, 80, 82, 83, 84, 86, 87, 89, 91, 92, 93, 94, 95, 96,
];

fn valid(d: &[u8]) -> bool {
    let n = |i: usize| (d[i] - b'0') as u16;
    PROVINCES.contains(&(n(0) * 100 + n(1) * 10 + n(2))) && n(3) <= 3
}

pub struct Cccd;

impl Matcher for Cccd {
    /// the digits and one byte of context on each side
    fn max_len(&self) -> usize {
        LEN + 2
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
            let start = i;
            while i < hay.len() && digit(hay[i]) {
                i += 1;
            }
            let after_ok = i < hay.len() || ctx.end;
            let before_ok = start > 0 || !ctx.before.is_some_and(digit);
            if i - start == LEN && after_ok && before_ok && valid(&hay[start..i]) {
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
    use crate::guard::{Feed, Guard, tests::run};

    fn mask(chunks: &[&[u8]]) -> (Vec<u8>, Vec<u32>) {
        let mut g = Guard::new(vec![Box::new(Cccd)], true);
        let out = run(&mut g, chunks);
        (out, g.found().to_vec())
    }

    #[test]
    fn masks_in_json() {
        let (out, found) = mask(&[br#"{"cccd":"001203012345","n":1}"#]);
        assert_eq!(out, br#"{"cccd":"************","n":1}"#);
        assert_eq!(found, [RULE]);
    }

    #[test]
    fn every_split_point() {
        let body = b"id 079099001122, 001203012345.";
        for s in 0..=body.len() {
            let (out, _) = mask(&[&body[..s], &body[s..]]);
            assert_eq!(out, b"id ************, ************.", "{s}");
        }
    }

    #[test]
    fn not_masked() {
        for body in [
            &b"1700000000123"[..],  // 13 digits (ms timestamp)
            b"00120301234",         // 11 digits
            b"003203012345",        // province 003 does not exist
            b"001503012345",        // century digit 5
            b"order 9999203012345", // longer run
        ] {
            let (out, found) = mask(&[body]);
            assert_eq!(out, body);
            assert!(found.is_empty(), "{:?}", body.escape_ascii().to_string());
        }
    }

    #[test]
    fn longer_run_split_across_chunks_is_not_masked() {
        // 13 digits, the first one emitted with the first chunk
        let body = b"x 0001203012345 y";
        for s in 0..=body.len() {
            let (out, _) = mask(&[&body[..s], &body[s..]]);
            assert_eq!(out, body, "{s}");
        }
    }

    #[test]
    fn end_of_stream_is_a_boundary() {
        let mut g = Guard::new(vec![Box::new(Cccd)], true);
        assert_eq!(g.chunk(b"001203012345", Feed::More).unwrap(), b"");
        assert_eq!(g.chunk(b"", Feed::Last).unwrap(), b"************");
    }
}
