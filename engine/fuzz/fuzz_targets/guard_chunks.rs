//! Data guard: however the body is cut into chunks (and flushed), the
//! output has the same length, and without flushes it equals the output of
//! a single chunk.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libstrata::detectors::response::{cccd::Cccd, db_errors::DbErrors, jwt::Jwt};
use libstrata::guard::{Feed, Guard, Matcher};

fn guard() -> Guard {
    let m: Vec<Box<dyn Matcher>> = vec![Box::new(Cccd), Box::new(Jwt::new()), Box::new(DbErrors)];
    Guard::new(m, true)
}

fuzz_target!(|data: &[u8]| {
    // first byte: cut sizes seed; second: flush every n-th chunk (0: never)
    if data.len() < 2 {
        return;
    }
    let (seed, flush_every, body) = (data[0] as usize, data[1] as usize % 4, &data[2..]);

    let mut whole = guard();
    let once = whole.chunk(body, Feed::Last).unwrap();
    assert_eq!(once.len(), body.len());

    let mut g = guard();
    let mut out = vec![];
    let (mut i, mut k) = (0, 0);
    while i < body.len() {
        let n = 1 + (seed * 31 + k * 17) % 97;
        let end = (i + n).min(body.len());
        k += 1;
        let feed = if flush_every != 0 && k % flush_every == 0 { Feed::Flush } else { Feed::More };
        out.extend(g.chunk(&body[i..end], feed).unwrap());
        i = end;
    }
    out.extend(g.chunk(&[], Feed::Last).unwrap());
    assert_eq!(out.len(), body.len());
    if flush_every == 0 {
        assert_eq!(out, once);
    }
});
