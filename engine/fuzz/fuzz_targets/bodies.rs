//! Body parsers (multipart, JSON, XML) on any input: never panic, stay
//! within their bounds, return slices of the body.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libstrata::{json, multipart, xml};

fuzz_target!(|data: &[u8]| {
    // first byte: boundary length; then the boundary, then the body
    let (b_len, rest) = match data.split_first() {
        Some((n, r)) => ((*n as usize % 80).min(r.len()), r),
        None => return,
    };
    let (boundary, body) = rest.split_at(b_len);

    if !boundary.is_empty() {
        let range = body.as_ptr_range();
        let parts = multipart::parts(body, boundary);
        assert!(parts.len() <= multipart::MAX_PARTS);
        for p in &parts {
            for s in [p.name, p.content].into_iter().chain(p.filename) {
                let r = s.as_ptr_range();
                assert!(s.is_empty() || (r.start >= range.start && r.end <= range.end));
            }
        }
    }
    let _ = multipart::boundary(rest);

    let args = json::args(rest, 1024);
    assert!(args.len() <= 1024);
    for (name, _) in &args {
        assert!(name.starts_with(b"json"));
    }
    let _ = json::is_json(rest);

    let x = xml::parse(rest);
    assert!(x.attrs.len() <= xml::MAX_ATTRS);
    // decoding never makes text longer than its source
    assert!(x.text.len() <= rest.len());
    assert!(x.attrs.iter().map(Vec::len).sum::<usize>() <= rest.len());
    let _ = xml::is_xml(rest);
});
