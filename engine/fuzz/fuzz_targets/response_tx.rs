//! A transaction driven like a connector with arbitrary status, headers
//! and chunks: never panics, the bytes sent add up to the body length.
#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use libstrata::bundle::{Mode, Oversize, PolicySpec, Response, Spec, build, public_key};
use libstrata::engine::Engine;
use libstrata::tx::Tx;

fn engine() -> Arc<Engine> {
    static E: OnceLock<Arc<Engine>> = OnceLock::new();
    E.get_or_init(|| {
        let p = PolicySpec {
            response: Response(Response::ALL),
            ..PolicySpec::new("example-guard", Mode::Enforce, Oversize::Pass)
        };
        let spec = Spec { version: 1, created_at_ms: 0, flags: 0, policies: &[p], sections: &[] };
        let b = build(&spec, &[1; 32]).unwrap();
        Arc::new(Engine::map(Box::new(b), &public_key(&[1; 32])).unwrap())
    })
    .clone()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let status = u16::from_le_bytes([data[0], data[1]]);
    let shadow = if data[2] & 1 != 0 { libstrata::verdict::TXF_FORCE_SHADOW } else { 0 };
    let step = 1 + data[3] as usize % 64;
    let body = &data[4..];

    let mut t = Tx::new(Some(engine()), b"web-01", shadow);
    t.set_policy(b"example-guard");
    t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1");
    t.request_headers(&[(b"Accept", b"application/json")]);
    t.request_body_chunk(b"", true);
    t.response_headers(status);

    let mut sent = 0;
    let chunks: Vec<&[u8]> = body.chunks(step).collect();
    for (i, c) in chunks.iter().enumerate() {
        let (_, out) = t.response_body_chunk(c, i + 1 == chunks.len());
        sent += out.map_or(c.len(), |o| o.len());
        if i % 3 == 2 {
            sent += t.response_body_flush().1.map_or(0, |o| o.len());
        }
    }
    if chunks.is_empty() {
        sent += t.response_body_chunk(b"", true).1.map_or(0, |o| o.len());
    }
    assert_eq!(sent, body.len());
    let _ = t.verdict();
});
