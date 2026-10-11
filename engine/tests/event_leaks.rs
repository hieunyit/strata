use std::sync::Arc;

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use libstrata::engine::Engine;
use libstrata::tx::Tx;

/// A NUL in a Cookie header raises 100013; the cookie value must not be in the event.
#[test]
fn cookie_with_nul_is_not_in_the_event() {
    let p = PolicySpec::new("example-api", Mode::Enforce, Oversize::Pass);
    let spec = Spec {
        version: 1,
        created_at_ms: 0,
        flags: 0,
        policies: &[p],
        sections: &[],
    };
    let b = build(&spec, &[3; 32]).unwrap();
    let e = Arc::new(Engine::map(Box::new(b), &public_key(&[3; 32])).unwrap());
    let mut t = Tx::new(Some(e), b"node", 0);
    t.set_policy(b"example-api");
    let _ = t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1");
    let _ = t.request_headers(&[(b"Host", b"a"), (b"Cookie", b"session=SECRETSESSION\x00x")]);
    let ev = t
        .encode_event()
        .expect("a NUL in a header blocks, so there is an event");
    assert!(
        !ev.windows(13).any(|w| w == b"SECRETSESSION"),
        "cookie value present in the event"
    );
}

/// A CTL in an Authorization header raises 100014; the token value must not be in the event.
#[test]
fn authorization_header_with_ctl_is_not_in_the_event() {
    let p = PolicySpec::new("example-api", Mode::Enforce, Oversize::Pass);
    let spec = Spec {
        version: 1,
        created_at_ms: 0,
        flags: 0,
        policies: &[p],
        sections: &[],
    };
    let b = build(&spec, &[3; 32]).unwrap();
    let e = Arc::new(Engine::map(Box::new(b), &public_key(&[3; 32])).unwrap());
    let mut t = Tx::new(Some(e), b"node", 0);
    t.set_policy(b"example-api");
    let _ = t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1");
    let _ = t.request_headers(&[
        (b"Host", b"a"),
        (b"Content-Length", b"bad"),
        (b"Authorization", b"Bearer abc\x01def"),
    ]);
    let ev = t.encode_event().expect("a blocked request has an event");
    assert!(
        !ev.windows(3).any(|w| w == b"abc"),
        "authorization token present in the event"
    );
}
