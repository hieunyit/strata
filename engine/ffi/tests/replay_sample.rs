//! W12-N-01: replay samples through the C ABI (1.5). A sampled transaction
//! gives one datagram (SAMPLE_MAGIC + event.proto ReplaySample) anonymized
//! with the group's key: no original sensitive value survives, attack
//! payloads do. The rate is a share of transactions; 0 switches it off.

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use libstrata::privacy::PrivacySpec;
use strata::abi::*;
use strata::ffi::*;

const SEED: [u8; 32] = [8; 32];
const KEY: [u8; 32] = [0x5a; 32];

fn s(b: &[u8]) -> strata_str_t {
    strata_str_t {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn engine() -> *mut EngineHandle {
    engine_with(&[])
}

/// The engine with privacy settings for example-api (P-01 §1), if any.
fn engine_with(fields_patterns: &[(&[&str], &[&str])]) -> *mut EngineHandle {
    let privacy: Vec<PrivacySpec> = fields_patterns
        .iter()
        .map(|(f, p)| PrivacySpec {
            policy_index: 0,
            sensitive_fields: f.iter().map(|s| s.to_string()).collect(),
            mask_patterns: p.iter().map(|s| s.to_string()).collect(),
            identity_hmac: false,
        })
        .collect();
    let section = libstrata::privacy::encode(&privacy, None).unwrap();
    let policies = [PolicySpec {
        privacy: !privacy.is_empty(),
        ..PolicySpec::new("example-api", Mode::Enforce, Oversize::Pass)
    }];
    let sections = [(libstrata::bundle::kind::PRIVACY, &section[..])];
    let spec = Spec {
        version: 3,
        created_at_ms: 0,
        flags: 0,
        policies: &policies,
        sections: if privacy.is_empty() { &[] } else { &sections },
    };
    // libstrata does not copy the bundle: it must outlive the engine
    let bundle: &[u8] = Box::leak(build(&spec, &SEED).unwrap().into_boxed_slice());
    let mut err = strata_err_t {
        code: 0,
        msg: [0; 256],
    };
    let e = unsafe {
        strata_engine_map(
            bundle.as_ptr(),
            bundle.len(),
            public_key(&SEED).as_ptr(),
            &mut err,
        )
    };
    assert!(!e.is_null());
    e
}

const BODY: &[u8] = br#"{"cccd":"001099012345","name":"Nguyen Van A","phone":"0912345678","q":"' UNION SELECT 1--","n":42}"#;

/// One request through a transaction; its sample, if any.
fn request(e: *mut EngineHandle, uri: &[u8]) -> Option<Vec<u8>> {
    let conn = strata_conn_t {
        client_addr: s(b"198.51.100.7"),
        client_port: 40000,
        _reserved: 0,
        flags: 0,
        node_id: s(b"edge-01"),
        identity: s(b""),
        request_id: s(b""),
    };
    let headers = [
        (&b"Host"[..], &b"api.example.test"[..]),
        (
            b"Authorization",
            b"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",
        ),
        (b"Cookie", b"sid=s3cr3t; theme=dark"),
        (b"X-Forwarded-For", b"203.0.113.9"),
        (b"User-Agent", b"sqlmap/1.8"),
        (b"Content-Type", b"application/json"),
    ];
    let hs: Vec<strata_str_pair_t> = headers
        .iter()
        .map(|(k, v)| strata_str_pair_t {
            key: s(k),
            val: s(v),
        })
        .collect();
    unsafe {
        let tx = strata_tx_new(e, s(b"example-api"), &conn, 0);
        let (path, args) = match uri.iter().position(|&c| c == b'?') {
            Some(i) => (&uri[..i], &uri[i + 1..]),
            None => (uri, &b""[..]),
        };
        strata_tx_request_line(tx, s(b"POST"), s(uri), s(path), s(args), s(b"HTTP/1.1"));
        strata_tx_request_headers(tx, hs.as_ptr(), hs.len());
        strata_tx_request_body_chunk(tx, BODY.as_ptr(), BODY.len(), 1);
        let mut v = std::mem::zeroed::<strata_verdict_t>();
        strata_tx_verdict(tx, &mut v);
        let mut buf = vec![0u8; 8192];
        let mut n = strata_tx_sample(tx, buf.as_mut_ptr(), buf.len());
        // without a sample, the call may carry the per-policy counts
        // instead (RV-N-01, tests/policy_counters.rs): not a sample
        if buf[..n].starts_with(b"\xffSC1") {
            n = 0;
        }
        assert_eq!(
            strata_tx_sample(tx, std::ptr::null_mut(), 0),
            n,
            "length without a buffer"
        );
        strata_tx_free(tx);
        (n > 0).then(|| {
            buf.truncate(n);
            buf
        })
    }
}

/// field number -> value of a flat protobuf message
fn fields(mut b: &[u8]) -> std::collections::HashMap<u32, Vec<u8>> {
    let varint = |b: &mut &[u8]| {
        let (mut v, mut sh) = (0u64, 0);
        loop {
            let c = b[0];
            *b = &b[1..];
            v |= u64::from(c & 0x7f) << sh;
            sh += 7;
            if c < 0x80 {
                return v;
            }
        }
    };
    let mut m = std::collections::HashMap::new();
    while !b.is_empty() {
        let tag = varint(&mut b);
        let (f, wt) = ((tag >> 3) as u32, tag & 7);
        if wt == 0 {
            m.insert(f, varint(&mut b).to_string().into_bytes());
        } else {
            let n = varint(&mut b) as usize;
            m.insert(f, b[..n].to_vec());
            b = &b[n..];
        }
    }
    m
}

#[test]
fn a_sampled_request_is_anonymized() {
    let e = engine();
    assert_eq!(strata_abi_version(), (1 << 16) | 7);
    // off by default
    assert!(request(e, b"/v1/verify").is_none());
    assert_eq!(
        unsafe { strata_engine_set_replay(e, s(b"grp-edge-1"), KEY.as_ptr(), 32, 10_000) },
        STRATA_OK
    );
    let d = request(
        e,
        b"/v1/verify?user=alice%40example.test&q=1%27%20OR%201%3D1&token=abc123",
    )
    .expect("sampled");
    assert!(d.len() <= 8192);
    assert_eq!(&d[..4], b"\xffSR1");
    let f = fields(&d[4..]);
    let str_of = |n: u32| String::from_utf8_lossy(&f[&n]).into_owned();
    assert_eq!(
        (str_of(1), str_of(3), str_of(4), str_of(5), str_of(9)),
        (
            "grp-edge-1".into(),
            "edge-01".into(),
            "example-api".into(),
            "POST".into(),
            "HTTP/1.1".into()
        )
    );
    assert!(
        str_of(10).starts_with("~h:") && str_of(10).ends_with(":s12"),
        "client {}",
        str_of(10)
    );
    assert_eq!(str_of(13), BODY.len().to_string());
    assert_eq!(str_of(18), "3"); // bundle version
    let all = String::from_utf8_lossy(&d).into_owned();
    for secret in [
        "alice@example.test",
        "alice%40example.test",
        "abc123",
        "eyJhbGciOiJIUzI1NiJ9",
        "s3cr3t",
        "203.0.113.9",
        "198.51.100.7",
        "001099012345",
        "0912345678",
        "Nguyen Van A",
    ] {
        assert!(!all.contains(secret), "{secret} survived: {all}");
    }
    // what rules need is still there
    for kept in [
        "' UNION SELECT 1--",
        "q=1%27%20OR%201%3D1",
        "sqlmap/1.8",
        "theme=~h:",
        "Bearer ~h:",
    ] {
        assert!(all.contains(kept), "{kept} lost: {all}");
    }
    // the same key gives the same token: the controller can join samples
    let d2 = request(e, b"/v1/verify?user=alice%40example.test").unwrap();
    assert_eq!(fields(&d2[4..])[&10], f[&10]);

    // 1%: about 1 in 100
    assert_eq!(
        unsafe { strata_engine_set_replay(e, s(b"grp-edge-1"), KEY.as_ptr(), 32, 100) },
        STRATA_OK
    );
    let n = (0..20_000).filter(|_| request(e, b"/x").is_some()).count();
    assert!((120..280).contains(&n), "1% sampled {n}/20000");
    // off again
    assert_eq!(
        unsafe { strata_engine_set_replay(e, s(b""), std::ptr::null(), 0, 0) },
        STRATA_OK
    );
    assert!(request(e, b"/x").is_none());
    unsafe { strata_engine_release(e) };
}

#[test]
fn bad_arguments_keep_the_setting() {
    let e = engine();
    assert_eq!(
        unsafe { strata_engine_set_replay(e, s(b"k1"), KEY.as_ptr(), 32, 10_000) },
        STRATA_OK
    );
    for (id, key, len, rate) in [
        (&b"k1"[..], KEY.as_ptr(), 31, 10_000),
        (b"k1", std::ptr::null(), 32, 10_000),
        (b"k1", KEY.as_ptr(), 32, 10_001),
        (b"", KEY.as_ptr(), 32, 10_000),
        (b"bad id", KEY.as_ptr(), 32, 10_000),
        (b"a-key-id-longer-than-16", KEY.as_ptr(), 32, 10_000),
    ] {
        assert_eq!(
            unsafe { strata_engine_set_replay(e, s(id), key, len, rate) },
            STRATA_E_INVALID,
            "{id:?} {len} {rate}"
        );
    }
    assert_eq!(
        unsafe { strata_engine_set_replay(std::ptr::null(), s(b"k1"), KEY.as_ptr(), 32, 1) },
        STRATA_E_INVALID
    );
    let d = request(e, b"/x").expect("the setting in force is kept");
    assert_eq!(&fields(&d[4..])[&1], b"k1");
    assert_eq!(
        unsafe { strata_tx_sample(std::ptr::null(), std::ptr::null_mut(), 0) },
        0
    );
    unsafe { strata_engine_release(e) };
}

// A body that grows past the datagram once anonymized: the body kept
// shrinks, the sample still goes.
#[test]
fn the_sample_fits_one_datagram() {
    let e = engine();
    assert_eq!(
        unsafe { strata_engine_set_replay(e, s(b"k1"), KEY.as_ptr(), 32, 10_000) },
        STRATA_OK
    );
    let conn = strata_conn_t {
        client_addr: s(b"198.51.100.7"),
        client_port: 1,
        _reserved: 0,
        flags: 0,
        node_id: s(b"edge-01"),
        identity: s(b""),
        request_id: s(b""),
    };
    let body: Vec<u8> = (0..800).flat_map(|_| *b"0912345678 ").collect(); // every phone becomes a 23-byte token
    unsafe {
        let tx = strata_tx_new(e, s(b"example-api"), &conn, 0);
        strata_tx_request_line(tx, s(b"POST"), s(b"/f"), s(b"/f"), s(b""), s(b"HTTP/1.1"));
        let hs = [strata_str_pair_t {
            key: s(b"Content-Type"),
            val: s(b"text/plain"),
        }];
        strata_tx_request_headers(tx, hs.as_ptr(), 1);
        strata_tx_request_body_chunk(tx, body.as_ptr(), body.len(), 1);
        let mut buf = vec![0u8; 8192];
        let n = strata_tx_sample(tx, buf.as_mut_ptr(), buf.len());
        strata_tx_free(tx);
        assert!(n > 0 && n <= 8192, "{n}");
        let f = fields(&buf[4..n]);
        assert_eq!(f[&13], body.len().to_string().into_bytes());
        assert_eq!(f[&14], b"1"); // truncated
        assert!(f[&12].len() < 8192 && !String::from_utf8_lossy(&f[&12]).contains("0912345678"));
    }
    unsafe { strata_engine_release(e) };
}

/// #75: the policy's `privacy.sensitive_fields` and `mask_patterns` apply to
/// samples as to events: a value the built-in lists do not know becomes a
/// token. The same request without the settings keeps it.
#[test]
fn the_policy_privacy_settings_apply_to_samples() {
    let uri = b"/v1/orders?ma_khach_hang=C0012345&ref=KH12345678&q=1%27%20OR%201%3D1";
    let sample = |e: *mut EngineHandle| {
        assert_eq!(
            unsafe { strata_engine_set_replay(e, s(b"grp-edge-1"), KEY.as_ptr(), 32, 10_000) },
            STRATA_OK
        );
        let d = request(e, uri).expect("sampled");
        unsafe { strata_engine_release(e) };
        String::from_utf8_lossy(&d).into_owned()
    };
    let plain = sample(engine());
    assert!(
        plain.contains("C0012345") && plain.contains("KH12345678"),
        "{plain}"
    );
    let private = sample(engine_with(&[(&["MA_KHACH_HANG"], &["KH[0-9]{8}"])]));
    for secret in ["C0012345", "KH12345678"] {
        assert!(!private.contains(secret), "{secret} in {private}");
    }
    // names and attack payloads stay
    assert!(private.contains("ma_khach_hang=~h%3A"), "{private}");
    assert!(private.contains("ref=~h%3A"), "{private}");
    assert!(private.contains("1%27%20OR%201%3D1"), "{private}");
}
