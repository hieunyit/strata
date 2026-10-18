use libstrata::{
    bundle,
    engine::Engine,
    tx::Tx,
    verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_LOG, OK},
};
use std::sync::Arc;
#[path = "common/staging_fixture.rs"]
mod fixture;

fn engine(ids: &[u32]) -> Arc<Engine> {
    Arc::new(
        Engine::map(
            Box::new(fixture::image(ids, !ids.is_empty())),
            &bundle::public_key(&[7; 32]),
        )
        .unwrap(),
    )
}
fn tx(engine: Arc<Engine>, policy: &[u8], value: &[u8]) -> Tx {
    let mut tx = Tx::new(Some(engine), b"example-node", 0);
    tx.set_policy(policy);
    assert_eq!(tx.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1"), OK);
    assert_eq!(tx.request_headers(&fixture::headers(value)), OK);
    tx
}
// Decode only protobuf wire types emitted by Event; no substring assertions.
fn int_field(mut bytes: &[u8], field: u64) -> u64 {
    fn varint(b: &mut &[u8]) -> u64 {
        let mut n = 0;
        for shift in (0..70).step_by(7) {
            let v = b[0];
            *b = &b[1..];
            n |= u64::from(v & 127) << shift;
            if v < 128 {
                return n;
            }
        }
        panic!("bad fixture varint")
    }
    while !bytes.is_empty() {
        let tag = varint(&mut bytes);
        match tag & 7 {
            0 => {
                let n = varint(&mut bytes);
                if tag >> 3 == field {
                    return n;
                }
            }
            2 => {
                let n = varint(&mut bytes) as usize;
                bytes = &bytes[n..]
            }
            _ => panic!("bad fixture wire type"),
        }
    }
    0
}
#[test]
fn staging_keeps_detection_logs_and_other_policy_enforcement() {
    let e = engine(&[700011, 700013]);
    for (policy, value, action, score, would) in [
        (
            b"example-api".as_slice(),
            b"first".as_slice(),
            ACTION_LOG,
            0,
            0,
        ),
        (b"example-api", b"first second", ACTION_LOG, 60, 1),
        (b"example-api", b"alone", ACTION_LOG, 0, 1),
        (b"example-api", b"alone second", ACTION_LOG, 60, 1),
        (b"example-web", b"first second", ACTION_BLOCK, 120, 1),
        (b"example-web", b"alone", ACTION_BLOCK, 0, 1),
        (b"example-api", b"clean", ACTION_ALLOW, 0, 0),
    ] {
        let tx = tx(e.clone(), policy, value);
        let v = tx.verdict();
        assert_eq!((v.action, v.score), (action, score));
        if action != ACTION_ALLOW {
            assert!(v.n_rules > 0);
            assert!(v.id.unwrap().starts_with(if action == ACTION_BLOCK {
                b"STR-"
            } else {
                b"EVT-"
            }));
            let ev = tx.encode_event().expect("matched rule must log");
            assert_eq!(int_field(&ev, 21), would);
        }
    }
    let max = fixture::patch_rule(fixture::image(&[700011], true), 0, 8, 1000);
    let max = Arc::new(Engine::map(Box::new(max), &bundle::public_key(&[7; 32])).unwrap());
    let max = tx(max, b"example-api", b"first");
    assert_eq!((max.verdict().action, max.verdict().score), (ACTION_LOG, 0));
    assert_eq!(int_field(&max.encode_event().unwrap(), 21), 1);
    // The unrelated blocking rule still blocks after a staged match; staging
    // cannot short-circuit evaluation of subsequent rules.
    let t = tx(engine(&[700011]), b"example-api", b"first alone");
    assert_eq!(t.verdict().action, ACTION_BLOCK);
    let mut t = tx(e.clone(), b"example-api", b"first");
    t.set_budget_exceeded();
    assert!(!t.verdict().fail_closed);
    let mut t = tx(e, b"example-api", b"first second");
    t.set_budget_exceeded();
    assert!(t.verdict().fail_closed);
}
#[test]
fn invalid_staging_membership_and_flag_pairs_reject_bundle() {
    for (ids, flag) in [
        (&[42][..], true),
        (&[100020][..], true),
        (&[700011][..], false),
        (&[][..], true),
    ] {
        assert!(
            Engine::map(
                Box::new(fixture::image(ids, flag)),
                &bundle::public_key(&[7; 32])
            )
            .is_err()
        );
    }
    for (layer, stage) in [
        ("protocol", "request_headers"),
        ("managed", "response_body"),
    ] {
        // Without an overlay the tables are valid: rejection must be the staging
        // request-layer/type restriction, not unrelated bundle corruption.
        assert!(
            Engine::map(
                Box::new(fixture::image_with_kind(&[], false, layer, stage)),
                &bundle::public_key(&[7; 32])
            )
            .is_ok()
        );
        assert!(
            Engine::map(
                Box::new(fixture::image_with_kind(&[700011], true, layer, stage)),
                &bundle::public_key(&[7; 32])
            )
            .is_err()
        );
    }
    for (index, offset, value) in [(0, 8, u32::MAX), (0, 8, 1001), (1, 0, 700011)] {
        let bytes = fixture::patch_rule(fixture::image(&[700011], true), index, offset, value);
        assert!(
            Engine::map(Box::new(bytes), &bundle::public_key(&[7; 32])).is_err(),
            "ambiguous or invalid rule accepted for staging"
        );
    }
}
