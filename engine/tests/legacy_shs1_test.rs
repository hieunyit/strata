use libstrata::engine::Engine;
use libstrata::tx::Tx;
use std::sync::Arc;

#[test]
fn loads_legacy_shs1_bundle() {
    let bundle_bytes = include_bytes!("fixtures/legacy_shs1.sbn");
    let pub_key = include_bytes!("../../connectors/nginx/t/fixtures/bundle.pub");
    let mapped = strata_hs::AlignedBuf::from_bytes(bundle_bytes);
    let engine = Arc::new(Engine::map(Box::new(mapped), pub_key).expect("load legacy SHS1 bundle"));
    assert_eq!(engine.info().version, 1);

    // Verify rules and evaluation with legacy SHS1 bundle
    let mut tx = Tx::new(Some(engine), b"node-1", 0);
    tx.set_policy(b"example-api");
    tx.set_client_addr(b"1.2.3.4");
    let rc = tx.request_line(b"GET", b"/test", b"/test", b"", b"HTTP/1.1");
    assert_eq!(rc, libstrata::verdict::OK);
    let v = tx.verdict();
    assert_eq!(v.action, libstrata::verdict::ACTION_ALLOW);
}
