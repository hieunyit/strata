//! Response layer (W06-R-01): 15 cases through the transaction API, the
//! way a connector drives it (status + headers, then body chunks).

use std::sync::Arc;

use libstrata::bundle::{Mode, Oversize, PolicySpec, Response, Spec, build, public_key};
use libstrata::detectors::response::{STATUS_NOT_ALLOWED, cccd, db_errors, jwt};
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, OK, TXF_FORCE_SHADOW, Verdict};

const SEED: [u8; 32] = [9; 32];
const TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

fn engine() -> Arc<Engine> {
    let all = PolicySpec {
        response: Response(Response::ALL),
        ..PolicySpec::new("example-guard", Mode::Enforce, Oversize::Pass)
    };
    let spec = Spec {
        version: 1,
        created_at_ms: 0,
        flags: 0,
        policies: &[
            all,
            PolicySpec::new("example-api", Mode::Enforce, Oversize::Pass),
        ],
        sections: &[],
    };
    let b = build(&spec, &SEED).unwrap();
    Arc::new(Engine::map(Box::new(b), &public_key(&SEED)).unwrap())
}

/// A request that passed, under `policy`, now at its response.
fn tx(policy: &[u8], flags: u32, status: u16) -> Tx {
    let mut t = Tx::new(Some(engine()), b"web-01", flags);
    t.set_policy(policy);
    assert_eq!(t.request_line(b"GET", b"/a", b"/a", b"", b"HTTP/1.1"), OK);
    assert_eq!(t.request_headers(&[]), OK);
    assert_eq!(t.request_body_chunk(b"", true), OK);
    assert_eq!(t.response_headers(status), OK);
    t
}

/// Body as the client receives it.
fn body(t: &mut Tx, chunks: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![];
    for (i, c) in chunks.iter().enumerate() {
        let (rc, rw) = t.response_body_chunk(c, i + 1 == chunks.len());
        assert_eq!(rc, OK);
        out.extend(rw.unwrap_or_else(|| c.to_vec()));
    }
    out
}

fn rules(v: &Verdict) -> Vec<u32> {
    v.rules[..v.n_rules as usize].to_vec()
}

fn guard(chunks: &[&[u8]]) -> (Vec<u8>, Verdict) {
    let mut t = tx(b"example-guard", 0, 200);
    let out = body(&mut t, chunks);
    assert_eq!(out.len(), chunks.concat().len(), "same length");
    (out, t.verdict())
}

#[test]
fn case01_status_200_allowed() {
    let t = tx(b"example-guard", 0, 200);
    let v = t.verdict();
    assert!(rules(&v).is_empty() && v.id.is_none());
    assert!(v.need_response);
}

#[test]
fn case02_status_500_recorded_not_blocked() {
    let v = tx(b"example-guard", 0, 500).verdict();
    assert_eq!(rules(&v), [STATUS_NOT_ALLOWED]);
    assert_eq!(v.action, ACTION_ALLOW, "the response is already going out");
    assert!(v.id.unwrap().starts_with(b"EVT-"));
}

#[test]
fn case03_status_418() {
    assert_eq!(
        rules(&tx(b"example-guard", 0, 418).verdict()),
        [STATUS_NOT_ALLOWED]
    );
}

#[test]
fn case04_mysql_error_in_html() {
    let (out, v) = guard(&[b"<p>You have an error in your SQL syntax; check the manual</p>"]);
    assert_eq!(rules(&v), [db_errors::MYSQL]);
    assert!(!out.contains(&b'*'), "detected, not masked");
}

#[test]
fn case05_postgresql_error_split_between_chunks() {
    let (_, v) = guard(&[b"Warning: pg_query(): Que", b"ry failed: ERROR"]);
    assert_eq!(rules(&v), [db_errors::POSTGRESQL]);
}

#[test]
fn case06_oracle_code() {
    let (_, v) = guard(&[b"ORA-00933: SQL command not properly ended"]);
    assert_eq!(rules(&v), [db_errors::ORACLE]);
}

#[test]
fn case07_ordinary_error_text() {
    let (out, v) = guard(&[b"<h1>Error</h1><p>Something went wrong, try again.</p>"]);
    assert!(rules(&v).is_empty());
    assert_eq!(
        out,
        b"<h1>Error</h1><p>Something went wrong, try again.</p>"
    );
}

#[test]
fn case08_cccd_in_json_masked() {
    let (out, v) = guard(&[br#"{"name":"A","cccd":"001203012345"}"#]);
    assert_eq!(out, br#"{"name":"A","cccd":"************"}"#);
    assert_eq!(rules(&v), [cccd::RULE]);
}

#[test]
fn case09_cccd_split_between_chunks() {
    let (out, _) = guard(&[br#"{"cccd":"0012030"#, br#"12345"}"#]);
    assert_eq!(out, br#"{"cccd":"************"}"#);
}

#[test]
fn case10_unknown_province_not_masked() {
    let (out, v) = guard(&[br#"{"id":"003203012345"}"#]);
    assert_eq!(out, br#"{"id":"003203012345"}"#);
    assert!(rules(&v).is_empty());
}

#[test]
fn case11_thirteen_digits_not_masked() {
    let (out, _) = guard(&[br#"{"ts":1760000000123}"#]);
    assert_eq!(out, br#"{"ts":1760000000123}"#);
}

#[test]
fn case12_jwt_in_json_masked() {
    let b = format!(r#"{{"access_token":"{TOKEN}"}}"#);
    let (out, v) = guard(&[b.as_bytes()]);
    assert_eq!(
        out,
        format!(r#"{{"access_token":"{}"}}"#, "*".repeat(TOKEN.len())).as_bytes()
    );
    assert_eq!(rules(&v), [jwt::RULE]);
}

#[test]
fn case13_long_jwt_over_many_chunks() {
    let token = format!("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.{}", "Q".repeat(6000));
    let b = format!("<script>var t='{token}';</script>");
    let chunks: Vec<&[u8]> = b.as_bytes().chunks(700).collect();
    let (out, _) = guard(&chunks);
    let want = format!("<script>var t='{}';</script>", "*".repeat(token.len()));
    assert_eq!(out, want.as_bytes());
}

#[test]
fn case14_eyj_that_is_not_a_token() {
    let (out, v) = guard(&[b"eyJ is how base64 of '{\"' starts. eyJhbGciOiJub25lIn0 alone"]);
    assert_eq!(
        out,
        b"eyJ is how base64 of '{\"' starts. eyJhbGciOiJub25lIn0 alone"
    );
    assert!(rules(&v).is_empty());
}

#[test]
fn case15_policy_without_response_layer() {
    let mut t = tx(b"example-api", 0, 500);
    let b = br#"{"cccd":"001203012345","e":"ORA-00933"}"#;
    assert_eq!(body(&mut t, &[b]), b);
    let v = t.verdict();
    assert!(rules(&v).is_empty() && v.id.is_none());
    // test-hooks builds always ask for the body (test masking literal)
    assert_eq!(v.need_response, cfg!(feature = "test-hooks"));
}

#[test]
fn shadow_records_but_never_masks() {
    let mut t = tx(b"example-guard", TXF_FORCE_SHADOW, 200);
    let b = format!(r#"{{"cccd":"001203012345","t":"{TOKEN}"}}"#);
    let (rc, rw) = t.response_body_chunk(b.as_bytes(), true);
    assert_eq!((rc, rw), (OK, None));
    assert_eq!(rules(&t.verdict()), [cccd::RULE, jwt::RULE]);
}

#[test]
fn flush_sends_everything_held() {
    let mut t = tx(b"example-guard", 0, 200);
    let mut out = t.response_body_chunk(b"data: hello\n\n", false).1.unwrap();
    out.extend(t.response_body_flush().1.unwrap());
    assert_eq!(out, b"data: hello\n\n");
    let mut out = t
        .response_body_chunk(b"data: 001203012345\n\n", false)
        .1
        .unwrap();
    out.extend(t.response_body_flush().1.unwrap());
    assert_eq!(out, b"data: ************\n\n");
    assert_eq!(t.response_body_flush().1.unwrap(), b"");
}
