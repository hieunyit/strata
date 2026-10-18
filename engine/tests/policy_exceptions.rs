use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK};
use libstrata::{bundle, engine::Engine, exceptions::Exception, tx::Tx};
use std::sync::Arc;
#[path = "common/exception_fixture.rs"]
mod fixture;
use fixture::{exception, image};

const METHOD: &[u8] = b"POST";
const HOST: &[u8] = b"api.example.test";
const PATH: &[u8] = b"/v1/login";
const SQL: &[u8] = b"Name=1+OR+1%3D1";
type RequestCase<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8]);

fn engine(entries: &[Exception]) -> Arc<Engine> {
    Arc::new(
        Engine::map(
            Box::new(image(entries, !entries.is_empty())),
            &bundle::public_key(&[7; 32]),
        )
        .unwrap(),
    )
}
fn verdict(
    e: Arc<Engine>,
    method: &[u8],
    host: &[u8],
    path: &[u8],
    body: &[u8],
    duplicate_host: bool,
) -> u32 {
    let mut tx = Tx::new(Some(e), b"example-node", 0);
    tx.set_policy(b"example-api");
    tx.request_line(method, path, path, b"", b"HTTP/1.1");
    let mut headers = vec![
        (&b"Host"[..], host),
        (
            &b"Content-Type"[..],
            &b"application/x-www-form-urlencoded"[..],
        ),
    ];
    if duplicate_host {
        headers.push((b"Host", host));
    }
    tx.request_headers(&headers);
    tx.request_body_chunk(body, true);
    tx.verdict().action
}
fn normal(e: Arc<Engine>, body: &[u8]) -> u32 {
    verdict(e, METHOD, HOST, PATH, body, false)
}

#[test]
fn scoped_exception_does_not_hide_a_second_field_or_expand_case() {
    // Optional signed fixture export for the NGINX sanitizer probe.
    if let Some(dir) = std::env::var_os("STRATA_EXCEPTION_FIXTURE_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut e = exception("REQUEST_HEADERS:X-Example-Filter", u64::MAX / 2);
        e.method = "GET".into();
        e.path = "/header-sql".into();
        std::fs::write(dir.join("bundle.sbn"), image(&[e], true)).unwrap();
        std::fs::write(dir.join("bundle.pub"), bundle::public_key(&[7; 32])).unwrap();
    }
    let e = engine(&[exception("ARGS:Name", u64::MAX / 2)]);
    assert_eq!(normal(e.clone(), SQL), ACTION_ALLOW);
    let cases: &[RequestCase<'_>] = &[
        (b"GET", HOST, PATH, SQL),
        (METHOD, b"other.example.test", PATH, SQL),
        (METHOD, b"", PATH, SQL),
        (METHOD, HOST, b"/v1/Login", SQL),
        (METHOD, HOST, PATH, b"name=1+OR+1%3D1"),
        (METHOD, HOST, PATH, b"Name=1+OR+1%3D1&other=1+OR+1%3D1"),
        (
            METHOD,
            HOST,
            PATH,
            b"Name=ordinary&Name=1+OR+1%3D1&other=1+OR+1%3D1",
        ),
    ];
    for &(method, host, path, body) in cases {
        assert_eq!(
            verdict(e.clone(), method, host, path, body, false),
            ACTION_BLOCK
        );
    }
    assert_eq!(verdict(e, METHOD, HOST, PATH, SQL, true), ACTION_BLOCK);
}
#[test]
fn decoded_field_alias_is_not_a_literal_parameter_name() {
    let e = engine(&[exception("ARGS:Name", u64::MAX / 2)]);
    assert_eq!(normal(e.clone(), b"Name=MSBPUiAxPTE%3D"), ACTION_ALLOW);
    assert_eq!(normal(e, b"Name%7Cbase64=1+OR+1%3D1"), ACTION_BLOCK);
    let e = engine(&[exception("ARGS:Name|base64", u64::MAX / 2)]);
    assert_eq!(normal(e, b"Name=MSBPUiAxPTE%3D"), ACTION_BLOCK);
}
#[test]
fn expiry_and_missing_flags_fail_closed_for_exceptions() {
    assert_eq!(
        normal(engine(&[exception("ARGS:Name", 1)]), SQL),
        ACTION_BLOCK
    );
    for (entries, flag) in [(vec![], true), (vec![exception("ARGS:Name", 1000)], false)] {
        assert!(
            Engine::map(
                Box::new(image(&entries, flag)),
                &bundle::public_key(&[7; 32])
            )
            .is_err()
        );
    }
    let mut unknown = exception("ARGS:Name", 1000);
    unknown.rule_id = 999999;
    assert!(
        Engine::map(
            Box::new(image(&[unknown], true)),
            &bundle::public_key(&[7; 32])
        )
        .is_err()
    );
}
#[test]
fn loaded_exception_expires_for_a_new_transaction_without_reload() {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let now = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    };
    let expires = now() + 5000;
    let e = engine(&[exception("ARGS:Name", expires)]);
    assert_eq!(normal(e.clone(), SQL), ACTION_ALLOW);
    std::thread::sleep(Duration::from_millis(expires.saturating_sub(now()) + 10));
    assert_eq!(normal(e, SQL), ACTION_BLOCK);
}
