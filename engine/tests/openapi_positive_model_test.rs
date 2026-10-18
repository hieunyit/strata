//! Integration tests for W21-R-01: Positive Security Model with OpenAPI Schema Enforcement.

use std::sync::Arc;

use libstrata::bundle::{self, Mode, Oversize, PolicySpec, Spec};
use libstrata::engine::Engine;
use libstrata::openapi::{
    ApiEndpoint, ApiSchema, RULE_METHOD_NOT_ALLOWED, RULE_MISSING_REQUIRED_FIELD,
    RULE_UNDECLARED_BODY_FIELD, RULE_UNDECLARED_PARAM, RULE_UNKNOWN_ENDPOINT,
};
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_LOG};

const SEED: [u8; 32] = [42; 32];

fn make_test_engine(mode: Mode) -> Arc<Engine> {
    let spec = Spec {
        version: 2101,
        created_at_ms: 1000,
        flags: 0,
        policies: &[PolicySpec::new("openapi-policy", mode, Oversize::Pass)],
        sections: &[],
    };

    let bundle_bytes = bundle::build(&spec, &SEED).expect("build bundle");
    Arc::new(Engine::map(Box::new(bundle_bytes), &bundle::public_key(&SEED)).expect("map engine"))
}

fn make_petstore_schema() -> Arc<ApiSchema> {
    let mut schema = ApiSchema::new("petstore-api", "Petstore Microservice", "3.0.0");

    // Endpoint 1: /api/v1/pets
    schema.add_endpoint(
        ApiEndpoint::new("/api/v1/pets")
            .with_methods(&["GET", "POST"])
            .with_query_params(&["limit", "page", "status"], false)
            .with_body_fields(&["name", "category"], &["name", "category", "tag", "photo_url"], false),
    );

    // Endpoint 2: /api/v1/pets/{id}
    schema.add_endpoint(
        ApiEndpoint::new("/api/v1/pets/{id}")
            .with_methods(&["GET", "PUT", "DELETE"])
            .with_query_params(&[], false)
            .with_body_fields(&["name"], &["name", "tag"], false),
    );

    Arc::new(schema)
}

#[test]
fn test_openapi_valid_request_allowed() {
    let engine = make_test_engine(Mode::Enforce);
    let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-openapi", 0);
    tx.set_policy(b"openapi-policy");
    tx.set_api_schema(make_petstore_schema());

    // Valid GET /api/v1/pets?limit=10&status=available
    tx.check_api_schema(
        "GET",
        "/api/v1/pets",
        &[("limit", "10"), ("status", "available")],
        None,
    );

    let v = tx.verdict();
    assert_eq!(v.action, ACTION_ALLOW);
    assert_eq!(v.score, 0);
    assert_eq!(v.n_rules, 0);
}

#[test]
fn test_openapi_unknown_endpoint_blocked() {
    let engine = make_test_engine(Mode::Enforce);
    let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-openapi", 0);
    tx.set_policy(b"openapi-policy");
    tx.set_api_schema(make_petstore_schema());

    // Request to undeclared endpoint /api/v1/admin/dump
    tx.check_api_schema("GET", "/api/v1/admin/dump", &[], None);

    let v = tx.verdict();
    assert_eq!(v.action, ACTION_BLOCK);
    assert!(v.score >= 100);

    // Verify rule ID 600001
    assert!(
        v.rules[..v.n_rules as usize].contains(&RULE_UNKNOWN_ENDPOINT),
        "should record RULE_UNKNOWN_ENDPOINT"
    );
}

#[test]
fn test_openapi_method_not_allowed_blocked() {
    let engine = make_test_engine(Mode::Enforce);
    let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-openapi", 0);
    tx.set_policy(b"openapi-policy");
    tx.set_api_schema(make_petstore_schema());

    // PATCH /api/v1/pets (only GET and POST allowed)
    tx.check_api_schema("PATCH", "/api/v1/pets", &[], None);

    let v = tx.verdict();
    assert_eq!(v.action, ACTION_BLOCK);
    assert!(
        v.rules[..v.n_rules as usize].contains(&RULE_METHOD_NOT_ALLOWED),
        "should record RULE_METHOD_NOT_ALLOWED"
    );
}

#[test]
fn test_openapi_undeclared_query_param_blocked() {
    let engine = make_test_engine(Mode::Enforce);
    let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-openapi", 0);
    tx.set_policy(b"openapi-policy");
    tx.set_api_schema(make_petstore_schema());

    // Sending forbidden query parameter ?debug=true
    tx.check_api_schema(
        "GET",
        "/api/v1/pets",
        &[("limit", "10"), ("debug", "true")],
        None,
    );

    let v = tx.verdict();
    assert_eq!(v.action, ACTION_BLOCK);
    assert!(
        v.rules[..v.n_rules as usize].contains(&RULE_UNDECLARED_PARAM),
        "should record RULE_UNDECLARED_PARAM"
    );
}

#[test]
fn test_openapi_missing_required_body_field() {
    let engine = make_test_engine(Mode::Enforce);
    let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-openapi", 0);
    tx.set_policy(b"openapi-policy");
    tx.set_api_schema(make_petstore_schema());

    // POST /api/v1/pets requires "name" and "category"
    // Sending only "name"
    let body = br#"{"name": "Fido", "tag": "golden-retriever"}"#;
    tx.check_api_schema("POST", "/api/v1/pets", &[], Some(body));

    let v = tx.verdict();
    assert_eq!(v.action, ACTION_BLOCK);
    assert!(
        v.rules[..v.n_rules as usize].contains(&RULE_MISSING_REQUIRED_FIELD),
        "should record RULE_MISSING_REQUIRED_FIELD"
    );
}

#[test]
fn test_openapi_undeclared_body_field() {
    let engine = make_test_engine(Mode::Enforce);
    let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-openapi", 0);
    tx.set_policy(b"openapi-policy");
    tx.set_api_schema(make_petstore_schema());

    // Sending undeclared property "is_admin": true
    let body = br#"{"name": "Fido", "category": "dogs", "is_admin": true}"#;
    tx.check_api_schema("POST", "/api/v1/pets", &[], Some(body));

    let v = tx.verdict();
    assert_eq!(v.action, ACTION_BLOCK);
    assert!(
        v.rules[..v.n_rules as usize].contains(&RULE_UNDECLARED_BODY_FIELD),
        "should record RULE_UNDECLARED_BODY_FIELD"
    );
}

#[test]
fn test_openapi_shadow_mode_would_block() {
    let engine = make_test_engine(Mode::Shadow);
    let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-openapi", 0);
    tx.set_policy(b"openapi-policy");
    tx.set_api_schema(make_petstore_schema());

    // In shadow mode, an invalid request should NOT be dropped with ACTION_BLOCK,
    // but should register would_block = true
    tx.check_api_schema("DELETE", "/api/v1/nonexistent", &[], None);

    let v = tx.verdict();
    assert_eq!(v.action, ACTION_LOG);
    assert!(v.score >= 100);
    assert!(v.rules[..v.n_rules as usize].contains(&RULE_UNKNOWN_ENDPOINT));
}
