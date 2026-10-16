//! Unit and integration tests for Rule Action Resolution (W14-R-01).
//!
//! Tests priority: Exception before Override before Default, unexpired check,
//! conflict detection, and active exception filtering.

use strata_compiler::resolution::{
    Action, Exception, Override, RuleContext, filter_active_exceptions, resolve_rule_action,
    validate_overrides,
};

#[test]
fn test_exception_overrides_override() {
    let ctx = RuleContext {
        policy: "example-api",
        path: "/api/v1/auth/login",
        rule_id: 942100,
        field: "args.username",
        now_ms: 1000,
    };

    // Override specifies Block for this path and rule
    let overrides = vec![Override {
        id: "ovr-block-login".to_string(),
        policy: "example-api".to_string(),
        path_prefix: "/api/v1/auth".to_string(),
        rule_id: Some(942100),
        action: Action::Block,
    }];

    // Active approved Exception specifies Skip for this rule and field
    let exceptions = vec![Exception {
        id: "exc-login-user".to_string(),
        policy: "example-api".to_string(),
        rule_id: 942100,
        field: "args.username".to_string(),
        expires_at_ms: 5000, // unexpired
        approved: true,
    }];

    let (action, reason) =
        resolve_rule_action(&ctx, Action::Log, &exceptions, &overrides);

    // Exception MUST WIN over Override
    assert_eq!(action, Action::Skip);
    assert_eq!(reason, "exception:exc-login-user");
}

#[test]
fn test_override_takes_effect_when_no_exception() {
    let ctx = RuleContext {
        policy: "example-api",
        path: "/upload",
        rule_id: 942100,
        field: "body.file",
        now_ms: 1000,
    };

    let overrides = vec![Override {
        id: "ovr-skip-upload".to_string(),
        policy: "example-api".to_string(),
        path_prefix: "/upload".to_string(),
        rule_id: Some(942100),
        action: Action::Skip,
    }];

    let (action, reason) = resolve_rule_action(&ctx, Action::Block, &[], &overrides);

    assert_eq!(action, Action::Skip);
    assert_eq!(reason, "override:ovr-skip-upload");
}

#[test]
fn test_expired_exception_is_ignored_and_override_applies() {
    let ctx = RuleContext {
        policy: "example-api",
        path: "/api/v1/auth/login",
        rule_id: 942100,
        field: "args.username",
        now_ms: 10000, // now is 10000
    };

    let overrides = vec![Override {
        id: "ovr-count-login".to_string(),
        policy: "example-api".to_string(),
        path_prefix: "/api/v1/auth".to_string(),
        rule_id: Some(942100),
        action: Action::Count,
    }];

    // Exception expired at 5000 (< 10000)
    let exceptions = vec![Exception {
        id: "exc-expired".to_string(),
        policy: "example-api".to_string(),
        rule_id: 942100,
        field: "args.username".to_string(),
        expires_at_ms: 5000,
        approved: true,
    }];

    let (action, reason) =
        resolve_rule_action(&ctx, Action::Block, &exceptions, &overrides);

    // Expired exception ignored -> Override applies!
    assert_eq!(action, Action::Count);
    assert_eq!(reason, "override:ovr-count-login");
}

#[test]
fn test_unapproved_exception_is_ignored() {
    let ctx = RuleContext {
        policy: "example-api",
        path: "/api/v1/search",
        rule_id: 941100,
        field: "query.q",
        now_ms: 1000,
    };

    let exceptions = vec![Exception {
        id: "exc-pending".to_string(),
        policy: "example-api".to_string(),
        rule_id: 941100,
        field: "query.q".to_string(),
        expires_at_ms: 5000,
        approved: false, // not approved
    }];

    let (action, reason) =
        resolve_rule_action(&ctx, Action::Block, &exceptions, &[]);

    assert_eq!(action, Action::Block);
    assert_eq!(reason, "default");
}

#[test]
fn test_field_mismatch_exception_is_ignored() {
    let ctx = RuleContext {
        policy: "example-api",
        path: "/api/v1/search",
        rule_id: 941100,
        field: "query.other",
        now_ms: 1000,
    };

    let exceptions = vec![Exception {
        id: "exc-q".to_string(),
        policy: "example-api".to_string(),
        rule_id: 941100,
        field: "query.q".to_string(),
        expires_at_ms: 5000,
        approved: true,
    }];

    let (action, reason) =
        resolve_rule_action(&ctx, Action::Block, &exceptions, &[]);

    assert_eq!(action, Action::Block);
    assert_eq!(reason, "default");
}

#[test]
fn test_filter_active_exceptions() {
    let exceptions = vec![
        Exception {
            id: "e1".into(),
            policy: "pol".into(),
            rule_id: 1,
            field: "f".into(),
            expires_at_ms: 2000,
            approved: true,
        },
        Exception {
            id: "e2-expired".into(),
            policy: "pol".into(),
            rule_id: 2,
            field: "f".into(),
            expires_at_ms: 500,
            approved: true,
        },
        Exception {
            id: "e3-unapproved".into(),
            policy: "pol".into(),
            rule_id: 3,
            field: "f".into(),
            expires_at_ms: 3000,
            approved: false,
        },
    ];

    let active = filter_active_exceptions(&exceptions, 1000);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, "e1");
}

#[test]
fn test_override_conflict_detection() {
    let ok_overrides = vec![
        Override {
            id: "o1".into(),
            policy: "api".into(),
            path_prefix: "/login".into(),
            rule_id: Some(100),
            action: Action::Count,
        },
        Override {
            id: "o2".into(),
            policy: "api".into(),
            path_prefix: "/upload".into(),
            rule_id: Some(100),
            action: Action::Skip,
        },
    ];
    assert!(validate_overrides(&ok_overrides).is_ok());

    let conflicting = vec![
        Override {
            id: "c1".into(),
            policy: "api".into(),
            path_prefix: "/login".into(),
            rule_id: Some(100),
            action: Action::Count,
        },
        Override {
            id: "c2".into(),
            policy: "api".into(),
            path_prefix: "/login".into(),
            rule_id: Some(100),
            action: Action::Block,
        },
    ];
    let err = validate_overrides(&conflicting).unwrap_err();
    assert!(err.contains("conflicting overrides"));
}
