//! Rule action resolution (W14-R-01): Exception before Override priority.
//!
//! Evaluates the decision order for a rule violation:
//! 1. Exceptions (narrow, bounded): highest priority -> Action::Skip
//! 2. Overrides (conditional): second priority -> Override's action
//! 3. Default action -> default_action

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Block,
    Log,
    Count,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exception {
    pub id: String,
    pub policy: String,
    pub rule_id: u32,
    pub field: String,
    pub expires_at_ms: u64,
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub id: String,
    pub policy: String,
    pub path_prefix: String,
    pub rule_id: Option<u32>, // None means wildcard for all rules on this path
    pub action: Action,
}

#[derive(Debug, Clone)]
pub struct RuleContext<'a> {
    pub policy: &'a str,
    pub path: &'a str,
    pub rule_id: u32,
    pub field: &'a str,
    pub now_ms: u64,
}

/// Resolves the effective action for a rule violation.
/// Priority order:
/// 1. Exception (if approved, matching policy, rule, field, and unexpired) -> Action::Skip
/// 2. Override (if matching policy, path prefix, and rule) -> ovr.action
/// 3. Default -> default_action
pub fn resolve_rule_action(
    ctx: &RuleContext,
    default_action: Action,
    exceptions: &[Exception],
    overrides: &[Override],
) -> (Action, String) {
    // 1. Exception evaluation first
    for exc in exceptions {
        if !exc.approved {
            continue;
        }
        if !exc.policy.is_empty() && exc.policy != ctx.policy {
            continue;
        }
        if exc.rule_id != ctx.rule_id {
            continue;
        }
        if !exc.field.is_empty() && exc.field != "*" && exc.field != ctx.field {
            continue;
        }
        if exc.expires_at_ms > 0 && ctx.now_ms > exc.expires_at_ms {
            // Expired exception, ignore!
            continue;
        }
        return (Action::Skip, format!("exception:{}", exc.id));
    }

    // 2. Override evaluation second
    for ovr in overrides {
        if !ovr.policy.is_empty() && ovr.policy != ctx.policy {
            continue;
        }
        if !ovr.path_prefix.is_empty() && !ctx.path.starts_with(&ovr.path_prefix) {
            continue;
        }
        if ovr.rule_id.is_some_and(|rid| rid != ctx.rule_id) {
            continue;
        }
        return (ovr.action, format!("override:{}", ovr.id));
    }

    // 3. Default action
    (default_action, "default".to_string())
}

/// Filters active exceptions: retains only approved and unexpired exceptions.
pub fn filter_active_exceptions(exceptions: &[Exception], now_ms: u64) -> Vec<Exception> {
    exceptions
        .iter()
        .filter(|e| e.approved && (e.expires_at_ms == 0 || e.expires_at_ms >= now_ms))
        .cloned()
        .collect()
}

/// Validates overrides and returns an error if conflicting actions are configured
/// for the exact same policy, path_prefix, and rule_id.
pub fn validate_overrides(overrides: &[Override]) -> Result<(), String> {
    for (i, o1) in overrides.iter().enumerate() {
        for o2 in &overrides[i + 1..] {
            if o1.policy == o2.policy
                && o1.path_prefix == o2.path_prefix
                && o1.rule_id == o2.rule_id
                && o1.action != o2.action
            {
                return Err(format!(
                    "conflicting overrides {} and {} for rule {:?} on path {:?}",
                    o1.id, o2.id, o1.rule_id, o1.path_prefix
                ));
            }
        }
    }
    Ok(())
}
