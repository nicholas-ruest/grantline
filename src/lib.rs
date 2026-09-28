#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub spend_cents: u64,
    pub tool_calls: u64,
    pub tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mandate {
    pub schema_version: u32,
    pub id: String,
    pub principal: String,
    pub delegate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    pub models: Vec<String>,
    pub counterparties: Vec<String>,
    pub budget: Budget,
    pub valid_from: u64,
    pub expires_at: u64,
    pub remaining_delegations: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_above_cents: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub action: String,
    pub resource: String,
    pub model: String,
    pub counterparty: String,
    pub spend_cents: u64,
    pub tool_calls: u64,
    pub tokens: u64,
    pub timestamp: u64,
    #[serde(default)]
    pub human_approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Violation {
    pub code: &'static str,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainReport {
    pub valid: bool,
    pub mandates: usize,
    pub links_checked: usize,
    pub leaf_id: Option<String>,
    pub violations: Vec<Violation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub allowed: bool,
    pub mandate_id: String,
    pub delegate: String,
    pub violations: Vec<Violation>,
}

#[must_use]
pub fn verify_chain(chain: &[Mandate]) -> ChainReport {
    let mut violations = Vec::new();

    if chain.is_empty() {
        violations.push(violation(
            "empty_chain",
            "chain",
            "at least one mandate is required",
        ));
    }

    for (index, mandate) in chain.iter().enumerate() {
        validate_mandate(mandate, index, &mut violations);
        if index == 0 {
            if mandate.parent_id.is_some() {
                violations.push(violation(
                    "root_has_parent",
                    format!("chain[{index}].parent_id"),
                    "the root mandate must not name a parent",
                ));
            }
        } else {
            validate_attenuation(&chain[index - 1], mandate, index, &mut violations);
        }
    }

    ChainReport {
        valid: violations.is_empty(),
        mandates: chain.len(),
        links_checked: chain.len().saturating_sub(1),
        leaf_id: chain.last().map(|mandate| mandate.id.clone()),
        violations,
    }
}

#[must_use]
pub fn authorize(mandate: &Mandate, request: &ActionRequest) -> Decision {
    let mut violations = Vec::new();
    validate_mandate(mandate, 0, &mut violations);

    require_exact_member(
        &mandate.actions,
        &request.action,
        "action_not_allowed",
        "request.action",
        &mut violations,
    );
    require_selector_match(
        &mandate.resources,
        &request.resource,
        "resource_not_allowed",
        "request.resource",
        &mut violations,
    );
    require_exact_member(
        &mandate.models,
        &request.model,
        "model_not_allowed",
        "request.model",
        &mut violations,
    );
    require_selector_match(
        &mandate.counterparties,
        &request.counterparty,
        "counterparty_not_allowed",
        "request.counterparty",
        &mut violations,
    );

    if request.timestamp < mandate.valid_from {
        violations.push(violation(
            "not_yet_valid",
            "request.timestamp",
            format!("{} is before mandate validity", request.timestamp),
        ));
    }
    if request.timestamp >= mandate.expires_at {
        violations.push(violation(
            "expired",
            "request.timestamp",
            format!("{} is at or after mandate expiry", request.timestamp),
        ));
    }

    check_budget(
        request.spend_cents,
        mandate.budget.spend_cents,
        "spend_exceeded",
        "request.spend_cents",
        &mut violations,
    );
    check_budget(
        request.tool_calls,
        mandate.budget.tool_calls,
        "tool_calls_exceeded",
        "request.tool_calls",
        &mut violations,
    );
    check_budget(
        request.tokens,
        mandate.budget.tokens,
        "tokens_exceeded",
        "request.tokens",
        &mut violations,
    );

    if mandate
        .approval_above_cents
        .is_some_and(|threshold| request.spend_cents > threshold && !request.human_approved)
    {
        violations.push(violation(
            "approval_required",
            "request.human_approved",
            "spend exceeds the mandate's human-approval threshold",
        ));
    }

    Decision {
        allowed: violations.is_empty(),
        mandate_id: mandate.id.clone(),
        delegate: mandate.delegate.clone(),
        violations,
    }
}

fn validate_mandate(mandate: &Mandate, index: usize, violations: &mut Vec<Violation>) {
    let prefix = format!("chain[{index}]");
    if mandate.schema_version != SUPPORTED_SCHEMA_VERSION {
        violations.push(violation(
            "unsupported_schema",
            format!("{prefix}.schema_version"),
            format!(
                "expected schema version {SUPPORTED_SCHEMA_VERSION}, got {}",
                mandate.schema_version
            ),
        ));
    }
    for (field, value) in [
        ("id", &mandate.id),
        ("principal", &mandate.principal),
        ("delegate", &mandate.delegate),
    ] {
        if value.trim().is_empty() {
            violations.push(violation(
                "empty_identity",
                format!("{prefix}.{field}"),
                format!("{field} must not be empty"),
            ));
        }
    }
    if mandate.valid_from >= mandate.expires_at {
        violations.push(violation(
            "invalid_window",
            format!("{prefix}.expires_at"),
            "expires_at must be greater than valid_from",
        ));
    }
    for (field, values) in [
        ("actions", &mandate.actions),
        ("resources", &mandate.resources),
        ("models", &mandate.models),
        ("counterparties", &mandate.counterparties),
    ] {
        if values.is_empty() {
            violations.push(violation(
                "empty_capability_set",
                format!("{prefix}.{field}"),
                format!("{field} must contain at least one entry"),
            ));
        }
        let unique: BTreeSet<_> = values.iter().collect();
        if unique.len() != values.len() {
            violations.push(violation(
                "duplicate_capability",
                format!("{prefix}.{field}"),
                format!("{field} contains duplicate entries"),
            ));
        }
    }
}

fn validate_attenuation(
    parent: &Mandate,
    child: &Mandate,
    index: usize,
    violations: &mut Vec<Violation>,
) {
    let prefix = format!("chain[{index}]");
    if child.parent_id.as_deref() != Some(parent.id.as_str()) {
        violations.push(violation(
            "parent_mismatch",
            format!("{prefix}.parent_id"),
            format!("expected parent id {}", parent.id),
        ));
    }
    if child.principal != parent.principal {
        violations.push(violation(
            "principal_changed",
            format!("{prefix}.principal"),
            "a child mandate must preserve the principal",
        ));
    }
    check_exact_subset(
        &parent.actions,
        &child.actions,
        "action_expanded",
        &format!("{prefix}.actions"),
        violations,
    );
    check_selector_subset(
        &parent.resources,
        &child.resources,
        "resource_expanded",
        &format!("{prefix}.resources"),
        violations,
    );
    check_exact_subset(
        &parent.models,
        &child.models,
        "model_expanded",
        &format!("{prefix}.models"),
        violations,
    );
    check_selector_subset(
        &parent.counterparties,
        &child.counterparties,
        "counterparty_expanded",
        &format!("{prefix}.counterparties"),
        violations,
    );
    check_child_limit(
        child.budget.spend_cents,
        parent.budget.spend_cents,
        "spend_expanded",
        &format!("{prefix}.budget.spend_cents"),
        violations,
    );
    check_child_limit(
        child.budget.tool_calls,
        parent.budget.tool_calls,
        "tool_calls_expanded",
        &format!("{prefix}.budget.tool_calls"),
        violations,
    );
    check_child_limit(
        child.budget.tokens,
        parent.budget.tokens,
        "tokens_expanded",
        &format!("{prefix}.budget.tokens"),
        violations,
    );
    if child.valid_from < parent.valid_from {
        violations.push(violation(
            "validity_started_earlier",
            format!("{prefix}.valid_from"),
            "a child mandate cannot begin before its parent",
        ));
    }
    if child.expires_at > parent.expires_at {
        violations.push(violation(
            "expiry_extended",
            format!("{prefix}.expires_at"),
            "a child mandate cannot outlive its parent",
        ));
    }
    if parent.remaining_delegations == 0
        || child.remaining_delegations >= parent.remaining_delegations
    {
        violations.push(violation(
            "delegation_depth_expanded",
            format!("{prefix}.remaining_delegations"),
            "a child must consume at least one remaining delegation",
        ));
    }
    check_approval_attenuation(parent, child, &prefix, violations);
}

fn check_approval_attenuation(
    parent: &Mandate,
    child: &Mandate,
    prefix: &str,
    violations: &mut Vec<Violation>,
) {
    match (parent.approval_above_cents, child.approval_above_cents) {
        (Some(_), None) => violations.push(violation(
            "approval_removed",
            format!("{prefix}.approval_above_cents"),
            "a child cannot remove its parent's approval threshold",
        )),
        (Some(parent_limit), Some(child_limit)) if child_limit > parent_limit => {
            violations.push(violation(
                "approval_weakened",
                format!("{prefix}.approval_above_cents"),
                "a child approval threshold cannot be higher than its parent's",
            ));
        }
        _ => {}
    }
}

fn selector_covers(parent: &str, child: &str) -> bool {
    let parent_prefix = parent.strip_suffix('*');
    let child_prefix = child.strip_suffix('*');
    match (parent_prefix, child_prefix) {
        (Some(prefix), Some(child_value)) => child_value.starts_with(prefix),
        (Some(prefix), None) => child.starts_with(prefix),
        (None, Some(_)) => false,
        (None, None) => parent == child,
    }
}

fn check_exact_subset(
    parent: &[String],
    child: &[String],
    code: &'static str,
    path: &str,
    violations: &mut Vec<Violation>,
) {
    let parent: BTreeSet<_> = parent.iter().collect();
    for value in child {
        if !parent.contains(value) {
            violations.push(violation(
                code,
                path,
                format!("{value:?} is not allowed by the parent mandate"),
            ));
        }
    }
}

fn check_selector_subset(
    parent: &[String],
    child: &[String],
    code: &'static str,
    path: &str,
    violations: &mut Vec<Violation>,
) {
    for value in child {
        if !parent
            .iter()
            .any(|candidate| selector_covers(candidate, value))
        {
            violations.push(violation(
                code,
                path,
                format!("{value:?} is not covered by a parent selector"),
            ));
        }
    }
}

fn require_exact_member(
    allowed: &[String],
    value: &str,
    code: &'static str,
    path: &str,
    violations: &mut Vec<Violation>,
) {
    if !allowed.iter().any(|candidate| candidate == value) {
        violations.push(violation(
            code,
            path,
            format!("{value:?} is outside the mandate"),
        ));
    }
}

fn require_selector_match(
    allowed: &[String],
    value: &str,
    code: &'static str,
    path: &str,
    violations: &mut Vec<Violation>,
) {
    if !allowed
        .iter()
        .any(|candidate| selector_covers(candidate, value))
    {
        violations.push(violation(
            code,
            path,
            format!("{value:?} is outside the mandate"),
        ));
    }
}

fn check_child_limit(
    child: u64,
    parent: u64,
    code: &'static str,
    path: &str,
    violations: &mut Vec<Violation>,
) {
    if child > parent {
        violations.push(violation(
            code,
            path,
            format!("child limit {child} exceeds parent limit {parent}"),
        ));
    }
}

fn check_budget(
    actual: u64,
    allowed: u64,
    code: &'static str,
    path: &str,
    violations: &mut Vec<Violation>,
) {
    if actual > allowed {
        violations.push(violation(
            code,
            path,
            format!("requested {actual}, mandate allows {allowed}"),
        ));
    }
}

fn violation(code: &'static str, path: impl Into<String>, message: impl Into<String>) -> Violation {
    Violation {
        code,
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> Mandate {
        Mandate {
            schema_version: 1,
            id: "root".into(),
            principal: "acme".into(),
            delegate: "planner".into(),
            parent_id: None,
            actions: vec!["quote".into(), "purchase".into()],
            resources: vec!["catalog/*".into()],
            models: vec!["model-a".into(), "model-b".into()],
            counterparties: vec!["supplier/*".into()],
            budget: Budget {
                spend_cents: 10_000,
                tool_calls: 20,
                tokens: 50_000,
            },
            valid_from: 100,
            expires_at: 500,
            remaining_delegations: 2,
            approval_above_cents: Some(5_000),
        }
    }

    fn child() -> Mandate {
        Mandate {
            id: "child".into(),
            delegate: "buyer".into(),
            parent_id: Some("root".into()),
            actions: vec!["quote".into()],
            resources: vec!["catalog/laptops/*".into()],
            models: vec!["model-a".into()],
            counterparties: vec!["supplier/approved".into()],
            budget: Budget {
                spend_cents: 4_000,
                tool_calls: 10,
                tokens: 20_000,
            },
            valid_from: 120,
            expires_at: 400,
            remaining_delegations: 1,
            approval_above_cents: Some(2_000),
            ..root()
        }
    }

    fn request() -> ActionRequest {
        ActionRequest {
            action: "quote".into(),
            resource: "catalog/laptops/13-inch".into(),
            model: "model-a".into(),
            counterparty: "supplier/approved".into(),
            spend_cents: 1_500,
            tool_calls: 3,
            tokens: 2_000,
            timestamp: 200,
            human_approved: false,
        }
    }

    #[test]
    fn accepts_attenuated_chain() {
        let report = verify_chain(&[root(), child()]);
        assert!(report.valid, "{:?}", report.violations);
        assert_eq!(report.links_checked, 1);
        assert_eq!(report.leaf_id.as_deref(), Some("child"));
    }

    #[test]
    fn rejects_expanded_action_and_budget() {
        let mut child = child();
        child.actions.push("delete".into());
        child.budget.spend_cents = 20_000;
        let report = verify_chain(&[root(), child]);
        let codes: BTreeSet<_> = report.violations.iter().map(|v| v.code).collect();
        assert!(codes.contains("action_expanded"));
        assert!(codes.contains("spend_expanded"));
    }

    #[test]
    fn rejects_wider_resource_selector() {
        let mut child = child();
        child.resources = vec!["catalog/*".into(), "secrets/*".into()];
        let report = verify_chain(&[root(), child]);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.code == "resource_expanded")
        );
    }

    #[test]
    fn rejects_expired_child_and_changed_principal() {
        let mut child = child();
        child.expires_at = 600;
        child.principal = "other".into();
        let report = verify_chain(&[root(), child]);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.code == "expiry_extended")
        );
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.code == "principal_changed")
        );
    }

    #[test]
    fn rejects_unconsumed_delegation_depth() {
        let mut child = child();
        child.remaining_delegations = 2;
        let report = verify_chain(&[root(), child]);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.code == "delegation_depth_expanded")
        );
    }

    #[test]
    fn rejects_weaker_approval_rule() {
        let mut child = child();
        child.approval_above_cents = Some(8_000);
        let report = verify_chain(&[root(), child]);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.code == "approval_weakened")
        );
    }

    #[test]
    fn authorizes_request_inside_leaf_mandate() {
        let decision = authorize(&child(), &request());
        assert!(decision.allowed, "{:?}", decision.violations);
    }

    #[test]
    fn requires_approval_above_threshold() {
        let mut request = request();
        request.spend_cents = 3_000;
        let decision = authorize(&child(), &request);
        assert!(!decision.allowed);
        assert!(
            decision
                .violations
                .iter()
                .any(|v| v.code == "approval_required")
        );
        request.human_approved = true;
        assert!(authorize(&child(), &request).allowed);
    }

    #[test]
    fn denies_wrong_model_resource_and_counterparty() {
        let mut request = request();
        request.model = "model-z".into();
        request.resource = "catalog/servers/gpu".into();
        request.counterparty = "supplier/unapproved".into();
        let decision = authorize(&child(), &request);
        assert_eq!(decision.violations.len(), 3);
    }

    #[test]
    fn denies_expired_and_over_budget_request() {
        let mut request = request();
        request.timestamp = 400;
        request.tokens = 30_000;
        let decision = authorize(&child(), &request);
        let codes: BTreeSet<_> = decision.violations.iter().map(|v| v.code).collect();
        assert!(codes.contains("expired"));
        assert!(codes.contains("tokens_exceeded"));
    }

    #[test]
    fn rejects_unknown_json_fields() {
        let json = serde_json::to_string(&root()).expect("serialize");
        let changed = json.replacen('{', "{\"unexpected\":true,", 1);
        assert!(serde_json::from_str::<Mandate>(&changed).is_err());
    }
}
