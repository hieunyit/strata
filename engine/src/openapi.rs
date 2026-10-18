//! Positive Security Model: OpenAPI Schema validation (W21-R-01).
//!
//! Validates incoming requests against an API OpenAPI specification:
//! - Endpoint path matching (with {param} wildcard support)
//! - Allowed HTTP methods
//! - Allowed query parameters (rejects undeclared parameters if not allowed)
//! - Request body JSON schema (required fields, undeclared fields)
//!
//! Violations generate corresponding security findings with Rule IDs 600001 - 600005.
#![forbid(unsafe_code)]

use std::collections::HashSet;

/// Rule ID for requests targeting an unknown or undeclared API endpoint.
pub const RULE_UNKNOWN_ENDPOINT: u32 = 600001;
/// Rule ID for requests using an HTTP method not declared for the endpoint.
pub const RULE_METHOD_NOT_ALLOWED: u32 = 600002;
/// Rule ID for requests containing undeclared query parameters.
pub const RULE_UNDECLARED_PARAM: u32 = 600003;
/// Rule ID for requests missing a required request body field.
pub const RULE_MISSING_REQUIRED_FIELD: u32 = 600004;
/// Rule ID for requests containing undeclared request body fields.
pub const RULE_UNDECLARED_BODY_FIELD: u32 = 600005;

/// Specification for a single API endpoint in OpenAPI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiEndpoint {
    /// URL path pattern, e.g. `/api/v1/users` or `/api/v1/users/{id}`.
    pub path_pattern: String,
    /// List of allowed uppercase HTTP methods, e.g. `["GET", "POST"]`.
    pub methods: Vec<String>,
    /// Allowed query parameter names.
    pub allowed_query_params: Vec<String>,
    /// If true, undeclared query parameters are permitted.
    pub allow_extra_params: bool,
    /// Required JSON body property names.
    pub required_fields: Vec<String>,
    /// Allowed JSON body property names.
    pub allowed_fields: Vec<String>,
    /// If true, undeclared JSON body properties are permitted.
    pub allow_extra_fields: bool,
}

impl ApiEndpoint {
    /// Creates a new builder for an API endpoint.
    pub fn new(path_pattern: impl Into<String>) -> Self {
        Self {
            path_pattern: path_pattern.into(),
            methods: Vec::new(),
            allowed_query_params: Vec::new(),
            allow_extra_params: false,
            required_fields: Vec::new(),
            allowed_fields: Vec::new(),
            allow_extra_fields: false,
        }
    }

    /// Sets allowed HTTP methods.
    pub fn with_methods(mut self, methods: &[&str]) -> Self {
        self.methods = methods.iter().map(|m| m.to_ascii_uppercase()).collect();
        self
    }

    /// Sets allowed query parameters.
    pub fn with_query_params(mut self, params: &[&str], allow_extra: bool) -> Self {
        self.allowed_query_params = params.iter().map(|p| p.to_string()).collect();
        self.allow_extra_params = allow_extra;
        self
    }

    /// Sets request body fields.
    pub fn with_body_fields(
        mut self,
        required: &[&str],
        allowed: &[&str],
        allow_extra: bool,
    ) -> Self {
        self.required_fields = required.iter().map(|f| f.to_string()).collect();
        self.allowed_fields = allowed.iter().map(|f| f.to_string()).collect();
        self.allow_extra_fields = allow_extra;
        self
    }

    /// Matches a request path against this endpoint's pattern.
    /// Supports `/exact/path` and `/prefix/{param}/subpath` matching.
    pub fn matches_path(&self, request_path: &str) -> bool {
        let pattern = self.path_pattern.trim_matches('/');
        let actual = request_path.trim_matches('/');

        if pattern == actual {
            return true;
        }

        let pattern_segments: Vec<&str> = pattern.split('/').collect();
        let actual_segments: Vec<&str> = actual.split('/').collect();

        if pattern_segments.len() != actual_segments.len() {
            return false;
        }

        for (pat_seg, act_seg) in pattern_segments.iter().zip(actual_segments.iter()) {
            if pat_seg.starts_with('{') && pat_seg.ends_with('}') {
                // Wildcard parameter segment matches non-empty segment
                if act_seg.is_empty() {
                    return false;
                }
            } else if *pat_seg != *act_seg {
                return false;
            }
        }

        true
    }
}

/// Collection of API endpoints representing an OpenAPI definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiSchema {
    pub id: String,
    pub name: String,
    pub version: String,
    pub endpoints: Vec<ApiEndpoint>,
    /// If true, paths with no matching endpoint are passed through rather than blocked.
    pub allow_unknown_endpoints: bool,
}

impl ApiSchema {
    pub fn new(id: impl Into<String>, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: version.into(),
            endpoints: Vec::new(),
            allow_unknown_endpoints: false,
        }
    }

    pub fn add_endpoint(&mut self, endpoint: ApiEndpoint) {
        self.endpoints.push(endpoint);
    }

    /// Finds the first matching endpoint for the given request path.
    pub fn match_endpoint(&self, request_path: &str) -> Option<&ApiEndpoint> {
        self.endpoints.iter().find(|ep| ep.matches_path(request_path))
    }
}

/// Detailed schema violation description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaViolation {
    UnknownEndpoint {
        path: String,
    },
    MethodNotAllowed {
        method: String,
        allowed: Vec<String>,
    },
    UndeclaredParam {
        param: String,
    },
    MissingRequiredField {
        field: String,
    },
    UndeclaredBodyField {
        field: String,
    },
}

impl SchemaViolation {
    pub fn rule_id(&self) -> u32 {
        match self {
            SchemaViolation::UnknownEndpoint { .. } => RULE_UNKNOWN_ENDPOINT,
            SchemaViolation::MethodNotAllowed { .. } => RULE_METHOD_NOT_ALLOWED,
            SchemaViolation::UndeclaredParam { .. } => RULE_UNDECLARED_PARAM,
            SchemaViolation::MissingRequiredField { .. } => RULE_MISSING_REQUIRED_FIELD,
            SchemaViolation::UndeclaredBodyField { .. } => RULE_UNDECLARED_BODY_FIELD,
        }
    }

    pub fn target_field(&self) -> &'static str {
        match self {
            SchemaViolation::UnknownEndpoint { .. } => "REQUEST_URI",
            SchemaViolation::MethodNotAllowed { .. } => "REQUEST_METHOD",
            SchemaViolation::UndeclaredParam { .. } => "ARGS",
            SchemaViolation::MissingRequiredField { .. } => "REQUEST_BODY",
            SchemaViolation::UndeclaredBodyField { .. } => "REQUEST_BODY",
        }
    }

    pub fn message(&self) -> String {
        match self {
            SchemaViolation::UnknownEndpoint { path } => {
                format!("Endpoint {} is not defined in the API schema", path)
            }
            SchemaViolation::MethodNotAllowed { method, allowed } => {
                format!(
                    "HTTP method {} is not allowed (allowed: {})",
                    method,
                    allowed.join(", ")
                )
            }
            SchemaViolation::UndeclaredParam { param } => {
                format!("Query parameter {} is not declared in the API schema", param)
            }
            SchemaViolation::MissingRequiredField { field } => {
                format!("Required request body field {} is missing", field)
            }
            SchemaViolation::UndeclaredBodyField { field } => {
                format!("Request body field {} is not declared in the API schema", field)
            }
        }
    }

    pub fn snippet(&self) -> Vec<u8> {
        self.message().into_bytes()
    }
}

/// High-performance validator for OpenAPI Positive Security Model.
pub struct SchemaValidator<'a> {
    schema: &'a ApiSchema,
}

impl<'a> SchemaValidator<'a> {
    pub fn new(schema: &'a ApiSchema) -> Self {
        Self { schema }
    }

    /// Validates an incoming request against the OpenAPI schema.
    pub fn validate(
        &self,
        method: &str,
        path: &str,
        query_params: &[(&str, &str)],
        body_json: Option<&[u8]>,
    ) -> Vec<SchemaViolation> {
        let mut violations = Vec::new();

        let endpoint = match self.schema.match_endpoint(path) {
            Some(ep) => ep,
            None => {
                if !self.schema.allow_unknown_endpoints {
                    violations.push(SchemaViolation::UnknownEndpoint {
                        path: path.to_string(),
                    });
                }
                return violations;
            }
        };

        // 1. Method check
        let upper_method = method.to_ascii_uppercase();
        if !endpoint.methods.is_empty()
            && !endpoint.methods.iter().any(|m| m.eq_ignore_ascii_case(&upper_method))
        {
            violations.push(SchemaViolation::MethodNotAllowed {
                method: upper_method,
                allowed: endpoint.methods.clone(),
            });
        }

        // 2. Query parameters check
        if !endpoint.allow_extra_params {
            let allowed_set: HashSet<String> = endpoint
                .allowed_query_params
                .iter()
                .map(|p| p.to_ascii_lowercase())
                .collect();

            for &(param_name, _) in query_params {
                if !allowed_set.contains(&param_name.to_ascii_lowercase()) {
                    violations.push(SchemaViolation::UndeclaredParam {
                        param: param_name.to_string(),
                    });
                }
            }
        }

        // 3. Request Body check (if JSON)
        if let Some(body) = body_json
            && !body.is_empty()
        {
            let parsed_keys = extract_json_keys(body);
                let present_set: HashSet<String> =
                    parsed_keys.iter().map(|k| k.to_string()).collect();

                // Check required fields
                for req in &endpoint.required_fields {
                    if !present_set.contains(req) {
                        violations.push(SchemaViolation::MissingRequiredField {
                            field: req.clone(),
                        });
                    }
                }

                // Check undeclared fields
                if !endpoint.allow_extra_fields && !endpoint.allowed_fields.is_empty() {
                    let mut allowed_all: HashSet<String> =
                        endpoint.allowed_fields.iter().cloned().collect();
                    for req in &endpoint.required_fields {
                        allowed_all.insert(req.clone());
                    }

                    for key in &parsed_keys {
                        if !allowed_all.contains(key) {
                            violations.push(SchemaViolation::UndeclaredBodyField {
                                field: key.clone(),
                            });
                        }
                    }
                }
        }

        violations
    }
}

/// Helper function to extract top-level object keys from a JSON buffer.
fn extract_json_keys(bytes: &[u8]) -> Vec<String> {
    let mut keys = Vec::new();
    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t.trim(),
        Err(_) => return keys,
    };

    if !text.starts_with('{') {
        return keys;
    }

    let mut in_str = false;
    let mut escaped = false;
    let mut depth = 0;
    let mut current_str = String::new();
    let mut is_key = false;

    let chars = text.chars();
    for c in chars {
        if in_str {
            if escaped {
                current_str.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
                if is_key && depth == 1 {
                    keys.push(current_str.clone());
                    is_key = false;
                }
            } else {
                current_str.push(c);
            }
            continue;
        }

        match c {
            '"' => {
                in_str = true;
                current_str.clear();
            }
            '{' => {
                depth += 1;
                if depth == 1 {
                    is_key = true;
                }
            }
            '}' => {
                if depth > 0 {
                    depth -= 1;
                }
                is_key = false;
            }
            ',' if depth == 1 => {
                is_key = true;
            }
            ':' if depth == 1 => {
                is_key = false;
            }
            _ => {}
        }
    }

    keys
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_path_matching() {
        let ep = ApiEndpoint::new("/api/v1/users/{id}").with_methods(&["GET", "PUT"]);
        assert!(ep.matches_path("/api/v1/users/42"));
        assert!(ep.matches_path("api/v1/users/admin"));
        assert!(!ep.matches_path("/api/v1/users"));
        assert!(!ep.matches_path("/api/v1/users/42/details"));
        assert!(!ep.matches_path("/api/v2/users/42"));
    }

    #[test]
    fn test_validator_allowed_requests() {
        let mut schema = ApiSchema::new("test-api", "User Service", "1.0.0");
        schema.add_endpoint(
            ApiEndpoint::new("/api/v1/users")
                .with_methods(&["GET", "POST"])
                .with_query_params(&["page", "limit"], false)
                .with_body_fields(&["username", "email"], &["username", "email", "age"], false),
        );

        let validator = SchemaValidator::new(&schema);

        // Valid GET request
        let v = validator.validate("GET", "/api/v1/users", &[("page", "1"), ("limit", "20")], None);
        assert!(v.is_empty());

        // Valid POST request with JSON body
        let body = br#"{"username": "alice", "email": "alice@example.com", "age": 30}"#;
        let v = validator.validate("POST", "/api/v1/users", &[], Some(body));
        assert!(v.is_empty());
    }

    #[test]
    fn test_validator_violations() {
        let mut schema = ApiSchema::new("test-api", "User Service", "1.0.0");
        schema.add_endpoint(
            ApiEndpoint::new("/api/v1/users")
                .with_methods(&["GET", "POST"])
                .with_query_params(&["page"], false)
                .with_body_fields(&["username"], &["username", "email"], false),
        );

        let validator = SchemaValidator::new(&schema);

        // 1. Unknown endpoint
        let v = validator.validate("GET", "/api/v1/unknown", &[], None);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule_id(), RULE_UNKNOWN_ENDPOINT);

        // 2. Method not allowed (DELETE on /api/v1/users)
        let v = validator.validate("DELETE", "/api/v1/users", &[], None);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule_id(), RULE_METHOD_NOT_ALLOWED);

        // 3. Undeclared query param (?debug=true)
        let v = validator.validate("GET", "/api/v1/users", &[("debug", "true")], None);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule_id(), RULE_UNDECLARED_PARAM);

        // 4. Missing required field in body
        let body_missing = br#"{"email": "test@example.com"}"#;
        let v = validator.validate("POST", "/api/v1/users", &[], Some(body_missing));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule_id(), RULE_MISSING_REQUIRED_FIELD);

        // 5. Undeclared field in body (extra "role": "admin")
        let body_undeclared = br#"{"username": "bob", "role": "admin"}"#;
        let v = validator.validate("POST", "/api/v1/users", &[], Some(body_undeclared));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule_id(), RULE_UNDECLARED_BODY_FIELD);
    }
}
