# ngx_http_strata_module

NGINX dynamic module connector for Strata WAF engine (`libstrata`).  
Architectural design: `docs/design/nginx-module.md`.

---

## 1. Build and Test Commands

```bash
# Build NGINX with dynamic module
deploy/dev/run.sh make nginx NGINX_VERSION=1.25.4

# Run test suite with Test::Nginx
deploy/dev/run.sh make test-nginx NGINX_VERSION=1.25.4

# Memory sanitizers (AddressSanitizer + UndefinedBehaviorSanitizer)
deploy/dev/run.sh make nginx-asan test-nginx-asan NGINX_VERSION=1.25.4

# Valgrind memory leak verification
deploy/dev/run.sh make test-nginx-valgrind
```

---

## 2. Configuration Directives Reference (W15-N-01)

The module provides the following configuration directives matching the C implementation (`connectors/nginx/src/ngx_http_strata_module.c`):

| Directive | Context | Syntax & Default | Description |
| :--- | :--- | :--- | :--- |
| `strata` | `http`, `server`, `location` | `strata on \| off;`<br>Default: `off` | Enables or disables WAF inspection in this context. |
| `strata_control_file` | `http` | `strata_control_file <path>;` | Path to atomic control file specifying current active bundle generation. |
| `strata_bundle_dir` | `http` | `strata_bundle_dir <path>;` | Directory containing verified immutable `.bundle` binary packages. |
| `strata_bundle_pubkey` | `http` | `strata_bundle_pubkey <path>;` | Path to raw 32-byte Ed25519 public key file for bundle signature verification. |
| `strata_bundle_check` | `http` | `strata_bundle_check <time>;`<br>Default: `1s` | Interval for checking generation changes in `strata_control_file`. |
| `strata_node_id` | `http` | `strata_node_id <string>;` | Node identifier stamped on every emitted security event. |
| `strata_event_socket` | `http` | `strata_event_socket <unix_path>;` | Path to Unix datagram socket read by `strata-agent`. |
| `strata_metrics_file` | `http` | `strata_metrics_file <path>;` | Path to local Prometheus textfile metrics export. |
| `strata_policy` | `server`, `location` | `strata_policy <name>;` | Specifies the WAF policy name applied to matching requests. |
| `strata_mode` | `http`, `server`, `location` | `strata_mode by_policy \| shadow \| enforce \| off;`<br>Default: `by_policy` | Overrides policy action mode (`shadow` logs without blocking, `enforce` blocks matching attacks). |
| `strata_fail_mode` | `http`, `server`, `location` | `strata_fail_mode open \| closed;`<br>Default: `open` | Fail-open allows request through on engine error/budget timeout; fail-closed returns 503 with Event ID. |
| `strata_request_body_mode` | `http`, `server`, `location` | `strata_request_body_mode by_policy \| on \| off;`<br>Default: `by_policy` | Controls request body buffering and inspection. |
| `strata_request_body_limit`| `http`, `server`, `location` | `strata_request_body_limit <size>;`<br>Default: `128k` | Maximum request body buffer inspected. Requests larger than this trigger oversize handling. |
| `strata_response_inspect` | `http`, `server`, `location` | `strata_response_inspect on \| off;`<br>Default: `off` | Enables inspection and Data Guard masking on response bodies. |
| `strata_response_body_limit`| `http`, `server`, `location`| `strata_response_body_limit <size>;`<br>Default: `256k` | Maximum response body buffer inspected. |
| `strata_identity` | `http`, `server`, `location` | `strata_identity <string_or_var>;` | Expression evaluating client identity (e.g. `$http_authorization`, `$cookie_session`). |
| `strata_block_page` | `http`, `server`, `location` | `strata_block_page <html_or_file>;` | Custom HTML block page template supporting `{{block_id}}`, `{{support_contact}}`. |
| `strata_cpu_budget` | `http`, `server`, `location` | `strata_cpu_budget <msec>;`<br>Default: `50ms` | Cooperative CPU budget for request evaluation. Once budget runs out, inspection yields immediately. |
| `strata_breaker` | `http` | `strata_breaker on \| off;`<br>Default: `on` | Enables per-worker circuit breaker protection against engine crashes, timeouts, or alloc errors. |
| `strata_breaker_threshold` | `http` | `strata_breaker_threshold <type> <rate> <window> [cooldown];` | Configures circuit breaker tripping threshold (`engine`, `budget`, `alloc`, `drop`). |
| `strata_breaker_action` | `http`, `server`, `location` | `strata_breaker_action bypass \| shadow \| fail_open;`<br>Default: `shadow` | Action taken when worker circuit breaker is tripped. |

---

## 3. Example Configuration

```nginx
http {
    # Main WAF configuration
    strata_control_file   /var/lib/strata/current;
    strata_bundle_dir     /var/lib/strata/bundles;
    strata_bundle_pubkey  /etc/strata/bundle_signing.pub;
    strata_event_socket   /run/strata/events.sock;
    strata_node_id        edge-node-01;

    # Circuit breaker protection
    strata_breaker            on;
    strata_breaker_threshold  engine 0.05 10s 30s;
    strata_breaker_threshold  budget 0.10 10s 30s;

    server {
        listen 443 ssl;
        server_name api.example.test;

        # Standard API route: Enforce mode with fail-open
        location /v1/ {
            strata                on;
            strata_policy         core-api;
            strata_mode           enforce;
            strata_fail_mode      open;
            strata_cpu_budget     10ms;
            proxy_pass            http://backend;
        }

        # Sensitive Authentication & Payment route: Fail-closed protection
        location /v1/auth/ {
            strata                on;
            strata_policy         strict-auth;
            strata_mode           enforce;
            strata_fail_mode      closed;
            strata_cpu_budget     25ms;
            proxy_pass            http://auth_backend;
        }
    }
}
```
