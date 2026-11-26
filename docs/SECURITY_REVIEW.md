# SecScan v0.2 Security Review

This document tracks security findings and controls verified across the v0.2 Web UI and Docker packaging.

| Finding / Control | Source | Severity | Status | Covering Test / Check |
|---|---|---|---|---|
| Report JSON Schema v1 strict validation (size `<= 5 MiB`, depth `<= 16`, symlink escape, legacy v0.1 rejection) | Design / Threat Model | High | Implemented | `tests/test_ui_backend/test_schema_and_store.py` |
| Path-traversal `scan_id` rejection | Design / Threat Model | High | Implemented | `test_path_traversal_scan_id_rejected` |
| Stored XSS & ANSI/control-char neutralization in UI | Web Security Req. | High | Implemented | `test_escapes_xss_and_strips_ansi_control_chars` |
| Strict CSP (`script-src 'none'`, `frame-ancestors 'none'`), `nosniff`, `no-referrer`, `no-store` | Web Security Req. | High | Implemented | `test_security_headers_present` |
| `Host` header allowlist (DNS-rebinding defence) | Web Security Req. | High | Implemented | `test_bad_host_header_rejected` |
| Synchronizer CSRF protection (`SameSite=Strict`) | Web Security Req. | High | Implemented | `test_missing_csrf_token_rejected` |
| Malicious declarative dashboard JSON rejection (no HTML/URLs/control chars) | Web Security Req. | Medium | Implemented | `test_malicious_dashboard_json_rejected` |
| Request size cap (`64 KiB`) & per-IP rate limiting (`429`) | Web Security Req. | Medium | Implemented | `test_oversized_post_rejected`, `test_rate_limit_returns_429` |
| Fail-closed non-localhost bind guard | Web Security Req. | High | Implemented | `test_non_localhost_bind_fails_closed` |
| Hardened Docker container (`read_only`, `cap_drop: [ALL]`, `no-new-privileges`, `:ro` reports, `127.0.0.1` publish, fail-closed `HOST_UID`/`HOST_GID`) | Docker Security Req. | High | Implemented (pending live Docker daemon test) | `Dockerfile`, `docker-compose.yml`, CI `docker-smoke` job |
