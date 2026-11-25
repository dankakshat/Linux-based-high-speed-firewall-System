# Threat Model & Guardrails

## Mitigated Threats
1. **SSH Brute Force (`T1110`)**: Sliding-window detection of repeated authentication failures in SSH logs.
2. **Web Exploitation (`T1190`)**: Pattern detection for SQL injection, directory traversal (`../`, `%2e%2e`), and reflected XSS payloads in HTTP access logs.
3. **Network Reconnaissance (`T1046`)**: High-frequency unique-port TCP SYN sweep tracking.
4. **Multi-Stage Intrusion (`SCAN_THEN_BRUTE`)**: Sequence correlation escalating port scans followed by SSH login attempts into extended 1-hour blocks.
5. **Volumetric SYN Flood (`T1498`)**: Rapid SYN burst detection and high-speed packet dropping when operating in `enforce` mode.

## Self-Lockout Safeguards
* Loopback (`127.0.0.1`, `::1`), local NIC addresses, and discovered default gateways are automatically added to `guardrail_ips` and kernel/backend `allowed_ips`.
* Static trusted hosts in `known_ips.txt` are protected on boot and cannot be blocked via automated playbooks or manual `block` commands.
* `detect` mode enables full rule evaluation and dashboard auditing without dropping live traffic.
