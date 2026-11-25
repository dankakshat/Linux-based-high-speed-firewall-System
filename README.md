# XDP-Engine (Python)

A Python-powered **eBPF/XDP Intrusion Mitigation & SOAR Engine** with real-time log correlation, automated YAML playbooks, an interactive CLI controller, and a live Flask telemetry dashboard.

---

## Key Features

* **Dual Packet Backends**:
  * **`ebpf-bcc` (Linux Kernel 5.8+)**: Compiles and attaches an XDP packet filter directly to a network interface from Python via BCC, tracking up to 1,000,000 blocked IPs and detecting port sweeps / SYN floods in kernel space.
  * **`python-sim` (Cross-Platform)**: Pure-Python packet filter and attack simulator that runs on Windows, macOS, and Linux without root privileges for development, testing, and live demos.
* **Real-Time Log Detection (SIEM)**: Asynchronous log tailing (`LogTailer`) with rotation handling for HTTP access logs (SQLi, path traversal, XSS) and SSH auth logs (brute-force failures).
* **Stateful Rule Engine (`rules.yaml`)**: Supports sliding-window `threshold` rules (`SSH_BRUTE_FORCE`, `HTTP_ATTACK`, `PORT_SCAN`, `SYN_FLOOD`) and multi-stage `sequence` correlation (`SCAN_THEN_BRUTE`).
* **Automated SOAR Playbooks (`playbooks.yaml`)**: Executes `enrich`, `block`, `notify` (webhook via `XDP_WEBHOOK_URL`), and `record` (SQLite WAL).
* **Dynamic Mode Switching**: Toggle seamlessly between **`detect`** (audit-only) and **`enforce`** (active drops) via console or `xdp-cli`.
* **Safety Guardrails**: Automatically whitelists `127.0.0.1`, `::1`, local interface IPs, and default gateway routes to prevent self-lockout.
* **Live Telemetry Dashboard**: Flask web console (`/`) and presentation showcase (`/?showcase=1`) backed by SQLite WAL.

---

## Project Structure

```text
xdp-engine/
├── xdp_engine/
│   ├── backends/
│   │   ├── base.py          # Abstract PacketBackend contract
│   │   ├── ebpf_bcc.py      # Linux XDP/eBPF backend via Python BCC
│   │   └── simulator.py     # Cross-platform pure-Python backend
│   ├── detectors.py         # HttpDetector, SshDetector, LogTailer
│   ├── rule_engine.py       # Threshold + sequence correlation engine
│   ├── playbook_runner.py   # SOAR playbook execution & guardrails
│   ├── storage.py           # Thread-safe SQLite WAL persistence
│   ├── notifier.py          # Webhook alert dispatcher
│   ├── ipc.py               # Localhost JSON control server/client
│   ├── engine.py            # Main daemon & interactive console
│   └── cli.py               # Standalone IPC CLI controller
├── dashboard/
│   ├── app.py               # Flask telemetry API & UI server
│   └── templates/
│       ├── index.html       # Operations console
│       └── showcase.html    # Live exhibition/showcase view
├── tests/
│   └── test_engine.py       # Unit & end-to-end integration tests
├── simulate_attacks.py      # 5-scenario attack lab script
├── rules.yaml               # Detection rules
├── playbooks.yaml           # Response playbooks
├── known_ips.txt            # Static whitelist
├── blocklist.txt            # Static blocklist
└── requirements.txt
```

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

*(For real Linux kernel XDP mode, also install your distro's `python3-bcc` / `bcc` package and run with `sudo`.)*

### 2. Run the Web Dashboard
```bash
python -m dashboard.app
```
Open `http://127.0.0.1:5000` (or `http://127.0.0.1:5000/?showcase=1` for Showcase Mode).

### 3. Start the Engine
```bash
# Cross-platform simulator mode:
python -m xdp_engine.engine sim0 --backend sim --mode detect

# Linux real eBPF/XDP mode (requires root + python3-bcc):
sudo python3 -m xdp_engine.engine eth0 --backend bcc --mode detect
```

### 4. Control via Interactive Console or `cli`
Inside the engine terminal (or from another terminal using `python -m xdp_engine.cli <cmd>`):
* `mode enforce` / `enforce` — Switch to active packet dropping
* `mode detect` / `detect` — Switch to audit-only detection
* `block <IP> [TTL]` — Manually block an IP
* `unblock <IP>` — Remove an IP block
* `allow <IP>` / `unallow <IP>` — Manage whitelist
* `list` — Show active blocked IPs and remaining TTLs
* `stats` — Print packet counters and drop rate
* `alerts` — Print recent security alerts
* `quit` — Detach cleanly and exit

---

## Attack Simulation & Tests

Run the full 5-scenario simulation demo:
```bash
python simulate_attacks.py --scenario all-demo
```

Run the automated test suite:
```bash
python -m unittest discover -s tests -v
```
