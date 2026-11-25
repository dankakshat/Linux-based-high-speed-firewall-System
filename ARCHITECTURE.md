# Architecture

XDP-Engine uses a modular three-tier Python architecture: a pluggable Packet Filtering Backend, a User-Space Detection & SOAR Daemon, and a Read-Only Flask Telemetry Dashboard.

```text
+-------------------------------------------------------------------+
|                     PACKET FILTERING LAYER                        |
|  - BccXdpBackend (Linux kernel XDP via Python BCC)                |
|  - SimulatorBackend (Cross-platform pure-Python filter)           |
|    * Maps: blocked_ips, allowed_ips, stats, scan_tracker          |
+----------------------------+--------------------------------------+
                             | telemetry events / map updates
                             v
+-------------------------------------------------------------------+
|                   USER-SPACE ENGINE (Python)                      |
|  [LogTailer] -> [HttpDetector / SshDetector]                      |
|                        |                                          |
|                        v (SecurityEvent)                          |
|                  [RuleEngine] <--- rules.yaml                     |
|                        |                                          |
|                        v (Alert)                                  |
|                [PlaybookRunner] <--- playbooks.yaml               |
|                  |     |     |                                    |
|           block  |     |     | record                             |
|                  v     |     v                                    |
|            [Backend]   |  [Storage (SQLite WAL)] <-- [IPC Server] |
|                        v                                          |
|                   [Notifier (Webhook)]                            |
+----------------------------+--------------------------------------+
                             | read-only SQLite queries
                             v
+-------------------------------------------------------------------+
|                PRESENTATION LAYER (Flask UI)                      |
|  dashboard/app.py -> / (Operations) & /?showcase=1 (Showcase)     |
+-------------------------------------------------------------------+
```
