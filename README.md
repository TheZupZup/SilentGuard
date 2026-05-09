# SilentGuard

[![Release](https://img.shields.io/badge/release-v0.1.0--alpha-blue)](https://codeberg.org/TheZupZup/SilentGuard/releases)
[![AUR](https://img.shields.io/badge/AUR-available-blue?logo=arch-linux)](#)
[![Python](https://img.shields.io/badge/python-3.x-blue?logo=python)](#)
![CI](https://github.com/TheZupZup/SilentGuard/actions/workflows/python-app.yml/badge.svg)



A lightweight network & privacy monitor with smart alerts.

SilentGuard helps you visualize outgoing network connections in real time and detect suspicious activity on your system.

---
## Screenshots

![SilentGuard UI](screenshot.png)

---

## Features

- Real-time monitoring of outgoing connections
- Process → IP mapping
- Trust classification with local rules file (`~/.silentguard_rules.json`):
  - Known (process matches `known_processes`)
  - Trusted (remote IP matches `trusted_ips`)
  - Unknown (everything else, surfaced for review)
  - Local (loopback, RFC 1918, link-local)
  - Blocked (remote IP matches `blocked_ips`)
- Detection of new connections
- Simple and clean GTK interface
- TUI mode with memory actions, blocklist updates (`B` key), and JSON export (`E` key)
- Local flood / DDoS-style anomaly detection (visibility only — never
  automatic blocking; cannot absorb upstream bandwidth saturation)
- Opt-in, human-approved temporary local mitigation (default mode is
  `detection_only` — see "Opt-in flood mitigation" below for the full
  safety contract)

---

## Requirements

- Python 3
- GTK 3
- psutil

---
## Quick start

# Codeberg
```bash
git clone https://codeberg.org/TheZupZup/SilentGuard
cd SilentGuard
pip install .
silentguard
```

# TUI (server / headless)
```
silentguard-tui
```
---

## How to run

```bash
pip install .
silentguard      # GTK GUI
silentguard-tui  # Text UI
silentguard-api  # Read-only local API (optional)
```

## Read-only local API (preview)

SilentGuard ships an optional local-only HTTP API that exposes the same
data the TUI/GUI display. It is intended as the foundation for future
integrations (notably Nova) to consume SilentGuard state.

Important properties:

- **Local-only by default.** Binds to `127.0.0.1:8765`.
- **Read-only.** Only `GET` is supported. The API never blocks IPs,
  unblocks IPs, mutates trusted IPs, or touches the firewall.
- **Optional.** The TUI and GUI work whether or not the API is running.
- **No new dependencies.** Built on the Python standard library.

Start it with:

```bash
silentguard-api               # http://127.0.0.1:8765
silentguard-api --port 9000   # custom port
```

Endpoints:

| Method | Path                            | Purpose                                          |
| ------ | ------------------------------- | ------------------------------------------------ |
| GET    | `/status`                       | API identity / health summary                    |
| GET    | `/connections`                  | Current outgoing connection snapshot             |
| GET    | `/connections/summary`          | Compact aggregate view of outgoing connections   |
| GET    | `/connections/recent-unknown`   | Recently observed unknown destinations (cached)  |
| GET    | `/blocked`                      | Locally-marked blocked IPs from rules            |
| GET    | `/trusted`                      | Trusted IPs from rules                           |
| GET    | `/alerts`                       | Local flood / anomaly alerts (detection only)    |
| GET    | `/alerts/summary`               | Compact alert counts by severity / type          |
| GET    | `/mitigation`                   | Current mitigation mode, active temp blocks, audit tail |
| POST   | `/mitigation/enable-temporary`  | Switch to opt-in `temporary_auto_block` mode (loopback only) |
| POST   | `/mitigation/disable`           | Return to `detection_only` (loopback only)       |
| POST   | `/blocked/temporary`            | Add a temporary local block (loopback only)      |
| POST   | `/blocked/<ip>/unblock`         | Remove a temporary local block (loopback only)   |

Each endpoint returns JSON. Collections use a stable `{"items": [...]}`
shape so future schema additions stay backwards compatible. When data is
not yet available (for example, alerts are not implemented yet), the
response includes `"status": "not_available"` alongside an empty list.

### `/connections/summary`

`/connections/summary` is intended for Nova and other local tools that
want to describe the network state at a glance without parsing the full
connection list. It is **visibility only** — it does not, and never will,
control the firewall, mutate rules, or take any action.

Example payload:

```json
{
  "total": 55,
  "local": 38,
  "known": 12,
  "unknown": 5,
  "trusted": 2,
  "blocked": 0,
  "recent_unknown": [
    {
      "ip": "203.0.113.10",
      "process": "firefox",
      "seen_count": 3,
      "first_seen": "2026-05-09T20:10:00Z",
      "last_seen": "2026-05-09T20:15:00Z",
      "classification": "unknown"
    }
  ],
  "by_process": [
    {"process": "firefox", "count": 8, "known": 6, "unknown": 2}
  ],
  "top_remote_hosts": [
    {"ip": "93.184.216.34", "count": 3, "classification": "known"}
  ]
}
```

Notes:

- Top-level counts use the canonical classifications (`local`, `known`,
  `unknown`, `trusted`, `blocked`). Each connection has exactly one
  classification: blocked > trusted > local > known > unknown.
- `recent_unknown` is read from a small local cache of recently-seen
  unknown destinations (see "Connection classification & unknown
  tracking" below). It is capped to a small safe number per response.
- `by_process` groups connections by process name and is capped to a
  small number of entries.
- `top_remote_hosts` lists the most-frequent non-local remote IPs and is
  also capped. Hostnames are not resolved (the API performs no DNS or
  external network calls), so only the IP is reported.
- When no connections can be enumerated (for example, if `psutil` lacks
  permissions), the response carries zeros plus `"status": "not_available"`.

### `/connections/recent-unknown`

Returns the most-recently-seen unknown destinations from the local
cache, as the read-only equivalent of the `recent_unknown` field in
the summary but with a larger cap so consumers can paginate or browse:

```json
{
  "items": [
    {
      "ip": "203.0.113.10",
      "process": "firefox",
      "seen_count": 3,
      "first_seen": "2026-05-09T20:10:00Z",
      "last_seen": "2026-05-09T20:15:00Z",
      "classification": "unknown"
    }
  ]
}
```

If the cache is unreadable, the response degrades gracefully to
`{"items": [], "status": "not_available"}`.

### `/alerts` and `/alerts/summary`

SilentGuard performs lightweight, **local-only** detection of patterns
that may indicate flood or DDoS-style activity. Alerts surface through
two read-only endpoints.

What this gives you:

- Visibility into the local connection state when something looks wrong.
- Deterministic thresholds with conservative defaults, so a normal
  desktop should not generate alerts.
- A stable JSON shape consumers can rely on as the schema grows.

What this **does not** do — by design, without explicit user opt-in:

- ❌ It does **not** automatically block IPs. The default mitigation
  mode is `detection_only`. Blocking is opt-in via the mitigation
  endpoints and is always temporary, reversible, and audited — see
  "Opt-in flood mitigation" below.
- ❌ It does **not** modify firewall rules (`ufw`, `firewalld`,
  `nftables`, `iptables`). Even when mitigation is enabled, the only
  enforcement is the local SilentGuard classification path.
- ❌ It does **not** run privileged or shell commands.
- ❌ It does **not** take autonomous defensive actions.
- ❌ It does **not** depend on Nova or any other external service.

Honest limitation — please read:

> SilentGuard runs on the local machine. It cannot absorb upstream DDoS
> attacks that saturate the internet uplink before traffic reaches the
> local NIC. For volumetric attacks against a public-facing service,
> use ISP- or edge-level DDoS protection. SilentGuard's detection is
> for **local visibility and alerting only**. Any future mitigation
> must require explicit human confirmation.

Detection signals (current set):

- **Per-remote-IP flood** — one remote IP appears in many concurrent
  outgoing connections.
- **Connection spike** — total active outgoing connections are
  unusually high.
- **Unknown burst** — many distinct unknown remote IPs are active in
  the current snapshot.
- **Connection churn** — many distinct unknown destinations were
  observed in the recent rolling window (5 minutes).

Severity levels are `low`, `medium`, `high`, and `critical`, assigned
deterministically from the count vs. each detector's medium / high /
critical thresholds (see `silentguard/detection.py`).

Example alert object:

```json
{
  "id": "flood-remote-ip-203.0.113.10",
  "severity": "medium",
  "type": "possible_flood",
  "title": "Repeated connections from one remote IP",
  "message": "One remote IP appears in many concurrent outgoing connections, which can indicate a flood pattern. SilentGuard detects only and does not block automatically.",
  "source_ip": "203.0.113.10",
  "count": 120,
  "created_at": "2026-05-09T20:15:00Z",
  "status": "active"
}
```

`window_seconds` is included on alerts that look back over a window
(e.g. churn). Fields whose value is not applicable are omitted from
the payload to keep responses compact.

`/alerts/summary` returns a small overview that's safe to poll:

```json
{
  "total": 2,
  "by_severity": {"low": 0, "medium": 1, "high": 1, "critical": 0},
  "by_type": {"possible_flood": 1, "connection_churn": 1},
  "highest_severity": "high"
}
```

If the underlying monitor cannot enumerate connections, both endpoints
degrade gracefully to an empty payload with `"status": "not_available"`.

The `/alerts` endpoint exposes alert summaries only. It deliberately
does **not** include raw packet data, full process command lines,
process environment variables, or PIDs / ports — see
`silentguard/detection.py` for the schema and `connection_state.py`
for the cache storage policy.

### Opt-in flood mitigation (local, temporary, reversible)

SilentGuard ships an **opt-in** mitigation layer for the same flood/DDoS
patterns the `/alerts` endpoint surfaces. It is intentionally narrow:

- **Default mode is `detection_only`. SilentGuard never blocks
  automatically out of the box.** Mitigation has to be turned on by an
  explicit user action via the local API.
- Blocks are **temporary, time-bounded, and reversible**. Each block
  has an `expires_at` timestamp and is removed automatically when it
  expires. There is also an explicit unblock endpoint.
- Blocks are **local-only**. SilentGuard does not touch `iptables` /
  `nftables` / `ufw` / `firewalld`. It marks the IP as `Blocked` in
  the SilentGuard classification path so the TUI/GUI/API report it
  consistently. Real firewall integration is intentionally out of
  scope for this PR.
- Every block, unblock, expiry, mode change, and rejection is recorded
  in a local audit log (`~/.silentguard_mitigation_audit.json`).

> **Honest limitation.** SilentGuard cannot absorb upstream DDoS
> attacks that saturate the internet uplink before traffic reaches the
> local NIC. This feature is **local mitigation only**. For volumetric
> attacks against a public-facing service, use ISP- or edge-level DDoS
> protection.

#### Modes

- `detection_only` (default) — never blocks. Detection runs, alerts
  surface via `/alerts`, the user is in full control.
- `ask_before_blocking` — surface the prompt to the UI/Nova so the
  user can decide whether to enable enforcement. The mode itself
  still does not auto-block; flipping to `temporary_auto_block` is a
  separate explicit action.
- `temporary_auto_block` — auto-block IPs that exceed the strict
  high-severity flood threshold (`REMOTE_IP_FLOOD_HIGH`, currently
  200 concurrent connections) for a bounded duration. Must be
  enabled explicitly with `acknowledge: true` in the request body.

#### What is **never** auto-blocked

The mitigation module refuses any of the following, even when the
mode is `temporary_auto_block`:

- Loopback (`127.0.0.0/8`, `::1`).
- RFC 1918 private ranges (`10/8`, `172.16/12`, `192.168/16`).
- Link-local (`169.254/16`, `fe80::/10`).
- Multicast, reserved, and unspecified addresses (covers most LAN
  hardware and gateway/router IPs whose addresses are private).
- Any IP in the `trusted_ips` list of `~/.silentguard_rules.json`.
- Any IP in the user-configured `protected_ips` list (see below).
- IPs that are already temporarily blocked.

`protected_ips` is the user's explicit allowlist for VPN/Tailscale/
Cloudflare-Tunnel endpoints, DNS resolvers, and the Nova/SilentGuard
host's own IPs. Populate it in `~/.silentguard_mitigation.json`:

```json
{
  "version": 1,
  "mode": "detection_only",
  "protected_ips": ["100.64.0.1", "1.1.1.1", "192.0.2.1"],
  "temp_blocks": []
}
```

#### Conservative thresholds and rate limits

- Auto-block fires only on `possible_flood` alerts at `high` or
  `critical` severity. `medium` alerts always surface for human
  review only.
- Block lifetimes are clamped to the `[30, 3600]` second range, with
  a default of 600 seconds (10 minutes). Temporary blocks self-heal.
- The mitigation policy refuses more than 10 automatic blocks within
  any 60-second window. Burst rejections are recorded in the audit
  log with `rejection_reason: "rate_limited"`.

#### `GET /mitigation`

Returns the current mode, the auto-block threshold, the rate-limit
posture, the active temporary blocks, the protected-IP list, and the
last few audit entries. Read-only and safe to poll.

```json
{
  "mode": "detection_only",
  "default_mode": "detection_only",
  "available_modes": ["detection_only", "ask_before_blocking", "temporary_auto_block"],
  "prompt": "This activity resembles a possible flood/DDoS-style attack. ...",
  "disclaimer": "SilentGuard cannot absorb upstream DDoS attacks ...",
  "auto_block_threshold": "REMOTE_IP_FLOOD_HIGH",
  "auto_block_severities": ["critical", "high"],
  "auto_block_rate_limit": {"max_blocks": 10, "window_seconds": 60},
  "temp_block_duration_seconds": {"default": 600, "min": 30, "max": 3600},
  "protected_ips": [],
  "active_temp_blocks": [],
  "recent_audit": []
}
```

#### `POST /mitigation/enable-temporary`

Body **must** include `"acknowledge": true`. Without it the request
is rejected with `400 acknowledge_required` so the mode cannot be
escalated by accident. The endpoint is loopback-only; non-loopback
callers receive `403 forbidden` even when the server is bound to a
broader interface.

```bash
curl -X POST http://127.0.0.1:8765/mitigation/enable-temporary \
     -H "Content-Type: application/json" \
     -d '{"acknowledge": true, "note": "operator confirmed"}'
```

#### `POST /mitigation/disable`

Returns to `detection_only`. Optionally clears any active temporary
blocks if `"clear_temp_blocks": true` is set.

#### `POST /blocked/temporary`

Adds a single temporary block. Validates the IP against the full
never-block list above. Always records an audit entry — including
on rejection — so the operator has a complete timeline.

```bash
curl -X POST http://127.0.0.1:8765/blocked/temporary \
     -H "Content-Type: application/json" \
     -d '{"ip": "203.0.113.10", "reason": "manual", "duration_seconds": 600}'
```

#### `POST /blocked/<ip>/unblock`

Removes a temporary block. Returns `404` if no such block exists.

#### Nova's role

Nova **explains and asks**. It does not enforce.

- Nova may render the prompt copy from `GET /mitigation` and ask the
  user whether to enable temporary mitigation.
- Nova must **not** silently enable mitigation. The flow is always
  user-initiated.
- Nova must **not** block IPs directly. If the user agrees, Nova
  calls `POST /mitigation/enable-temporary` with `acknowledge: true`
  and SilentGuard owns enforcement.
- Nova must clearly state when the mode is active.

### Connection classification & unknown tracking

SilentGuard owns its classification logic in
`silentguard/connection_state.py` so the TUI, GUI, and API report the
same labels for the same data. Each outgoing connection is classified
exactly once using this precedence:

1. `blocked` — remote IP matches `blocked_ips` in the rules file.
2. `trusted` — remote IP matches `trusted_ips` in the rules file.
3. `local`   — remote IP is loopback, RFC 1918, or link-local.
4. `known`   — process name matches `known_processes`.
5. `unknown` — anything else.

To help local consumers like Nova describe newly-observed traffic,
SilentGuard maintains a small on-disk cache of recently-seen unknown
destinations at `~/.silentguard_unknown.json`. The cache is updated
whenever connections are enumerated (TUI/GUI refresh, or a hit on
`/connections/summary`).

What the cache **stores** for each entry:

- `ip` — remote IP only (no DNS resolution is ever performed).
- `process` — the observed process name, when safely available.
- `first_seen` / `last_seen` — UTC ISO timestamps.
- `seen_count` — number of snapshots in which the destination appeared.
- `classification` — current canonical classification. Entries that
  transition out of `unknown` (e.g. you trusted the IP) keep their row
  with the updated label so the transition is visible.

What the cache **does not** store, by design:

- No PIDs, ports, or per-connection rows.
- No process command lines or arguments.
- No environment variables.
- No raw socket data, packet contents, or byte counters.
- No DNS lookups or remote hostnames sourced from the network.

The cache is local-only and intended as read-only context for tools
that ask SilentGuard about its state. SilentGuard never sends it
anywhere, never blocks IPs based on it, and Nova consumes it only
read-only.

## Rules file (optional)

Create `~/.silentguard_rules.json` to customize trust classification:

```json
{
  "known_processes": ["firefox", "python3"],
  "trusted_ips": ["1.1.1.1"],
  "blocked_ips": ["203.0.113.10"]
}
```

When an IP is in `blocked_ips`, it appears as `Blocked` in the UI/TUI.
When an IP is in `trusted_ips`, it appears as `Trusted` and is reported
separately from `Known` in API summaries.
---

## Arch Linux (AUR - in progress)

You can already build and install manually:

```bash
git clone https://codeberg.org/TheZupZup/SilentGuard
cd SilentGuard/packaging/aur
makepkg -si
```
---
## Mirror & Contributing

- GitLab: https://gitlab.com/TheZupZup/SilentGuard
- Codeberg: https://codeberg.org/TheZupZup/SilentGuard

Contributions welcome! Check the [ROADMAP](ROADMAP.md) and open issues.
Feel free to open a PR or issue on either platform.

## Status 

Early development — actively improving

## Branding

The name "SilentGuard" and associated branding may not be used without permission.
