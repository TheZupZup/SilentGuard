# SilentGuard — Reality-Based Roadmap

This document replaces aspirational planning with immediately actionable work based on the current codebase.

---

## Issue 1: Establish a reliable local dev/test workflow

## Overview
Current tests do not run out of the box in a clean environment because import paths and runtime dependencies are not documented or enforced in test commands.

## What needs to be done
- [ ] Add a `make test` (or documented equivalent) that sets `PYTHONPATH=src`.
- [ ] Add `requirements-dev.txt` or update docs so `pytest` and runtime dependencies are installed predictably.
- [ ] Add a CI check that runs tests exactly as contributors are expected to run them.

## Goal
Any contributor can clone the repo and run tests successfully with one documented command.

## Notes
Existing tests cover only parts of `monitor.py`; no UI/TUI behavior is currently validated.

Labels: `good first issue`

---

## Issue 2: Remove or merge duplicate GTK entrypoints

## Overview
`src/silentguard/main.py` contains the GTK app implementation while `src/silentguard/ui.py` is an empty file, which is confusing and suggests unfinished refactoring.

## What needs to be done
- [ ] Decide one canonical GTK module (`main.py` or `ui.py`).
- [ ] Remove dead file(s) or move code and keep compatibility import path if needed.
- [ ] Update README references if module names change.

## Goal
The GTK UI has one clear home in the source tree.

## Notes
This is a code-clarity task only; no feature expansion needed.

Labels: `good first issue`

---

## Issue 3: Make blocking language honest (UI blocklist vs firewall block)

## Overview
Current “block” behavior writes IPs to the local rules/memory files and marks trust as `Blocked`, but it does not block network traffic at OS/firewall level. The opt-in mitigation flow (see `silentguard/mitigation.py`) layers temporary, reversible local blocks on top of the same classification path — still no firewall integration, by design.

## What needs to be done
- [ ] Update README and in-app wording to clearly say “mark as blocked in SilentGuard” unless real firewall integration exists.
- [ ] Add a short architecture note explaining current behavior and limitations.
- [ ] Add tests for rule-file block/unblock behavior (already partly covered) and ensure docs match behavior.

## Goal
Users are not misled into thinking SilentGuard enforces network policy today.

## Notes
Do **not** implement privileged firewall integration in this issue. The
mitigation layer added in the flood-mitigation PR is **local only**,
opt-in, temporary, and reversible. It is not a substitute for upstream
DDoS protection or for an OS-level firewall.

Labels: `help wanted`

---

## Issue 4: Stabilize memory file behavior

## Overview
`memory.py` works as a simple append/remove JSON store but lacks schema validation, migration strategy, and corruption recovery beyond fallback to empty data.

## What needs to be done
- [ ] Define minimal entry schema (`action`, `target`, `reason`, `timestamp`).
- [ ] Validate loaded data shape before using it in TUI.
- [ ] Add tests for malformed but valid-JSON memory content.

## Goal
Memory mode remains usable even with partially bad local data.

## Notes
Keep this file-based and local; no database migration needed yet.

Labels: `help wanted`

---

## Issue 5: Convert placeholder modules into tracked decisions

## Overview
`actions.py`, `rules.py`, and `blocked_view.py` are mostly placeholders with TODO comments and non-functional stubs.

## What needs to be done
- [ ] For each module, choose one: implement MVP behavior now or remove the module until needed.
- [ ] If keeping stubs, raise explicit `NotImplementedError` in callable placeholders.
- [ ] Link each kept placeholder to a concrete roadmap item.

## Goal
Repository no longer implies implemented capability where none exists.

## Notes
Avoid speculative abstractions (service rules, advanced kill workflows) until core monitoring quality improves.

Labels: `help wanted`

---

## Not planned yet (intentionally deferred)

These are currently too large or too risky for the project stage:

- Full firewall backend matrix (ufw/firewalld/nftables) with cross-distro support.
- Automated process-kill and reaction pipelines.
- Advanced service-level rule engines.
- Complex GUI/TUI feature parity work before baseline testing/packaging is stable.

Focus first on reliability, clarity, and contributor onboarding.
