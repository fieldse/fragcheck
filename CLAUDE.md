# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`linux-vuln-auditor` is a Go tool that audits a Linux host for vulnerability to a small set of recent kernel privilege-escalation exploits, and produces a clear, fast, structured table report the user can act on to remediate.

**Defensive tool.** It detects exposure for remediation. It does **not** run, ship, or weaponize exploit code. Detection is by kernel version-range matching (corrected for distro backports) plus exploit-precondition/mitigation heuristics — never by executing real exploit payloads.

## Status

Early scaffolding. Repo is otherwise empty — no Go module yet.

## Target CVEs

### Primary — 2026 page-cache-write privesc family

These are the focus. They are newer than the assistant's knowledge cutoff; treat this table as ground truth and do not invent details not recorded here.

| Nickname             | CVE / Advisory                       | Description (short)                                                                        |
| -------------------- | ------------------------------------ | ----------------------------------------------------------------------------------------- |
| Dirty Pipe           | CVE-2022-0847                        | Uninitialized pipe-buffer flag → page-cache write → overwrite read-only/SUID files → root  |
| Copy Fail            | CVE-2026-31431 (GHSA-2274-3hgr-wxv6) | `algif_aead` AF_ALG crypto logic bug → deterministic 4-byte page-cache write → root        |
| Dirty Frag (ESP)     | CVE-2026-43284                       | In-place ESP/IPsec decrypt over unowned skb frags → page-cache write → root (actively exploited) |
| Dirty Frag (RxRPC)   | CVE-2026-43500                       | Same flaw in RxRPC/AFS path → OOB page-cache write via unprivileged syscalls → root         |
| Fragnesia            | CVE-2026-46300                       | ESP-in-TCP lost shared-frag flag (born from Dirty Frag patch) → page-cache write → root     |

### Secondary — well-documented legacy privesc CVEs

Lower priority; useful as a baseline set with stable, public vuln ranges.

| CVE            | Name              | Subsystem            | Impact     | Vuln kernels (approx)        |
| -------------- | ----------------- | -------------------- | ---------- | ---------------------------- |
| CVE-2024-1086  | nf_tables UAF     | netfilter            | Local root | ~5.14–6.6 (CISA KEV)         |
| CVE-2023-0386  | OverlayFS privesc | OverlayFS            | Local root | ~5.11–6.2                    |
| CVE-2023-32233 | netfilter UAF     | netfilter (nf_tables)| Local root | ≤6.3.x                       |

Note: Dirty Pipe (CVE-2022-0847) is the conceptual bridge between the two sets — same page-cache-write outcome.

## Design (locked — full spec in `docs/SPEC.md`)

- **Toolchain:** Go 1.26. Module `github.com/fieldse/linux-vuln-auditor`, binary `linux-vuln-auditor`. Offline, assumes **root**, local host only.
- **Architecture seam:** `internal/collect` (impure → `HostFacts`) + `internal/detect` (pure: facts + dataset → verdicts) + `cmd/`. Keeps detection testable with fixtures, no real host needed.
- **Version source/compare:** installed kernel from package DB (`dpkg`/`rpm`, authoritative for backports); comparison shells out to native tools for correct distro semantics; backport-corrected for Ubuntu/Debian/RHEL.
- **Reboot gap:** verdict judged on the **running** kernel; patched-but-not-rebooted → still `vulnerable` with a "reboot pending" note.
- **Preconditions:** autoload-aware (loaded OR built-in OR autoloadable = present); evidence shows loaded-now vs autoload-reachable separately; only **hard blocks** demote to `mitigated`.
- **Verdicts (5-state):** `vulnerable` / `likely-vulnerable` / `mitigated` / `not-affected` / `unknown`. Unsupported platform → refuse cleanly, non-zero exit, no table.
- **Data:** `go:embed` YAML/JSON CVE defs (id, nickname, advisory, CVSS, KEV flag, upstream ranges, per-distro fixed pkg versions, preconditions, remediation = fixed version + mitigations).
- **Output:** default audits all CVEs → pretty table via stdlib `text/tabwriter` + manual ANSI (zero deps); `--json` for machine output. Columns: CVE, nickname, severity (CVSS+KEV), verdict, evidence, remediation.
- **Testing:** golden `HostFacts` fixtures → asserted verdict tables, table-driven against `detect`.

**Deferred:** finding-based exit codes, markdown output, remote-over-SSH.

## Commands

None yet — no Go module. Add build/test/run commands here once `go.mod` and entry points exist.
