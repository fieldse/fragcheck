# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`fragcheck` is a Go tool that audits a Linux host for vulnerability to a small set of recent kernel privilege-escalation exploits, and produces a clear, fast, structured table report the user can act on to remediate.

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
| DirtyClone           | CVE-2026-43503                       | skb-clone helpers (`__pskb_copy_fclone`/`skb_shift`) drop shared-frag flag → ESP decrypt → page-cache write → root |
| pedit COW            | CVE-2026-46331                       | `net/sched` `act_pedit` OOB write (runtime offset escapes COW bounds check) → page-cache write → root |

### Secondary — well-documented legacy privesc CVEs

Lower priority; useful as a baseline set with stable, public vuln ranges.

| CVE            | Name              | Subsystem            | Impact     | Vuln kernels (approx)        |
| -------------- | ----------------- | -------------------- | ---------- | ---------------------------- |
| CVE-2024-1086  | nf_tables UAF     | netfilter            | Local root | ~5.14–6.6 (CISA KEV)         |
| CVE-2023-0386  | OverlayFS privesc | OverlayFS            | Local root | ~5.11–6.2                    |
| CVE-2023-32233 | netfilter UAF     | netfilter (nf_tables)| Local root | ≤6.3.x                       |

Note: Dirty Pipe (CVE-2022-0847) is the conceptual bridge between the two sets — same page-cache-write outcome.

## Design (locked — full spec in `docs/SPEC.md`)

- **Toolchain:** Go 1.26. Module `github.com/fieldse/fragcheck`, binary `fragcheck`. Offline, local host only. Root is recommended for the fullest signal but not required — the audit reads mostly world-readable state, and anything unreadable degrades to an `unknown` verdict (warning printed when non-root).
- **Architecture seam:** `internal/collect` (impure → `HostFacts`) + `internal/detect` (pure: facts + dataset → verdicts) + `cmd/`. Keeps detection testable with fixtures, no real host needed.
- **Version source/compare:** installed kernel from package DB (`dpkg`/`rpm`, authoritative for backports); comparison shells out to native tools for correct distro semantics; backport-corrected for Ubuntu/Debian/RHEL.
- **Reboot gap:** verdict judged on the **running** kernel; patched-but-not-rebooted → still `vulnerable` with a "reboot pending" note.
- **Preconditions:** autoload-aware (loaded OR built-in OR autoloadable = present); evidence shows loaded-now vs autoload-reachable separately; only **hard blocks** demote to `mitigated`.
- **Verdicts (5-state):** `vulnerable` / `likely-vulnerable` / `mitigated` / `not-affected` / `unknown`. Unsupported platform → refuse cleanly, non-zero exit, no table.
- **Data (v2):** `go:embed` YAML CVE defs — per-stable-branch fixed points, per-distro-*release* fixed package versions, `CONFIG_*` gates, required modules, per-CVE userns dependence, unaffected-distro list, CVSS/KEV, remediation. Detection: authoritative per-release package comparison (→ confirmed `vulnerable`), graceful upstream-branch fallback (→ `likely-vulnerable`), required-CONFIG-off → `not-affected`, kernel newer than the mainline fix → `not-affected`.
- **Output:** default audits all CVEs → pretty table via stdlib `text/tabwriter` + manual ANSI (zero deps); `--json` for machine output. Columns: CVE, nickname, severity (CVSS+KEV), verdict, evidence, remediation.
- **Testing:** golden `HostFacts` fixtures → asserted verdict tables, table-driven against `detect`.

**Deferred:** finding-based exit codes, markdown output, remote-over-SSH.

## Commands

```sh
go build ./...                      # build all packages
go vet ./...                        # static checks
go test ./...                       # full test suite
go test ./internal/detect/...       # the core verdict logic (golden fixtures)
go test -run TestEvaluate ./internal/detect/...   # a single test
go run ./cmd/fragcheck             # run (table); refuses cleanly off Linux / non-root
go run ./cmd/fragcheck --json      # JSON output
```

Linux end-to-end (the collector only does real work on Linux). Cross-compile and run in a
container as root:

```sh
mkdir -p bin
GOOS=linux GOARCH=arm64 go build -o bin/lva-linux ./cmd/fragcheck
podman run --rm -v "$PWD/bin/lva-linux:/lva:ro" ubuntu:22.04 /lva
```

Exit codes: `0` audit completed (regardless of findings), `1` internal error (e.g. dataset load),
`2` refused (non-Linux or unsupported distro).

## Known follow-ups

- The **5 primary CVEs are `verified: true`**, populated from the source-of-truth knowledgebase
  (`docs/cves.md` / the SecondBrain note). The knowledgebase flags that some point-releases were
  single-sourced — re-validate against distro trackers before treating a single verdict as gospel.
- **Missing Debian per-release fixes for Dirty Frag ESP/RxRPC** (`CVE-2026-43284` / `-43500`): the
  knowledgebase had no Debian DSA, so on Debian these fall to the upstream-branch fallback and
  report `likely-vulnerable` instead of confirmed `vulnerable`. Add `distro_fixed.debian` once the
  DSA versions are known.
- The **3 legacy CVEs remain `verified: false`** (provisional single-branch data; not in the
  knowledgebase).
- **DirtyClone (`CVE-2026-43503`) and pedit COW (`CVE-2026-46331`) are `verified: false`** — added
  from `docs/research/detection-{dirtyclone,peditcow}-*.md` (kernel.org-authoritative branch data,
  live distro trackers). Open items before flipping to `true`:
  - **DirtyClone RHEL**: RHEL 9/10 are "Affected" but no errata/NVR is indexed yet, so `distro_fixed.rhel`
    is empty and RHEL falls to the upstream-branch fallback (`likely-vulnerable`). Correction vs. the
    threat-report doc: `rxrpc` is **not** a precondition for this CVE (esp4/esp6 only). SUSE data was
    single-sourced — re-verify. `introduced: "3.9"` is kernel.org's value but a loose lower bound (the
    flaw only bites once the shared-frag mechanism exists — pre-mechanism kernels are covered by the
    43284/43500 entries).
  - **pedit COW**: fix is mainline-fresh (v7.1-rc7) — **no 6.1.x/6.6.x branch backport exists yet**, so
    hosts on those LTS series resolve to `unknown` (no per-release fix or matching branch), not
    `likely-vulnerable`. RHEL 8/9/10 NVRs not indexed; Debian 11's tracker entry is a suspected
    false-positive (5.10 predates the v5.18 introduction). `introduced: "5.18"` cleanly excludes
    RHEL 6/7 and Ubuntu ≤16.04.
- Verified end-to-end on a real Debian 13 host (kernel 6.12.63-1): Copy Fail confirmed
  `vulnerable`, Fragnesia `not-affected` (espintcp not built), legacy/Dirty Pipe `not-affected`.
