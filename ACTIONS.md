# Actions Log

Chronological record of notable work. Newest entries at the top.

## 2026-07-01 — Add DirtyClone + pedit COW, fix version-matching false-negative

**Added two CVEs to the dataset** (`internal/cve/data/cves.yaml`), both `verified: false`:
- **CVE-2026-43503 (DirtyClone)** — shared-frag LPE cluster; `esp4`/`esp6` only (not
  `rxrpc`); kernel.org-authoritative branch data; Debian/Ubuntu `distro_fixed`, RHEL left
  empty (affected, no errata indexed → falls to `likely-vulnerable`).
- **CVE-2026-46331 (pedit COW)** — `net/sched act_pedit` OOB write; `introduced: 5.18`;
  no 6.1.x/6.6.x backport yet.

**Detection research** — web-research subagents produced sourced, field-by-field reports:
- `docs/research/detection-dirtyclone-cve-2026-43503.md`
- `docs/research/detection-peditcow-cve-2026-46331.md`

**Docs** — README coverage table + CLAUDE.md primary table and known-follow-ups updated.

**Golden fixtures** — added `detect` cases for the two new verdicts (vulnerable /
likely-vulnerable / mitigated / not-affected / unknown paths).

**Fix: false-negative in `evalVersion`** — the fallback cleared any kernel whose version
was ≥ the highest per-series *backport* (`maxFixed`), even when its series had no branch
entry. Unsound: a later stable series can fork before the fix and sit numerically above a
backport yet stay vulnerable. Real case: a Fedora host on **6.19.10** (built pre-disclosure)
reported `not-affected` for Copy Fail (6.19.10 > 6.18.22) and `unknown` for the 7.0-era cluster.
- Added `Entry.FixedMainline` — the first mainline release carrying the fix; the only sound
  upper bound for an untracked series. Clear a kernel only when it is ≥ `fixed_mainline`.
- Dropped the `maxFixed` shortcut; an in-range kernel in an untracked series now stays
  `likely-vulnerable` rather than being wrongly cleared or reported `unknown`.
- Populated `fixed_mainline` where authoritative (Dirty Pipe 5.17; DirtyClone/pedit 7.1;
  legacy 6.8/6.2/6.4). Left empty (safe → `likely-vulnerable`) for Copy Fail and the Dirty
  Frag ESP/RxRPC/Fragnesia cluster.
- Regression fixtures pin the 6.19.10 behaviour.

Commits: `30327bb` (add CVEs), `e4f1e95` (false-negative fix). `go build/vet/test ./...` green.

**Open follow-ups**
- Backfill `fixed_mainline` for Copy Fail + Dirty Frag ESP/RxRPC/Fragnesia (research their
  mainline release) so genuinely-patched newer kernels resolve to `not-affected`.
- Resolve the two new CVEs' `verified: false` items (DirtyClone RHEL errata; pedit COW RHEL
  NVRs, 6.1/6.6 backport timing, Debian-11 tracker false-positive).
