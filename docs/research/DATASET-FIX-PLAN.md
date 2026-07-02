# Dataset correction plan (from adversarial verification, 2026-07-02)

## Context

A 50-agent research + adversarial-verification pass (`DETECTION-FACTS.md`,
`DETECTION-CORRECTIONS.md`, `detection-*.md`) found ~20 grounded errors in
`internal/cve/data/cves.yaml`: fabricated branch fixes, RHEL NVRs that were actually
AlmaLinux rebuilds, wrong `introduced` versions, four wrong `kev` flags, and one
false-negative class (pedit COW). This plan applies the verified corrections and adds a
per-kernel-line vulnerable-range model so the false-negative can be expressed precisely.

Two decisions are locked in:
1. **`kev` means "listed on the CISA KEV catalog"** — nothing else. "Actively exploited"
   is a separate real-world fact that stays in prose only (no new field).
2. **Per-line vulnerable ranges** — add an optional `affected_from` lower bound per branch
   so a kernel line can be "vulnerable from X upward, no fix" (pedit COW's LTS case).

Everything below is CONFIRMED/REFUTED against a named primary source in the fact tables.

---

## Part 1 — Schema: per-line `affected_from` (`internal/cve/types.go`)

- Add `AffectedFrom string \`yaml:"affected_from"\`` to the `Branch` struct: the per-line
  lower bound. Empty = use the entry's global `Introduced`.
- Allow `Branch.Fixed` to be **empty** — meaning "affected from `affected_from` upward, no
  fix in this line yet."

## Part 2 — Loader validation (`internal/cve/load.go`)

- A branch must have `series` **and at least one** of `fixed` / `affected_from`.
- Validate `affected_from` as a version (reuse `versionPattern`); validate `fixed` only when
  present (it's now optional).

## Part 3 — Detect logic (`internal/detect/detect.go`)

- Change `matchBranch` to return the whole `Branch` (not just `fixed`).
- In the branch-matched block of `evalVersion`, apply the line's lower bound:
  - `lower := b.AffectedFrom` (per-line); if the running kernel `< lower` → **not-affected**
    ("predates this line's introduction").
  - else if `b.Fixed != "" && running >= b.Fixed` → **not-affected** (upstream-only patched).
  - else → **affected** (below fix, or no fix recorded for the line). `confirmed=false`
    (upstream-only), unchanged.
- No change to the no-branch-match fallback (global `introduced` + `fixed_mainline`) built
  earlier — it still governs series with no branch entry.
- Net effect: setting a CVE's global `introduced` to the lowest affected line, plus per-line
  `affected_from` entries, flags backported-but-unfixed LTS kernels as vulnerable while
  keeping pre-backport kernels in the same line `not-affected`.

## Part 4 — Data corrections (`internal/cve/data/cves.yaml`)

### KEV flags (Part-1 decision)
- Copy Fail (CVE-2026-31431): `kev: false → true` (KEV dateAdded 2026-05-01)
- OverlayFS (CVE-2023-0386): `kev: false → true` (KEV dateAdded 2025-06-17)
- Dirty Frag ESP (CVE-2026-43284): `kev: true → false` (not on KEV; SSVC=poc)
- Dirty Frag RxRPC (CVE-2026-43500): `kev: true → false` (not on KEV)

### Dirty Pipe (CVE-2022-0847)
- `distro.debian.11`: `5.10.103-1 → 5.10.92-2` (DSA-5092-1)
- `distro.rhel`: **remove `9`** (invented `5.14.0-0`; RHEL 9 not affected); **add
  `8: 4.18.0-348.20.1.el8_5`** (RHSA-2022:0825)

### Copy Fail (CVE-2026-31431)
- `branch:6.1`: `6.1.174 → 6.1.170`
- **add `branch:6.19 → 6.19.12`** (pins the reported Fedora 6.19.10 box as confirmed-affected)
- `distro.debian.13`: `6.12.90-2 → 6.12.94-1`
- `fixed_mainline: "" → 7.0`

### Dirty Frag ESP (CVE-2026-43284)
- `distro.rhel.8`: `→ 4.18.0-553.124.1.el8_10` (RHSA-2026:16195)
- `distro.rhel.9`: `→ 5.14.0-611.55.1.el9_7` (RHSA-2026:16206)
- `distro.rhel.10`: `→ 6.12.0-124.56.1.el10_1` (RHSA-2026:16062)
- `fixed_mainline: "" → 7.1`
- (all branches CONFIRMED — no change)

### Dirty Frag RxRPC (CVE-2026-43500)
- **remove branches `5.10`, `5.15`, `6.1`** (fabricated — no fix in those lines)
- `branch:6.6`: `6.6.138 → 6.6.140`; `branch:6.12`: `6.12.87 → 6.12.88` (6.18.29/7.0.6 keep)
- **remove the whole `rhel` map** (Red Hat: not affected — rxrpc binary RPM never shipped)
- `distro.debian.13`: `6.12.90-2 → 6.12.94-1`
- `fixed_mainline: "" → 7.1`

### Fragnesia (CVE-2026-46300)
- `introduced: 5.6 → 3.9`
- `branch:5.10`: `5.10.258 → 5.10.257`; **add `branch:6.18 → 6.18.33`**
- `distro.debian.13`: `6.12.90-2 → 6.12.94-1`
- `distro.rhel.8`: `→ 4.18.0-553.125.1.el8_10` (RHSA-2026:19666)
- `distro.rhel.9`: `→ 5.14.0-687.10.1.el9_8` (RHSA-2026:19568)
- `distro.rhel.10`: `→ 6.12.0-211.16.1.el10_2` (RHSA-2026:19569)
- `fixed_mainline: "" → 7.1`
- keep `amazon` unaffected, `CONFIG_INET_ESPINTCP`, `debian.11` (verified correct)

### nf_tables UAF (CVE-2024-1086)
- `introduced: 5.14 → 3.15` (CNA JSON)

### netfilter UAF (CVE-2023-32233)
- description: "in chain deletion" → "via anonymous-set mishandling during nf_tables batch
  processing"

### pedit COW (CVE-2026-46331) — the false-negative fix
- `introduced: 5.18 → 4.19` (lowest affected line, so the global check never clears a
  vulnerable LTS kernel)
- **add per-line `affected_from` branches, no `fixed`** (vulnerable, unfixed in-line):
  `4.19→4.19.244`, `5.4→5.4.195`, `5.10→5.10.117`, `5.15→5.15.41`, `5.17→5.17.9`
- keep existing `6.12→6.12.94`, `6.18→6.18.36`, `7.0→7.0.13`, `fixed_mainline: 7.1`
- fix inline comment: `899ee91156e5` is the **fix** commit; culprit is `8b796475fd78`

### DirtyClone (CVE-2026-43503)
- No value changes (0 refuted). See follow-ups for the RHEL-not-affected coverage gap.

## Part 5 — Tests

- `internal/cve/load_test.go`: Fragnesia `debian.13` assertion `6.12.90-2 → 6.12.94-1`
  (CVE count stays 10). Add a small assertion that a branch may carry `affected_from`.
- `internal/detect/detect_test.go`: add golden cases for the new lower-bound logic —
  (a) running `< affected_from` in a matched line → `not-affected`;
  (b) running `>= affected_from` with no `fixed` → `likely-vulnerable`;
  (c) pedit-style LTS case (e.g. 5.10.120 vulnerable, 5.10.50 not).
- Loader-reject case: branch with neither `fixed` nor `affected_from`.

## Part 6 — Docs

- `CLAUDE.md`: note the corrections applied + the new `affected_from` model in the design
  section; leave the "actively exploited" prose for Dirty Frag as-is (KEV flag now `false`).
- `docs/research/DETECTION-CORRECTIONS.md`: mark items resolved.
- README table unchanged (carries no version/KEV data).

## Verification

- `go build ./... && go vet ./... && go test ./...` green.
- Simulate the reported host (kernel 6.19.10, Fedora, non-root) against the real dataset:
  Copy Fail now version-confirmed affected via the new 6.19 branch (still `likely-vulnerable`
  non-root due to unread preconditions; `vulnerable` as root).
- Add a temporary sim harness (as before) to confirm a 5.10.120 host → pedit COW
  `likely-vulnerable` (false-negative gone) and 5.10.50 → `not-affected`.
- `make linux-arm64` to refresh the binary for re-testing on the Fedora box.

## Out of scope / follow-ups

- **Version-scoped "not affected"**: DirtyClone (RHEL 6/7/8 + rhcos), RxRPC (all RHEL), and
  pedit (RHEL 6/7) are Red-Hat-"Not affected" but our schema can't express a per-release
  unaffected floor, so those read `likely-vulnerable` on RHEL (false-positive, safe
  direction). Needs a new mechanism (e.g. per-distro `unaffected_releases`).
- **Multi-range per line** (fixed-then-reintroduced regressions): single `affected_from`
  per line covers every current CVE; revisit only if a real double-range CVE appears.
- **`verified` flags**: keep the 5 primary `true` (now adversarially confirmed), DirtyClone
  and pedit `false` until their RHEL coverage gaps are resolved.
- Backfill `fixed_mainline` for Copy Fail is done here (7.0); no remaining empties.
