# Dataset corrections from adversarial verification (2026-07-02)

> **STATUS: APPLIED (2026-07-02).** All A/B/C corrections below are landed in
> `internal/cvedata/cves.yaml` per `DATASET-FIX-PLAN.md`. Section A used the new per-line
> `affected_from` schema for the pedit-COW LTS false-negative. Section D (dataset already
> correct) was left unchanged. Section E coverage gaps remain open follow-ups.

Per-fact tables and sources: `DETECTION-FACTS.md` and `detection-*.md`. This file is the
**curated** action list — the raw `agrees=false` set includes cases where our dataset is
actually correct (the researcher/adversary was wrong); those are separated out below.

Confidence key: every correction here was CONFIRMED or REFUTED by the adversarial fleet
against a named primary source (kernel.org CVE feed, MITRE CNA JSON, distro tracker, CISA KEV).

---

## A. Wrong values that produce WRONG verdicts — fix first

### pedit COW (CVE-2026-46331) — false-negative risk on LTS (highest priority)
`introduced: "5.18"` is only the *mainline* introduction. The CNA record shows the flaw was
**independently backported into LTS with no fix**: 4.19.244, 5.4.195, 5.10.117, 5.15.41, 5.17.9.
A host on those series at/above those points is vulnerable but we mark it `not-affected` (predates
5.18) — the exact false-negative class we just fixed. Needs a decision: lower `introduced` (safe,
some false-positives on pre-backport old LTS) or add per-series introduced points (schema change).

### Dirty Frag RxRPC (CVE-2026-43500)
- Branches `5.10.255`, `5.15.206`, `6.1.172` are **fabricated** — kernel.org/CNA list *no* fix for
  those series (only 6.6.140 / 6.12.88 / 6.18.29 / 7.0.6 / 7.1). Remove them.
- `branch:6.6` 6.6.138 → **6.6.140**; `branch:6.12` 6.12.87 → **6.12.88** (6.18.29 / 7.0.6 are correct).
- `distro:debian:13` 6.12.90-2 → **6.12.94-1**.
- Entire `rhel` map is fabricated — Red Hat marks RHEL 6/7/8/9/10 **Not affected** (rxrpc binary RPM
  never shipped). Clear the map.

### Dirty Frag ESP (CVE-2026-43284)
RHEL NVRs are **AlmaLinux rebuild versions, not Red Hat's** (off by a point release):
- rhel 8: `4.18.0-553.123.2.el8_10` → **4.18.0-553.124.1.el8_10** (RHSA-2026:16195)
- rhel 9: `5.14.0-611.54.3.el9_7` → **5.14.0-611.55.1.el9_7** (RHSA-2026:16206)
- rhel 10: `6.12.0-124.55.3.el10_1` → **6.12.0-124.56.1.el10_1** (RHSA-2026:16062)

### Fragnesia (CVE-2026-46300)
- `introduced` 5.6 → **3.9** (CNA JSON).
- `branch:5.10` 5.10.258 → **5.10.257**.
- `distro:debian:13` 6.12.90-2 → **6.12.94-1**.
- RHEL NVRs point to wrong releases: rhel 8 → **4.18.0-553.125.1.el8_10** (RHSA-2026:19666);
  rhel 9 → **5.14.0-687.10.1.el9_8** (RHSA-2026:19568); rhel 10 → **6.12.0-211.16.1.el10_2**
  (RHSA-2026:19569).

### Copy Fail (CVE-2026-31431)
- `branch:6.1` 6.1.174 → **6.1.170** (kernel.org + CNA + Debian DSA-6243-1 all agree).
- `distro:debian:13` 6.12.90-2 → **6.12.94-1**.

### nf_tables UAF (CVE-2024-1086)
- `introduced` 5.14 → **3.15** (CNA JSON: affected 3.15, lessThan 6.8).

### Dirty Pipe (CVE-2022-0847)
- `distro:debian:11` 5.10.103-1 → **5.10.92-2** (DSA-5092-1).
- `distro:rhel:9` `5.14.0-0` is **invented** — RHEL 9 is Not affected. Remove it.
- `distro:rhel:8` is **missing** — add **4.18.0-348.20.1.el8_5** (RHSA-2022:0825).

---

## B. KEV flag errors (display/severity only — no verdict impact)
- **Copy Fail** `kev: false` → **true** (CISA KEV, dateAdded 2026-05-01).
- **OverlayFS** `kev: false` → **true** (CISA KEV, dateAdded 2025-06-17).
- **Dirty Frag ESP** `kev: true` → **false** — not in CISA KEV (SSVC = poc). ⚠️ Tension: our KB /
  threat report call this "actively exploited." KEV membership and "actively exploited" differ;
  the `kev` field means CISA-KEV-listed, so `false` is accurate. Keep the "actively exploited"
  note in prose. **User decision.**
- **Dirty Frag RxRPC** `kev: true` → **false** — same as ESP.

---

## C. Description / comment fixes
- **netfilter UAF (CVE-2023-32233)** description "chain deletion" → "anonymous-set mishandling
  during nf_tables batch processing" (MITRE/NVD/Red Hat all agree).
- **pedit COW** inline comment labels `899ee91156e5` as the "culprit commit" — it is the **fix**
  commit; the culprit is **8b796475fd78** (Fixes: tag confirms).

---

## D. NOT corrections — dataset is already right (adversary/researcher was wrong)
- **Fragnesia** `config:CONFIG_INET_ESPINTCP` — correct; the alternate `CONFIG_XFRM_ESPINTCP` is the
  wrong (non-promptable) symbol.
- **Fragnesia** `unaffected: amazon` — correct; AWS confirms espintcp absent → not affected.
- **Fragnesia** `distro:debian:11` 6.1.174-1~deb11u1 — correct (DLA-4607-1, verbatim).

---

## E. Coverage gaps (schema limits — follow-up, not a wrong value)
- **DirtyClone** RHEL 6/7/8 and OpenShift rhcos are Red Hat "Not affected", but our empty `rhel`
  map + `fixed_mainline: 7.1` means RHEL 8 reports `likely-vulnerable` (false-positive, safe
  direction). Needs a version-scoped unaffected mechanism to resolve cleanly.
- Empty `fixed_mainline` for Copy Fail / Dirty Frag ESP / RxRPC / Fragnesia still stands; backfill
  from the now-verified mainline data (ESP/RxRPC/Fragnesia fix into 7.1; Copy Fail has no 7.x
  branch — mainline ≈ 6.19 era, confirm before setting).
