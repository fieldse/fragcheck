# fragcheck detection facts — research + adversarial verification

Generated 2026-07-02. Every value in `internal/cve/data/cves.yaml` was researched against
primary sources (kernel.org CVE feed, MITRE CNA JSON, Debian/Ubuntu/Red Hat/SUSE trackers,
CISA KEV, NVD) by one agent per CVE, then re-checked by a separate adversarial fleet that
defaulted to `UNVERIFIABLE` unless it could independently corroborate from a primary source.

- **verdict** — the adversarial fleet's confidence in the *value* (CONFIRMED / REFUTED / UNVERIFIABLE)
- **✓/✗** — whether our dataset currently matches reality (`agrees`)
- A ✗ with a CONFIRMED or REFUTED verdict = a dataset error to fix. See per-CVE tables below.

Full detection write-ups: `docs/research/detection-*.md`. Machine-readable source of these
tables: the workflow result JSON.

## Dirty Pipe — CVE-2022-0847

CONFIRMED 19 · REFUTED 0 · UNVERIFIABLE 0  (19 facts)

| Field | Dataset says | Reality | Verdict | OK |
|---|---|---|---|:--:|
| `cvss` | 7.8 | 7.8 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) | CONFIRMED | ✓ |
| `kev` | true | true (dateAdded 2022-04-25) | CONFIRMED | ✓ |
| `advisory` | RHSB-2022-002 | RHSB-2022-002, titled "Dirty Pipe - kernel arbitrary file manipulation", covers exactly th | CONFIRMED | ✓ |
| `commit:fix` |  | 9d2231c5d74e13b2a0546fee6737ee4446017903 ("lib/iov_iter: initialize \"flags\" in new pipe_ | CONFIRMED | ✗ |
| `commit:introduced` |  | 241699cd72a8 ("new iov_iter flavour: pipe-backed", Linux 4.9, 2016) is the original refact | CONFIRMED | ✗ |
| `introduced` | 5.8 | 5.8 | CONFIRMED | ✓ |
| `fixed_mainline` | 5.17 | 5.17 (fix commit lands between v5.17-rc5 and v5.17-rc6) | CONFIRMED | ✓ |
| `branch:5.16` | 5.16.11 | 5.16.11 (fix commit present in v5.16.10..v5.16.11 range) | CONFIRMED | ✓ |
| `branch:5.15` | 5.15.25 | 5.15.25 (fix commit present in v5.15.24..v5.15.25 range) | CONFIRMED | ✓ |
| `branch:5.10` | 5.10.102 | 5.10.102 (fix commit present in v5.10.101..v5.10.102 range) | CONFIRMED | ✓ |
| `modules` | [] | none — flaw is in core VFS/pipe code (lib/iov_iter.c), not a loadable module | CONFIRMED | ✓ |
| `configs` | [] | none — no CONFIG gate documented by any source | CONFIRMED | ✓ |
| `needs_unpriv_userns` | false | false — exploitable by any local unprivileged user, no namespace/capability requirement | CONFIRMED | ✓ |
| `distro:debian:11` | 5.10.103-1 | 5.10.92-2 | CONFIRMED | ✗ |
| `distro:debian:buster/stretch-unaffected` | (not in map; comment says not affected) | confirmed not affected — both explicitly listed as (not affected), "Vulnerable code introd | CONFIRMED | ✓ |
| `distro:ubuntu:empty-map-comment` | ubuntu: {} — comment: HWE 5.13<5.13.0-35.40, OEM 5.14<5.14.0-1027.30; GA 5.4/4.15 not affe | confirmed — 5.13.0-35.40 and 5.14.0-1027.30 both appear as Fixed thresholds on Ubuntu's tr | CONFIRMED | ✓ |
| `distro:rhel:9` | 5.14.0-0 | Not affected (categorical, per Red Hat's package_state) — no version "5.14.0-0" exists any | CONFIRMED | ✗ |
| `distro:rhel:8` |  | kernel-0:4.18.0-348.20.1.el8_5, fixed via RHSA-2022:0825 (main GA stream); kernel-rt-0:4.1 | CONFIRMED | ✗ |
| `distro:rhel:6-7-unaffected` | (not in map; comment says RHEL 7 not affected) | confirmed — RHEL 6 kernel and RHEL 7 kernel/kernel-rt all marked Not affected | CONFIRMED | ✓ |

## Copy Fail — CVE-2026-31431

CONFIRMED 21 · REFUTED 3 · UNVERIFIABLE 0  (24 facts)

| Field | Dataset says | Reality | Verdict | OK |
|---|---|---|---|:--:|
| `introduced` | 4.14 | 4.14 | CONFIRMED | ✓ |
| `fixed_mainline` |  | 7.0 | CONFIRMED | ✗ |
| `branch:5.10` | 5.10.254 | 5.10.254 | CONFIRMED | ✓ |
| `branch:5.15` | 5.15.204 | 5.15.204 | CONFIRMED | ✓ |
| `branch:6.1` | 6.1.174 | 6.1.170 | REFUTED | ✗ |
| `branch:6.6` | 6.6.137 | 6.6.137 | CONFIRMED | ✓ |
| `branch:6.12` | 6.12.85 | 6.12.85 | CONFIRMED | ✓ |
| `branch:6.18` | 6.18.22 | 6.18.22 | CONFIRMED | ✓ |
| `branch:6.19` |  | 6.19.12 | CONFIRMED | ✗ |
| `module:algif_aead` | algif_aead | algif_aead | CONFIRMED | ✓ |
| `config:CONFIG_CRYPTO_USER_API_AEAD` | CONFIG_CRYPTO_USER_API_AEAD | CONFIG_CRYPTO_USER_API_AEAD | CONFIRMED | ✓ |
| `needs_unpriv_userns` | false | false | CONFIRMED | ✓ |
| `distro:debian:11` | 5.10.257-1 | 5.10.257-1 | CONFIRMED | ✓ |
| `distro:debian:12` | 6.1.174-1 | 6.1.174-1 | CONFIRMED | ✓ |
| `distro:debian:13` | 6.12.90-2 | 6.12.94-1 | REFUTED | ✗ |
| `distro:ubuntu:22.04` | 5.15.0-179.189 | 5.15.0-179.189 | CONFIRMED | ✓ |
| `distro:ubuntu:24.04` | 6.8.0-117.117 | 6.8.0-117.117 | CONFIRMED | ✓ |
| `distro:rhel:8` | 4.18.0-553.123.1.el8_10 | 4.18.0-553.123.1.el8_10 | CONFIRMED | ✓ |
| `distro:rhel:9` | 5.14.0-611.54.1.el9_7 | 5.14.0-611.54.1.el9_7 | CONFIRMED | ✓ |
| `cvss` | 7.8 | 7.8 | CONFIRMED | ✓ |
| `kev` | false | true | REFUTED | ✗ |
| `advisory` | GHSA-2274-3hgr-wxv6 | GHSA-2274-3hgr-wxv6 | CONFIRMED | ✓ |
| `commit:fix` |  | a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5 | CONFIRMED | ✗ |
| `commit:introduced` |  | 72548b093ee38a6d4f2a19e6ef1948ae05c181f7 | CONFIRMED | ✗ |

## Dirty Frag (ESP) — CVE-2026-43284

CONFIRMED 25 · REFUTED 3 · UNVERIFIABLE 0  (28 facts)

| Field | Dataset says | Reality | Verdict | OK |
|---|---|---|---|:--:|
| `introduced` | 4.11 | 4.11 | CONFIRMED | ✓ |
| `fixed_mainline` |  | 7.1 (v7.1-rc3, commit f4c50a4034e6) | CONFIRMED | ✗ |
| `branch:5.10` | 5.10.255 | 5.10.255 (commit a6cb440f274a) | CONFIRMED | ✓ |
| `branch:5.15` | 5.15.206 | 5.15.206 (commit fe785bb3a809; superseded an earlier 5.15.205/ab8b995323e5 backport) | CONFIRMED | ✓ |
| `branch:6.1` | 6.1.172 | 6.1.172 (commit 8253aab4659c; superseded an earlier 6.1.171/5d55c7336f80 backport) | CONFIRMED | ✓ |
| `branch:6.6` | 6.6.138 | 6.6.138 (commit 50ed1e787310) | CONFIRMED | ✓ |
| `branch:6.12` | 6.12.87 | 6.12.87 (commit b54edf1e9a3f) | CONFIRMED | ✓ |
| `branch:6.18` | 6.18.28 | 6.18.28 (commit 71a1d9d985d2) | CONFIRMED | ✓ |
| `branch:7.0` | 7.0.5 | 7.0.5 (commit 52646cbd00e7) | CONFIRMED | ✓ |
| `module:esp4` | present | confirmed — net/ipv4/esp4.c is an affected file | CONFIRMED | ✓ |
| `module:esp6` | present | confirmed — net/ipv6/esp6.c is an affected file | CONFIRMED | ✓ |
| `config:CONFIG_XFRM` | present | required (structural dependency of esp4/esp6), consistent with kernel Kconfig | CONFIRMED | ✓ |
| `config:CONFIG_INET_ESP` | present | required for IPv4 esp4.c path, per kernel Kconfig (net/ipv4/Kconfig) | CONFIRMED | ✓ |
| `config:CONFIG_INET6_ESP` |  | required for the IPv6 esp6.c path (net/ipv6/Kconfig), distinct from CONFIG_INET_ESP, but a | CONFIRMED | ✗ |
| `needs_unpriv_userns` | true | true — Red Hat: "The xfrm-ESP variant requires unprivileged user or network namespace crea | CONFIRMED | ✓ |
| `distro:ubuntu:22.04` | 5.15.0-181.191 | 5.15.0-181.191 (Fixed) | CONFIRMED | ✓ |
| `distro:ubuntu:24.04` | 6.8.0-124.124 | 6.8.0-124.124 (Fixed) | CONFIRMED | ✓ |
| `distro:debian:11` | 5.10.251-4 | 5.10.251-4 (DLA-4572-1); note: live security-suite package has since moved to 5.10.257-1 v | CONFIRMED | ✓ |
| `distro:debian:12` | 6.1.170-3 | 6.1.170-3 (DSA-6258-1); live suite now at 6.1.174-1 | CONFIRMED | ✓ |
| `distro:debian:13` | 6.12.86-1 | 6.12.86-1 (DSA-6253-1); live suite now at 6.12.94-1 | CONFIRMED | ✓ |
| `distro:rhel:8` | 4.18.0-553.123.2.el8_10 | Real RHSA-2026:16195 fix is 4.18.0-553.124.1.el8_10; the dataset's value is an exact match | REFUTED | ✗ |
| `distro:rhel:9` | 5.14.0-611.54.3.el9_7 | Real RHSA-2026:16206 fix is 5.14.0-611.55.1.el9_7; dataset value exact-matches AlmaLinux A | REFUTED | ✗ |
| `distro:rhel:10` | 6.12.0-124.55.3.el10_1 | Real RHSA-2026:16062 fix is 6.12.0-124.56.1.el10_1; dataset value exact-matches AlmaLinux  | REFUTED | ✗ |
| `cvss` | 8.8 | 8.8 (kernel.org/CNA/NVD, S:C vector); CISA-ADP separately scores 7.8 (AC:H variant) — data | CONFIRMED | ✓ |
| `kev` | true | false — CVE-2026-43284 is absent from the live CISA KEV catalog (catalogVersion 2026.06.29 | CONFIRMED | ✗ |
| `advisory` | RHSB-2026-003 | RHSB-2026-003 confirmed to cover CVE-2026-43284, CVE-2026-43500, and CVE-2026-46300 togeth | CONFIRMED | ✓ |
| `commit:introduced` |  | cac2661c53f35cbe651bef9b07026a5a05ab8ce0 (Jan 2017, esp in-place decrypt fast path) | CONFIRMED | ✗ |
| `commit:fix` |  | f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4 (mainline fix, v7.1-rc3); per-branch backport com | CONFIRMED | ✗ |

## Dirty Frag (RxRPC) — CVE-2026-43500

CONFIRMED 20 · REFUTED 5 · UNVERIFIABLE 0  (25 facts)

| Field | Dataset says | Reality | Verdict | OK |
|---|---|---|---|:--:|
| `introduced` | 5.3 | 5.3 | CONFIRMED | ✓ |
| `fixed_mainline` |  | 7.1 | CONFIRMED | ✗ |
| `branch:5.10` | 5.10.255 |  | REFUTED | ✗ |
| `branch:5.15` | 5.15.206 |  | REFUTED | ✗ |
| `branch:6.1` | 6.1.172 |  | REFUTED | ✗ |
| `branch:6.6` | 6.6.138 | 6.6.140 | REFUTED | ✗ |
| `branch:6.12` | 6.12.87 | 6.12.88 | REFUTED | ✗ |
| `branch:6.18` | 6.18.29 | 6.18.29 | CONFIRMED | ✓ |
| `branch:7.0` | 7.0.6 | 7.0.6 | CONFIRMED | ✓ |
| `module:rxrpc` | rxrpc | rxrpc.ko (obj-$(CONFIG_AF_RXRPC) += rxrpc.o) | CONFIRMED | ✓ |
| `config:CONFIG_AF_RXRPC` | CONFIG_AF_RXRPC | CONFIG_AF_RXRPC | CONFIRMED | ✓ |
| `needs_unpriv_userns` | false | false | CONFIRMED | ✓ |
| `distro:debian:11` | 5.10.257-1 | 5.10.257-1 | CONFIRMED | ✓ |
| `distro:debian:12` | 6.1.174-1 | 6.1.174-1 | CONFIRMED | ✓ |
| `distro:debian:13` | 6.12.90-2 | 6.12.94-1 | CONFIRMED | ✗ |
| `distro:ubuntu:22.04` | 5.15.0-181.191 | 5.15.0-181.191 | CONFIRMED | ✓ |
| `distro:ubuntu:24.04` | 6.8.0-124.124 | 6.8.0-124.124 | CONFIRMED | ✓ |
| `distro:rhel:9` | 5.14.0-611.54.3.el9_7 | Not affected — rxrpc binary RPM not shipped by Red Hat | CONFIRMED | ✗ |
| `distro:rhel:10` | 6.12.0-124.55.3.el10_1 | Not affected — rxrpc binary RPM not shipped by Red Hat | CONFIRMED | ✗ |
| `unaffected:rhel` |  | RHEL 6,7,8,9,10 and OpenShift rhcos all explicitly 'Not affected' | CONFIRMED | ✗ |
| `cvss` | 7.8 | 7.8 | CONFIRMED | ✓ |
| `kev` | true | false | CONFIRMED | ✗ |
| `advisory` | RHSB-2026-003 | RHSB-2026-003 | CONFIRMED | ✓ |
| `commit:fix` | aa54b1d27fe0 (from yaml comment) | aa54b1d27fe0c2b78e664a34fd0fdf7cd1960d71 | CONFIRMED | ✓ |
| `commit:introduced` |  | d0d5c0cd1e711c98703f3544c1e6fc1372898de5 | CONFIRMED | ✗ |

## Fragnesia — CVE-2026-46300

CONFIRMED 24 · REFUTED 7 · UNVERIFIABLE 0  (31 facts)

| Field | Dataset says | Reality | Verdict | OK |
|---|---|---|---|:--:|
| `introduced` | 5.6 | 3.9 | REFUTED | ✗ |
| `fixed_mainline` |  | 7.1 | CONFIRMED | ✗ |
| `branch:5.10` | 5.10.258 | 5.10.257 | REFUTED | ✗ |
| `branch:5.15` | 5.15.208 | 5.15.208 | CONFIRMED | ✓ |
| `branch:6.1` | 6.1.174 | 6.1.174 | CONFIRMED | ✓ |
| `branch:6.6` | 6.6.141 | 6.6.141 | CONFIRMED | ✓ |
| `branch:6.12` | 6.12.91 | 6.12.91 | CONFIRMED | ✓ |
| `branch:6.18` |  | 6.18.33 | CONFIRMED | ✗ |
| `branch:7.0` | 7.0.10 | 7.0.10 | CONFIRMED | ✓ |
| `commit:introduced` |  | cef401de7be8c4e155c6746bfccf721a4fa5fab9 | CONFIRMED | ✗ |
| `commit:fix` |  | f84eca5817390257cef78013d0112481c503b4a3 | CONFIRMED | ✗ |
| `module:esp4` | esp4 | esp4 | CONFIRMED | ✓ |
| `module:esp6` | esp6 | esp6 | CONFIRMED | ✓ |
| `config:CONFIG_XFRM` | CONFIG_XFRM | CONFIG_XFRM | CONFIRMED | ✓ |
| `config:CONFIG_INET_ESP` | CONFIG_INET_ESP | CONFIG_INET_ESP | CONFIRMED | ✓ |
| `config:CONFIG_INET_ESPINTCP` | CONFIG_INET_ESPINTCP | CONFIG_XFRM_ESPINTCP | REFUTED | ✗ |
| `needs_unpriv_userns` | true | true | CONFIRMED | ✓ |
| `distro:ubuntu:22.04` | 5.15.0-181.191 | 5.15.0-181.191 | CONFIRMED | ✓ |
| `distro:ubuntu:24.04` | 6.8.0-124.124 | 6.8.0-124.124 | CONFIRMED | ✓ |
| `distro:ubuntu:25.10` | 6.17.0-35.35 | 6.17.0-35.35 | CONFIRMED | ✓ |
| `distro:ubuntu:26.04` | 7.0.0-22.22 | 7.0.0-22.22 | CONFIRMED | ✓ |
| `distro:debian:11` | 6.1.174-1~deb11u1 | 5.10.257-1 | CONFIRMED | ✗ |
| `distro:debian:12` | 6.1.174-1 | 6.1.174-1 | CONFIRMED | ✓ |
| `distro:debian:13` | 6.12.90-2 | 6.12.90-1 (DSA-6295-1 fix-point) / 6.12.94-1 (current live trixie-security package) | REFUTED | ✗ |
| `distro:rhel:8` | 4.18.0-553.124.3.el8_10 | 4.18.0-553.125.1.el8_10 | REFUTED | ✗ |
| `distro:rhel:9` | 5.14.0-611.54.5.el9_7 | 5.14.0-687.10.1.el9_8 | REFUTED | ✗ |
| `distro:rhel:10` | 6.12.0-124.56.3.el10_1 | 6.12.0-211.16.1.el10_2 | REFUTED | ✗ |
| `unaffected:amazon` | amazon (espintcp absent from Amazon Linux kernels) | NOT unaffected — Amazon Linux 2 and 2023 both shipped Fixed kernel advisories for this CVE | CONFIRMED | ✗ |
| `cvss` | 7.8 | 7.8 | CONFIRMED | ✓ |
| `kev` | false | false | CONFIRMED | ✓ |
| `advisory` | RHSB-2026-003 | RHSB-2026-003 | CONFIRMED | ✓ |

## nf_tables UAF — CVE-2024-1086

CONFIRMED 27 · REFUTED 2 · UNVERIFIABLE 2  (31 facts)

| Field | Dataset says | Reality | Verdict | OK |
|---|---|---|---|:--:|
| `introduced` | 5.14 | 3.15 | CONFIRMED | ✗ |
| `fixed_mainline` | 6.8 | 6.8 (fix commit f342de4e2f33e0e39165d8639387aa6c19dff660, merged v6.8-rc2) | CONFIRMED | ✓ |
| `branch:6.8` | 6.8 | redundant with fixed_mainline; not a real per-series backport entry | CONFIRMED | ✗ |
| `branch:4.19` |  | 4.19.307 | CONFIRMED | ✗ |
| `branch:5.4` |  | 5.4.269 | CONFIRMED | ✗ |
| `branch:5.10` |  | 5.10.210 | CONFIRMED | ✗ |
| `branch:5.15` |  | 5.15.149 | CONFIRMED | ✗ |
| `branch:6.1` |  | 6.1.76 | CONFIRMED | ✗ |
| `branch:6.6` |  | 6.6.15 | CONFIRMED | ✗ |
| `branch:6.7` |  | UNVERIFIABLE as fixed — checked 6.7.9 through 6.7.12 (branch's final release before EOL),  | REFUTED | ✗ |
| `module:nf_tables` | nf_tables | nf_tables | CONFIRMED | ✓ |
| `needs_unpriv_userns` | true | true | CONFIRMED | ✓ |
| `configs` |  | no source names an explicit CONFIG_* gate beyond CONFIG_NF_TABLES implied by the module it | REFUTED | ✓ |
| `distro:debian:10` |  | 4.19.316-1 (DLA-3840-1); also linux-5.10 backport 5.10.209-2~deb10u1 (DLA-3841-1) | CONFIRMED | ✗ |
| `distro:debian:11` |  | 5.10.209-2 | CONFIRMED | ✗ |
| `distro:debian:12` |  | 6.1.76-1 | CONFIRMED | ✗ |
| `distro:ubuntu:16.04` |  | 4.4.0-252.286 (xenial, Ubuntu Pro/ESM) | CONFIRMED | ✗ |
| `distro:ubuntu:18.04` |  | 4.15.0-223.235 (bionic, Ubuntu Pro/ESM) | CONFIRMED | ✗ |
| `distro:ubuntu:20.04` |  | 5.4.0-174.193 (focal) | CONFIRMED | ✗ |
| `distro:ubuntu:22.04` |  | 5.15.0-101.111 (jammy) | CONFIRMED | ✗ |
| `distro:rhel:7` |  | kernel-0:3.10.0-1160.114.2.el7 (RHSA-2024:1249) | CONFIRMED | ✗ |
| `distro:rhel:8` |  | kernel-0:4.18.0-513.24.1.el8_9 (RHSA-2024:1607) | CONFIRMED | ✗ |
| `distro:rhel:9` |  | kernel-0:5.14.0-427.13.1.el9_4 (RHSA-2024:2394) | CONFIRMED | ✗ |
| `unaffected:rhel:6` |  | RHEL 6 kernel package_state.fix_state = 'Not affected' | CONFIRMED | ✗ |
| `unaffected:ubuntu:14.04` |  | trusty (14.04) = 'Not affected' — kernel predates the true 3.15 introduction point | CONFIRMED | ✗ |
| `cvss` | 7.8 | 7.8 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) | CONFIRMED | ✓ |
| `kev` | true | true (dateAdded 2024-05-30, knownRansomwareCampaignUse: Known) | CONFIRMED | ✓ |
| `advisory` |  |  | UNVERIFIABLE | ✓ |
| `commit:fix` |  | f342de4e2f33e0e39165d8639387aa6c19dff660 | CONFIRMED | ✓ |
| `commit:introduced` |  | e0abdadcc6e113ed2e22c85b350074487095875b ('netfilter: nf_tables: accept QUEUE/DROP verdict | CONFIRMED | ✓ |
| `verified` | false | cvss/kev/fixed_mainline/preconditions now solidly cross-sourced; introduced needs correcti | UNVERIFIABLE | ✗ |

## OverlayFS privesc — CVE-2023-0386

CONFIRMED 19 · REFUTED 2 · UNVERIFIABLE 0  (21 facts)

| Field | Dataset says | Reality | Verdict | OK |
|---|---|---|---|:--:|
| `introduced` | 5.11 | 5.11 (confirmed via fix commit 4f11ada10d0a's own "Cc: <stable@vger.kernel.org> # v5.11" t | CONFIRMED | ✓ |
| `fixed_mainline` | 6.2 | 6.2 (fix commit merged in the v6.2-rc6 cycle, commit date 2023-01-24, v6.2 final released  | CONFIRMED | ✓ |
| `branch:6.2` | 6.2 | 6.2 (this is a duplicate restatement of fixed_mainline, not a distinct stable-series backp | CONFIRMED | ✓ |
| `branch:5.15` |  | 5.15.91 (fix commit present verbatim in the raw upstream stable changelog) | CONFIRMED | ✗ |
| `branch:6.1` |  | UNVERIFIABLE - no official upstream 6.1.x stable backport found (checked every published C | REFUTED | ✗ |
| `module:overlay` | overlay | overlay (Red Hat mitigation guidance explicitly names blacklisting the overlay module) | CONFIRMED | ✓ |
| `needs_unpriv_userns` | true | true (Debian DSA-5402: "A local user permitted to mount overlay mounts in user namespaces" | CONFIRMED | ✓ |
| `distro:debian:11` |  | 5.10.257-1 (current security-tracker fixed version); originally fixed at 5.10.179-1 via DS | CONFIRMED | ✗ |
| `distro:debian:12` |  | 6.1.174-1 (current security-tracker fixed version; bookworm was not yet stable at CVE disc | CONFIRMED | ✗ |
| `distro:debian:13` |  | 6.12.94-1 (current security-tracker fixed version; trixie not stable at disclosure time) | CONFIRMED | ✗ |
| `distro:ubuntu:22.04` |  | 5.15.0-70.77 (linux package, via USN-6025-1, published 2023-04-19) | CONFIRMED | ✗ |
| `distro:rhel:8` |  | 4.18.0-425.19.2.el8_7 (RHSA-2023:1566); CAVEAT: Red Hat states the flaw was only introduce | CONFIRMED | ✗ |
| `distro:rhel:9` |  | 5.14.0-162.23.1.el9_1 (RHSA-2023:1703) | CONFIRMED | ✗ |
| `unaffected:rhel6` |  | RHEL 6 kernel package: Not affected (per Red Hat package_state) | CONFIRMED | ✗ |
| `unaffected:rhel7` |  | RHEL 7 kernel and kernel-rt packages: Not affected (per Red Hat package_state) | CONFIRMED | ✗ |
| `unaffected:amazon` |  | UNVERIFIABLE - Amazon Linux ALAS page is fully client-rendered (JS); no package-level data | REFUTED | ✗ |
| `cvss` | 7.8 | 7.8 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) - matches CNA, NVD, and SUSE's own cros | CONFIRMED | ✓ |
| `kev` | false | true - added to CISA KEV catalog on 2025-06-17, dueDate 2025-07-08, vulnerability name "Li | CONFIRMED | ✗ |
| `advisory` |  | No single canonical advisory ID exists; plural per-distro advisories: Debian DSA-5402, Ubu | CONFIRMED | ✗ |
| `commit:fix` |  | 4f11ada10d0ad3fd53e2bd67806351de63a4f9c3 ("ovl: fail on invalid uid/gid mapping at copy up | CONFIRMED | ✗ |
| `commit:introduced` |  | 459c7c565ac36ba09ffbf24231147f408fde4203 ("ovl: unprivieged mounts", authored 2020-12-14,  | CONFIRMED | ✗ |

## netfilter UAF — CVE-2023-32233

CONFIRMED 24 · REFUTED 0 · UNVERIFIABLE 2  (26 facts)

| Field | Dataset says | Reality | Verdict | OK |
|---|---|---|---|:--:|
| `fixed_mainline` | 6.4 | 6.4 (v6.4-rc1, commit c1592a89942e9678f7d9c8030efa777c0d57edab; confirmed ancestor of v6.4 | CONFIRMED | ✓ |
| `introduced` |  | UNVERIFIABLE (exact introducing commit not pinned); confirmed present at least since Linux | UNVERIFIABLE | ✓ |
| `branch:6.4` | 6.4 | 6.4 (correct, but redundant with fixed_mainline; the fix landed pre-6.4.0 release during t | CONFIRMED | ✓ |
| `branch:6.3` |  | 6.3.2 | CONFIRMED | ✗ |
| `branch:6.1` |  | 6.1.28 | CONFIRMED | ✗ |
| `branch:5.15` |  | 5.15.111 | CONFIRMED | ✗ |
| `branch:5.10` |  | 5.10.180 | CONFIRMED | ✗ |
| `branch:5.4` |  | 5.4.243 | CONFIRMED | ✗ |
| `branch:4.19` |  | 4.19.283 | CONFIRMED | ✗ |
| `branch:4.14` |  | 4.14.315 | CONFIRMED | ✗ |
| `module:nf_tables` | nf_tables | nf_tables (confirmed as the exploited module; Red Hat's official mitigation is literally t | CONFIRMED | ✓ |
| `needs_unpriv_userns` | true | true (Red Hat: "local unprivileged users can exploit unprivileged user namespaces (CONFIG_ | CONFIRMED | ✓ |
| `distro:debian:11` |  | 5.10.179-1 (DSA-5402-1, bullseye) | CONFIRMED | ✗ |
| `distro:debian:10` |  | 4.19.289-1 (DLA-3508-1, buster LTS/ELTS) | CONFIRMED | ✗ |
| `distro:ubuntu:22.04` |  | 5.15.0-73.80 (jammy) | CONFIRMED | ✗ |
| `distro:ubuntu:20.04` |  | 5.4.0-150.167 (focal) | CONFIRMED | ✗ |
| `distro:rhel:9` |  | 5.14.0-284.18.1.el9_2 (RHSA-2023:3723) | CONFIRMED | ✗ |
| `distro:rhel:8` |  | 4.18.0-477.13.1.el8_8 (RHSA-2023:3349) | CONFIRMED | ✗ |
| `distro:rhel:7` |  | 3.10.0-1160.102.1.el7 (RHSA-2023:5622, published 2023-10-10 — notably slower than RHEL 8/9 | CONFIRMED | ✗ |
| `unaffected:rhel6` |  | RHEL 6 kernel package fix_state = "Not affected" (does not map cleanly to fragcheck's unaf | CONFIRMED | ✗ |
| `cvss` | 7.8 | 7.8, CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (identical across MITRE CNA, NVD, and Re | CONFIRMED | ✓ |
| `kev` | false | false (confirmed absent from live CISA KEV JSON feed, catalogVersion 2026.06.29, 1630 entr | CONFIRMED | ✓ |
| `advisory` |  | No single canonical bulletin exists, but Debian's DSA-5402-1 is the clearest primary-advis | CONFIRMED | ✗ |
| `commit:fix` |  | c1592a89942e9678f7d9c8030efa777c0d57edab ("netfilter: nf_tables: deactivate anonymous set  | CONFIRMED | ✗ |
| `commit:introduced` |  | UNVERIFIABLE — no introducing commit identified without deeper git archaeology; only confi | UNVERIFIABLE | ✓ |
| `description` | chain deletion | anonymous-set mishandling during nf_tables batch-request processing (not chain deletion);  | CONFIRMED | ✗ |

## DirtyClone — CVE-2026-43503

CONFIRMED 34 · REFUTED 0 · UNVERIFIABLE 1  (35 facts)

| Field | Dataset says | Reality | Verdict | OK |
|---|---|---|---|:--:|
| `introduced` | 3.9 | 3.9 (commit cef401de7be8c4e155c6746bfccf721a4fa5fab9) | CONFIRMED | ✓ |
| `fixed_mainline` | 7.1 | 7.1 (v7.1-rc5, fix commit 48f6a5356a33dd78e7144ae1faef95ffc990aae0) | CONFIRMED | ✓ |
| `branch:5.10` | 5.10.257 | 5.10.257 (commit fbeab9555564a1b98e8582cd106dfe46c4606991) | CONFIRMED | ✓ |
| `branch:5.15` | 5.15.208 | 5.15.208 (commit 179f1852bdedc300e373e807cc102cd81feff196) | CONFIRMED | ✓ |
| `branch:6.1` | 6.1.174 | 6.1.174 (commit 12401fcfb01f53ccc63ab0a3246570fe8f3105ee); cross-checked against Debian bo | CONFIRMED | ✓ |
| `branch:6.6` | 6.6.141 | 6.6.141 (commit 989214c66884d70716d83dc1d0bf5e16287bf349) | CONFIRMED | ✓ |
| `branch:6.12` | 6.12.91 | 6.12.91 (commit fc6eb39c55e97df2f94ad974b8a5bbcd019da2c8); Debian trixie shipped a later p | CONFIRMED | ✓ |
| `branch:6.18` | 6.18.33 | 6.18.33 (commit ff375cc75f9167168db38e0464a482d5fbc8d81d); no distro currently ships 6.18  | CONFIRMED | ✓ |
| `branch:7.0` | 7.0.10 | 7.0.10 (commit 9bc9d6d6967a2239aa57af2aa53554eddd640d20); cross-checked against Debian sid | CONFIRMED | ✓ |
| `commit:branch7.0-fix` | 9bc9d6d69672 (yaml comment, pre-fix) | 9bc9d6d6967a2239aa57af2aa53554eddd640d20 | CONFIRMED | ✗ |
| `commit:fix (mainline)` | 48f6a5356a33 (yaml comment) | 48f6a5356a33dd78e7144ae1faef95ffc990aae0 | CONFIRMED | ✓ |
| `commit:introduced` |  | cef401de7be8c4e155c6746bfccf721a4fa5fab9 | CONFIRMED | ✓ |
| `cvss` | 8.8 | 8.8 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H, Linux kernel CNA); Red Hat ADP separate | CONFIRMED | ✓ |
| `kev` | false | false — CVE-2026-43503 absent from CISA KEV; catalogVersion 2026.06.29 checked live, count | CONFIRMED | ✓ |
| `advisory` | USN-8373-1 | USN-8373-1 confirmed — CVE-2026-43503 is listed in the notice's References/description alo | CONFIRMED | ✓ |
| `module:esp4` | esp4 | esp4.c named explicitly as one of two in-place ESP writers in the CNA description | CONFIRMED | ✓ |
| `module:esp6` | esp6 | esp6.c named explicitly alongside esp4.c in the CNA description | CONFIRMED | ✓ |
| `module:rxrpc` | (absent) | not required for this specific CVE — kernel.org text names only esp4.c/esp6.c, and JFrog's | CONFIRMED | ✓ |
| `config:CONFIG_XFRM` | CONFIG_XFRM | real Kconfig symbol (net/xfrm/Kconfig, hidden bool auto-selected via INET/INET6-derived op | CONFIRMED | ✓ |
| `config:CONFIG_INET_ESP` | CONFIG_INET_ESP | real Kconfig symbol; net/ipv4/Makefile gates esp4.o build with obj-$(CONFIG_INET_ESP), con | CONFIRMED | ✓ |
| `config:CONFIG_INET6_ESP` | CONFIG_INET6_ESP | real Kconfig symbol; net/ipv6/Makefile gates esp6.o build with obj-$(CONFIG_INET6_ESP), co | CONFIRMED | ✓ |
| `config:CONFIG_NETFILTER_XT_TARGET_TEE` | (absent, deliberately not gated) | UNVERIFIABLE as a formally documented precondition — no CVE tracker enumerates this Kconfi | UNVERIFIABLE | ✓ |
| `needs_unpriv_userns` | true | true — JFrog's PoC literally runs `unshare -Urn` to obtain CAP_NET_ADMIN as an unprivilege | CONFIRMED | ✓ |
| `distro:ubuntu:22.04` | 5.15.0-181.191 | 5.15.0-181.191 (jammy, Fixed) | CONFIRMED | ✓ |
| `distro:ubuntu:24.04` | 6.8.0-124.124 | 6.8.0-124.124 (noble, Fixed) | CONFIRMED | ✓ |
| `distro:ubuntu:25.10` | 6.17.0-35.35 | 6.17.0-35.35 (questing, Fixed) | CONFIRMED | ✓ |
| `distro:ubuntu:26.04` | 7.0.0-22.22 | 7.0.0-22.22 (resolute, Fixed) | CONFIRMED | ✓ |
| `distro:debian:11` | 5.10.257-1 | 5.10.257-1 (bullseye-security, DLA-4606-1) | CONFIRMED | ✓ |
| `distro:debian:12` | 6.1.174-1 | 6.1.174-1 (bookworm-security, DSA-6306-1) | CONFIRMED | ✓ |
| `distro:debian:13` | 6.12.94-1 | 6.12.94-1 (trixie-security, referenced by DSA-6295-1) — Debian's raw fixed-version table n | CONFIRMED | ✓ |
| `distro:rhel (all releases)` | {} (empty/unknown) | confirmed empty is correct — Red Hat's security-data API shows RHEL 9 and 10 kernel packag | CONFIRMED | ✓ |
| `unaffected:rhel6` | (not in unaffected_distros list) | Red Hat explicitly states RHEL 6 kernel = "Not affected" | CONFIRMED | ✗ |
| `unaffected:rhel7` | (not in unaffected_distros list) | Red Hat explicitly states RHEL 7 kernel and kernel-rt = "Not affected" | CONFIRMED | ✗ |
| `unaffected:rhel8` | (not in unaffected_distros list) | Red Hat explicitly states RHEL 8 kernel = "Not affected" | CONFIRMED | ✗ |
| `unaffected:openshift4-rhcos` | (not in unaffected_distros list) | Red Hat explicitly states OpenShift Container Platform 4 rhcos package = "Not affected" | CONFIRMED | ✗ |

## pedit COW — CVE-2026-46331

CONFIRMED 32 · REFUTED 0 · UNVERIFIABLE 0  (32 facts)

| Field | Dataset says | Reality | Verdict | OK |
|---|---|---|---|:--:|
| `introduced` | 5.18 | 5.18 for the mainline/mainline-derived range (confirmed), BUT the CVE record separately sh | CONFIRMED | ✗ |
| `branch:5.10` |  | introduced at 5.10.117 (commit abe35bf3be51), no fix published; branch actively maintained | CONFIRMED | ✗ |
| `branch:5.15` |  | introduced at 5.15.41 (commit b773640d5bb9), no fix published; branch actively maintained  | CONFIRMED | ✗ |
| `branch:4.19` |  | introduced at 4.19.244 (commit d0c38a914b0c), no fix published; branch fully EOL (absent f | CONFIRMED | ✓ |
| `branch:5.4` |  | introduced at 5.4.195 (commit 2ec2dd7d51a9), no fix published; branch fully EOL — moot in  | CONFIRMED | ✓ |
| `branch:5.17` |  | introduced at 5.17.9 (commit c19cc520b3d6), no fix published; branch fully EOL — moot in p | CONFIRMED | ✓ |
| `branch:6.1` |  | no branch-specific fix found in CNA record; falls within the mainline 5.18–6.12.94 affecte | CONFIRMED | ✓ |
| `branch:6.6` |  | no branch-specific fix found in CNA record; falls within the mainline 5.18–6.12.94 affecte | CONFIRMED | ✓ |
| `branch:6.12` | 6.12.94 | 6.12.94, fix commit 2bec122b9fb91507a758ab5e3e5c4fbe7cb3f61b (tagged [ Upstream commit 899 | CONFIRMED | ✓ |
| `branch:6.18` | 6.18.36 | 6.18.36, fix commit b198ed4e52580a7238c7c7082f03906f8b310313 (tagged [ Upstream commit 899 | CONFIRMED | ✓ |
| `branch:7.0` | 7.0.13 | 7.0.13, fix commit 3dee9d0c198faeb95d052c1b94c2958751a28512 (tagged [ Upstream commit 899e | CONFIRMED | ✓ |
| `fixed_mainline` | 7.1 | v7.1-rc7, merge commit 899ee91156e57784090c5565e4f31bd7dbffbc5a | CONFIRMED | ✓ |
| `commit:introduced` | 899ee91156e5 (labeled 'culprit commit' in cves.yaml's inline comment on the introduced fie | 8b796475fd7882663a870456466a4fb315cc1bd6 (Paolo Abeni, 2022-05-10, 'net/sched: act_pedit:  | CONFIRMED | ✗ |
| `commit:fix` | 899ee91156e5 (per comment) | 899ee91156e57784090c5565e4f31bd7dbffbc5a — confirmed as the mainline fix commit | CONFIRMED | ✓ |
| `distro:debian:13` | 6.12.94-1 | 6.12.94-1 (security), fixed via DSA-6355-1; pre-fix trixie non-security was 6.12.86-1 | CONFIRMED | ✓ |
| `distro:debian:11` |  | vulnerable, no fix: pkg 5.10.223-1 (regular) / 5.10.257-1 (security). This is a REAL expos | CONFIRMED | ✗ |
| `distro:debian:12` |  | vulnerable, no fix: pkg 6.1.170-3 (regular) / 6.1.174-1 (security) — already correctly fal | CONFIRMED | ✓ |
| `distro:ubuntu` | {} (empty map) | all supported releases (18.04–26.04, incl. 25.10) listed Vulnerable with no fixed kernel p | CONFIRMED | ✓ |
| `distro:rhel:8` |  | 4.18.0-553.136.1.el8_10 (RHSA-2026:27353, released 2026-06-19) | CONFIRMED | ✗ |
| `distro:rhel:9` |  | 5.14.0-687.17.1.el9_8 (RHSA-2026:27789) | CONFIRMED | ✗ |
| `distro:rhel:10` |  | 6.12.0-211.26.1.el10_2 (RHSA-2026:27288); EUS 10.0 variant fixed separately at 6.12.0-55.8 | CONFIRMED | ✗ |
| `unaffected:rhel:6` |  | confirmed not affected (defaultStatus:unaffected in CNA; fix_state 'Not affected' for kern | CONFIRMED | ✓ |
| `unaffected:rhel:7` |  | confirmed not affected, same sourcing as RHEL 6 (kernel and kernel-rt packages both 'Not a | CONFIRMED | ✓ |
| `module:act_pedit` | act_pedit | confirmed hard gate — kernel.org CNA lists net/sched/act_pedit.c as the affected file; RHS | CONFIRMED | ✓ |
| `config:CONFIG_NET_SCHED` | present | confirmed real, current Kconfig symbol ('menuconfig NET_SCHED') in live kernel.org net/sch | CONFIRMED | ✓ |
| `config:CONFIG_NET_CLS_ACT` | present | confirmed real, current Kconfig symbol, required for any action (including pedit) to be in | CONFIRMED | ✓ |
| `config:CONFIG_NET_ACT_PEDIT` | present | confirmed real, current Kconfig symbol, builds act_pedit, depends on NET_CLS_ACT | CONFIRMED | ✓ |
| `needs_unpriv_userns` | true | confirmed — PoC requires unshare(CLONE_NEWUSER CLONE_NEWNET) for CAP_NET_ADMIN; independen | CONFIRMED | ✓ |
| `cvss` | 7.8 | 7.8 HIGH, CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (kernel.org CNA score) | CONFIRMED | ✓ |
| `cvss_redhat` | 6.7 (per dataset comment) | 6.7 MEDIUM, CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H — Red Hat scores PR:H instead of  | CONFIRMED | ✓ |
| `kev` | false | not present in CISA KEV (live feed, catalogVersion 2026.06.29, 1630 entries, no CVE-2026-4 | CONFIRMED | ✓ |
| `advisory` | RHSB-2026-008 | confirmed real and matches this exact CVE: 'RHSB-2026-008 Traffic Control Privilege Escala | CONFIRMED | ✓ |

