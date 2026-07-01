# Linux Kernel LPE Cluster — Page-Cache Corruption Family

**Date:** July 1, 2026  
**Bug class:** Page-cache corruption via in-place cryptographic decryption on zero-copy/splice paths  
**Impact:** Deterministic, race-free local privilege escalation (LPE) to root  
**Requirement:** Local foothold — no remote code execution on its own  
**macOS / FreeBSD:** Unaffected  

---

## CVE Summary Table

| # | Name | CVE(s) | Disclosed | Module / Subsystem | Researcher |
|---|------|---------|-----------|-------------------|------------|
| 1 | **CopyFail** | CVE-2026-31431 | Apr 29, 2026 | `algif_aead` (AF_ALG crypto socket) | Theori |
| 2 | **DirtyFrag** | CVE-2026-43284, CVE-2026-43500 | May 7, 2026 | `esp4`/`esp6` (xfrm-ESP/IPsec), `rxrpc` | Hyunwoo Kim (@v4bel) |
| 3 | **Fragnesia** | CVE-2026-46300 | May 14, 2026 | `esp4`/`esp6` (ESP-in-TCP ULP, xfrm) | William Bowling, V12 team |
| 4 | **DirtyDecrypt** (DirtyCBC) | CVE-2026-31635 | May 18, 2026 (PoC) | `rxgk_decrypt_skb()` — RxGK/RxRPC (AFS) | Zellic + V12 (Luna Tong) |
| 5 | **CVE-2025-48595** | CVE-2025-48595 | Jun 2, 2026 (CISA KEV) | cgroups v1 `release_agent` | — |

---

## Bug Class

CVEs 1–4 share the same root mechanism: they abuse trusted syscalls dealing with memory (`splice`, `vmsplice`, and related zero-copy mechanisms) to alter cached file contents in RAM without changing the file on disk. Unlike race-condition-based exploits, this class is deterministic and highly reliable — comparable to Dirty Pipe (CVE-2022-0847).

The core contract violation: any kernel code path that moves fragment descriptors or performs in-place decryption on shared `skb` fragments must propagate the copy-on-write guard and shared-frag bit. Any path where this contract is not honored is a potential new variant. The class is likely not exhausted.

**Key defensive implications:**
- File-integrity monitoring (FIM) is blind to exploitation — the on-disk file is never modified
- Rebooting restores the original binary (page cache is volatile)
- `drop_caches` evicts the corrupted page but does not undo privilege already obtained
- Docker/Podman container image distro label is irrelevant — host or VM kernel version determines vulnerability

---

## Individual CVEs

### 1. CopyFail — CVE-2026-31431

**Disclosed:** April 29, 2026 (Theori)  
**CISA KEV:** Yes — actively exploited in the wild  
**Entry point:** `algif_aead` — the AF_ALG kernel socket interface for authenticated encryption  
**Introduced:** Linux 4.14 (2017), commit `72548b093ee3`  

The AF_ALG socket interface exposes authenticated encryption primitives to userspace. The in-place decryption path inside `algif_aead` can be coerced to write into page-cache pages shared with on-disk files. The result is an in-memory binary patch of a setuid binary (e.g. `/usr/bin/su`) granting root on next invocation.

**Mitigation:** denylist/unload `algif_aead`  
**References:** https://www.openwall.com/lists/oss-security/2026/04/29/23

---

### 2. DirtyFrag — CVE-2026-43284 + CVE-2026-43500

**Disclosed:** May 7, 2026 (Hyunwoo Kim, @v4bel)  
**Entry points:**
- CVE-2026-43284 — xfrm-ESP (IPsec) page-cache write; patch commit `f4c50a4034e6`
- CVE-2026-43500 — RxRPC page-cache write; patch commit `aa54b1d27fe0`

Two independent page-cache write primitives, disclosed as a single campaign. Both allow manipulation of shared page-cache memory via zero-copy networking paths.

**Notably:** DirtyFrag is exploitable regardless of whether the CopyFail (`algif_aead`) mitigation is applied — it is a fully independent attack path.

**Disclosure note:** Researcher was under agreed embargo; a patch for CVE-2026-43284 was merged into the public tree on May 5, and a third party — unaware of the embargo — independently discovered the vulnerability from the fix commit, triggering early public disclosure.

**Mitigation:** blacklist `esp4`, `esp6`, `rxrpc`  
**References:** https://www.openwall.com/lists/oss-security/2026/05/07/8

---

### 3. Fragnesia — CVE-2026-46300

**Disclosed:** May 14, 2026 (William Bowling, V12 team)  
**Entry point:** `esp4`/`esp6` — ESP-in-TCP ULP subsystem (xfrm)  

A separate bug from DirtyFrag in the same ESP/XFRM surface. The `skb_try_coalesce()` path drops the shared-frag bit during coalescing — the skb "forgets" that a fragment is shared with a page-cache page. The DirtyFrag patch did not close this path.

Like DirtyFrag, it requires `unshare(CLONE_NEWUSER | CLONE_NEWNET)` to obtain `CAP_NET_ADMIN` (available to unprivileged users on most distros by default). No race condition — fully deterministic.

Microsoft's existing DirtyFrag detection signatures (Trojan:Linux/DirtyFrag.Z!MTB and .DA!MTB) also cover the public Fragnesia PoC.

**Mitigation:** same as DirtyFrag — blacklist `esp4`, `esp6`, `rxrpc`  
**PoC:** https://github.com/v12-security/pocs/tree/main/fragnesia

---

### 4. DirtyDecrypt (DirtyCBC) — CVE-2026-31635

**Disclosed:** May 18, 2026 — PoC released (Zellic + V12: Luna Tong / cts / gf_256)  
**CVSS:** 7.5  
**Entry point:** `rxgk_decrypt_skb()` — RxGK subsystem (GSS-API security layer for RxRPC/AFS)  
**Patch merged:** April 25, 2026 (upstream, pre-disclosure); RxRPC path also addressed by `aa54b1d27fe0` (May 10, 2026)  

The `rxgk_decrypt_skb()` function decrypts incoming RxGK RESPONSE tokens over `sk_buff` data that may alias page-cache pages supplied via `MSG_SPLICE_PAGES`. The code decrypts before MAC verification and lacks a COW guard — decrypted bytes land directly in page-cache pages belonging to privileged files (`/etc/shadow`, SUID binaries).

Discovered May 9; kernel maintainers informed the team it was a duplicate of a fix already merged upstream. No independent CVE was assigned to the V12 report — the NVD links the PoC to CVE-2026-31635, which officially describes a related DoS bug in the same code path (inverted length check in `rxgk_verify_response()`).

**Distro scope:** Fedora, Arch Linux, openSUSE Tumbleweed (require `CONFIG_RXGK`). Debian/Ubuntu/RHEL unaffected by default.  
**Mitigation:** blacklist `rxrpc` (also mitigated by DirtyFrag patch `aa54b1d27fe0`)  
**PoC:** https://github.com/v12-security/pocs (V12 team)

---

### 5. CVE-2025-48595 — cgroups v1 release_agent LPE

**Disclosed:** June 2, 2026 (CISA KEV addition)  
**Entry point:** cgroups v1 `release_agent` feature  
**CISA KEV:** Yes  

Architecturally distinct from the splice/page-cache family. An improper authentication vulnerability in the cgroups v1 `release_agent` notification mechanism allows privilege escalation to root. This path has been known as a container escape vector since at least the Felix Wilhelm PoC era; this CVE formalizes active exploitation.

**Mitigation:** disable cgroups v1 (`systemd.unified_cgroup_hierarchy=1`) or restrict `release_agent` via seccomp/AppArmor policy; prefer cgroups v2  
**References:** https://nvd.nist.gov/vuln/detail/CVE-2025-48595

---

## Shared Mitigations — Splice / Page-Cache Family (CVEs 1–4)

```bash
# DirtyFrag / Fragnesia / DirtyDecrypt (rxrpc path)
printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' \
  > /etc/modprobe.d/dirtyfrag.conf
rmmod esp4 esp6 rxrpc 2>/dev/null

# CopyFail
printf 'install algif_aead /bin/false\n' > /etc/modprobe.d/copyfail.conf
rmmod algif_aead 2>/dev/null

# After applying any mitigation — evict potentially corrupted pages
echo 3 > /proc/sys/vm/drop_caches
```

**Tradeoffs:**
- Blacklisting `esp4`/`esp6` breaks IPsec VPN (OPNsense, strongSwan, etc.)
- Blacklisting `rxrpc` breaks AFS client
- Blacklisting `algif_aead` breaks AF_ALG AEAD userspace crypto consumers
- Disabling unprivileged user namespaces (`kernel.unprivileged_userns_clone=0`) closes the `CAP_NET_ADMIN` acquisition path for all four — but breaks rootless containers, some CI sandboxes, and sandboxed browser profiles

---

## Detection

```bash
# Check for unprivileged namespace exploitation
auditctl -a always,exit -F arch=b64 -S unshare -k ns_create

# Monitor: unexpected root grants from unprivileged UIDs following namespace creation
# FIM will NOT detect exploitation — disk image is never modified

# Verify loaded modules
lsmod | grep -E 'esp4|esp6|rxrpc|algif_aead|act_pedit'

# Post-incident: drop page cache to restore clean binary images from disk
echo 3 > /proc/sys/vm/drop_caches
```

---

## Patch Status by Distro (splice/page-cache family)

| Distro | Status |
|--------|--------|
| Ubuntu 24.04+ | AppArmor restricts namespace creation — blocks default exploit path for CVEs 2–3 |
| Fedora / Debian | Unprivileged user namespaces enabled by default — fully exposed without patch |
| AzureLinux 3.0 | Fixed in kernel `6.6.139.1-1.azl3+` |
| AlmaLinux / CloudLinux | Kernel patches released |
| RHEL | Patches available; track RHSB advisories |

Advisories: Ubuntu USN-8373-1 · Debian security-tracker · SUSE security advisories · Red Hat RHSB-2026-003

---

## References

- Theori — CopyFail: https://www.openwall.com/lists/oss-security/2026/04/29/23
- THN — DirtyFrag: https://thehackernews.com/2026/05/linux-kernel-dirty-frag-lpe-exploit.html
- oss-sec — Fragnesia: https://seclists.org/oss-sec/2026/q2/515
- Huntress — CopyFail/DirtyFrag/Fragnesia overview: https://www.huntress.com/blog/linux-kernel-flaws-copyfail-dirty-frag-fragnesia
- THN — DirtyDecrypt: https://thehackernews.com/2026/05/dirtydecrypt-poc-released-for-linux.html
- Moselwal — DirtyDecrypt deep-dive: https://moselwal.com/blog/dirtydecrypt-linux-kernel-rxgk-cve-2026-31635
- CISA KEV — CVE-2025-48595: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Microsoft Security Blog — DirtyFrag: https://www.microsoft.com/en-us/security/blog/2026/05/08/active-attack-dirty-frag-linux-vulnerability-expands-post-compromise-risk/
- V12 PoC repo: https://github.com/v12-security/pocs
