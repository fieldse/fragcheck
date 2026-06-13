# Tracked CVEs

The CVEs `fragcheck` audits for. The **primary** set is the focus; the **secondary** set
is a baseline of well-documented older privilege-escalation bugs.

> Note: the 2026 CVEs are newer than the assistant's knowledge cutoff. The entries below are
> recorded from the project owner's own notes and are treated as ground truth — do not embellish
> them with unverified detail.

## Primary — page-cache-write privilege escalation

These share an outcome: an unprivileged local user induces a write into the page cache and uses it
to overwrite a trusted file (or otherwise gain code execution), ending in root.

| Nickname | CVE / Advisory | Description |
| --- | --- | --- |
| Dirty Pipe | CVE-2022-0847 | Uninitialized pipe-buffer flag lets a page-cache write overwrite read-only / SUID files, leading to root. The conceptual ancestor of the 2026 family. |
| Copy Fail | CVE-2026-31431 (GHSA-2274-3hgr-wxv6) | `algif_aead` AF_ALG crypto logic bug yields a deterministic 4-byte page-cache write, leading to root. |
| Dirty Frag (ESP) | CVE-2026-43284 | In-place ESP/IPsec decryption over unowned skb fragments writes into the page cache, leading to root. Actively exploited. |
| Dirty Frag (RxRPC) | CVE-2026-43500 | The same flaw in the RxRPC/AFS path: an out-of-bounds page-cache write reachable through unprivileged syscalls, leading to root. |
| Fragnesia | CVE-2026-46300 | ESP-in-TCP loses the shared-fragment flag (a regression introduced by the Dirty Frag patch), again allowing a page-cache write to root. |

## Secondary — legacy privilege escalation

Lower priority, included as a baseline with stable, public version ranges.

| CVE | Name | Subsystem | Impact | Vulnerable kernels (approx) |
| --- | --- | --- | --- | --- |
| CVE-2024-1086 | nf_tables use-after-free | netfilter | Local root | ~5.14–6.6 (CISA KEV) |
| CVE-2023-0386 | OverlayFS privilege escalation | OverlayFS | Local root | ~5.11–6.2 |
| CVE-2023-32233 | netfilter nf_tables use-after-free | netfilter | Local root | ≤ 6.3.x |
