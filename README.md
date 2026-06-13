# fragcheck

A command-line tool that checks a Linux host for exposure to a specific set of recent, serious kernel privilege-escalation vulnerabilities, and provides remediation guidance for each.

| Nickname | CVE | Summary |
| --- | --- | --- |
| Dirty Pipe | CVE-2022-0847 | Pipe-buffer flaw lets an unprivileged user overwrite read-only files and gain root |
| Copy Fail | CVE-2026-31431 | Crypto (AF_ALG) logic bug gives a precise page-cache write, leading to root |
| Dirty Frag (ESP) | CVE-2026-43284 | IPsec/ESP packet decryption writes into the page cache, leading to root — actively exploited |
| Dirty Frag (RxRPC) | CVE-2026-43500 | Same flaw in the RxRPC/AFS path, reachable through ordinary syscalls |
| Fragnesia | CVE-2026-46300 | Follow-on to Dirty Frag via ESP-in-TCP, again writing into the page cache |

For each one, it weighs two things: whether the running kernel is an affected version, and whether the conditions the exploit needs are actually present. It reads the kernel version from the system's package manager and accounts for distribution backports, so patched versions on Ubuntu, Debian, and RHEL aren't flagged by mistake.

## Status values

- **vulnerable** — affected kernel, and the exploit's conditions are present
- **likely vulnerable** — affected version, but the conditions couldn't be confirmed
- **mitigated** — affected, but something on the host blocks the exploit path
- **not affected** — kernel isn't in the affected range, including backport-patched
- **unknown** — required information couldn't be read

A host running an old kernel is still reported as vulnerable even if a patched one is installed but not yet rebooted into.

## Safety

It runs locally, needs no network, and ships as a single binary. Root is recommended for the fullest signal but not required — anything it cannot read is reported as `unknown` rather than guessed. It only detects exposure — it never runs or includes exploit code.

## Output

By default, results print as a table: one row per CVE, showing the status, a severity rating, the evidence behind it, and the recommended fix. Pass `--json` for the same results in machine-readable form, suitable for piping into other tools.

## Usage

Common tasks are wrapped in the `Makefile` (run `make help` for the full list):

```sh
make build      # build the binary into bin/
make test       # run the full test suite
make check      # format, vet, and test
make run        # run the auditor (refuses cleanly off Linux / non-root)
```

The collector only does real work on Linux. Cross-compile for a target architecture:

```sh
make linux-amd64   # build bin/fragcheck-linux-amd64
make linux-arm64   # build bin/fragcheck-linux-arm64
make linux         # build both
```

Exit codes: `0` audit completed, `1` internal error, `2` refused (non-Linux or unsupported distribution).

## Project status

Early development. Design notes in `docs/SPEC.md`; full CVE details in `docs/cves.md`.
