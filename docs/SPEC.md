# fragcheck — Project Spec

## Purpose

A Go CLI that audits the local Linux host for vulnerability to a small set of recent kernel
privilege-escalation exploits, and prints a clear, fast, structured table the operator can act on
to remediate. Defensive tool: it detects exposure, it does not run or ship exploit code.

## Scope

- **Target:** local host only. Offline at runtime (no network).
- **Privilege:** root recommended for the fullest read of sysctls, modules, and kernel/pkg state,
  but not required — unreadable signals degrade to an `unknown` verdict (warning printed when non-root).
- **Platform:** Linux with a supported distro. Non-Linux / unknown distro → refuse cleanly
  (message + non-zero exit, no table).
- **Toolchain:** Go 1.26.
- **CVEs:** see `CLAUDE.md` / `docs/cves.md` — primary 2026 page-cache-write family + secondary legacy set.

## Architecture

A collector/detector seam keeps detection testable without real vulnerable hosts:

- **`internal/collect`** (impure) reads the host and produces a `HostFacts` struct:
  running kernel (`uname`), installed kernel **package** version (`dpkg`/`rpm`), distro
  (`/etc/os-release`), loaded modules, module autoload/blacklist state, relevant sysctls.
- **`internal/detect`** (pure) maps `HostFacts` + embedded CVE dataset → verdicts. No I/O.
- **`cmd/fragcheck`** wires collect → detect → render.

Module path `github.com/fieldse/fragcheck`; binary `fragcheck`.

## Detection model

### Version source & comparison

- Installed kernel version is read from the **package DB** (`dpkg`/`rpm`) — the only source that
  reflects distro backports. `uname` is the running-kernel fallback.
- Version comparison **shells out** to native tools (`dpkg --compare-versions`, `rpm`) so distro
  version-ordering semantics (epochs, tildes) are correct. Backport-corrected against the distro's
  fixed package version (Ubuntu / Debian / RHEL).

### Running vs installed (reboot gap)

- Verdict is judged on the **running** kernel. If a patched package is installed but the old
  vulnerable kernel is still running → still `vulnerable`, with evidence note
  "patched kernel installed — reboot pending."

### Preconditions

- **Autoload-aware:** a module counts as present if loaded OR built-in OR autoloadable
  (not blacklisted/disabled). "Not in `/proc/modules`" does **not** mean safe.
- Evidence reports loaded-now vs autoload-reachable **separately**; verdict uses the conservative
  (autoload-aware) reading.
- Only **hard blocks** (module blacklisted/disabled, userns hard-off, sysctl that closes the path)
  demote a verdict to `mitigated`. Soft hardening is noted as evidence but does not downgrade.

### Verdict taxonomy (5-state)

| Verdict             | Meaning                                                                 |
| ------------------- | ----------------------------------------------------------------------- |
| `vulnerable`        | Running kernel in vulnerable range AND preconditions reachable.         |
| `likely-vulnerable` | Version in range but backport/preconditions unconfirmed (e.g. no pkg DB).|
| `mitigated`         | Version vulnerable but a hard block removes the exploit path.           |
| `not-affected`      | Running kernel outside range (incl. distro backport patched).           |
| `unknown`           | Required signals could not be read.                                     |

## Data

CVE definitions in an **embedded data file** (`go:embed` YAML/JSON) — offline, editable without
touching detection logic. Each entry carries:

- id, nickname, advisory, **CVSS base score**, **KEV (known-exploited) flag**, short description
- affected upstream kernel range(s)
- per-distro fixed package versions (ubuntu/debian/rhel)
- preconditions (modules, sysctls, userns, etc.)
- remediation: fixed version **+ interim mitigations**

## Output

- **Default:** audit **all** CVEs, print full pretty table to stdout via stdlib `text/tabwriter`
  + manual ANSI color (zero third-party deps).
  Columns: CVE, nickname, severity (CVSS + KEV), **verdict**, evidence, remediation.
- **`--json`:** machine-readable equivalent.

## Testing

- Golden `HostFacts` fixtures (Ubuntu vuln, Ubuntu patched, RHEL, reboot-pending, no-pkg-DB, …),
  each asserting the full verdict table. Table-driven Go tests against the pure `detect` layer.
- `collect` is thin and integration-tested separately.

## Deferred / out of scope (v1)

- Finding-based exit codes for CI (note: unsupported-platform still exits non-zero).
- Markdown output.
- Remote-over-SSH.
- Severity scoring convention beyond CVSS+KEV.
