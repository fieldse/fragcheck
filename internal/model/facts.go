// Package model holds the core data types shared across the auditor: the host
// facts gathered by the collector and the verdicts produced by the detector.
// It is a leaf package with no internal dependencies, which keeps the
// collect/detect/report packages decoupled and free of import cycles.
package model

// Distro identifies the host's distribution family, which selects the backport
// version scheme used when judging kernel patch level.
type Distro string

const (
	DistroUbuntu  Distro = "ubuntu"
	DistroDebian  Distro = "debian"
	DistroRHEL    Distro = "rhel"
	DistroUnknown Distro = "unknown"
)

// Supported reports whether the distro has backport-aware handling. An
// unsupported distro causes the CLI to refuse rather than emit misleading
// verdicts.
func (d Distro) Supported() bool {
	switch d {
	case DistroUbuntu, DistroDebian, DistroRHEL:
		return true
	default:
		return false
	}
}

// Fact carries a value that may not have been readable, so the detector can
// tell "absent" (Known, zero value) apart from "could not read" (!Known). The
// distinction drives the choice between a not-affected and an unknown verdict.
type Fact[T any] struct {
	Value T
	Known bool   // true when the value was read successfully
	Err   string // why the value could not be read, when !Known
}

// Readable returns a known Fact.
func Readable[T any](v T) Fact[T] { return Fact[T]{Value: v, Known: true} }

// Unreadable returns an unknown Fact carrying the reason it could not be read.
func Unreadable[T any](reason string) Fact[T] { return Fact[T]{Err: reason} }

// ModuleState captures everything the detector needs to decide whether a
// kernel module's code path is reachable. A module is reachable if it is
// loaded, built into the kernel, or autoloadable on demand; "not currently
// loaded" alone does not make it safe.
type ModuleState struct {
	Name         string
	Loaded       bool
	BuiltIn      bool
	Autoloadable bool // a module exists and is not blocked from loading
	Blacklisted  bool // hard block: explicitly blacklisted/disabled
	Known        bool // false when module state could not be determined
}

// Reachable reports whether the module's code path can be exercised by an
// attacker (loaded now, compiled in, or autoloadable).
func (m ModuleState) Reachable() bool {
	return m.Loaded || m.BuiltIn || m.Autoloadable
}

// HardBlocked reports a genuine kill: the module is blacklisted/disabled and is
// not already loaded or built in. Only a hard block demotes a verdict to
// mitigated; soft hardening does not.
func (m ModuleState) HardBlocked() bool {
	return m.Blacklisted && !m.Loaded && !m.BuiltIn
}

// HostFacts is the complete, collector-produced snapshot the pure detector
// consumes. Every field that can fail to read carries its own provenance so
// the detector never guesses.
type HostFacts struct {
	// Distro and its version id (e.g. "22.04", "9.3"), from /etc/os-release.
	Distro          Distro
	DistroVersionID string

	// RunningKernel is the upstream release reported by uname -r; verdicts are
	// judged on it, and it drives upstream per-branch matching.
	RunningKernel Fact[string]

	// RunningKernelPackage is the installed package version of the *running*
	// kernel (dpkg-query on linux-image-$(uname -r), or rpm). Unlike the uname
	// string it reflects distro backports, so it is the value compared against
	// per-distro-release fixed versions.
	RunningKernelPackage Fact[string]

	// InstalledKernel is the newest kernel package version installed. When it is
	// newer than the running kernel a patch is installed but pending a reboot —
	// the host is still judged on the running kernel.
	InstalledKernel Fact[string]

	// KernelConfigs holds build-config values (CONFIG_X -> "y"/"m"/"n") read
	// from /boot/config-$(uname -r) or /proc/config.gz, used to gate CVEs whose
	// exploit requires a kernel feature to be compiled in.
	KernelConfigs map[string]Fact[string]

	// PackageDBAvailable is false on hosts without dpkg/rpm, where backport
	// correction cannot be performed and verdicts fall back to version-only.
	PackageDBAvailable bool

	// Modules is keyed by module name; entries are populated on demand for the
	// modules named in the CVE dataset.
	Modules map[string]ModuleState

	// Sysctls is keyed by sysctl name (e.g. "kernel.unprivileged_userns_clone").
	Sysctls map[string]Fact[string]
}

// Module returns the state for a named module, marked unknown if absent.
func (h HostFacts) Module(name string) ModuleState {
	if m, ok := h.Modules[name]; ok {
		return m
	}
	return ModuleState{Name: name, Known: false}
}

// Sysctl returns the value Fact for a named sysctl, unreadable if absent.
func (h HostFacts) Sysctl(name string) Fact[string] {
	if v, ok := h.Sysctls[name]; ok {
		return v
	}
	return Unreadable[string]("sysctl not collected: " + name)
}

// Config returns the value Fact for a named kernel build config (e.g.
// "CONFIG_INET_ESP"), unreadable if not collected.
func (h HostFacts) Config(name string) Fact[string] {
	if v, ok := h.KernelConfigs[name]; ok {
		return v
	}
	return Unreadable[string]("kernel config not collected: " + name)
}
