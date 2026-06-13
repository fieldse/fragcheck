package cve

// Dataset is the top-level embedded CVE catalogue.
type Dataset struct {
	CVEs []Entry `yaml:"cves"`
}

// Entry describes a single CVE: how to tell whether the host's kernel is
// affected, what the exploit needs, and how to remediate.
type Entry struct {
	ID       string  `yaml:"id"`
	Nickname string  `yaml:"nickname"`
	Advisory string  `yaml:"advisory"`
	CVSS     float64 `yaml:"cvss"`
	KEV      bool    `yaml:"kev"`
	// Verified is true once ranges/fixed versions/preconditions are sourced
	// from the authoritative knowledgebase. Unverified entries still load.
	Verified    bool   `yaml:"verified"`
	Description string `yaml:"description"`

	// Introduced is the lowest upstream version that carries the flaw; a
	// running kernel below it is not affected. Empty means "unknown lower bound".
	Introduced string `yaml:"introduced"`

	// Branches lists the first upstream version that fixes the flaw in each
	// stable series (e.g. {Series: "5.15", Fixed: "5.15.208"}). Used for the
	// upstream-version fallback when no per-distro-release fix is recorded.
	Branches []Branch `yaml:"branches"`

	// DistroFixed maps a distro release to the patched package version, the
	// authoritative (backport-aware) signal compared against the running
	// kernel's package version.
	DistroFixed DistroFixed `yaml:"distro_fixed"`

	// UnaffectedDistros names distro families that are categorically not
	// affected (e.g. the feature is absent from their kernels).
	UnaffectedDistros []string `yaml:"unaffected_distros"`

	Preconditions Preconditions `yaml:"preconditions"`
	Remediation   string        `yaml:"remediation"`
}

// Branch is the first fixed upstream version within a stable series.
type Branch struct {
	Series string `yaml:"series"` // major.minor, e.g. "6.12"
	Fixed  string `yaml:"fixed"`  // first fixed patch release, e.g. "6.12.91"
}

// DistroFixed holds patched package versions keyed by distro release id
// (matching /etc/os-release VERSION_ID). Empty maps degrade to the upstream
// branch fallback.
type DistroFixed struct {
	Ubuntu map[string]string `yaml:"ubuntu"` // "22.04" -> "5.15.0-181.191"
	Debian map[string]string `yaml:"debian"` // "12"    -> "6.1.174-1"
	RHEL   map[string]string `yaml:"rhel"`   // "9"     -> "5.14.0-611.54.3.el9_7"
}

// For returns the recorded fixed package version for a distro family and
// release id, or "" when none is recorded.
func (d DistroFixed) For(distro, release string) string {
	switch distro {
	case "ubuntu":
		return d.Ubuntu[release]
	case "debian":
		return d.Debian[release]
	case "rhel":
		return d.RHEL[release]
	default:
		return ""
	}
}

// Preconditions are the host conditions an exploit needs to be reachable.
type Preconditions struct {
	// Modules are kernel modules whose code path the exploit requires; reachable
	// if loaded, built in, or autoloadable. Empty means no module gate.
	Modules []string `yaml:"modules"`
	// Configs are kernel build options that must be enabled (=y or =m) for the
	// flaw to exist; any one disabled makes the host not affected.
	Configs []string `yaml:"configs"`
	// NeedsUnprivUserns is true when the exploit requires unprivileged user
	// namespaces (so disabling them is a hard block — but only for these CVEs).
	NeedsUnprivUserns bool `yaml:"needs_unpriv_userns"`
}
