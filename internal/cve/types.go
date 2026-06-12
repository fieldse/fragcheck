package cve

// Dataset is the top-level embedded CVE catalogue.
type Dataset struct {
	CVEs []Entry `yaml:"cves"`
}

// Entry describes a single CVE: how to tell whether the host's kernel is
// affected, what the exploit needs, and how to remediate.
type Entry struct {
	ID          string `yaml:"id"`
	Nickname    string `yaml:"nickname"`
	Advisory    string `yaml:"advisory"`
	CVSS        float64 `yaml:"cvss"`
	KEV         bool   `yaml:"kev"`
	// Verified is true only once the ranges/fixed versions/preconditions have
	// been confirmed against an authoritative advisory. Unverified entries are
	// loaded but their accuracy is not guaranteed.
	Verified      bool          `yaml:"verified"`
	Description   string        `yaml:"description"`
	Affected      []KernelRange `yaml:"affected"`
	DistroFixed   DistroFixed   `yaml:"distro_fixed"`
	Preconditions Preconditions `yaml:"preconditions"`
	Remediation   string        `yaml:"remediation"`
}

// KernelRange is an upstream affected range: vulnerable for kernels >=
// Introduced and < Fixed. Either bound may be empty when unknown.
type KernelRange struct {
	Introduced string `yaml:"introduced"`
	Fixed      string `yaml:"fixed"`
}

// DistroFixed holds the patched package version per supported distro, used for
// backport-corrected comparison. Empty means "not yet recorded".
type DistroFixed struct {
	Ubuntu string `yaml:"ubuntu"`
	Debian string `yaml:"debian"`
	RHEL   string `yaml:"rhel"`
}

// Preconditions are the host conditions an exploit needs to be reachable.
type Preconditions struct {
	// Modules are kernel modules whose code path the exploit requires. The
	// detector treats a module as reachable if loaded, built in, or
	// autoloadable; an empty list means no module gate (e.g. core pipe code).
	Modules []string `yaml:"modules"`
	// NeedsUnprivUserns is true when the exploit requires unprivileged user
	// namespaces.
	NeedsUnprivUserns bool `yaml:"needs_unpriv_userns"`
}
