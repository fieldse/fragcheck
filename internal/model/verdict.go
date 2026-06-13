package model

// Status is the graded outcome of auditing one CVE against the host.
type Status string

const (
	// StatusVulnerable: running kernel is in an affected range and the
	// exploit's preconditions are reachable.
	StatusVulnerable Status = "vulnerable"
	// StatusLikelyVulnerable: affected version, but backport status or
	// preconditions could not be confirmed (e.g. no package DB).
	StatusLikelyVulnerable Status = "likely-vulnerable"
	// StatusMitigated: affected version, but a hard block removes the path.
	StatusMitigated Status = "mitigated"
	// StatusNotAffected: running kernel is outside the affected range,
	// including distro backport-patched kernels.
	StatusNotAffected Status = "not-affected"
	// StatusUnknown: a signal required to decide could not be read.
	StatusUnknown Status = "unknown"
)

// Severity describes how serious a CVE is, sourced from the dataset.
type Severity struct {
	CVSS float64 `json:"cvss"`
	KEV  bool    `json:"kev"` // listed in CISA Known Exploited Vulnerabilities
}

// Verdict is the per-CVE audit result rendered to the user.
type Verdict struct {
	CVE         string   `json:"cve"`
	Nickname    string   `json:"nickname"`
	Severity    Severity `json:"severity"`
	Status      Status   `json:"status"`
	Evidence    []string `json:"evidence"`    // why this status was reached
	Remediation string   `json:"remediation"` // fixed version + interim mitigations
}
