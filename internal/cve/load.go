package cve

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed data/cves.yaml
var rawDataset []byte

// cveIDPattern matches a CVE identifier, e.g. CVE-2024-1086.
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// versionPattern requires a version to start with a digit (e.g. "5.16.11").
var versionPattern = regexp.MustCompile(`^\d`)

// seriesPattern matches a major.minor stable series, e.g. "6.12".
var seriesPattern = regexp.MustCompile(`^\d+\.\d+$`)

// Load parses and validates the embedded CVE dataset. It fails fast on a
// malformed or structurally incomplete dataset so a bad catalogue can never
// produce silently wrong verdicts.
func Load() (*Dataset, error) {
	return parse(rawDataset)
}

func parse(raw []byte) (*Dataset, error) {
	var ds Dataset
	if err := yaml.Unmarshal(raw, &ds); err != nil {
		return nil, fmt.Errorf("cve: parsing dataset: %w", err)
	}
	if err := ds.Validate(); err != nil {
		return nil, fmt.Errorf("cve: validating dataset: %w", err)
	}
	return &ds, nil
}

// Validate checks structural completeness of the dataset.
func (ds *Dataset) Validate() error {
	if len(ds.CVEs) == 0 {
		return fmt.Errorf("dataset has no CVE entries")
	}
	seen := make(map[string]bool, len(ds.CVEs))
	for i, e := range ds.CVEs {
		where := fmt.Sprintf("entry %d (%q)", i, e.ID)
		if !cveIDPattern.MatchString(e.ID) {
			return fmt.Errorf("%s: invalid or missing CVE id", where)
		}
		if seen[e.ID] {
			return fmt.Errorf("%s: duplicate CVE id", where)
		}
		seen[e.ID] = true
		if strings.TrimSpace(e.Nickname) == "" {
			return fmt.Errorf("%s: missing nickname", where)
		}
		if e.CVSS < 0 || e.CVSS > 10 {
			return fmt.Errorf("%s: cvss %.1f out of range 0..10", where, e.CVSS)
		}
		if strings.TrimSpace(e.Remediation) == "" {
			return fmt.Errorf("%s: missing remediation", where)
		}
		if e.Introduced != "" && !versionPattern.MatchString(e.Introduced) {
			return fmt.Errorf("%s: introduced %q is not a version", where, e.Introduced)
		}
		if !hasVersionSignal(e) {
			return fmt.Errorf("%s: no version signal (need a branch, distro fix, or introduced bound)", where)
		}
		for j, b := range e.Branches {
			if !seriesPattern.MatchString(b.Series) {
				return fmt.Errorf("%s: branches[%d] series %q is not major.minor", where, j, b.Series)
			}
			if !versionPattern.MatchString(b.Fixed) {
				return fmt.Errorf("%s: branches[%d] fixed %q is not a version", where, j, b.Fixed)
			}
		}
	}
	return nil
}

// hasVersionSignal reports whether an entry carries enough to make any version
// decision: a branch fix, a per-distro fix, or at least an introduced bound.
func hasVersionSignal(e Entry) bool {
	if e.Introduced != "" || len(e.Branches) > 0 {
		return true
	}
	return len(e.DistroFixed.Ubuntu)+len(e.DistroFixed.Debian)+len(e.DistroFixed.RHEL) > 0
}
