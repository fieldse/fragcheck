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

// kernelVersionPattern requires a version to start with a digit (e.g. "5.16.11").
// Empty bounds are permitted by callers; this only checks non-empty values.
var kernelVersionPattern = regexp.MustCompile(`^\d`)

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
		if len(e.Affected) == 0 {
			return fmt.Errorf("%s: needs at least one affected range", where)
		}
		for j, r := range e.Affected {
			if r.Introduced == "" && r.Fixed == "" {
				continue // an all-empty range is a recorded "unknown bound"
			}
			if r.Introduced != "" && !kernelVersionPattern.MatchString(r.Introduced) {
				return fmt.Errorf("%s: affected[%d] introduced %q is not a version", where, j, r.Introduced)
			}
			if r.Fixed != "" && !kernelVersionPattern.MatchString(r.Fixed) {
				return fmt.Errorf("%s: affected[%d] fixed %q is not a version", where, j, r.Fixed)
			}
		}
	}
	return nil
}
