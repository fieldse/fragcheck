package cve

import "testing"

func TestLoadEmbedded(t *testing.T) {
	ds, err := Load()
	if err != nil {
		t.Fatalf("Load() embedded dataset: %v", err)
	}
	if got, want := len(ds.CVEs), 10; got != want {
		t.Errorf("CVE count = %d, want %d", got, want)
	}

	byID := map[string]Entry{}
	for _, e := range ds.CVEs {
		byID[e.ID] = e
	}

	// The five primary entries must be present and verified.
	for _, id := range []string{
		"CVE-2022-0847", "CVE-2026-31431", "CVE-2026-43284", "CVE-2026-43500", "CVE-2026-46300",
	} {
		e, ok := byID[id]
		if !ok {
			t.Errorf("primary CVE %s missing", id)
			continue
		}
		if !e.Verified {
			t.Errorf("%s should be verified", id)
		}
		if len(e.Branches) == 0 {
			t.Errorf("%s should have per-branch fix data", id)
		}
	}

	// Spot-check a known per-release distro fix is wired through.
	if got := byID["CVE-2026-46300"].DistroFixed.For("debian", "13"); got != "6.12.94-1" {
		t.Errorf("Fragnesia debian 13 fixed = %q, want 6.12.94-1", got)
	}

	// pedit COW carries per-line lower bounds (affected_from, no in-line fix).
	var gotAffectedFrom bool
	for _, b := range byID["CVE-2026-46331"].Branches {
		if b.Series == "5.10" && b.Fixed == "" && b.AffectedFrom == "5.10.117" {
			gotAffectedFrom = true
		}
	}
	if !gotAffectedFrom {
		t.Errorf("pedit COW should carry a 5.10 branch with affected_from 5.10.117 and no fix")
	}
}

func TestValidateRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"no entries": `cves: []`,
		"bad id": `
cves:
  - {id: NOT-A-CVE, nickname: x, cvss: 7.0, remediation: patch, introduced: "5.8"}`,
		"duplicate id": `
cves:
  - {id: CVE-2022-0847, nickname: a, cvss: 7.0, remediation: patch, introduced: "5.8"}
  - {id: CVE-2022-0847, nickname: b, cvss: 7.0, remediation: patch, introduced: "5.8"}`,
		"missing nickname": `
cves:
  - {id: CVE-2022-0847, cvss: 7.0, remediation: patch, introduced: "5.8"}`,
		"cvss out of range": `
cves:
  - {id: CVE-2022-0847, nickname: x, cvss: 11.5, remediation: patch, introduced: "5.8"}`,
		"missing remediation": `
cves:
  - {id: CVE-2022-0847, nickname: x, cvss: 7.0, introduced: "5.8"}`,
		"no version signal": `
cves:
  - {id: CVE-2022-0847, nickname: x, cvss: 7.0, remediation: patch}`,
		"bad branch series": `
cves:
  - id: CVE-2022-0847
    nickname: x
    cvss: 7.0
    remediation: patch
    branches: [{series: "five", fixed: "5.0"}]`,
		"bad branch fixed": `
cves:
  - id: CVE-2022-0847
    nickname: x
    cvss: 7.0
    remediation: patch
    branches: [{series: "5.15", fixed: "vfive"}]`,
		"branch with neither fixed nor affected_from": `
cves:
  - id: CVE-2022-0847
    nickname: x
    cvss: 7.0
    remediation: patch
    branches: [{series: "5.15"}]`,
		"bad branch affected_from": `
cves:
  - id: CVE-2022-0847
    nickname: x
    cvss: 7.0
    remediation: patch
    branches: [{series: "5.15", affected_from: "vfive"}]`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parse([]byte(raw)); err == nil {
				t.Errorf("parse(%s) = nil error, want validation failure", name)
			}
		})
	}
}
