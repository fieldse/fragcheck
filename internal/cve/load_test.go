package cve

import "testing"

func TestLoadEmbedded(t *testing.T) {
	ds, err := Load()
	if err != nil {
		t.Fatalf("Load() embedded dataset: %v", err)
	}
	if got, want := len(ds.CVEs), 8; got != want {
		t.Errorf("CVE count = %d, want %d", got, want)
	}
	// Spot-check that a known primary entry is present and well-formed.
	var dirtyPipe *Entry
	for i := range ds.CVEs {
		if ds.CVEs[i].ID == "CVE-2022-0847" {
			dirtyPipe = &ds.CVEs[i]
		}
	}
	if dirtyPipe == nil {
		t.Fatal("CVE-2022-0847 (Dirty Pipe) missing from dataset")
	}
	if dirtyPipe.Nickname != "Dirty Pipe" {
		t.Errorf("Dirty Pipe nickname = %q", dirtyPipe.Nickname)
	}
}

func TestValidateRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"no entries": `cves: []`,
		"bad id": `
cves:
  - id: NOT-A-CVE
    nickname: x
    cvss: 7.0
    remediation: patch
    affected: [{fixed: "5.0"}]`,
		"duplicate id": `
cves:
  - id: CVE-2022-0847
    nickname: a
    cvss: 7.0
    remediation: patch
    affected: [{fixed: "5.0"}]
  - id: CVE-2022-0847
    nickname: b
    cvss: 7.0
    remediation: patch
    affected: [{fixed: "5.0"}]`,
		"missing nickname": `
cves:
  - id: CVE-2022-0847
    cvss: 7.0
    remediation: patch
    affected: [{fixed: "5.0"}]`,
		"cvss out of range": `
cves:
  - id: CVE-2022-0847
    nickname: x
    cvss: 11.5
    remediation: patch
    affected: [{fixed: "5.0"}]`,
		"missing remediation": `
cves:
  - id: CVE-2022-0847
    nickname: x
    cvss: 7.0
    affected: [{fixed: "5.0"}]`,
		"no affected ranges": `
cves:
  - id: CVE-2022-0847
    nickname: x
    cvss: 7.0
    remediation: patch`,
		"non-version bound": `
cves:
  - id: CVE-2022-0847
    nickname: x
    cvss: 7.0
    remediation: patch
    affected: [{fixed: "vfive"}]`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parse([]byte(raw)); err == nil {
				t.Errorf("parse(%s) = nil error, want validation failure", name)
			}
		})
	}
}
