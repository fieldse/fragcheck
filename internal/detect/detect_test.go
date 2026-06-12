package detect

import (
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/fieldse/linux-vuln-auditor/internal/cve"
	"github.com/fieldse/linux-vuln-auditor/internal/model"
)

// fakeCmp compares dotted/dashed numeric version strings field by field. It is
// good enough for fixtures with clean versions and keeps tests independent of
// the real dpkg/rpm comparator.
func fakeCmp(a, b string) int {
	as, bs := splitVer(a), splitVer(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

func splitVer(s string) []int {
	fields := strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsDigit(r) })
	nums := make([]int, len(fields))
	for i, f := range fields {
		nums[i], _ = strconv.Atoi(f)
	}
	return nums
}

// entryNf is a module- and userns-gated CVE (modelled on nf_tables).
func entryNf() cve.Entry {
	return cve.Entry{
		ID: "CVE-2024-1086", Nickname: "nf_tables UAF", CVSS: 7.8, KEV: true, Verified: true,
		Affected:      []cve.KernelRange{{Introduced: "5.14", Fixed: "6.8"}},
		DistroFixed:   cve.DistroFixed{Ubuntu: "5.15.0.92", Debian: "5.10.0.30", RHEL: "5.14.0.300"},
		Preconditions: cve.Preconditions{Modules: []string{"nf_tables"}, NeedsUnprivUserns: true},
		Remediation:   "patch",
	}
}

// entryPipe has no module/namespace precondition (modelled on Dirty Pipe).
func entryPipe() cve.Entry {
	return cve.Entry{
		ID: "CVE-2022-0847", Nickname: "Dirty Pipe", CVSS: 7.8, Verified: true,
		Affected:    []cve.KernelRange{{Introduced: "5.8", Fixed: "5.16.11"}},
		DistroFixed: cve.DistroFixed{Ubuntu: "5.15.0.92"},
		Remediation: "patch",
	}
}

// entryNoData has only empty ranges and no distro fix (modelled on an
// unverified 2026 placeholder).
func entryNoData() cve.Entry {
	return cve.Entry{
		ID: "CVE-2026-43284", Nickname: "Dirty Frag (ESP)", CVSS: 7.8, Verified: false,
		Affected:      []cve.KernelRange{{}},
		Preconditions: cve.Preconditions{Modules: []string{"esp4"}},
		Remediation:   "patch when available",
	}
}

func loaded() model.ModuleState      { return model.ModuleState{Loaded: true, Known: true} }
func autoloadable() model.ModuleState { return model.ModuleState{Autoloadable: true, Known: true} }
func blacklisted() model.ModuleState  { return model.ModuleState{Blacklisted: true, Known: true} }

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name       string
		entry      cve.Entry
		facts      model.HostFacts
		want       model.Status
		wantEvHas  string // substring that must appear in evidence (optional)
	}{
		{
			name:  "ubuntu vulnerable",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, PackageDBAvailable: true,
				RunningKernel: model.Readable("5.15.0.80"),
				Modules:       map[string]model.ModuleState{"nf_tables": loaded()},
				Sysctls:       map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
			},
			want: model.StatusVulnerable,
		},
		{
			name:  "ubuntu patched",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, PackageDBAvailable: true,
				RunningKernel: model.Readable("5.15.0.95"),
			},
			want: model.StatusNotAffected,
		},
		{
			name:  "patched installed but reboot pending",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, PackageDBAvailable: true,
				RunningKernel:   model.Readable("5.15.0.80"),
				InstalledKernel: model.Readable("5.15.0.95"),
				Modules:         map[string]model.ModuleState{"nf_tables": loaded()},
				Sysctls:         map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
			},
			want:      model.StatusVulnerable,
			wantEvHas: "reboot pending",
		},
		{
			name:  "rhel vulnerable via autoloadable module",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroRHEL, PackageDBAvailable: true,
				RunningKernel: model.Readable("5.14.0.100"),
				Modules:       map[string]model.ModuleState{"nf_tables": autoloadable()},
				Sysctls:       map[string]model.Fact[string]{"user.max_user_namespaces": model.Readable("10000")},
			},
			want: model.StatusVulnerable,
		},
		{
			name:  "mitigated by blacklisted module",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, PackageDBAvailable: true,
				RunningKernel: model.Readable("5.15.0.80"),
				Modules:       map[string]model.ModuleState{"nf_tables": blacklisted()},
				Sysctls:       map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
			},
			want: model.StatusMitigated,
		},
		{
			name:  "mitigated by userns disabled",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, PackageDBAvailable: true,
				RunningKernel: model.Readable("5.15.0.80"),
				Modules:       map[string]model.ModuleState{"nf_tables": loaded()},
				Sysctls:       map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("0")},
			},
			want: model.StatusMitigated,
		},
		{
			name:  "likely vulnerable without package DB",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, PackageDBAvailable: false,
				RunningKernel: model.Readable("5.15.5"),
				Modules:       map[string]model.ModuleState{"nf_tables": loaded()},
				Sysctls:       map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
			},
			want:      model.StatusLikelyVulnerable,
			wantEvHas: "version-only",
		},
		{
			name:  "likely vulnerable when precondition unknown",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, PackageDBAvailable: true,
				RunningKernel: model.Readable("5.15.0.80"),
				// nf_tables absent from the map => state unknown.
				Sysctls: map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
			},
			want: model.StatusLikelyVulnerable,
		},
		{
			name:  "unknown when running kernel unreadable",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, PackageDBAvailable: true,
				RunningKernel: model.Unreadable[string]("uname failed"),
			},
			want: model.StatusUnknown,
		},
		{
			name:  "vulnerable with no precondition gate",
			entry: entryPipe(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, PackageDBAvailable: true,
				RunningKernel: model.Readable("5.15.0.80"),
			},
			want: model.StatusVulnerable,
		},
		{
			name:  "unknown when CVE has no version data",
			entry: entryNoData(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, PackageDBAvailable: true,
				RunningKernel: model.Readable("5.15.0.80"),
			},
			want: model.StatusUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ds := &cve.Dataset{CVEs: []cve.Entry{tc.entry}}
			got := Run(ds, tc.facts, fakeCmp)
			if len(got) != 1 {
				t.Fatalf("Run returned %d verdicts, want 1", len(got))
			}
			if got[0].Status != tc.want {
				t.Errorf("status = %q, want %q\nevidence: %v", got[0].Status, tc.want, got[0].Evidence)
			}
			if tc.wantEvHas != "" && !evidenceContains(got[0].Evidence, tc.wantEvHas) {
				t.Errorf("evidence %v does not contain %q", got[0].Evidence, tc.wantEvHas)
			}
		})
	}
}

func evidenceContains(ev []string, sub string) bool {
	for _, e := range ev {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}
