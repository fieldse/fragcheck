package detect

import (
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/fieldse/fragcheck/internal/cve"
	"github.com/fieldse/fragcheck/internal/model"
)

// fakeCmp compares dotted/dashed numeric version strings field by field.
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
		Introduced:    "5.14",
		FixedMainline: "5.16",
		Branches:      []cve.Branch{{Series: "5.15", Fixed: "5.15.208"}},
		DistroFixed: cve.DistroFixed{
			Ubuntu: map[string]string{"22.04": "5.15.0.92"},
			RHEL:   map[string]string{"9": "5.14.0.300"},
		},
		Preconditions: cve.Preconditions{Modules: []string{"nf_tables"}, NeedsUnprivUserns: true},
		Remediation:   "patch",
	}
}

// entryPipe has no module/config/namespace precondition (modelled on Dirty Pipe).
func entryPipe() cve.Entry {
	return cve.Entry{
		ID: "CVE-2022-0847", Nickname: "Dirty Pipe", CVSS: 7.8, Verified: true,
		Introduced:  "5.8",
		Branches:    []cve.Branch{{Series: "5.15", Fixed: "5.15.25"}},
		DistroFixed: cve.DistroFixed{Ubuntu: map[string]string{"22.04": "5.15.0.92"}},
		Remediation: "patch",
	}
}

// entryEsp is config-gated (modelled on Dirty Frag ESP).
func entryEsp() cve.Entry {
	return cve.Entry{
		ID: "CVE-2026-43284", Nickname: "Dirty Frag (ESP)", CVSS: 8.8, KEV: true, Verified: true,
		Introduced: "4.11",
		Branches:   []cve.Branch{{Series: "6.12", Fixed: "6.12.87"}},
		Preconditions: cve.Preconditions{
			Modules: []string{"esp4"}, Configs: []string{"CONFIG_INET_ESP"}, NeedsUnprivUserns: true,
		},
		Remediation: "patch",
	}
}

// entryClone is the DirtyClone entry: esp4/esp6 + config + userns gated, with a
// distro fix on Debian but none on RHEL (so RHEL falls to the upstream branch).
func entryClone() cve.Entry {
	return cve.Entry{
		ID: "CVE-2026-43503", Nickname: "DirtyClone", CVSS: 8.8, Verified: false,
		Introduced: "3.9",
		Branches: []cve.Branch{
			{Series: "6.1", Fixed: "6.1.174"},
			{Series: "6.12", Fixed: "6.12.91"},
		},
		DistroFixed: cve.DistroFixed{
			Debian: map[string]string{"12": "6.1.174-1"},
			// rhel intentionally empty — RHEL is Affected but no errata indexed.
		},
		Preconditions: cve.Preconditions{
			Modules:           []string{"esp4", "esp6"},
			Configs:           []string{"CONFIG_XFRM", "CONFIG_INET_ESP", "CONFIG_INET6_ESP"},
			NeedsUnprivUserns: true,
		},
		Remediation: "patch",
	}
}

// entryPedit is the pedit COW entry: act_pedit + config + userns gated. The
// 6.1.x/6.6.x LTS series have no branch fix yet (fix is mainline-fresh).
func entryPedit() cve.Entry {
	return cve.Entry{
		ID: "CVE-2026-46331", Nickname: "pedit COW", CVSS: 7.8, Verified: false,
		Introduced: "5.18",
		Branches: []cve.Branch{
			{Series: "6.12", Fixed: "6.12.94"},
			{Series: "6.18", Fixed: "6.18.36"},
			{Series: "7.0", Fixed: "7.0.13"},
		},
		DistroFixed: cve.DistroFixed{
			Debian: map[string]string{"13": "6.12.94-1"},
		},
		Preconditions: cve.Preconditions{
			Modules:           []string{"act_pedit"},
			Configs:           []string{"CONFIG_NET_SCHED", "CONFIG_NET_CLS_ACT", "CONFIG_NET_ACT_PEDIT"},
			NeedsUnprivUserns: true,
		},
		Remediation: "patch",
	}
}

// entryBackportOnly mirrors the Copy Fail shape: per-series backports topping at
// 6.18.22, no preconditions, and (by default) no recorded mainline fix. It is the
// regression guard for the false-negative where a kernel in a newer, untracked
// series (e.g. 6.19.x) was wrongly cleared just for being numerically above the
// highest backport.
func entryBackportOnly() cve.Entry {
	return cve.Entry{
		ID: "CVE-2026-31431", Nickname: "Copy Fail", CVSS: 7.8, Verified: true,
		Introduced: "4.14",
		Branches: []cve.Branch{
			{Series: "6.12", Fixed: "6.12.85"},
			{Series: "6.18", Fixed: "6.18.22"},
		},
		// FixedMainline intentionally empty by default.
		Remediation: "patch",
	}
}

func loaded() model.ModuleState       { return model.ModuleState{Loaded: true, Known: true} }
func autoloadable() model.ModuleState { return model.ModuleState{Autoloadable: true, Known: true} }
func blacklisted() model.ModuleState  { return model.ModuleState{Blacklisted: true, Known: true} }

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name      string
		entry     cve.Entry
		facts     model.HostFacts
		want      model.Status
		wantEvHas string
	}{
		{
			name:  "ubuntu vulnerable (distro-confirmed)",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, DistroVersionID: "22.04", PackageDBAvailable: true,
				RunningKernel:        model.Readable("5.15.0"),
				RunningKernelPackage: model.Readable("5.15.0.80"),
				Modules:              map[string]model.ModuleState{"nf_tables": loaded()},
				Sysctls:              map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
			},
			want: model.StatusVulnerable,
		},
		{
			name:  "ubuntu patched",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, DistroVersionID: "22.04", PackageDBAvailable: true,
				RunningKernel:        model.Readable("5.15.0"),
				RunningKernelPackage: model.Readable("5.15.0.95"),
			},
			want: model.StatusNotAffected,
		},
		{
			name:  "reboot pending",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, DistroVersionID: "22.04", PackageDBAvailable: true,
				RunningKernel:        model.Readable("5.15.0"),
				RunningKernelPackage: model.Readable("5.15.0.80"),
				InstalledKernel:      model.Readable("5.15.0.95"),
				Modules:              map[string]model.ModuleState{"nf_tables": loaded()},
				Sysctls:              map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
			},
			want: model.StatusVulnerable, wantEvHas: "reboot pending",
		},
		{
			name:  "rhel vulnerable via autoloadable module",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroRHEL, DistroVersionID: "9", PackageDBAvailable: true,
				RunningKernel:        model.Readable("5.14.0"),
				RunningKernelPackage: model.Readable("5.14.0.100"),
				Modules:              map[string]model.ModuleState{"nf_tables": autoloadable()},
				Sysctls:              map[string]model.Fact[string]{"user.max_user_namespaces": model.Readable("10000")},
			},
			want: model.StatusVulnerable,
		},
		{
			name:  "mitigated by blacklisted module",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, DistroVersionID: "22.04", PackageDBAvailable: true,
				RunningKernel:        model.Readable("5.15.0"),
				RunningKernelPackage: model.Readable("5.15.0.80"),
				Modules:              map[string]model.ModuleState{"nf_tables": blacklisted()},
				Sysctls:              map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
			},
			want: model.StatusMitigated,
		},
		{
			name:  "mitigated by userns disabled",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, DistroVersionID: "22.04", PackageDBAvailable: true,
				RunningKernel:        model.Readable("5.15.0"),
				RunningKernelPackage: model.Readable("5.15.0.80"),
				Modules:              map[string]model.ModuleState{"nf_tables": loaded()},
				Sysctls:              map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("0")},
			},
			want: model.StatusMitigated,
		},
		{
			name:  "likely vulnerable from upstream branch only",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, DistroVersionID: "22.04", PackageDBAvailable: false,
				RunningKernel: model.Readable("5.15.100"),
				Modules:       map[string]model.ModuleState{"nf_tables": loaded()},
				Sysctls:       map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
			},
			want: model.StatusLikelyVulnerable, wantEvHas: "upstream-only",
		},
		{
			name:  "likely vulnerable when precondition unknown",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, DistroVersionID: "22.04", PackageDBAvailable: true,
				RunningKernel:        model.Readable("5.15.0"),
				RunningKernelPackage: model.Readable("5.15.0.80"),
				Sysctls:              map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
			},
			want: model.StatusLikelyVulnerable,
		},
		{
			name:  "not affected when newer than the mainline fix",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroDebian, DistroVersionID: "13", PackageDBAvailable: true,
				RunningKernel: model.Readable("6.12.63"),
			},
			want: model.StatusNotAffected, wantEvHas: "mainline fix",
		},
		{
			name:  "unknown when running kernel unreadable",
			entry: entryNf(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, DistroVersionID: "22.04", PackageDBAvailable: true,
				RunningKernel: model.Unreadable[string]("uname failed"),
			},
			want: model.StatusUnknown,
		},
		{
			name:  "vulnerable with no precondition gate",
			entry: entryPipe(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, DistroVersionID: "22.04", PackageDBAvailable: true,
				RunningKernel:        model.Readable("5.15.0"),
				RunningKernelPackage: model.Readable("5.15.0.80"),
			},
			want: model.StatusVulnerable,
		},
		{
			name:  "not affected when required config disabled",
			entry: entryEsp(),
			facts: model.HostFacts{
				Distro: model.DistroDebian, DistroVersionID: "13", PackageDBAvailable: true,
				RunningKernel: model.Readable("6.12.63"),
				Modules:       map[string]model.ModuleState{"esp4": loaded()},
				Sysctls:       map[string]model.Fact[string]{"user.max_user_namespaces": model.Readable("10000")},
				KernelConfigs: map[string]model.Fact[string]{"CONFIG_INET_ESP": model.Readable("n")},
			},
			want: model.StatusNotAffected, wantEvHas: "not enabled",
		},
		{
			name:  "not affected on categorically-unaffected distro",
			entry: func() cve.Entry { e := entryEsp(); e.UnaffectedDistros = []string{"amazon"}; return e }(),
			facts: model.HostFacts{
				Distro: model.Distro("amazon"), DistroVersionID: "2023", PackageDBAvailable: true,
				RunningKernel: model.Readable("6.12.0"),
			},
			want: model.StatusNotAffected,
		},

		// ---- DirtyClone (CVE-2026-43503) ----
		{
			name:  "dirtyclone: debian vulnerable (distro-confirmed)",
			entry: entryClone(),
			facts: model.HostFacts{
				Distro: model.DistroDebian, DistroVersionID: "12", PackageDBAvailable: true,
				RunningKernel:        model.Readable("6.1.140"),
				RunningKernelPackage: model.Readable("6.1.170-1"),
				Modules:              map[string]model.ModuleState{"esp4": loaded(), "esp6": loaded()},
				Sysctls:              map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
				KernelConfigs: map[string]model.Fact[string]{
					"CONFIG_XFRM": model.Readable("y"), "CONFIG_INET_ESP": model.Readable("y"), "CONFIG_INET6_ESP": model.Readable("y"),
				},
			},
			want: model.StatusVulnerable,
		},
		{
			// RHEL has no distro_fixed entry, so the verdict rests on the upstream
			// branch alone — provisional (likely-vulnerable), not confirmed.
			name:  "dirtyclone: rhel likely-vulnerable (upstream branch only)",
			entry: entryClone(),
			facts: model.HostFacts{
				Distro: model.DistroRHEL, DistroVersionID: "10", PackageDBAvailable: true,
				RunningKernel:        model.Readable("6.12.0"),
				RunningKernelPackage: model.Readable("6.12.0-124"),
				Modules:              map[string]model.ModuleState{"esp4": loaded(), "esp6": autoloadable()},
				Sysctls:              map[string]model.Fact[string]{"user.max_user_namespaces": model.Readable("10000")},
				KernelConfigs: map[string]model.Fact[string]{
					"CONFIG_XFRM": model.Readable("y"), "CONFIG_INET_ESP": model.Readable("y"), "CONFIG_INET6_ESP": model.Readable("y"),
				},
			},
			want: model.StatusLikelyVulnerable, wantEvHas: "upstream-only",
		},
		{
			name:  "dirtyclone: not affected when ESP compiled out",
			entry: entryClone(),
			facts: model.HostFacts{
				Distro: model.DistroDebian, DistroVersionID: "13", PackageDBAvailable: true,
				RunningKernel: model.Readable("6.12.63"),
				Modules:       map[string]model.ModuleState{"esp4": loaded(), "esp6": loaded()},
				Sysctls:       map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
				KernelConfigs: map[string]model.Fact[string]{
					"CONFIG_XFRM": model.Readable("y"), "CONFIG_INET_ESP": model.Readable("y"), "CONFIG_INET6_ESP": model.Readable("n"),
				},
			},
			want: model.StatusNotAffected, wantEvHas: "not enabled",
		},

		// ---- pedit COW (CVE-2026-46331) ----
		{
			name:  "pedit: debian vulnerable (distro-confirmed)",
			entry: entryPedit(),
			facts: model.HostFacts{
				Distro: model.DistroDebian, DistroVersionID: "13", PackageDBAvailable: true,
				RunningKernel:        model.Readable("6.12.90"),
				RunningKernelPackage: model.Readable("6.12.90-1"),
				Modules:              map[string]model.ModuleState{"act_pedit": loaded()},
				Sysctls:              map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
				KernelConfigs: map[string]model.Fact[string]{
					"CONFIG_NET_SCHED": model.Readable("y"), "CONFIG_NET_CLS_ACT": model.Readable("y"), "CONFIG_NET_ACT_PEDIT": model.Readable("m"),
				},
			},
			want: model.StatusVulnerable,
		},
		{
			// The 6.6 LTS series has no branch fix and sits below the mainline fix
			// (7.1), so it is in the affected range and must not be cleared —
			// likely-vulnerable, never unknown or (worse) not-affected.
			name:  "pedit: likely-vulnerable on LTS series with no branch fix",
			entry: func() cve.Entry { e := entryPedit(); e.FixedMainline = "7.1"; return e }(),
			facts: model.HostFacts{
				Distro: model.DistroDebian, DistroVersionID: "12", PackageDBAvailable: true,
				RunningKernel: model.Readable("6.6.50"),
				Modules:       map[string]model.ModuleState{"act_pedit": loaded()},
				Sysctls:       map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
				KernelConfigs: map[string]model.Fact[string]{
					"CONFIG_NET_SCHED": model.Readable("y"), "CONFIG_NET_CLS_ACT": model.Readable("y"), "CONFIG_NET_ACT_PEDIT": model.Readable("m"),
				},
			},
			want: model.StatusLikelyVulnerable, wantEvHas: "< mainline fix",
		},
		{
			name:  "pedit: mitigated by blacklisted act_pedit",
			entry: entryPedit(),
			facts: model.HostFacts{
				Distro: model.DistroDebian, DistroVersionID: "13", PackageDBAvailable: true,
				RunningKernel:        model.Readable("6.12.90"),
				RunningKernelPackage: model.Readable("6.12.90-1"),
				Modules:              map[string]model.ModuleState{"act_pedit": blacklisted()},
				Sysctls:              map[string]model.Fact[string]{"kernel.unprivileged_userns_clone": model.Readable("1")},
				KernelConfigs: map[string]model.Fact[string]{
					"CONFIG_NET_SCHED": model.Readable("y"), "CONFIG_NET_CLS_ACT": model.Readable("y"), "CONFIG_NET_ACT_PEDIT": model.Readable("m"),
				},
			},
			want: model.StatusMitigated,
		},
		{
			name:  "pedit: not affected when kernel predates introduction",
			entry: entryPedit(),
			facts: model.HostFacts{
				Distro: model.DistroUbuntu, DistroVersionID: "16.04", PackageDBAvailable: true,
				RunningKernel: model.Readable("4.15.0"),
			},
			want: model.StatusNotAffected, wantEvHas: "predates introduction",
		},

		// ---- False-negative regression (the 6.19.10 case) ----
		{
			// A kernel numerically above the highest backport (6.18.22) but in an
			// untracked series must NOT be cleared. With no mainline fix recorded,
			// it stays in the affected range -> likely-vulnerable, never not-affected.
			name:  "regression: newer untracked series not falsely cleared (no mainline)",
			entry: entryBackportOnly(),
			facts: model.HostFacts{
				Distro: model.DistroDebian, DistroVersionID: "13", PackageDBAvailable: true,
				RunningKernel: model.Readable("6.19.10"),
			},
			want: model.StatusLikelyVulnerable, wantEvHas: "no recorded fix",
		},
		{
			// Same kernel, but a real mainline fix (7.1) is recorded and 6.19.10 is
			// below it -> still affected. The mainline bound is the only thing that
			// may clear it, and this kernel does not meet it.
			name:  "regression: below mainline fix stays affected",
			entry: func() cve.Entry { e := entryBackportOnly(); e.FixedMainline = "7.1"; return e }(),
			facts: model.HostFacts{
				Distro: model.DistroDebian, DistroVersionID: "13", PackageDBAvailable: true,
				RunningKernel: model.Readable("6.19.10"),
			},
			want: model.StatusLikelyVulnerable, wantEvHas: "< mainline fix",
		},
		{
			// At/above the mainline fix, an untracked series IS cleared.
			name:  "regression: at or above mainline fix is not affected",
			entry: func() cve.Entry { e := entryBackportOnly(); e.FixedMainline = "7.1"; return e }(),
			facts: model.HostFacts{
				Distro: model.DistroDebian, DistroVersionID: "13", PackageDBAvailable: true,
				RunningKernel: model.Readable("7.2.0"),
			},
			want: model.StatusNotAffected, wantEvHas: "mainline fix",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ds := &cve.Dataset{CVEs: []cve.Entry{tc.entry}}
			got := Run(ds, tc.facts, fakeCmp)
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
