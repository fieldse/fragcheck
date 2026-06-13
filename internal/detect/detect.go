package detect

import (
	"fmt"
	"regexp"

	"github.com/fieldse/linux-vuln-auditor/internal/cve"
	"github.com/fieldse/linux-vuln-auditor/internal/model"
)

// VerCmp compares two version strings and returns -1, 0, or +1. It is injected
// so the detector stays pure: the real implementation (which shells out to
// dpkg/rpm) lives in the collect package, while tests pass a fake.
type VerCmp func(a, b string) int

// Run audits every CVE in the dataset against the host facts and returns one
// verdict per CVE, in dataset order. It performs no I/O.
func Run(ds *cve.Dataset, facts model.HostFacts, cmp VerCmp) []model.Verdict {
	out := make([]model.Verdict, 0, len(ds.CVEs))
	for i := range ds.CVEs {
		out = append(out, evaluate(&ds.CVEs[i], facts, cmp))
	}
	return out
}

type versionState int

const (
	verUnknown versionState = iota
	verAffected
	verPatched
)

type precondState int

const (
	preReachable precondState = iota
	preHardBlock
	preUnknown
)

type configState int

const (
	configEnabled configState = iota
	configDisabled
	configUnknown
)

var seriesRE = regexp.MustCompile(`^(\d+\.\d+)`)

func evaluate(e *cve.Entry, facts model.HostFacts, cmp VerCmp) model.Verdict {
	v := model.Verdict{
		CVE:         e.ID,
		Nickname:    e.Nickname,
		Severity:    model.Severity{CVSS: e.CVSS, KEV: e.KEV},
		Remediation: e.Remediation,
	}
	if !e.Verified {
		v.Evidence = append(v.Evidence, "dataset entry unverified — ranges/preconditions provisional")
	}

	// A distro family that categorically lacks the feature is not affected.
	for _, d := range e.UnaffectedDistros {
		if d == string(facts.Distro) {
			v.Status = model.StatusNotAffected
			v.Evidence = append(v.Evidence, fmt.Sprintf("%s is not affected (feature absent on this distro)", facts.Distro))
			return v
		}
	}

	verState, confirmed, verEv := evalVersion(e, facts, cmp)
	v.Evidence = append(v.Evidence, verEv...)
	switch verState {
	case verUnknown:
		v.Status = model.StatusUnknown
		return v
	case verPatched:
		v.Status = model.StatusNotAffected
		return v
	}

	// Affected by version. A required kernel feature being compiled out means
	// the flaw is not present regardless of version.
	cfgState, cfgEv := evalConfigs(e, facts)
	v.Evidence = append(v.Evidence, cfgEv...)
	if cfgState == configDisabled {
		v.Status = model.StatusNotAffected
		return v
	}

	preState, preEv := evalPreconditions(e, facts)
	v.Evidence = append(v.Evidence, preEv...)

	switch {
	case preState == preHardBlock:
		v.Status = model.StatusMitigated
	case preState == preUnknown || cfgState == configUnknown:
		v.Status = model.StatusLikelyVulnerable
	case confirmed:
		v.Status = model.StatusVulnerable
	default:
		// Reachable, but the version signal was upstream-only (no backport
		// confirmation): caution rather than a confirmed verdict.
		v.Status = model.StatusLikelyVulnerable
	}
	return v
}

// evalVersion decides whether the running kernel is affected. confirmed is true
// when the decision used a per-distro-release fixed version (backport-aware); a
// decision from upstream branch fixes alone is provisional.
func evalVersion(e *cve.Entry, facts model.HostFacts, cmp VerCmp) (versionState, bool, []string) {
	running := facts.RunningKernel
	if !running.Known {
		return verUnknown, false, []string{"running kernel version unreadable: " + running.Err}
	}
	up := running.Value

	if e.Introduced != "" && cmp(up, e.Introduced) < 0 {
		return verPatched, true, []string{fmt.Sprintf("running kernel %s predates introduction %s", up, e.Introduced)}
	}

	// Authoritative: compare the running kernel's package version against the
	// fixed package version for this exact distro release.
	if fixed := e.DistroFixed.For(string(facts.Distro), facts.DistroVersionID); facts.PackageDBAvailable && fixed != "" {
		if pkg := facts.RunningKernelPackage; pkg.Known {
			label := fmt.Sprintf("%s %s", facts.Distro, facts.DistroVersionID)
			if cmp(pkg.Value, fixed) >= 0 {
				return verPatched, true, []string{fmt.Sprintf("running %s kernel package %s >= fixed %s", label, pkg.Value, fixed)}
			}
			ev := []string{fmt.Sprintf("running %s kernel package %s < fixed %s", label, pkg.Value, fixed)}
			if inst := facts.InstalledKernel; inst.Known && cmp(inst.Value, fixed) >= 0 {
				ev = append(ev, fmt.Sprintf("patched kernel %s installed — reboot pending", inst.Value))
			}
			return verAffected, true, ev
		}
		// Distro fix recorded but running package version unreadable — fall
		// through to the upstream branch signal below.
	}

	// Fallback: match the running kernel's stable series to a branch fix.
	if fixed, ok := matchBranch(up, e.Branches); ok {
		if cmp(up, fixed) >= 0 {
			return verPatched, false, []string{fmt.Sprintf("running kernel %s >= branch fix %s (upstream-only, backports not checked)", up, fixed)}
		}
		return verAffected, false, []string{fmt.Sprintf("running kernel %s < branch fix %s (upstream-only, backports not checked)", up, fixed)}
	}
	// No series match: a kernel newer than the highest (mainline) fix carries
	// the fix in all later releases, so it is not affected.
	if mx := maxFixed(e.Branches, cmp); mx != "" && cmp(up, mx) >= 0 {
		return verPatched, true, []string{fmt.Sprintf("running kernel %s is newer than the latest fix %s", up, mx)}
	}
	return verUnknown, false, []string{fmt.Sprintf("no per-release fix or matching branch for running kernel %s", up)}
}

// maxFixed returns the highest fixed version across all branches (the mainline
// fix point), or "" when there are no branches.
func maxFixed(branches []cve.Branch, cmp VerCmp) string {
	best := ""
	for _, b := range branches {
		if best == "" || cmp(b.Fixed, best) > 0 {
			best = b.Fixed
		}
	}
	return best
}

// matchBranch returns the fixed version for the stable series of the running
// kernel (e.g. running 6.12.x matches branch series "6.12").
func matchBranch(running string, branches []cve.Branch) (string, bool) {
	s := seriesRE.FindString(running)
	if s == "" {
		return "", false
	}
	for _, b := range branches {
		if b.Series == s {
			return b.Fixed, true
		}
	}
	return "", false
}

// evalConfigs reports whether the kernel features the exploit needs are built.
// Any required config known-disabled makes the host not affected; an unreadable
// required config yields unknown.
func evalConfigs(e *cve.Entry, facts model.HostFacts) (configState, []string) {
	var ev []string
	unknown := false
	for _, name := range e.Preconditions.Configs {
		f := facts.Config(name)
		switch {
		case !f.Known:
			unknown = true
			ev = append(ev, name+": state unknown")
		case f.Value == "" || f.Value == "n":
			return configDisabled, append(ev, name+": not enabled")
		default:
			ev = append(ev, name+"="+f.Value)
		}
	}
	if unknown {
		return configUnknown, ev
	}
	return configEnabled, ev
}

// evalPreconditions checks the modules and namespace settings the exploit
// requires. A hard block mitigates; an unreadable required condition yields
// unknown; otherwise the path is reachable.
func evalPreconditions(e *cve.Entry, facts model.HostFacts) (precondState, []string) {
	p := e.Preconditions
	var ev []string
	unknown := false

	for _, name := range p.Modules {
		m := facts.Module(name)
		if !m.Known {
			unknown = true
			ev = append(ev, "module "+name+": state unknown")
			continue
		}
		if m.HardBlocked() {
			return preHardBlock, append(ev, "module "+name+": blacklisted/disabled (hard block)")
		}
		ev = append(ev, "module "+name+": "+moduleReachabilityDesc(m))
	}

	if p.NeedsUnprivUserns {
		switch unprivUsernsState(facts) {
		case usernsOff:
			return preHardBlock, append(ev, "unprivileged user namespaces disabled (hard block)")
		case usernsUnknown:
			unknown = true
			ev = append(ev, "unprivileged user namespaces: state unknown")
		default:
			ev = append(ev, "unprivileged user namespaces enabled")
		}
	}

	if unknown {
		return preUnknown, ev
	}
	if len(p.Modules) == 0 && !p.NeedsUnprivUserns {
		ev = append(ev, "no module/namespace precondition gates this exploit")
	}
	return preReachable, ev
}

func moduleReachabilityDesc(m model.ModuleState) string {
	switch {
	case m.Loaded:
		return "loaded (reachable)"
	case m.BuiltIn:
		return "built into kernel (reachable)"
	case m.Autoloadable:
		return "not loaded but autoloadable (reachable)"
	default:
		return "not loaded and not autoloadable"
	}
}

type usernsResult int

const (
	usernsOn usernsResult = iota
	usernsOff
	usernsUnknown
)

// unprivUsernsState reads the sysctls that gate unprivileged user namespaces.
// Either knob being explicitly off is a hard block.
func unprivUsernsState(facts model.HostFacts) usernsResult {
	if clone := facts.Sysctl("kernel.unprivileged_userns_clone"); clone.Known {
		if clone.Value == "0" {
			return usernsOff
		}
		return usernsOn
	}
	if maxNS := facts.Sysctl("user.max_user_namespaces"); maxNS.Known {
		if maxNS.Value == "0" {
			return usernsOff
		}
		return usernsOn
	}
	return usernsUnknown
}
