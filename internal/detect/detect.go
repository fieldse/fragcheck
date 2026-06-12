package detect

import (
	"fmt"

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

// versionState is the outcome of the kernel-version check, judged on the
// running kernel.
type versionState int

const (
	verUnknown  versionState = iota // could not determine
	verAffected                     // running kernel is in an affected range
	verPatched                      // running kernel is patched / out of range
)

// precondState is the outcome of the exploit-precondition check.
type precondState int

const (
	preReachable  precondState = iota // the exploit's path is reachable
	preHardBlock                      // a hard block removes the path
	preUnknown                        // reachability could not be confirmed
)

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

	// Running kernel is in an affected range; weigh the preconditions.
	preState, preEv := evalPreconditions(e, facts)
	v.Evidence = append(v.Evidence, preEv...)

	switch preState {
	case preHardBlock:
		v.Status = model.StatusMitigated
	case preUnknown:
		v.Status = model.StatusLikelyVulnerable
	default: // preReachable
		if confirmed {
			v.Status = model.StatusVulnerable
		} else {
			// Affected by version-only signal (no package-DB backport
			// confirmation): caution, but not a confirmed verdict.
			v.Status = model.StatusLikelyVulnerable
		}
	}
	return v
}

// evalVersion decides whether the running kernel is affected. confirmed is true
// only when the decision used the package DB (backport-corrected); a version-
// only decision is provisional.
func evalVersion(e *cve.Entry, facts model.HostFacts, cmp VerCmp) (state versionState, confirmed bool, evidence []string) {
	running := facts.RunningKernel
	if !running.Known {
		return verUnknown, false, []string{"running kernel version unreadable: " + running.Err}
	}

	fixed := e.DistroFixed.For(string(facts.Distro))
	if facts.PackageDBAvailable && fixed != "" {
		// Backport-corrected: compare the running kernel against the distro's
		// patched package version.
		if cmp(running.Value, fixed) >= 0 {
			return verPatched, true, []string{fmt.Sprintf("running kernel %s >= %s fixed (%s)", running.Value, facts.Distro, fixed)}
		}
		ev := []string{fmt.Sprintf("running kernel %s < %s fixed (%s)", running.Value, facts.Distro, fixed)}
		// Reboot gap: a patched kernel may be installed but not yet running.
		if inst := facts.InstalledKernel; inst.Known && cmp(inst.Value, fixed) >= 0 {
			ev = append(ev, fmt.Sprintf("patched kernel %s installed — reboot pending", inst.Value))
		}
		return verAffected, true, ev
	}

	// Fallback: upstream version ranges only (no package DB / no recorded
	// distro fix). Lower confidence; backports are invisible here.
	return evalUpstreamRanges(e, running.Value, cmp)
}

func evalUpstreamRanges(e *cve.Entry, running string, cmp VerCmp) (versionState, bool, []string) {
	usable := false
	for _, r := range e.Affected {
		if r.Introduced == "" && r.Fixed == "" {
			continue
		}
		usable = true
		aboveFloor := r.Introduced == "" || cmp(running, r.Introduced) >= 0
		belowFix := r.Fixed == "" || cmp(running, r.Fixed) < 0
		if aboveFloor && belowFix {
			return verAffected, false, []string{fmt.Sprintf("running kernel %s in affected range [%s, %s) (version-only, backports not checked)", running, orAny(r.Introduced), orAny(r.Fixed))}
		}
	}
	if !usable {
		return verUnknown, false, []string{"no version range recorded for this CVE"}
	}
	return verPatched, false, []string{fmt.Sprintf("running kernel %s outside all recorded affected ranges", running)}
}

// evalPreconditions checks the modules and namespace settings the exploit
// requires. A hard block on any required condition mitigates; an unreadable
// required condition yields unknown; otherwise the path is reachable.
func evalPreconditions(e *cve.Entry, facts model.HostFacts) (precondState, []string) {
	p := e.Preconditions
	var evidence []string
	unknown := false

	for _, name := range p.Modules {
		m := facts.Module(name)
		if !m.Known {
			unknown = true
			evidence = append(evidence, "module "+name+": state unknown")
			continue
		}
		if m.HardBlocked() {
			return preHardBlock, append(evidence, "module "+name+": blacklisted/disabled (hard block)")
		}
		evidence = append(evidence, "module "+name+": "+moduleReachabilityDesc(m))
	}

	if p.NeedsUnprivUserns {
		switch s := unprivUsernsState(facts); s {
		case usernsOff:
			return preHardBlock, append(evidence, "unprivileged user namespaces disabled (hard block)")
		case usernsUnknown:
			unknown = true
			evidence = append(evidence, "unprivileged user namespaces: state unknown")
		default:
			evidence = append(evidence, "unprivileged user namespaces enabled")
		}
	}

	if unknown {
		return preUnknown, evidence
	}
	if len(p.Modules) == 0 && !p.NeedsUnprivUserns {
		evidence = append(evidence, "no module/namespace precondition gates this exploit")
	}
	return preReachable, evidence
}

// moduleReachabilityDesc reports both how the module is present now and whether
// it is reachable, so the evidence shows loaded-now vs autoload-reachable.
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

// unprivUsernsState reads the two sysctls that gate unprivileged user
// namespaces. Either being explicitly off is a hard block.
func unprivUsernsState(facts model.HostFacts) usernsResult {
	// Debian/Ubuntu knob.
	if clone := facts.Sysctl("kernel.unprivileged_userns_clone"); clone.Known {
		if clone.Value == "0" {
			return usernsOff
		}
		return usernsOn
	}
	// Generic cap on user namespaces.
	if maxNS := facts.Sysctl("user.max_user_namespaces"); maxNS.Known {
		if maxNS.Value == "0" {
			return usernsOff
		}
		return usernsOn
	}
	return usernsUnknown
}

func orAny(s string) string {
	if s == "" {
		return "*"
	}
	return s
}
