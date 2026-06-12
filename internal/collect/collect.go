package collect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fieldse/linux-vuln-auditor/internal/cve"
	"github.com/fieldse/linux-vuln-auditor/internal/model"
)

// usernsSysctls are the knobs that gate unprivileged user namespaces; the
// detector reads them by name from HostFacts.
var usernsSysctls = []string{
	"kernel.unprivileged_userns_clone",
	"user.max_user_namespaces",
}

// Collect gathers host facts needed to audit the given dataset. It never
// returns an error: failures to read individual signals are recorded as
// provenance on the facts so the detector can reason about them. The context
// bounds any external command (dpkg/rpm/uname).
func Collect(ctx context.Context, ds *cve.Dataset) model.HostFacts {
	distro, versionID := readDistro()

	facts := model.HostFacts{
		Distro:             distro,
		DistroVersionID:    versionID,
		RunningKernel:      readRunningKernel(ctx),
		InstalledKernel:    readInstalledKernel(ctx, distro),
		PackageDBAvailable: hasCmd("dpkg") || hasCmd("rpm"),
		Modules:            readModules(neededModules(ds)),
		Sysctls:            readSysctls(usernsSysctls),
	}
	return facts
}

// neededModules collects the distinct, normalized module names referenced by
// any CVE's preconditions.
func neededModules(ds *cve.Dataset) []string {
	seen := map[string]bool{}
	var names []string
	for _, e := range ds.CVEs {
		for _, m := range e.Preconditions.Modules {
			n := normalizeModule(m)
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	return names
}

func readDistro() (model.Distro, string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return model.DistroUnknown, ""
	}
	return parseOSRelease(string(data))
}

func readRunningKernel(ctx context.Context) model.Fact[string] {
	out, err := output(ctx, "uname", "-r")
	if err != nil {
		return model.Unreadable[string]("uname -r: " + err.Error())
	}
	return model.Readable(strings.TrimSpace(out))
}

// readInstalledKernel reports the newest installed kernel package version, used
// to detect a patched-but-not-rebooted host.
func readInstalledKernel(ctx context.Context, distro model.Distro) model.Fact[string] {
	switch {
	case hasCmd("dpkg-query"):
		out, err := output(ctx, "dpkg-query", "-W", "-f", "${Version}\n", "linux-image-*")
		if err != nil {
			return model.Unreadable[string]("dpkg-query: " + err.Error())
		}
		if v := newestVersion(ctx, strings.Fields(out)); v != "" {
			return model.Readable(v)
		}
		return model.Unreadable[string]("no linux-image package found")
	case hasCmd("rpm"):
		out, err := output(ctx, "rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n", "kernel")
		if err != nil {
			return model.Unreadable[string]("rpm -q kernel: " + err.Error())
		}
		if v := newestVersion(ctx, strings.Fields(out)); v != "" {
			return model.Readable(v)
		}
		return model.Unreadable[string]("no kernel package found")
	default:
		return model.Unreadable[string]("no package database (dpkg/rpm)")
	}
}

// newestVersion returns the greatest version among candidates using the host
// comparator.
func newestVersion(ctx context.Context, versions []string) string {
	cmp := NewComparator(ctx)
	best := ""
	for _, v := range versions {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if best == "" || cmp(v, best) > 0 {
			best = v
		}
	}
	return best
}

func readModules(names []string) map[string]model.ModuleState {
	if len(names) == 0 {
		return map[string]model.ModuleState{}
	}

	loaded, loadedOK := readSet("/proc/modules", parseLoadedModules)
	release := unameRelease()
	builtin, _ := readSet(filepath.Join("/lib/modules", release, "modules.builtin"), parseBuiltinModules)
	available, _ := readSet(filepath.Join("/lib/modules", release, "modules.dep"), parseAvailableModules)
	blacklist := readBlacklist()

	out := make(map[string]model.ModuleState, len(names))
	for _, name := range names {
		n := normalizeModule(name)
		st := model.ModuleState{
			Name:        name,
			Loaded:      loaded[n],
			BuiltIn:     builtin[n],
			Blacklisted: blacklist[n],
			// Reachable on demand only if a module exists and is not blocked.
			Autoloadable: available[n] && !blacklist[n],
			// We can only judge a module if we read the loaded set at minimum.
			Known: loadedOK,
		}
		out[name] = st
	}
	return out
}

// readBlacklist merges modprobe blacklist config from the standard directories.
func readBlacklist() map[string]bool {
	merged := map[string]bool{}
	dirs := []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			for k := range parseBlacklist(string(data)) {
				merged[k] = true
			}
		}
	}
	return merged
}

func readSysctls(names []string) map[string]model.Fact[string] {
	out := make(map[string]model.Fact[string], len(names))
	for _, name := range names {
		path := "/proc/sys/" + strings.ReplaceAll(name, ".", "/")
		data, err := os.ReadFile(path)
		if err != nil {
			out[name] = model.Unreadable[string](err.Error())
			continue
		}
		out[name] = model.Readable(strings.TrimSpace(string(data)))
	}
	return out
}

// readSet reads a file and applies a parser, reporting whether the read
// succeeded.
func readSet(path string, parse func(string) map[string]bool) (map[string]bool, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]bool{}, false
	}
	return parse(string(data)), true
}

func unameRelease() string {
	out, err := output(context.Background(), "uname", "-r")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func output(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}
