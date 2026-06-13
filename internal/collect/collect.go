package collect

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fieldse/fragcheck/internal/cve"
	"github.com/fieldse/fragcheck/internal/model"
)

// neededSysctls are the kernel knobs the detector reads by name: the two that
// gate unprivileged user namespaces, plus module-autoload lockdown.
var neededSysctls = []string{
	"kernel.unprivileged_userns_clone",
	"user.max_user_namespaces",
	"kernel.modules_disabled",
	"kernel.apparmor_restrict_unprivileged_userns",
}

// Collect gathers host facts needed to audit the given dataset. It never
// returns an error: failures to read individual signals are recorded as
// provenance on the facts so the detector can reason about them. The context
// bounds any external command (dpkg/rpm/uname).
func Collect(ctx context.Context, ds *cve.Dataset) model.HostFacts {
	distro, versionID := readDistro()

	facts := model.HostFacts{
		Distro:               distro,
		DistroVersionID:      versionID,
		RunningKernel:        readRunningKernel(ctx),
		RunningKernelPackage: readRunningKernelPackage(ctx),
		InstalledKernel:      readInstalledKernel(ctx, distro),
		PackageDBAvailable:   hasCmd("dpkg") || hasCmd("rpm"),
		Modules:              readModules(neededModules(ds)),
		Sysctls:              readSysctls(neededSysctls),
		KernelConfigs:        readKernelConfigs(neededConfigs(ds)),
	}
	return facts
}

// neededModules collects the distinct, normalized module names referenced by
// any CVE's preconditions.
func neededModules(ds *cve.Dataset) []string {
	return distinctPrecondition(ds, func(p cve.Preconditions) []string {
		out := make([]string, len(p.Modules))
		for i, m := range p.Modules {
			out[i] = normalizeModule(m)
		}
		return out
	})
}

// neededConfigs collects the distinct CONFIG_* names referenced by any CVE.
func neededConfigs(ds *cve.Dataset) []string {
	return distinctPrecondition(ds, func(p cve.Preconditions) []string { return p.Configs })
}

func distinctPrecondition(ds *cve.Dataset, pick func(cve.Preconditions) []string) []string {
	seen := map[string]bool{}
	var names []string
	for _, e := range ds.CVEs {
		for _, n := range pick(e.Preconditions) {
			if n != "" && !seen[n] {
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

// readRunningKernelPackage resolves the installed package version of the
// running kernel — the backport-aware value compared against per-distro-release
// fixed versions.
func readRunningKernelPackage(ctx context.Context) model.Fact[string] {
	release := unameRelease()
	if release == "" {
		return model.Unreadable[string]("uname -r unavailable")
	}
	switch {
	case hasCmd("dpkg-query"):
		out, err := output(ctx, "dpkg-query", "-W", "-f", "${Version}", "linux-image-"+release)
		if err != nil || strings.TrimSpace(out) == "" {
			return model.Unreadable[string]("dpkg-query for running kernel package failed")
		}
		return model.Readable(strings.TrimSpace(out))
	case hasCmd("rpm"):
		out, err := output(ctx, "rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "-f", "/boot/vmlinuz-"+release)
		if err != nil || strings.TrimSpace(out) == "" {
			return model.Unreadable[string]("rpm query for running kernel package failed")
		}
		return model.Readable(strings.TrimSpace(out))
	default:
		return model.Unreadable[string]("no package database (dpkg/rpm)")
	}
}

// readKernelConfigs resolves each requested CONFIG_* option. When the kernel
// config is readable, an option absent from it is reported as disabled ("n");
// when the config itself cannot be read, every option is unknown.
func readKernelConfigs(names []string) map[string]model.Fact[string] {
	out := make(map[string]model.Fact[string], len(names))
	data, ok := readKernelConfigFile()
	if !ok {
		for _, n := range names {
			out[n] = model.Unreadable[string]("kernel config not readable")
		}
		return out
	}
	cfg := parseKernelConfig(data)
	for _, n := range names {
		if v, present := cfg[n]; present {
			out[n] = model.Readable(v)
		} else {
			out[n] = model.Readable("n") // "is not set"
		}
	}
	return out
}

// readKernelConfigFile returns the kernel build config, from the on-disk
// /boot/config-<rel> or the gzipped /proc/config.gz.
func readKernelConfigFile() (string, bool) {
	if data, err := os.ReadFile(filepath.Join("/boot", "config-"+unameRelease())); err == nil {
		return string(data), true
	}
	if data, err := os.ReadFile("/proc/config.gz"); err == nil {
		if zr, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
			if plain, err := io.ReadAll(zr); err == nil {
				return string(plain), true
			}
		}
	}
	return "", false
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
	// modules_disabled=1 locks module loading: nothing can autoload on demand.
	loadLocked := strings.TrimSpace(readFileString("/proc/sys/kernel/modules_disabled")) == "1"

	out := make(map[string]model.ModuleState, len(names))
	for _, name := range names {
		n := normalizeModule(name)
		st := model.ModuleState{
			Name:        name,
			Loaded:      loaded[n],
			BuiltIn:     builtin[n],
			Blacklisted: blacklist[n],
			// Reachable on demand only if a module exists, is not blocked, and
			// module loading is not globally locked.
			Autoloadable: available[n] && !blacklist[n] && !loadLocked,
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

func readFileString(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
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
