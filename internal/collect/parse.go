package collect

import (
	"bufio"
	"strings"

	"github.com/fieldse/fragcheck/internal/model"
)

// normalizeModule canonicalizes a module name. The kernel reports module names
// with underscores; dataset/config may use hyphens.
func normalizeModule(name string) string {
	return strings.ReplaceAll(strings.TrimSpace(name), "-", "_")
}

// parseOSRelease extracts the distro family and version id from the contents of
// /etc/os-release. ID_LIKE is consulted so derivatives map to a known family.
func parseOSRelease(data string) (model.Distro, string) {
	kv := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}

	id := strings.ToLower(kv["ID"])
	like := strings.ToLower(kv["ID_LIKE"])
	version := kv["VERSION_ID"]

	switch id {
	case "ubuntu":
		return model.DistroUbuntu, version
	case "debian":
		return model.DistroDebian, version
	case "rhel", "centos", "rocky", "almalinux", "fedora":
		return model.DistroRHEL, version
	}
	switch {
	case strings.Contains(like, "ubuntu"):
		return model.DistroUbuntu, version
	case strings.Contains(like, "debian"):
		return model.DistroDebian, version
	case strings.Contains(like, "rhel") || strings.Contains(like, "fedora"):
		return model.DistroRHEL, version
	}
	return model.DistroUnknown, version
}

// parseLoadedModules returns the set of currently loaded modules from the
// contents of /proc/modules (first whitespace field of each line).
func parseLoadedModules(data string) map[string]bool {
	set := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		if name, _, ok := strings.Cut(strings.TrimSpace(sc.Text()), " "); ok {
			set[normalizeModule(name)] = true
		}
	}
	return set
}

// parseBuiltinModules returns the set of modules compiled into the kernel from
// the contents of modules.builtin (paths like kernel/net/.../nf_tables.ko).
func parseBuiltinModules(data string) map[string]bool {
	set := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		if base, ok := moduleBaseFromPath(strings.TrimSpace(sc.Text())); ok {
			set[base] = true
		}
	}
	return set
}

// parseAvailableModules returns the set of loadable modules (those with a .ko)
// from the contents of modules.dep (each line "path/foo.ko: deps...").
func parseAvailableModules(data string) map[string]bool {
	set := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		path, _, _ := strings.Cut(line, ":")
		if base, ok := moduleBaseFromPath(path); ok {
			set[base] = true
		}
	}
	return set
}

// parseBlacklist returns the set of modules disabled via modprobe config. It
// recognizes both "blacklist <name>" and "install <name> /bin/{true,false}".
func parseBlacklist(data string) map[string]bool {
	set := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "blacklist":
			set[normalizeModule(fields[1])] = true
		case "install":
			if len(fields) >= 3 && (strings.HasSuffix(fields[2], "/true") || strings.HasSuffix(fields[2], "/false")) {
				set[normalizeModule(fields[1])] = true
			}
		}
	}
	return set
}

// parseKernelConfig returns the set CONFIG_* options from a kernel build config
// (the contents of /boot/config-<rel> or decompressed /proc/config.gz). Lines
// like "CONFIG_X=y" are captured; "# CONFIG_X is not set" lines are skipped
// (callers treat an absent key as disabled).
func parseKernelConfig(data string) map[string]string {
	set := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			set[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return set
}

// moduleBaseFromPath turns "kernel/net/netfilter/nf_tables.ko[.zst]" into
// "nf_tables".
func moduleBaseFromPath(path string) (string, bool) {
	slash := strings.LastIndex(path, "/")
	base := path
	if slash >= 0 {
		base = path[slash+1:]
	}
	if i := strings.Index(base, ".ko"); i >= 0 {
		base = base[:i]
	} else if base == "" {
		return "", false
	} else {
		return "", false
	}
	if base == "" {
		return "", false
	}
	return normalizeModule(base), true
}
