package collect

import (
	"testing"

	"github.com/fieldse/linux-vuln-auditor/internal/model"
)

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		wantDistro  model.Distro
		wantVersion string
	}{
		{"ubuntu", "ID=ubuntu\nVERSION_ID=\"22.04\"\n", model.DistroUbuntu, "22.04"},
		{"debian", "ID=debian\nVERSION_ID=\"12\"\n", model.DistroDebian, "12"},
		{"rocky via id", "ID=rocky\nVERSION_ID=\"9.3\"\n", model.DistroRHEL, "9.3"},
		{"mint via id_like", "ID=linuxmint\nID_LIKE=ubuntu\nVERSION_ID=\"21\"\n", model.DistroUbuntu, "21"},
		{"unknown", "ID=arch\n", model.DistroUnknown, ""},
		{"comments and blanks", "# c\n\nID=ubuntu\nVERSION_ID=20.04\n", model.DistroUbuntu, "20.04"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, v := parseOSRelease(tc.data)
			if d != tc.wantDistro || v != tc.wantVersion {
				t.Errorf("got (%q,%q), want (%q,%q)", d, v, tc.wantDistro, tc.wantVersion)
			}
		})
	}
}

func TestParseLoadedModules(t *testing.T) {
	data := "nf_tables napi 0 - Live 0x0\noverlay 1 - Live 0x0\n"
	got := parseLoadedModules(data)
	if !got["nf_tables"] || !got["overlay"] {
		t.Errorf("expected nf_tables and overlay loaded, got %v", got)
	}
	if got["esp4"] {
		t.Errorf("esp4 should not be loaded")
	}
}

func TestParseBuiltinAndAvailable(t *testing.T) {
	builtin := parseBuiltinModules("kernel/net/netfilter/nf_tables.ko\nkernel/fs/overlayfs/overlay.ko\n")
	if !builtin["nf_tables"] || !builtin["overlay"] {
		t.Errorf("builtin parse missed entries: %v", builtin)
	}
	avail := parseAvailableModules("kernel/net/ipv4/esp4.ko.zst: kernel/net/xfrm/xfrm_algo.ko\n")
	if !avail["esp4"] {
		t.Errorf("available parse missed esp4: %v", avail)
	}
}

func TestParseBlacklist(t *testing.T) {
	data := "blacklist nf-tables\n# comment\ninstall overlay /bin/false\ninstall foo /sbin/modprobe bar\n"
	got := parseBlacklist(data)
	if !got["nf_tables"] { // hyphen normalized to underscore
		t.Errorf("nf_tables should be blacklisted: %v", got)
	}
	if !got["overlay"] {
		t.Errorf("overlay should be blocked via install /bin/false: %v", got)
	}
	if got["foo"] {
		t.Errorf("foo redirected to real modprobe is not a block: %v", got)
	}
}

func TestParseKernelConfig(t *testing.T) {
	data := "# comment\nCONFIG_INET_ESP=m\nCONFIG_XFRM=y\n# CONFIG_AF_RXRPC is not set\nCONFIG_NAME=\"quoted\"\n"
	got := parseKernelConfig(data)
	if got["CONFIG_INET_ESP"] != "m" {
		t.Errorf("CONFIG_INET_ESP = %q, want m", got["CONFIG_INET_ESP"])
	}
	if got["CONFIG_XFRM"] != "y" {
		t.Errorf("CONFIG_XFRM = %q, want y", got["CONFIG_XFRM"])
	}
	if _, present := got["CONFIG_AF_RXRPC"]; present {
		t.Errorf("CONFIG_AF_RXRPC should be absent (is-not-set line), got present")
	}
	if got["CONFIG_NAME"] != "quoted" {
		t.Errorf("CONFIG_NAME = %q, want quoted", got["CONFIG_NAME"])
	}
}

func TestFallbackCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"5.15.0-91-generic", "6.8", -1},
		{"6.8", "5.15.5", 1},
		{"5.15.0.92", "5.15.0.92", 0},
		{"5.15.0.80", "5.15.0.92", -1},
		{"6.2", "5.11", 1},
	}
	for _, tc := range tests {
		if got := fallbackCompare(tc.a, tc.b); got != tc.want {
			t.Errorf("fallbackCompare(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
