package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/fieldse/fragcheck/internal/model"
)

func sample() []model.Verdict {
	return []model.Verdict{
		{
			CVE: "CVE-2024-1086", Nickname: "nf_tables UAF",
			Severity: model.Severity{CVSS: 7.8, KEV: true},
			Status:   model.StatusVulnerable,
			Evidence: []string{"running kernel 5.15.0.80 < ubuntu fixed (5.15.0.92)", "module nf_tables: loaded (reachable)"},
			Remediation: "upgrade kernel",
		},
		{
			CVE: "CVE-2022-0847", Nickname: "Dirty Pipe",
			Severity: model.Severity{CVSS: 7.8},
			Status:   model.StatusNotAffected,
			Evidence: []string{"running kernel 5.15.0.95 >= ubuntu fixed (5.15.0.92)"},
			Remediation: "none required",
		},
	}
}

func TestTableNoColor(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, sample(), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Errorf("color=false output must not contain ANSI escapes:\n%s", out)
	}
	for _, want := range []string{
		"CVE-2024-1086", "nf_tables UAF", "7.8", "yes", "vulnerable",
		"CVE-2022-0847", "not-affected",
		"module nf_tables: loaded (reachable)", "fix: upgrade kernel",
		"Summary:", "1 vulnerable", "1 not-affected",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q\n%s", want, out)
		}
	}
}

func TestTableColor(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, sample(), true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, ansiRed) {
		t.Errorf("color=true output should colorize the vulnerable status with red")
	}
	if !strings.Contains(out, ansiReset) {
		t.Errorf("color=true output should reset color")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := sample()
	if err := JSON(&buf, in); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("JSON output must not contain ANSI escapes")
	}
	var out []model.Verdict
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("JSON round-trip mismatch:\nin=%+v\nout=%+v", in, out)
	}
}
