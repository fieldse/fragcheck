package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// On a non-Linux dev host the tool must refuse cleanly with a clear message and
// a non-zero exit, emitting nothing to stdout.
func TestRunRefusesNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("platform-refuse path only observable off Linux")
	}
	var out, errBuf bytes.Buffer
	code := run(nil, &out, &errBuf, false)

	if code != exitRefuse {
		t.Errorf("exit code = %d, want %d", code, exitRefuse)
	}
	if out.Len() != 0 {
		t.Errorf("expected no stdout on refuse, got %q", out.String())
	}
	if !strings.Contains(errBuf.String(), "unsupported platform") {
		t.Errorf("stderr should explain the refusal, got %q", errBuf.String())
	}
}

func TestRunRejectsUnknownFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--nope"}, &out, &errBuf, false); code != exitError {
		t.Errorf("exit code = %d, want %d for unknown flag", code, exitError)
	}
}

func TestRunVersion(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--version"}, &out, &errBuf, false); code != exitOK {
		t.Errorf("exit code = %d, want %d", code, exitOK)
	}
	if !strings.Contains(out.String(), "linux-vuln-auditor") {
		t.Errorf("version output = %q", out.String())
	}
}
