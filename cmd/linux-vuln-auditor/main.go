// Command linux-vuln-auditor audits the local Linux host for exposure to a
// curated set of recent kernel privilege-escalation CVEs and prints a
// remediation report. It runs as root, performs detection only, and never
// executes exploit code. See docs/SPEC.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/fieldse/linux-vuln-auditor/internal/collect"
	"github.com/fieldse/linux-vuln-auditor/internal/cve"
	"github.com/fieldse/linux-vuln-auditor/internal/detect"
	"github.com/fieldse/linux-vuln-auditor/internal/report"
)

// Exit codes. Finding-based exit codes are out of scope for v1; a completed
// audit always exits 0 regardless of the verdicts it reports.
const (
	exitOK     = 0 // audit completed
	exitError  = 1 // internal error (e.g. dataset load failure)
	exitRefuse = 2 // refused to run: wrong platform, not root, unsupported distro
)

// collectTimeout bounds the host-inspection commands (dpkg/rpm/uname) so a
// wedged tool cannot hang the audit.
const collectTimeout = 30 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, colorAllowed(os.Stdout)))
}

func run(args []string, stdout, stderr io.Writer, colorAllowed bool) int {
	fs := flag.NewFlagSet("linux-vuln-auditor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit results as JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	if runtime.GOOS != "linux" {
		fmt.Fprintf(stderr, "linux-vuln-auditor: unsupported platform %q; this tool audits Linux hosts only\n", runtime.GOOS)
		return exitRefuse
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "linux-vuln-auditor: must run as root to read kernel, package, and module state")
		return exitRefuse
	}

	ds, err := cve.Load()
	if err != nil {
		fmt.Fprintf(stderr, "linux-vuln-auditor: %v\n", err)
		return exitError
	}

	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()

	facts := collect.Collect(ctx, ds)
	if !facts.Distro.Supported() {
		fmt.Fprintf(stderr, "linux-vuln-auditor: unsupported distribution %q; cannot apply backport-aware checks\n", facts.Distro)
		return exitRefuse
	}

	verdicts := detect.Run(ds, facts, collect.NewComparator(ctx))

	if *jsonOut {
		if err := report.JSON(stdout, verdicts); err != nil {
			fmt.Fprintf(stderr, "linux-vuln-auditor: %v\n", err)
			return exitError
		}
		return exitOK
	}
	if err := report.Table(stdout, verdicts, colorAllowed && !*jsonOut); err != nil {
		fmt.Fprintf(stderr, "linux-vuln-auditor: %v\n", err)
		return exitError
	}
	return exitOK
}

// colorAllowed reports whether ANSI color should be emitted: only when writing
// to a terminal and NO_COLOR is unset.
func colorAllowed(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
