package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/fieldse/fragcheck/internal/model"
)

// ANSI color codes; only emitted when color rendering is enabled.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiGray   = "\x1b[90m"
)

func statusColor(s model.Status) string {
	switch s {
	case model.StatusVulnerable:
		return ansiRed
	case model.StatusLikelyVulnerable:
		return ansiYellow
	case model.StatusMitigated:
		return ansiCyan
	case model.StatusNotAffected:
		return ansiGreen
	default:
		return ansiGray
	}
}

// Table renders verdicts as a human-readable summary grid followed by a details
// section (evidence and remediation) for each CVE. ANSI color is emitted only
// when color is true; callers disable it for non-TTY output, NO_COLOR, or JSON.
func Table(w io.Writer, verdicts []model.Verdict, color bool) error {
	c := colorizer(color)

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, c(ansiBold, "CVE\tNICKNAME\tCVSS\tKEV\tSTATUS"))
	for _, v := range verdicts {
		kev := "-"
		if v.Severity.KEV {
			kev = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%.1f\t%s\t%s\n",
			v.CVE, v.Nickname, v.Severity.CVSS, kev,
			c(statusColor(v.Status), string(v.Status)),
		)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	for _, v := range verdicts {
		fmt.Fprintf(w, "\n%s %s — %s\n", v.CVE, v.Nickname, c(statusColor(v.Status), string(v.Status)))
		for _, e := range v.Evidence {
			fmt.Fprintf(w, "    - %s\n", e)
		}
		if v.Remediation != "" {
			fmt.Fprintf(w, "    fix: %s\n", v.Remediation)
		}
	}

	fmt.Fprintf(w, "\nSummary: %s\n", summarize(verdicts, c))
	return nil
}

// summaryOrder lists statuses worst-first for the footer count.
var summaryOrder = []model.Status{
	model.StatusVulnerable,
	model.StatusLikelyVulnerable,
	model.StatusMitigated,
	model.StatusNotAffected,
	model.StatusUnknown,
}

// summarize builds a "N vulnerable, M not-affected, ..." line, omitting
// zero-count statuses but always showing the vulnerable count.
func summarize(verdicts []model.Verdict, c func(code, text string) string) string {
	counts := map[model.Status]int{}
	for _, v := range verdicts {
		counts[v.Status]++
	}
	var parts []string
	for _, s := range summaryOrder {
		n := counts[s]
		if n == 0 && s != model.StatusVulnerable {
			continue
		}
		parts = append(parts, c(statusColor(s), fmt.Sprintf("%d %s", n, s)))
	}
	return strings.Join(parts, ", ")
}

// JSON writes verdicts as indented JSON. It never emits ANSI.
func JSON(w io.Writer, verdicts []model.Verdict) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(verdicts)
}

// colorizer returns a wrap function that applies an ANSI code when enabled, or
// returns the text unchanged otherwise.
func colorizer(enabled bool) func(code, text string) string {
	if !enabled {
		return func(_, text string) string { return text }
	}
	return func(code, text string) string { return code + text + ansiReset }
}
