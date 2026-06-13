package collect

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"unicode"
)

// NewComparator returns a version comparator using the host's native tooling so
// distribution version semantics (epochs, tildes) are correct: dpkg where
// available, then rpm, else a pure-Go dotted-numeric fallback. The returned
// function is assignable to detect.VerCmp and returns -1, 0, or +1. The context
// bounds each comparison command.
func NewComparator(ctx context.Context) func(a, b string) int {
	switch {
	case hasCmd("dpkg"):
		return func(a, b string) int { return dpkgCompare(ctx, a, b) }
	case hasCmd("rpm"):
		return func(a, b string) int { return rpmCompare(ctx, a, b) }
	default:
		return fallbackCompare
	}
}

// dpkgCompare uses `dpkg --compare-versions`, falling back to a pure comparison
// if the command misbehaves.
func dpkgCompare(ctx context.Context, a, b string) int {
	if a == b {
		return 0
	}
	lt := exec.CommandContext(ctx, "dpkg", "--compare-versions", a, "lt", b).Run() == nil
	if lt {
		return -1
	}
	gt := exec.CommandContext(ctx, "dpkg", "--compare-versions", a, "gt", b).Run() == nil
	if gt {
		return 1
	}
	return 0
}

// rpmCompare uses rpm's embedded Lua vercmp, falling back on error.
func rpmCompare(ctx context.Context, a, b string) int {
	expr := `%{lua: print(rpm.vercmp("` + a + `","` + b + `"))}`
	out, err := exec.CommandContext(ctx, "rpm", "--eval", expr).Output()
	if err != nil {
		return fallbackCompare(a, b)
	}
	switch strings.TrimSpace(string(out)) {
	case "-1":
		return -1
	case "1":
		return 1
	case "0":
		return 0
	default:
		return fallbackCompare(a, b)
	}
}

// fallbackCompare compares versions field by field on their numeric components.
// It is a last resort when no package manager is present.
func fallbackCompare(a, b string) int {
	as, bs := numericFields(a), numericFields(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

func numericFields(s string) []int {
	fields := strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsDigit(r) })
	nums := make([]int, len(fields))
	for i, f := range fields {
		nums[i], _ = strconv.Atoi(f)
	}
	return nums
}
