// Package detect is the pure verdict engine. It maps host facts plus the CVE
// dataset to graded verdicts, taking an injected version comparator so it has
// no dependency on the host or external tools and is fully fixture-testable.
package detect
