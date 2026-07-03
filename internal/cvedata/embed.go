// Package cvedata holds the embedded CVE dataset as raw bytes. It exists as a
// standalone package so the YAML can live at internal/cvedata/ rather than
// buried under the cve package: go:embed can only reference files within its
// own directory tree, so the embed directive must sit beside the data file.
package cvedata

import _ "embed"

// Raw is the embedded CVE dataset (cves.yaml). Parse it via cve.Load.
//
//go:embed cves.yaml
var Raw []byte
