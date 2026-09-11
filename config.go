package enterprise

// Config supplies the Enterprise CA/template identifiers required for
// machine certificate enrollment. None of these values are hardcoded; they
// must be provided by the caller (or a future orchestration layer).
type Config struct {
	// CA identifies the Enterprise CA in certreq.exe "-config" format:
	// "CAHostName\CAName" (the host and common name of the CA).
	CA string

	// Template is the certificate template name to request. When empty, the
	// template directive is omitted from the generated INF; the module makes
	// no claim about which template (if any) the CA then applies.
	Template string
}

// configured reports whether the required CA configuration is set.
func (c Config) configured() bool {
	return c.CA != ""
}
