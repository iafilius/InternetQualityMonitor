//go:build !linux

package monitor

// Non-Linux stub: legacy GeoIP C library not available.
func lookupLegacyCountry(ipStr string) (string, bool) { return "", false }
