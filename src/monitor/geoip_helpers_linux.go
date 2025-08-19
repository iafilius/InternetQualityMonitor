//go:build linux

package monitor

import "github.com/oschwald/geoip"

// lookupLegacyCountry provides a fallback using legacy GeoIP.dat database (Linux only).
func lookupLegacyCountry(ipStr string) (string, bool) {
	if db, err := geoip.Open("/usr/share/GeoIP/GeoIP.dat"); err == nil {
		cc, _ := db.GetCountry(ipStr)
		return cc, cc != ""
	}
	return "", false
}
