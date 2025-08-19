package monitor

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

// lookupGeoIP2Country attempts to open common GeoLite2 country database locations
// and return the ISO country code for the provided IP. Returns ok=false if
// database not found or lookup fails.
func lookupGeoIP2Country(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}
	paths := []string{
		"/usr/share/GeoIP/GeoLite2-Country.mmdb",
		"/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
		"/usr/share/GeoIP/GeoLite2-Country.mmdb.gz", // some distros compress; ignore if open fails
	}
	for _, p := range paths {
		if db, err := geoip2.Open(p); err == nil {
			rec, err2 := db.Country(ip)
			db.Close()
			if err2 == nil && rec != nil {
				return rec.Country.IsoCode, true
			}
		}
	}
	return "", false
}

// lookupGeoIP2ASN returns ASN info (number, org) if available.
func lookupGeoIP2ASN(ipStr string) (uint, string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, "", false
	}
	paths := []string{
		"/usr/share/GeoIP/GeoLite2-ASN.mmdb",
		"/usr/local/share/GeoIP/GeoLite2-ASN.mmdb",
	}
	for _, p := range paths {
		if db, err := geoip2.Open(p); err == nil {
			rec, err2 := db.ASN(ip)
			db.Close()
			if err2 == nil && rec != nil {
				return rec.AutonomousSystemNumber, rec.AutonomousSystemOrganization, true
			}
		}
	}
	return 0, "", false
}

// lookupLegacyCountry is implemented in geoip_helpers_linux.go (Linux) and geoip_helpers_other.go (stub for non-Linux).
