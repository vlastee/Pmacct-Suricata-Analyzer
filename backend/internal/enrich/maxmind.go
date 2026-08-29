package enrich

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// MaxMind resolves geo + ASN from local GeoLite2 databases (no network, no quota).
type MaxMind struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

// OpenMaxMind opens the City and ASN databases.
func OpenMaxMind(cityPath, asnPath string) (*MaxMind, error) {
	city, err := maxminddb.Open(cityPath)
	if err != nil {
		return nil, fmt.Errorf("geoip city db: %w", err)
	}
	asn, err := maxminddb.Open(asnPath)
	if err != nil {
		city.Close()
		return nil, fmt.Errorf("geoip asn db: %w", err)
	}
	return &MaxMind{city: city, asn: asn}, nil
}

// Close releases the databases.
func (m *MaxMind) Close() {
	m.city.Close()
	m.asn.Close()
}

// Name identifies the provider.
func (m *MaxMind) Name() string { return "maxmind" }

type mmCity struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
		TimeZone  string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
}

type mmASN struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// Lookup resolves one IP.
func (m *MaxMind) Lookup(ctx context.Context, ip string) (*db.IPInfo, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, err
	}
	var c mmCity
	if err := m.city.Lookup(addr).Decode(&c); err != nil {
		return nil, fmt.Errorf("maxmind city: %w", err)
	}
	var a mmASN
	_ = m.asn.Lookup(addr).Decode(&a)
	info := &db.IPInfo{Country: sp(c.Country.Names["en"]), CountryCode: sp(c.Country.ISOCode), City: sp(c.City.Names["en"]), Timezone: sp(c.Location.TimeZone)}
	if len(c.Subdivisions) > 0 {
		info.Region = sp(c.Subdivisions[0].Names["en"])
	}
	if c.Location.Latitude != 0 || c.Location.Longitude != 0 {
		lat, lon := c.Location.Latitude, c.Location.Longitude
		info.Lat, info.Lon = &lat, &lon
	}
	if a.Number != 0 {
		asn := fmt.Sprintf("AS%d", a.Number)
		info.ASN = &asn
		info.ASOrg = sp(a.Org)
		info.Org = sp(a.Org)
	}
	if info.CountryCode == nil && info.ASN == nil {
		return nil, fmt.Errorf("maxmind: no data for %s", ip)
	}
	return info, nil
}
