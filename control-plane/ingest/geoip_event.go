package ingest

// enrichGeoIP always discards producer-supplied location metadata. A disabled,
// missing or failed lookup cannot leave forged fields behind. Enrichment failure
// is observable but must not lose an otherwise valid security event.
func (s *IngestService) enrichGeoIP(evt *Event) {
	clearEventGeoIP(evt)
	if s.GeoIP == nil {
		return
	}
	loc, err := s.GeoIP.Resolve(evt.ClientIP)
	if err != nil {
		s.geoIPErrors.Add(1)
		return
	}
	if loc == nil {
		return
	}
	evt.CountryISO, evt.Region, evt.City = loc.CountryISO, loc.Region, loc.City
	evt.Lat, evt.Lon, evt.AccuracyKM = loc.Lat, loc.Lon, loc.AccuracyKM
	evt.ASN, evt.ASOrg, evt.GeoIPVersion = loc.ASN, loc.ASOrg, loc.Version
}

func clearEventGeoIP(evt *Event) {
	evt.CountryISO, evt.Region, evt.City, evt.ASOrg, evt.GeoIPVersion = "", "", "", "", ""
	evt.Lat, evt.Lon, evt.AccuracyKM, evt.ASN = nil, nil, nil, 0
}

// Old branch metadata had no server database fingerprint and could be forged.
// Keep its raw columns for operators, but do not present them as resolved data.
func sanitizeStoredGeoIP(evt *Event) {
	if evt.GeoIPVersion != "" {
		return
	}
	internal := false
	if evt.CountryISO == "INTERNAL" {
		if addr, ok := parseGeoIPAddr(evt.ClientIP); ok {
			internal = geoIPInternal(addr)
		}
	}
	clearEventGeoIP(evt)
	if internal {
		evt.CountryISO = "INTERNAL"
	}
}
