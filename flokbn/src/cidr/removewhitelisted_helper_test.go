package cidr

// RemoveWhitelisted is removeWhitelisted with an unparsed whitelist: the entry
// point of the whitelist-subtraction tests and the differential fuzz against
// the old per-candidate implementation.
func RemoveWhitelisted(blacklist []string, whitelist []string) []string {
	if len(whitelist) == 0 {
		return blacklist
	}
	return removeWhitelisted(blacklist, ParseIntervalSet(whitelist))
}
