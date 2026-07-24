package incidentops

import "encoding/json"

// mustJSON marshals v to a JSON string, returning "" on error (never used with
// values that can fail to marshal in practice; the empty string degrades to an
// empty payload rather than aborting a write).
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// decodeStrings parses a JSON string array, tolerating "" / malformed input as an
// empty slice (used for the agents perm_supported/perm_granted/perm_effective
// columns).
func decodeStrings(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if json.Unmarshal([]byte(raw), &out) != nil {
		return nil
	}
	return out
}
