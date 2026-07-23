package notification

import (
	"testing"
	"time"
)

func templateSamplePayload() Payload {
	return Payload{
		Event:          "incident.opened",
		IncidentID:     "inc_1",
		SiteID:         "site_1",
		State:          "open",
		Severity:       "critical",
		Scope:          "site",
		AgentCount:     2,
		SuspectedLayer: "wan",
		URL:            "http://console/incidents?incident=inc_1",
		At:             time.Date(2026, 7, 23, 10, 30, 0, 0, time.UTC),
		Details: []AlertDetail{
			// Deliberately out of order: warn(lan) listed first, critical(service)
			// second, plus a duplicate name — buildVars must sort worst-first and dedupe.
			{TargetName: "Warn Target", Target: "1.1.1.1", Severity: "warn", Layer: "lan",
				ProbeKind: "icmp", MetricKind: "probe.icmp.loss_pct", Comparator: "gt", Threshold: 10, Value: 50},
			{TargetName: "Crit Target", Target: "example.com", Severity: "critical", Layer: "service",
				ProbeKind: "http", MetricKind: "probe.http.status", Comparator: "eq", Threshold: 200, Value: 503},
			{TargetName: "Crit Target", Target: "example.com", Severity: "critical", Layer: "service",
				ProbeKind: "http", MetricKind: "probe.http.status", Comparator: "eq", Threshold: 200, Value: 502},
		},
	}
}

func TestBuildVars(t *testing.T) {
	vars := buildVars(templateSamplePayload(), "en")

	want := map[string]string{
		"event":           "incident.opened",
		"state":           "open",
		"severity":        "critical",
		"scope":           "site",
		"incident_id":     "inc_1",
		"site_id":         "site_1",
		"suspected_layer": "wan",
		"url":             "http://console/incidents?incident=inc_1",
		"agent_count":     "2",
		"at":              "2026-07-23T10:30:00Z",
		// Worst-first: critical target leads, warn follows; duplicate collapsed.
		"target":  "Crit Target",
		"targets": "Crit Target, Warn Target",
	}
	for k, v := range want {
		if vars[k] != v {
			t.Errorf("vars[%q]=%q, want %q", k, vars[k], v)
		}
	}
	if vars["title"] == "" || vars["text"] == "" || vars["summary"] == "" || vars["lines"] == "" {
		t.Fatalf("rendered vars empty: %+v", vars)
	}
}

func TestBuildVarsFallsBackToAddress(t *testing.T) {
	// A detail with no operator-set name falls back to the raw target address.
	p := Payload{Details: []AlertDetail{{Target: "8.8.8.8", Severity: "warn", Layer: "dns"}}}
	vars := buildVars(p, "en")
	if vars["target"] != "8.8.8.8" || vars["targets"] != "8.8.8.8" {
		t.Fatalf("target=%q targets=%q", vars["target"], vars["targets"])
	}
}

func TestEscapers(t *testing.T) {
	if got := escapeURLValue("a b&c=d"); got != "a%20b%26c%3Dd" {
		t.Errorf("escapeURLValue=%q", got)
	}
	if got := escapeJSONValue(`he said "hi"`); got != `he said \"hi\"` {
		t.Errorf("escapeJSONValue quotes=%q", got)
	}
	// A newline becomes a literal backslash-n (valid inside a JSON string literal).
	if got := escapeJSONValue("line1\nline2"); got != `line1\nline2` {
		t.Errorf("escapeJSONValue newline=%q", got)
	}
	if got := escapeHeaderValue("a\r\nb\nc"); got != "abc" {
		t.Errorf("escapeHeaderValue=%q", got)
	}
}

func TestSubstitute(t *testing.T) {
	vars := map[string]string{"severity": "critical", "text": `a "b"`}

	// Whitespace inside the braces is tolerated.
	if got := substitute("[{{ severity }}]", vars, escapeHeaderValue); got != "[critical]" {
		t.Errorf("whitespace token=%q", got)
	}
	// Unknown variables are left verbatim so typos are visible.
	if got := substitute("{{nope}}", vars, escapeHeaderValue); got != "{{nope}}" {
		t.Errorf("unknown token=%q", got)
	}
	// JSON context escapes the substituted value.
	if got := substitute(`{"c":"{{text}}"}`, vars, escapeJSONValue); got != `{"c":"a \"b\""}` {
		t.Errorf("json substitute=%q", got)
	}
}
