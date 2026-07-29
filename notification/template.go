package notification

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// varPattern matches a {{variable}} token, tolerating inner whitespace
// ({{ title }}). Variable names are lower_snake_case.
var varPattern = regexp.MustCompile(`\{\{\s*([a-z_]+)\s*\}\}`)

// buildVars computes the substitution values a webhook template can reference,
// rendered in the channel's configured language. The keys here are the authored
// variable set exposed in the UI docs; keep the two in sync.
//
//	title            headline ("网络告警" / "Network alert")
//	text             one-line scope/diagnosis
//	summary          one-line summary leading with the top fault
//	lines            per-target fault sentences, newline-joined
//	target           worst-first primary target name (storm: first monitor group)
//	targets          distinct target names, worst-first, comma-joined (storm: group names)
//	agents           agent names for a connectivity event, comma-joined (storm: the observing agent)
//	event/state/severity/scope/incident_id/storm_id/site_id/suspected_layer/url  raw Payload fields
//	agent_count      number of distinct alerting agents
//	at               incident time, RFC3339
//
// event takes the values incident.opened / incident.resolved / agent.offline /
// agent.recovered / storm.opened / storm.resolved / test. storm_id is empty for
// everything but the two storm events, and incident_id is empty for those.
func buildVars(p Payload, lang string) map[string]string {
	// target / targets: distinct friendly names in worst-first order, falling
	// back to the raw address when a target has no operator-set name.
	var targets []string
	seen := map[string]bool{}
	for _, d := range sortedDetails(p.Details) {
		name := d.TargetName
		if name == "" {
			name = d.Target
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		targets = append(targets, name)
	}
	target := ""
	if len(targets) > 0 {
		target = targets[0]
	}
	// agents: names present in a connectivity event, comma-joined.
	var agentNames []string
	for _, a := range p.Agents {
		name := a.Name
		if name == "" {
			name = a.AgentID
		}
		agentNames = append(agentNames, name)
	}
	// A storm has no per-target details of its own — it stands for many faults at
	// once. Fill the same two variables from the groups it hit and the Agent it was
	// seen from, so a template authored against incident events still renders
	// something true instead of an empty string.
	if p.Storm != nil {
		if len(targets) == 0 {
			for _, g := range p.Storm.Groups {
				if g.Name != "" {
					targets = append(targets, g.Name)
				}
			}
			if len(targets) > 0 {
				target = targets[0]
			}
		}
		if len(agentNames) == 0 && p.Storm.AgentName != "" {
			agentNames = append(agentNames, p.Storm.AgentName)
		}
	}
	return map[string]string{
		"title":           RenderTitle(p, lang),
		"text":            RenderScope(p, lang),
		"summary":         RenderSummary(p, lang),
		"lines":           strings.Join(RenderLines(p, lang), "\n"),
		"target":          target,
		"targets":         strings.Join(targets, ", "),
		"agents":          strings.Join(agentNames, ", "),
		"event":           p.Event,
		"state":           p.State,
		"severity":        p.Severity,
		"scope":           p.Scope,
		"incident_id":     p.IncidentID,
		"storm_id":        p.StormID,
		"site_id":         p.SiteID,
		"suspected_layer": p.SuspectedLayer,
		"url":             p.URL,
		"agent_count":     strconv.Itoa(p.AgentCount),
		"at":              p.At.Format(time.RFC3339),
	}
}

// substitute replaces every {{var}} token in tpl with esc(vars[var]) for the
// target context. Unknown variables are left verbatim, so a typo surfaces in the
// rendered output (and in a test send) instead of silently vanishing.
func substitute(tpl string, vars map[string]string, esc func(string) string) string {
	return varPattern.ReplaceAllStringFunc(tpl, func(m string) string {
		name := varPattern.FindStringSubmatch(m)[1]
		v, ok := vars[name]
		if !ok {
			return m
		}
		return esc(v)
	})
}

// escapeURLValue percent-encodes a value for substitution into any part of a URL.
// url.QueryEscape encodes spaces as '+', which is only correct in query strings;
// normalize to %20 so path-style templates (e.g. Bark's /:key/:title) are correct
// too.
func escapeURLValue(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// escapeJSONValue escapes a value for substitution INSIDE a JSON string literal,
// without the surrounding quotes, so a body template can write
// "content": "{{text}}". Newlines in {{lines}} therefore appear as literal \n
// (which renders as a line break in e.g. DingTalk's text.content).
func escapeJSONValue(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// escapeHeaderValue strips CR/LF so a substituted value can't inject additional
// header lines; the value is otherwise passed through verbatim.
func escapeHeaderValue(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}
