// Package routehist records the route history of periodic traceroute
// monitors (probe kind "trace") and detects route changes in it.
//
// # What it does
//
// Every scheduled sweep an agent reports is normalized — per TTL, the sorted
// set of responders, trailing silence trimmed — into an IP path, and through
// the injected asnlookup.Resolver into an AS path (hops without an AS skipped,
// adjacent repeats merged). The AS path is the route's identity: under ECMP the
// IP path differs nearly every run while the AS path holds, so IP paths are
// only counted as variants of the era they occur in.
//
// History is stored as EPOCHS: one row per (agent, monitor, AS path) era,
// extended in place while the route holds — run count, a mergeable
// log-bucket histogram of destination RTT, reach and loss counters — and a new
// row only when the route really changes. A run that disagrees with the open
// era is not a change yet: it becomes the pending candidate, and only
// ConfirmRuns consecutive runs agreeing on the same new AS path confirm it —
// the old era is closed, a new one opened from the candidate's runs, and a
// route_changes row written with its kind, segment and first diverging TTL.
// A shorter disagreement is absorbed into the era's deviation count and leaves
// no other trace. Partial sweeps (destination never answered) compare by the
// prefix that did answer, so ICMP-filtered destinations and timeouts deep in
// the path read as "the same route, seen less far".
//
// # Lookup-table refreshes are not route changes
//
// An AS path is derived from the addresses an agent reports through whatever
// table was loaded at the time, so swapping in a newer table can give an
// unchanged IP route a different AS path. A run that disagrees with the open
// era is therefore first checked against two rules before it may become a
// candidate: if any hop of the era's representative path was resolved under
// an older table version, that path is re-resolved under the current one and
// the era repointed at the result (AS path, dictionary rows and local egress
// facts) before comparing; and a run whose IP path names, TTL by TTL, the
// same addresses as a variant the era has already counted is the same route
// whatever its AS path reads. Either way the era continues and no deviation
// is counted. A real change still has to win ConfirmRuns runs against the
// re-described era, so it is classified with both sides in one table.
//
// # Why its own package and not part of fault
//
// fault hosts the availability and degradation detectors: verdicts over probe
// rounds that open faults, join incidents and plan notifications. Route change
// detection shares none of that machinery — it never notifies, never opens an
// incident, has no round or threshold — and its detection state IS its
// storage (an epoch is both the era being recorded and the baseline the next
// run is judged against). Putting it in fault would make fault own eight
// tables and the ASN dependency for a detector that uses none of fault's
// pipeline; keeping it here keeps fault's surface what its doc says it is.
//
// # Layering
//
// Like the rest of the domain core it is entered as (Scope, WriteTx) from the
// ingest transaction (ApplyTx) and never begins or commits a transaction of its
// own on that path; it imports no HTTP or console package. The read views and
// retention are plain methods on Service for the hosts that serve a console
// and run maintenance.
package routehist
