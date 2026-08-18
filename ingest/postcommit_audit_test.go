package ingest

// A structural audit of this package's own source: it proves, mechanically,
// that the post-commit side effects have exactly the supported shape and that
// no third path to them exists.
//
// The rule being enforced: a transaction owner may reach a post-commit side
// effect in exactly two ways — through the closure the transaction function
// returns to its owner, or through a plan the owner executes after the write
// transaction returned successfully. This package uses the second form. What
// must never appear is a third path: a side effect performed from inside the
// transaction function, or a second, unrelated caller that runs the executor
// without owning the transaction that produced its plan.
//
// Honest limits of this audit, both load-bearing:
//
//   - It constrains SOURCE STRUCTURE — how many call sites exist and which
//     function owns them — not runtime ordering. "Outside the transaction
//     function" does not mean "only after a successful commit".
//   - It only sees calls made through a NAME. The executor's first action is a
//     call through a function-typed field — an indirect call this scan cannot
//     attribute to anything, so a side effect moved into that closure is
//     invisible here.
//
// Both gaps are covered by runtime tests rather than by widening this one:
// TestNoSideEffectIOInsideTheTransaction (forward timing, and it counts the
// closure's executions specifically), TestPostCommitNeverRunsWhenTheTransactionFails
// (the plan of a failed transaction runs nothing at all), and the existing
// rollback tests. Only all of them together mechanize the property.
//
// Maintenance obligation: the audit names functions. A rename or a file move
// must update it in the same change — that is intended, because a rename is
// exactly when the invariant is easiest to lose silently.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// auditCall is one matched call site in a non-test source file of this package.
type auditCall struct {
	callee    string // the final identifier of the call's function expression
	file      string
	line      int
	enclosing string // name of the top-level func declaration containing it
	inTxFunc  bool   // lexically inside a function literal passed to WriteTx
}

// calleeName returns the final identifier of a call's function expression:
// "Publish" for s.bus.Publish(...), "ApplyPacketTx" for both
// s.ApplyPacketTx(...) and a bare ApplyPacketTx(...). Matching on the final
// identifier — rather than on a specific receiver spelling — is deliberate: a
// filter that only recognised one receiver shape would quietly stop seeing a
// violation written with another, and an audit that cannot see a violation is
// an audit that always passes.
func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// auditScan is the parsed picture of this package's non-test sources.
type auditScan struct {
	files      []string
	funcDecls  map[string]bool
	totalCalls int // every call expression seen, for the walker's own floor
	txFuncLits int // function literals passed to WriteTx
	calls      []auditCall
}

// scanPackageSource parses every non-test .go file in the package directory and
// collects the call sites whose callee is in watch.
func scanPackageSource(t *testing.T, watch map[string]bool) auditScan {
	t.Helper()
	out := auditScan{funcDecls: map[string]bool{}}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	fset := token.NewFileSet()
	var parsed []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		out.files = append(out.files, name)
		parsed = append(parsed, f)
	}
	sort.Strings(out.files)

	for i, f := range parsed {
		file := out.files[i]
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			out.funcDecls[fd.Name.Name] = true

			// The lexical ranges of every function literal handed to WriteTx
			// in this declaration: everything inside one of them runs while
			// the transaction is open.
			var txRanges [][2]token.Pos
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || calleeName(call) != "WriteTx" {
					return true
				}
				for _, arg := range call.Args {
					if lit, ok := arg.(*ast.FuncLit); ok {
						txRanges = append(txRanges, [2]token.Pos{lit.Pos(), lit.End()})
						out.txFuncLits++
					}
				}
				return true
			})

			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				out.totalCalls++
				name := calleeName(call)
				if !watch[name] {
					return true
				}
				inTx := false
				for _, r := range txRanges {
					if call.Pos() >= r[0] && call.End() <= r[1] {
						inTx = true
						break
					}
				}
				out.calls = append(out.calls, auditCall{
					callee:    name,
					file:      file,
					line:      fset.Position(call.Pos()).Line,
					enclosing: fd.Name.Name,
					inTxFunc:  inTx,
				})
				return true
			})
		}
	}
	return out
}

func (s auditScan) byCallee(name string) []auditCall {
	var out []auditCall
	for _, c := range s.calls {
		if c.callee == name {
			out = append(out, c)
		}
	}
	return out
}

// publishSurface is the set of side-effecting calls that may only run after a
// successful commit: the data-plane append, the in-memory latest-value cache
// fold, and every event publication.
var publishSurface = []string{
	"AppendRawSamples",
	"UpdateLatest",
	"PublishOutcome",
	"PublishTraceOutcome",
	"PublishSceneOutcome",
	"Publish",
}

// TestPostCommitCallSitesAreOwnedByTheEntryPoint asserts the structural half of
// the post-commit rule over this package's own sources:
//
//	(a) the transaction core has exactly one non-test call site, and it sits
//	    inside a function literal handed to the transaction owner;
//	(b) the post-commit executor has exactly one non-test call site, and it
//	    sits OUTSIDE every such literal — i.e. after the write transaction
//	    returned;
//	(c) the executor's BODY — the function that actually performs the side
//	    effects — has exactly one non-test caller, the executor entry point
//	    itself. Without this, (b) is trivially bypassable: the body is an
//	    ordinary method of this package, so any function here, a transaction
//	    callback included, could call it directly and run every side effect
//	    inside the transaction while (b) still saw a single, well-placed call
//	    to the entry point;
//	(d) every side-effecting publish/append/cache call in this package lives in
//	    the executor's body and nowhere else.
//
// The subtests named "self-control" are not about the rule; they are about the
// audit. Each of (a)-(c) is a statement of the form "nothing outside X does Y",
// and such a statement passes trivially if the scan sees nothing at all. The
// self-control subtests therefore assert floors on what the scan found — files
// parsed, call expressions walked, declarations located, function literals
// recognised — so a parser, filter or matcher that silently stops seeing the
// package fails here instead of turning the whole audit green by vacuity.
func TestPostCommitCallSitesAreOwnedByTheEntryPoint(t *testing.T) {
	watch := map[string]bool{"ApplyPacketTx": true, "Commit": true, "commitOnce": true}
	for _, n := range publishSurface {
		watch[n] = true
	}
	scan := scanPackageSource(t, watch)

	t.Run("self-control: the scan actually read this package", func(t *testing.T) {
		if len(scan.files) < 5 {
			t.Fatalf("scanned %d non-test source files (%v), want at least 5 — the scan lost sight of the package",
				len(scan.files), scan.files)
		}
		want := map[string]bool{"apply.go": false, "ingest.go": false}
		for _, f := range scan.files {
			if _, ok := want[f]; ok {
				want[f] = true
			}
		}
		for f, seen := range want {
			if !seen {
				t.Fatalf("%s was not among the scanned files %v", f, scan.files)
			}
		}
		if scan.totalCalls < 200 {
			t.Fatalf("walked %d call expressions, want at least 200 — the walker is not descending into function bodies",
				scan.totalCalls)
		}
	})

	t.Run("self-control: the audited declarations were located", func(t *testing.T) {
		for _, name := range []string{"ApplyPacketTx", "Commit", "commitOnce", "Ingest", "Prepare"} {
			if !scan.funcDecls[name] {
				t.Fatalf("no declaration named %q was found; the audit is naming something that no longer exists "+
					"(a rename must update this test in the same change)", name)
			}
		}
		if scan.txFuncLits < 1 {
			t.Fatal("no function literal handed to a write transaction was recognised — the " +
				"inside/outside classification below would be meaningless")
		}
	})

	t.Run("the transaction core has one call site, inside the transaction function", func(t *testing.T) {
		sites := scan.byCallee("ApplyPacketTx")
		if len(sites) != 1 {
			t.Fatalf("ApplyPacketTx has %d non-test call sites (%+v), want exactly 1", len(sites), sites)
		}
		if !sites[0].inTxFunc {
			t.Fatalf("ApplyPacketTx is called at %s:%d in %s, outside the transaction function — the "+
				"transaction core must run inside the owner's transaction",
				sites[0].file, sites[0].line, sites[0].enclosing)
		}
	})

	t.Run("the post-commit executor has one call site, outside the transaction function", func(t *testing.T) {
		sites := scan.byCallee("Commit")
		if len(sites) != 1 {
			t.Fatalf("Commit has %d non-test call sites (%+v), want exactly 1 — a second caller would be a "+
				"third path to the post-commit side effects", len(sites), sites)
		}
		if sites[0].inTxFunc {
			t.Fatalf("Commit is called at %s:%d in %s from inside the transaction function — the post-commit "+
				"plan must only run after the write transaction returned successfully",
				sites[0].file, sites[0].line, sites[0].enclosing)
		}
		// Lexically outside the transaction function is necessary but not
		// sufficient: it says nothing about whether the call is reached only
		// when the transaction succeeded. This assertion pins the one further
		// thing structure can honestly state — WHICH function owns the call —
		// so the executor cannot drift to a caller that never held the
		// transaction. Whether it runs only after success is a timing
		// question, answered by TestPostCommitNeverRunsWhenTheTransactionFails
		// and TestNoSideEffectIOInsideTheTransaction rather than here;
		// modelling control flow in this audit would mean guessing at the
		// error check, and an audit that guesses wrong stops seeing the very
		// thing it exists to catch.
		if sites[0].enclosing != "Ingest" {
			t.Fatalf("Commit is called from %s at %s:%d; the transaction owner is the only function that may "+
				"run the plan it produced", sites[0].enclosing, sites[0].file, sites[0].line)
		}
	})

	t.Run("the executor body is reachable only through the executor entry point", func(t *testing.T) {
		// (b) alone is not enough. The side effects are performed by the
		// executor's BODY, which is an ordinary method of this package: any
		// function here can call it directly, transaction callbacks included.
		// Such a caller would run all seven side effects inside the
		// transaction while (b) still saw one well-placed call to the entry
		// point, and the runtime timing tests would not execute the new caller
		// either. Confining the body to a single caller — the entry point,
		// which carries the single-use guard — is what makes (b) load-bearing.
		sites := scan.byCallee("commitOnce")
		if len(sites) != 1 {
			t.Fatalf("commitOnce has %d non-test call sites (%+v), want exactly 1 — the side effects must "+
				"only be reachable through the executor entry point", len(sites), sites)
		}
		if sites[0].enclosing != "Commit" {
			t.Fatalf("commitOnce is called from %s at %s:%d, bypassing the executor entry point and its "+
				"single-use guard", sites[0].enclosing, sites[0].file, sites[0].line)
		}
		if sites[0].inTxFunc {
			t.Fatalf("commitOnce is called at %s:%d from inside the transaction function — every side effect "+
				"it performs would run before the commit", sites[0].file, sites[0].line)
		}
	})

	t.Run("every side effect lives in the post-commit executor", func(t *testing.T) {
		var found int
		for _, name := range publishSurface {
			for _, c := range scan.byCallee(name) {
				found++
				if c.enclosing != "commitOnce" {
					t.Fatalf("%s is called at %s:%d from %s; the only function allowed to perform a "+
						"post-commit side effect is the executor body",
						name, c.file, c.line, c.enclosing)
				}
			}
		}
		// Self-control for this subtest specifically: the assertion above is
		// "no such call outside the executor", which a matcher that finds
		// nothing satisfies for free. The floor is the exact number of side
		// effects the executor performs today, so REMOVING one — the change
		// that would quietly hollow the rule out — fails here; adding one
		// inside the executor is fine.
		if found < 7 {
			t.Fatalf("matched %d side-effecting call sites, want at least 7 — either the matcher stopped "+
				"recognising the publish/append surface (so the rule above was checked against nothing), "+
				"or a side effect was removed and this floor must be re-justified", found)
		}
	})
}
