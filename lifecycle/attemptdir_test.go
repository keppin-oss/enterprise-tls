package lifecycle

import (
	"context"
	"errors"
	"testing"
)

type planDeleter struct {
	testDeleter
	plans []string
}

func (d *planDeleter) DeletePlanned(_ context.Context, plan string, a Artifact) error {
	d.plans = append(d.plans, plan)
	return d.testDeleter.Delete(ctx, a)
}

// Cleaner passes the plan ID to a PlanDeleter and never calls its Delete.
func TestCleanerUsesPlanDeleter(t *testing.T) {
	j := newTestJournal()
	d := &planDeleter{}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "attempt", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "attempt"); err != nil {
		t.Fatal(err)
	}
	if len(d.plans) != 2 || d.plans[0] != "attempt" || d.plans[1] != "attempt" || len(d.calls) != 2 {
		t.Fatalf("plans %v calls %d", d.plans, len(d.calls))
	}
	d2 := &planDeleter{testDeleter: testDeleter{results: []error{ErrNotOwned}}}
	j2 := newTestJournal()
	c2 := Cleaner{Journal: j2, Deleter: d2}
	if err := c2.Begin(ctx, "other", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	if err := c2.Resume(ctx, "other"); err == nil || !errors.Is(err, ErrNotOwned) {
		t.Fatalf("PlanDeleter result not checkpointed: %v", err)
	}
	if got := j2.state.Cleanups["other"].Items[0].Result; got != NotOwned {
		t.Fatalf("result %s", got)
	}
}

func TestAttemptNames(t *testing.T) {
	for id, ok := range map[string]bool{
		"0123456789abcdef0123456789abcdef":  true,
		"0123456789ABCDEF0123456789abcdef":  false,
		"0123456789abcdef0123456789abcde":   false,
		"0123456789abcdef0123456789abcdef0": false,
		"..":                                false,
		`0123456789abcdef\123456789abcdef`:  false,
	} {
		if validAttemptID(id) != ok {
			t.Errorf("attempt ID %q: want %t", id, ok)
		}
	}
	for name, ok := range map[string]bool{
		"request.inf": true, "retrieve-12.cer": true, "chain.p7b": true, "a_b": true,
		"": false, ".": false, "..": false, "x.": false, `a\b`: false, "a/b": false,
		"issued.cer:stream": false, "CON ": false, "é.cer": false,
		"NUL.cer": false, "nul": false, "CON": false, "com1.txt": false, "LPT9": false, "Aux.x.y": false,
		"prn.req": false, "COM0": false, "COM10.cer": true, "console.cer": true, "nul2": true, "lpt.cer": true,
	} {
		if validFileName(name) != ok {
			t.Errorf("file name %q: want %t", name, ok)
		}
	}
}
