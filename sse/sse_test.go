package sse

import (
	"bytes"
	"testing"
)

func TestBrokerRoutesTypedEventsBySite(t *testing.T) {
	b := NewBroker()
	t.Cleanup(b.Close)
	_, siteA := b.Subscribe("site-a")
	_, siteB := b.Subscribe("site-b")
	want := Event{Name: EventTargetStatusChanged, Data: []byte(`{"site_id":"site-a","target_ids":["target"]}`)}
	b.Notify("site-a", want)

	select {
	case got := <-siteA:
		if got.Name != want.Name || !bytes.Equal(got.Data, want.Data) {
			t.Fatalf("event = %+v, want %+v", got, want)
		}
	default:
		t.Fatal("site-a did not receive target-status event")
	}
	select {
	case got := <-siteB:
		t.Fatalf("site-b received site-a event: %+v", got)
	default:
	}
}
