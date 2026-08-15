package store

import (
	"testing"
	"time"

	"LogPilot/internal/model"
	"LogPilot/internal/query"
)

func TestStoreQueryIndexAndSnapshot(t *testing.T) {
	backend := New(t.TempDir())
	if err := backend.Init(); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	events := []model.Event{
		model.NewEvent(base, model.LevelInfo, "api", "ready", nil),
		model.NewEvent(base.Add(time.Minute), model.LevelError, "worker", "failed", map[string]string{"job": "42"}),
	}
	for i := range events {
		events[i].IngestedAt = base
	}
	if err := backend.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	if err := backend.RebuildIndex(); err != nil {
		t.Fatal(err)
	}
	if err := backend.ValidateIndex(); err != nil {
		t.Fatal(err)
	}
	result, err := backend.Query(query.Filter{MinLevel: model.LevelError, HasMinLevel: true, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched != 1 || result.Events[0].Source != "worker" {
		t.Fatalf("unexpected query: %+v", result)
	}
	digest, err := backend.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.CreateSnapshot("before", digest); err != nil {
		t.Fatal(err)
	}
}
