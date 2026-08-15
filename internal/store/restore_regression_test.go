package store

import (
	"testing"
	"time"

	"LogPilot/internal/model"
)

func TestRestoreSnapshotRebuildsIndexForRestoredEvents(t *testing.T) {
	backend := New(t.TempDir())
	if err := backend.Init(); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	old := model.NewEvent(base, model.LevelInfo, "api", "old", nil)
	old.IngestedAt = base
	if err := backend.SaveEvents([]model.Event{old}); err != nil {
		t.Fatal(err)
	}
	if err := backend.RebuildIndex(); err != nil {
		t.Fatal(err)
	}
	digest, err := backend.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.CreateSnapshot("before", digest); err != nil {
		t.Fatal(err)
	}
	newer := model.NewEvent(base.Add(time.Minute), model.LevelError, "api", "new", nil)
	newer.IngestedAt = base.Add(time.Minute)
	if err := backend.SaveEvents([]model.Event{old, newer}); err != nil {
		t.Fatal(err)
	}
	if err := backend.RebuildIndex(); err != nil {
		t.Fatal(err)
	}
	if err := backend.RestoreSnapshot("before"); err != nil {
		t.Fatal(err)
	}
	if err := backend.ValidateIndex(); err != nil {
		t.Fatalf("restored snapshot left an index from the newer store state: %v", err)
	}
}
