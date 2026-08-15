package detect

import (
	"testing"
	"time"

	"LogPilot/internal/config"
	"LogPilot/internal/model"
)

func TestThresholdGroupingAndResolution(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	rule := config.Rule{ID: "errors", Title: "Repeated errors", Enabled: true, Severity: "ERROR", All: []config.Predicate{{Field: "level", Op: "gte", Value: "ERROR"}}, GroupBy: []string{"source"}, Threshold: 2, Window: "5m", Cooldown: "10m", ResolveAfter: "30m"}
	events := []model.Event{
		model.NewEvent(base.Add(-time.Minute), model.LevelInfo, "api", "healthy", nil),
		model.NewEvent(base, model.LevelError, "api", "failed one", nil),
		model.NewEvent(base.Add(time.Minute), model.LevelError, "api", "failed two", nil),
	}
	engine := New([]config.Rule{rule})
	engine.Now = func() time.Time { return base.Add(2 * time.Minute) }
	result, err := engine.Detect(events, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Incidents) != 1 || result.Incidents[0].Count != 2 {
		t.Fatalf("unexpected detection: %+v", result)
	}
	engine.Now = func() time.Time { return base.Add(time.Hour) }
	resolved, err := engine.Detect(nil, result.Incidents)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Incidents[0].Status != model.IncidentResolved {
		t.Fatalf("incident did not resolve")
	}
}
