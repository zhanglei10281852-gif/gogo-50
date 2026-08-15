package model

import (
	"testing"
	"time"
)

func TestEventNormalizationAndFingerprint(t *testing.T) {
	timestamp := time.Date(2025, 1, 2, 3, 4, 5, 0, time.FixedZone("west", -5*3600))
	first := NewEvent(timestamp, LevelError, " API Gateway ", " request 123 failed \r\n retrying ", map[string]string{"region": "west"})
	second := NewEvent(timestamp.Add(time.Minute), LevelError, "api gateway", "request 456 failed\nretrying", map[string]string{"region": "west"})
	if first.Source != "api-gateway" {
		t.Fatalf("source = %q", first.Source)
	}
	if first.Message != "request 123 failed\n retrying" {
		t.Fatalf("message = %q", first.Message)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("numeric variants should deduplicate")
	}
	if first.Timestamp.Location() != time.UTC {
		t.Fatalf("timestamp was not normalized")
	}
	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestIncidentLifecycle(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	incident := Incident{ID: "i", RuleID: "r", Status: IncidentOpen, FirstSeen: now, LastSeen: now, Count: 1, UpdatedAt: now, Fingerprint: "f"}
	if err := incident.TransitionTo(IncidentAcknowledged, now.Add(time.Minute), "owned"); err != nil {
		t.Fatal(err)
	}
	if err := incident.TransitionTo(IncidentResolved, now.Add(2*time.Minute), "fixed"); err != nil {
		t.Fatal(err)
	}
	if incident.ResolvedAt == nil || incident.Status != IncidentResolved {
		t.Fatalf("not resolved: %+v", incident)
	}
}
