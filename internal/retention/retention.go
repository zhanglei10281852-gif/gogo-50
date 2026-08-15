package retention

import (
	"fmt"
	"sort"
	"time"

	"LogPilot/internal/config"
	"LogPilot/internal/model"
)

type Stats struct {
	BeforeEvents     int       `json:"before_events"`
	AfterEvents      int       `json:"after_events"`
	ExpiredEvents    int       `json:"expired_events"`
	DuplicateEvents  int       `json:"duplicate_events"`
	BeforeIncidents  int       `json:"before_incidents"`
	AfterIncidents   int       `json:"after_incidents"`
	ExpiredIncidents int       `json:"expired_incidents"`
	ClosedIncidents  int       `json:"closed_incidents"`
	Cutoff           time.Time `json:"cutoff"`
}

type Result struct {
	Events    []model.Event    `json:"events"`
	Incidents []model.Incident `json:"incidents"`
	Stats     Stats            `json:"stats"`
}

type Compactor struct {
	Policy config.Retention
	Now    func() time.Time
}

func New(policy config.Retention) *Compactor {
	return &Compactor{Policy: policy, Now: time.Now}
}

func (c *Compactor) Compact(events []model.Event, incidents []model.Incident) (Result, error) {
	if c.Policy.EventDays < 0 || c.Policy.IncidentDays < 0 {
		return Result{}, fmt.Errorf("retention days cannot be negative")
	}
	now := c.Now().UTC()
	eventCutoff := now.AddDate(0, 0, -c.Policy.EventDays)
	incidentCutoff := now.AddDate(0, 0, -c.Policy.IncidentDays)
	result := Result{}
	result.Stats.BeforeEvents = len(events)
	result.Stats.BeforeIncidents = len(incidents)
	result.Stats.Cutoff = eventCutoff
	seenID := map[string]bool{}
	seenFingerprint := map[string]bool{}
	orderedEvents := make([]model.Event, len(events))
	for i := range events {
		orderedEvents[i] = events[i].Clone()
	}
	model.SortEvents(orderedEvents)
	for _, event := range orderedEvents {
		if c.Policy.EventDays > 0 && event.Timestamp.Before(eventCutoff) {
			result.Stats.ExpiredEvents++
			continue
		}
		if seenID[event.ID] || c.Policy.Deduplicate && seenFingerprint[event.Fingerprint] {
			result.Stats.DuplicateEvents++
			continue
		}
		seenID[event.ID], seenFingerprint[event.Fingerprint] = true, true
		result.Events = append(result.Events, event)
	}
	available := map[string]bool{}
	for _, event := range result.Events {
		available[event.ID] = true
	}
	orderedIncidents := make([]model.Incident, len(incidents))
	for i := range incidents {
		orderedIncidents[i] = incidents[i].Clone()
	}
	model.SortIncidents(orderedIncidents)
	for _, incident := range orderedIncidents {
		if c.Policy.IncidentDays > 0 && incident.LastSeen.Before(incidentCutoff) {
			result.Stats.ExpiredIncidents++
			continue
		}
		ids := incident.EventIDs[:0]
		for _, id := range incident.EventIDs {
			if available[id] {
				ids = append(ids, id)
			}
		}
		incident.EventIDs = ids
		if incident.Status != model.IncidentResolved && c.Policy.EventDays > 0 && incident.LastSeen.Before(eventCutoff) {
			_ = incident.TransitionTo(model.IncidentResolved, now, "supporting events expired by retention")
			result.Stats.ClosedIncidents++
		}
		result.Incidents = append(result.Incidents, incident)
	}
	result.Stats.AfterEvents = len(result.Events)
	result.Stats.AfterIncidents = len(result.Incidents)
	return result, nil
}

func Estimate(events []model.Event, incidents []model.Incident, policy config.Retention, now time.Time) Stats {
	compactor := New(policy)
	compactor.Now = func() time.Time { return now }
	result, err := compactor.Compact(events, incidents)
	if err != nil {
		return Stats{BeforeEvents: len(events), BeforeIncidents: len(incidents)}
	}
	return result.Stats
}

func PartitionEvents(events []model.Event, cutoff time.Time) (keep, expire []model.Event) {
	for _, event := range events {
		if event.Timestamp.Before(cutoff) {
			expire = append(expire, event.Clone())
		} else {
			keep = append(keep, event.Clone())
		}
	}
	model.SortEvents(keep)
	model.SortEvents(expire)
	return keep, expire
}

func PartitionIncidents(incidents []model.Incident, cutoff time.Time) (keep, expire []model.Incident) {
	for _, incident := range incidents {
		if incident.LastSeen.Before(cutoff) {
			expire = append(expire, incident.Clone())
		} else {
			keep = append(keep, incident.Clone())
		}
	}
	model.SortIncidents(keep)
	model.SortIncidents(expire)
	return keep, expire
}

func MergeDuplicates(events []model.Event) ([]model.Event, int) {
	model.SortEvents(events)
	seen := map[string]bool{}
	result := make([]model.Event, 0, len(events))
	removed := 0
	for _, event := range events {
		key := event.Fingerprint
		if key == "" {
			key = event.ID
		}
		if seen[key] {
			removed++
			continue
		}
		seen[key] = true
		result = append(result, event.Clone())
	}
	return result, removed
}

func IncidentReferences(incidents []model.Incident) map[string][]string {
	references := map[string][]string{}
	for _, incident := range incidents {
		for _, id := range incident.EventIDs {
			references[id] = append(references[id], incident.ID)
		}
	}
	for id := range references {
		sort.Strings(references[id])
	}
	return references
}

func ValidateReferences(events []model.Event, incidents []model.Incident) []string {
	available := map[string]bool{}
	for _, event := range events {
		available[event.ID] = true
	}
	var missing []string
	for _, incident := range incidents {
		for _, id := range incident.EventIDs {
			if !available[id] {
				missing = append(missing, incident.ID+":"+id)
			}
		}
	}
	sort.Strings(missing)
	return missing
}
