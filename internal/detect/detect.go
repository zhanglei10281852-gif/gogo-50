package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"LogPilot/internal/config"
	"LogPilot/internal/model"
)

type Evaluation struct {
	Rule       string `json:"rule"`
	Examined   int    `json:"examined"`
	Matched    int    `json:"matched"`
	Triggered  int    `json:"triggered"`
	Suppressed int    `json:"suppressed"`
}

type Result struct {
	Incidents   []model.Incident `json:"incidents"`
	Evaluations []Evaluation     `json:"evaluations"`
}

type Engine struct {
	Rules []config.Rule
	Now   func() time.Time
}

type windowKey struct {
	Rule  string
	Group string
}

type bucket struct {
	Events        []model.Event
	LastTriggered time.Time
}

func New(rules []config.Rule) *Engine {
	return &Engine{Rules: append([]config.Rule(nil), rules...), Now: time.Now}
}

func (e *Engine) Detect(events []model.Event, existing []model.Incident) (Result, error) {
	ordered := make([]model.Event, len(events))
	copy(ordered, events)
	model.SortEvents(ordered)
	result := Result{}
	buckets := map[windowKey]*bucket{}
	for _, rule := range e.Rules {
		evaluation := Evaluation{Rule: rule.ID}
		if !rule.Enabled {
			result.Evaluations = append(result.Evaluations, evaluation)
			continue
		}
		window, err := time.ParseDuration(rule.Window)
		if err != nil {
			return result, fmt.Errorf("rule %s window: %w", rule.ID, err)
		}
		cooldown, err := time.ParseDuration(rule.Cooldown)
		if err != nil {
			return result, fmt.Errorf("rule %s cooldown: %w", rule.ID, err)
		}
		for _, event := range ordered {
			evaluation.Examined++
			matches, err := matchRule(rule, event)
			if err != nil {
				return result, fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			if !matches {
				continue
			}
			evaluation.Matched++
			group := groupValue(rule.GroupBy, event)
			key := windowKey{Rule: rule.ID, Group: group}
			current := buckets[key]
			if current == nil {
				current = &bucket{}
				buckets[key] = current
			}
			cutoff := event.Timestamp.Add(-window)
			kept := current.Events[:0]
			for _, candidate := range current.Events {
				if !candidate.Timestamp.Before(cutoff) {
					kept = append(kept, candidate)
				}
			}
			current.Events = append(kept, event)
			if len(current.Events) < rule.Threshold {
				continue
			}
			if !current.LastTriggered.IsZero() && event.Timestamp.Sub(current.LastTriggered) < cooldown {
				evaluation.Suppressed++
				continue
			}
			incident, err := createIncident(rule, group, current.Events, e.Now().UTC())
			if err != nil {
				return result, err
			}
			result.Incidents = append(result.Incidents, incident)
			current.LastTriggered = event.Timestamp
			evaluation.Triggered++
		}
		result.Evaluations = append(result.Evaluations, evaluation)
	}
	result.Incidents = reconcile(existing, result.Incidents, e.Rules, e.Now().UTC())
	model.SortIncidents(result.Incidents)
	sort.Slice(result.Evaluations, func(i, j int) bool { return result.Evaluations[i].Rule < result.Evaluations[j].Rule })
	return result, nil
}

func matchRule(rule config.Rule, event model.Event) (bool, error) {
	for _, predicate := range rule.All {
		matched, err := matchPredicate(predicate, event)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}
	if len(rule.Any) == 0 {
		return true, nil
	}
	for _, predicate := range rule.Any {
		matched, err := matchPredicate(predicate, event)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func matchPredicate(predicate config.Predicate, event model.Event) (bool, error) {
	actual, exists := event.Field(predicate.Field)
	operation := strings.ToLower(predicate.Op)
	matched := false
	switch operation {
	case "exists":
		expected := !strings.EqualFold(predicate.Value, "false")
		matched = exists == expected
	case "eq":
		matched = exists && strings.EqualFold(actual, predicate.Value)
	case "ne":
		matched = !exists || !strings.EqualFold(actual, predicate.Value)
	case "contains":
		matched = exists && strings.Contains(strings.ToLower(actual), strings.ToLower(predicate.Value))
	case "prefix":
		matched = exists && strings.HasPrefix(strings.ToLower(actual), strings.ToLower(predicate.Value))
	case "suffix":
		matched = exists && strings.HasSuffix(strings.ToLower(actual), strings.ToLower(predicate.Value))
	case "regex":
		expression, err := regexp.Compile(predicate.Value)
		if err != nil {
			return false, err
		}
		matched = exists && expression.MatchString(actual)
	case "in":
		for _, expected := range predicate.Values {
			if strings.EqualFold(actual, expected) {
				matched = exists
				break
			}
		}
	case "gt", "gte", "lt", "lte":
		if !exists {
			matched = false
			break
		}
		comparison, err := compareField(predicate.Field, actual, predicate.Value)
		if err != nil {
			return false, fmt.Errorf("field %s: %w", predicate.Field, err)
		}
		switch operation {
		case "gt":
			matched = comparison > 0
		case "gte":
			matched = comparison >= 0
		case "lt":
			matched = comparison < 0
		case "lte":
			matched = comparison <= 0
		}
	default:
		return false, fmt.Errorf("unsupported operation %q", predicate.Op)
	}
	if predicate.Negate {
		matched = !matched
	}
	return matched, nil
}

func compareField(field, actual, expected string) (int, error) {
	if strings.EqualFold(field, "level") {
		left, err := model.ParseLevel(actual)
		if err != nil {
			return 0, err
		}
		right, err := model.ParseLevel(expected)
		if err != nil {
			return 0, err
		}
		if left < right {
			return -1, nil
		}
		if left > right {
			return 1, nil
		}
		return 0, nil
	}
	return compare(actual, expected)
}

func compare(actual, expected string) (int, error) {
	left, leftErr := strconv.ParseFloat(actual, 64)
	right, rightErr := strconv.ParseFloat(expected, 64)
	if leftErr == nil && rightErr == nil {
		if left < right {
			return -1, nil
		}
		if left > right {
			return 1, nil
		}
		return 0, nil
	}
	leftTime, leftErr := time.Parse(time.RFC3339Nano, actual)
	rightTime, rightErr := time.Parse(time.RFC3339Nano, expected)
	if leftErr == nil && rightErr == nil {
		if leftTime.Before(rightTime) {
			return -1, nil
		}
		if leftTime.After(rightTime) {
			return 1, nil
		}
		return 0, nil
	}
	return strings.Compare(actual, expected), nil
}

func groupValue(fields []string, event model.Event) string {
	if len(fields) == 0 {
		return "all"
	}
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		value, exists := event.Field(field)
		if !exists {
			value = "<missing>"
		}
		parts = append(parts, field+"="+value)
	}
	return strings.Join(parts, "|")
}

func createIncident(rule config.Rule, group string, events []model.Event, now time.Time) (model.Incident, error) {
	if len(events) == 0 {
		return model.Incident{}, fmt.Errorf("cannot create incident without events")
	}
	severity, err := model.ParseLevel(rule.Severity)
	if err != nil {
		return model.Incident{}, err
	}
	first, last := events[0].Timestamp, events[0].Timestamp
	ids := make([]string, 0, len(events))
	fingerprints := make([]string, 0, len(events))
	seen := map[string]bool{}
	for _, event := range events {
		if event.Timestamp.Before(first) {
			first = event.Timestamp
		}
		if event.Timestamp.After(last) {
			last = event.Timestamp
		}
		if !seen[event.ID] {
			ids = append(ids, event.ID)
			seen[event.ID] = true
		}
		fingerprints = append(fingerprints, event.Fingerprint)
	}
	sort.Strings(ids)
	sort.Strings(fingerprints)
	fingerprint := incidentFingerprint(rule.ID, group, fingerprints)
	incident := model.Incident{
		ID: model.StableID("incident", rule.ID, group, first.UTC().Format(time.RFC3339Nano)), RuleID: rule.ID, Title: rule.Title,
		Status: model.IncidentOpen, Severity: severity, Group: group, Fingerprint: fingerprint,
		FirstSeen: first, LastSeen: last, OpenedAt: now, UpdatedAt: now, Count: len(events), EventIDs: ids, Labels: cloneLabels(rule.Labels),
		History: []model.Transition{{At: now, To: model.IncidentOpen, Reason: fmt.Sprintf("threshold %d reached in %s", rule.Threshold, rule.Window)}},
	}
	return incident, incident.Validate()
}

func reconcile(existing, detected []model.Incident, rules []config.Rule, now time.Time) []model.Incident {
	byKey := make(map[string]int)
	result := make([]model.Incident, len(existing))
	for i, incident := range existing {
		result[i] = incident.Clone()
		byKey[incident.RuleID+"\x00"+incident.Group] = i
	}
	active := map[string]bool{}
	for _, incident := range detected {
		key := incident.RuleID + "\x00" + incident.Group
		active[key] = true
		if index, ok := byKey[key]; ok {
			result[index].Merge(incident, now)
		} else {
			byKey[key] = len(result)
			result = append(result, incident.Clone())
		}
	}
	resolve := map[string]time.Duration{}
	for _, rule := range rules {
		resolve[rule.ID] = rule.ResolveDuration()
	}
	for index := range result {
		incident := &result[index]
		key := incident.RuleID + "\x00" + incident.Group
		if active[key] || incident.Status == model.IncidentResolved {
			continue
		}
		duration := resolve[incident.RuleID]
		if duration > 0 && now.Sub(incident.LastSeen) >= duration {
			_ = incident.TransitionTo(model.IncidentResolved, now, "no matching activity during resolve interval")
		}
	}
	return result
}

func incidentFingerprint(rule, group string, fingerprints []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00", rule, group)
	for _, fingerprint := range fingerprints {
		fmt.Fprintf(h, "%s\n", fingerprint)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	copy := make(map[string]string, len(labels))
	for key, value := range labels {
		copy[key] = value
	}
	return copy
}
