package query

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"LogPilot/internal/model"
)

type Filter struct {
	From        time.Time
	To          time.Time
	MinLevel    model.Level
	HasMinLevel bool
	Sources     []string
	Contains    string
	Fields      map[string]string
	IncidentID  string
	Limit       int
	Offset      int
	Descending  bool
}

func Parse(args []string) (Filter, error) {
	f := Filter{Limit: 100, Fields: map[string]string{}}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return f, fmt.Errorf("query term %q must be key=value", arg)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "from":
			t, err := parseTime(value)
			if err != nil {
				return f, fmt.Errorf("from: %w", err)
			}
			f.From = t
		case "to":
			t, err := parseTime(value)
			if err != nil {
				return f, fmt.Errorf("to: %w", err)
			}
			f.To = t
		case "level", "min_level":
			level, err := model.ParseLevel(value)
			if err != nil {
				return f, err
			}
			f.MinLevel, f.HasMinLevel = level, true
		case "source", "sources":
			for _, source := range strings.Split(value, ",") {
				source = model.NormalizeSource(source)
				if source != "" {
					f.Sources = append(f.Sources, source)
				}
			}
		case "contains":
			f.Contains = strings.ToLower(value)
		case "incident":
			f.IncidentID = value
		case "limit":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 100000 {
				return f, fmt.Errorf("limit must be between 0 and 100000")
			}
			f.Limit = n
		case "offset":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return f, fmt.Errorf("offset must be non-negative")
			}
			f.Offset = n
		case "order":
			switch strings.ToLower(value) {
			case "asc":
				f.Descending = false
			case "desc":
				f.Descending = true
			default:
				return f, fmt.Errorf("order must be asc or desc")
			}
		default:
			if strings.HasPrefix(key, "field.") {
				name := strings.TrimPrefix(key, "field.")
				if name == "" {
					return f, fmt.Errorf("field name cannot be empty")
				}
				f.Fields[name] = value
			} else {
				return f, fmt.Errorf("unknown query key %q", key)
			}
		}
	}
	if !f.From.IsZero() && !f.To.IsZero() && f.To.Before(f.From) {
		return f, fmt.Errorf("to precedes from")
	}
	f.Sources = uniqueSorted(f.Sources)
	return f, nil
}

func parseTime(value string) (time.Time, error) {
	if duration, err := time.ParseDuration(value); err == nil && strings.HasPrefix(value, "-") {
		return time.Now().UTC().Add(duration), nil
	}
	layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02", "2006-01-02 15:04:05"}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time %q", value)
}

func (f Filter) Match(event model.Event) bool {
	if !f.From.IsZero() && event.Timestamp.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && event.Timestamp.After(f.To) {
		return false
	}
	if f.HasMinLevel && event.Level < f.MinLevel {
		return false
	}
	if len(f.Sources) > 0 && !contains(f.Sources, event.Source) {
		return false
	}
	if f.Contains != "" {
		haystack := strings.ToLower(event.Message + " " + event.Source)
		if !strings.Contains(haystack, f.Contains) {
			return false
		}
	}
	for key, expected := range f.Fields {
		actual, ok := event.Field(key)
		if !ok || actual != expected {
			return false
		}
	}
	return true
}

func Apply(events []model.Event, filter Filter) []model.Event {
	matched := make([]model.Event, 0)
	for _, event := range events {
		if filter.Match(event) {
			matched = append(matched, event.Clone())
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].Timestamp.Equal(matched[j].Timestamp) {
			if filter.Descending {
				return matched[i].ID > matched[j].ID
			}
			return matched[i].ID < matched[j].ID
		}
		if filter.Descending {
			return matched[i].Timestamp.After(matched[j].Timestamp)
		}
		return matched[i].Timestamp.Before(matched[j].Timestamp)
	})
	if filter.Offset >= len(matched) {
		return []model.Event{}
	}
	matched = matched[filter.Offset:]
	if filter.Limit > 0 && len(matched) > filter.Limit {
		matched = matched[:filter.Limit]
	}
	return matched
}

func Describe(f Filter) string {
	parts := []string{}
	if !f.From.IsZero() {
		parts = append(parts, "from="+f.From.UTC().Format(time.RFC3339Nano))
	}
	if !f.To.IsZero() {
		parts = append(parts, "to="+f.To.UTC().Format(time.RFC3339Nano))
	}
	if f.HasMinLevel {
		parts = append(parts, "level="+f.MinLevel.String())
	}
	if len(f.Sources) > 0 {
		parts = append(parts, "sources="+strings.Join(f.Sources, ","))
	}
	if f.Contains != "" {
		parts = append(parts, "contains="+strconv.Quote(f.Contains))
	}
	keys := make([]string, 0, len(f.Fields))
	for key := range f.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, "field."+key+"="+strconv.Quote(f.Fields[key]))
	}
	parts = append(parts, fmt.Sprintf("offset=%d", f.Offset), fmt.Sprintf("limit=%d", f.Limit))
	if f.Descending {
		parts = append(parts, "order=desc")
	} else {
		parts = append(parts, "order=asc")
	}
	return strings.Join(parts, " ")
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func contains(values []string, value string) bool {
	index := sort.SearchStrings(values, value)
	return index < len(values) && values[index] == value
}
