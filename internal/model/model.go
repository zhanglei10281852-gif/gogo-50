package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Level int

const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

var levelNames = [...]string{"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"}

func (l Level) String() string {
	if int(l) < 0 || int(l) >= len(levelNames) {
		return "UNKNOWN"
	}
	return levelNames[l]
}

func ParseLevel(value string) (Level, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "TRACE", "VERBOSE":
		return LevelTrace, nil
	case "DEBUG":
		return LevelDebug, nil
	case "INFO", "INFORMATION", "NOTICE":
		return LevelInfo, nil
	case "WARN", "WARNING":
		return LevelWarn, nil
	case "ERROR", "ERR", "SEVERE":
		return LevelError, nil
	case "FATAL", "CRITICAL", "CRIT", "PANIC":
		return LevelFatal, nil
	default:
		return LevelInfo, fmt.Errorf("unknown level %q", value)
	}
}

func (l Level) MarshalJSON() ([]byte, error) { return json.Marshal(l.String()) }

func (l *Level) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		parsed, err := ParseLevel(text)
		if err != nil {
			return err
		}
		*l = parsed
		return nil
	}
	var number int
	if err := json.Unmarshal(data, &number); err != nil {
		return fmt.Errorf("level: %w", err)
	}
	if number < int(LevelTrace) || number > int(LevelFatal) {
		return fmt.Errorf("level value %d out of range", number)
	}
	*l = Level(number)
	return nil
}

type Event struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	Level       Level             `json:"level"`
	Source      string            `json:"source"`
	Message     string            `json:"message"`
	Fields      map[string]string `json:"fields,omitempty"`
	Fingerprint string            `json:"fingerprint"`
	Input       string            `json:"input,omitempty"`
	Line        int               `json:"line,omitempty"`
	IngestedAt  time.Time         `json:"ingested_at"`
}

func (e Event) Validate() error {
	if e.ID == "" {
		return fmt.Errorf("event id is required")
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("event timestamp is required")
	}
	if strings.TrimSpace(e.Source) == "" {
		return fmt.Errorf("event source is required")
	}
	if strings.TrimSpace(e.Message) == "" {
		return fmt.Errorf("event message is required")
	}
	if e.Fingerprint == "" {
		return fmt.Errorf("event fingerprint is required")
	}
	if e.Level < LevelTrace || e.Level > LevelFatal {
		return fmt.Errorf("event level is invalid")
	}
	return nil
}

func (e Event) Field(name string) (string, bool) {
	switch strings.ToLower(name) {
	case "id":
		return e.ID, true
	case "timestamp", "time":
		return e.Timestamp.UTC().Format(time.RFC3339Nano), true
	case "level":
		return e.Level.String(), true
	case "source":
		return e.Source, true
	case "message":
		return e.Message, true
	case "fingerprint":
		return e.Fingerprint, true
	case "input":
		return e.Input, e.Input != ""
	case "line":
		return strconv.Itoa(e.Line), e.Line != 0
	default:
		value, ok := e.Fields[name]
		if ok {
			return value, true
		}
		for key, value := range e.Fields {
			if strings.EqualFold(key, name) {
				return value, true
			}
		}
		return "", false
	}
}

func (e Event) Clone() Event {
	clone := e
	clone.Fields = cloneStrings(e.Fields)
	return clone
}

func NewEvent(timestamp time.Time, level Level, source, message string, fields map[string]string) Event {
	e := Event{Timestamp: timestamp.UTC(), Level: level, Source: NormalizeSource(source), Message: NormalizeMessage(message), Fields: cloneStrings(fields)}
	e.Fingerprint = EventFingerprint(e)
	e.ID = StableID("event", e.Timestamp.Format(time.RFC3339Nano), e.Source, e.Level.String(), e.Fingerprint)
	return e
}

func NormalizeSource(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func NormalizeMessage(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	lines := strings.Split(value, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t")
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func EventFingerprint(e Event) string {
	parts := []string{e.Source, e.Level.String(), canonicalMessage(e.Message)}
	keys := make([]string, 0, len(e.Fields))
	for key := range e.Fields {
		if strings.HasPrefix(strings.ToLower(key), "volatile.") {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key+"="+e.Fields[key])
	}
	return HashStrings(parts...)
}

func canonicalMessage(value string) string {
	fields := strings.Fields(strings.ToLower(value))
	for i, field := range fields {
		if _, err := strconv.ParseInt(strings.Trim(field, "[](),;:"), 10, 64); err == nil {
			fields[i] = "#"
		}
	}
	return strings.Join(fields, " ")
}

func StableID(namespace string, parts ...string) string {
	all := append([]string{namespace}, parts...)
	return HashStrings(all...)[:24]
}

func HashStrings(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(strconv.Itoa(len(part))))
		h.Write([]byte{':'})
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type IncidentStatus string

const (
	IncidentOpen         IncidentStatus = "open"
	IncidentAcknowledged IncidentStatus = "acknowledged"
	IncidentResolved     IncidentStatus = "resolved"
)

type Incident struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id"`
	Title       string            `json:"title"`
	Status      IncidentStatus    `json:"status"`
	Severity    Level             `json:"severity"`
	Group       string            `json:"group"`
	Fingerprint string            `json:"fingerprint"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	OpenedAt    time.Time         `json:"opened_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	ResolvedAt  *time.Time        `json:"resolved_at,omitempty"`
	Count       int               `json:"count"`
	EventIDs    []string          `json:"event_ids"`
	Labels      map[string]string `json:"labels,omitempty"`
	History     []Transition      `json:"history"`
}

type Transition struct {
	At     time.Time      `json:"at"`
	From   IncidentStatus `json:"from,omitempty"`
	To     IncidentStatus `json:"to"`
	Reason string         `json:"reason"`
}

func (i Incident) Validate() error {
	if i.ID == "" || i.RuleID == "" {
		return fmt.Errorf("incident id and rule id are required")
	}
	if i.Status != IncidentOpen && i.Status != IncidentAcknowledged && i.Status != IncidentResolved {
		return fmt.Errorf("invalid incident status %q", i.Status)
	}
	if i.FirstSeen.IsZero() || i.LastSeen.IsZero() {
		return fmt.Errorf("incident time range is required")
	}
	if i.LastSeen.Before(i.FirstSeen) {
		return fmt.Errorf("incident last_seen precedes first_seen")
	}
	if i.Count < 1 {
		return fmt.Errorf("incident count must be positive")
	}
	if i.Status == IncidentResolved && i.ResolvedAt == nil {
		return fmt.Errorf("resolved incident lacks resolved_at")
	}
	return nil
}

func (i Incident) Clone() Incident {
	clone := i
	clone.EventIDs = append([]string(nil), i.EventIDs...)
	clone.Labels = cloneStrings(i.Labels)
	clone.History = append([]Transition(nil), i.History...)
	if i.ResolvedAt != nil {
		value := *i.ResolvedAt
		clone.ResolvedAt = &value
	}
	return clone
}

func (i *Incident) TransitionTo(status IncidentStatus, at time.Time, reason string) error {
	if status != IncidentOpen && status != IncidentAcknowledged && status != IncidentResolved {
		return fmt.Errorf("invalid target status %q", status)
	}
	if at.Before(i.UpdatedAt) {
		return fmt.Errorf("transition time precedes current update")
	}
	if i.Status == IncidentResolved && status == IncidentAcknowledged {
		return fmt.Errorf("cannot acknowledge a resolved incident")
	}
	from := i.Status
	if from == status {
		return nil
	}
	i.Status = status
	i.UpdatedAt = at.UTC()
	if status == IncidentResolved {
		resolved := at.UTC()
		i.ResolvedAt = &resolved
	}
	if status == IncidentOpen {
		i.ResolvedAt = nil
	}
	i.History = append(i.History, Transition{At: at.UTC(), From: from, To: status, Reason: reason})
	return nil
}

func (i *Incident) Merge(other Incident, at time.Time) {
	if other.FirstSeen.Before(i.FirstSeen) {
		i.FirstSeen = other.FirstSeen
	}
	if other.LastSeen.After(i.LastSeen) {
		i.LastSeen = other.LastSeen
	}
	i.Count += other.Count
	ids := make(map[string]bool, len(i.EventIDs)+len(other.EventIDs))
	for _, id := range i.EventIDs {
		ids[id] = true
	}
	for _, id := range other.EventIDs {
		if !ids[id] {
			i.EventIDs = append(i.EventIDs, id)
			ids[id] = true
		}
	}
	sort.Strings(i.EventIDs)
	if i.Status == IncidentResolved {
		_ = i.TransitionTo(IncidentOpen, at, "matching activity resumed")
	}
	i.UpdatedAt = at.UTC()
}

func SortEvents(events []Event) {
	sort.SliceStable(events, func(a, b int) bool {
		if events[a].Timestamp.Equal(events[b].Timestamp) {
			return events[a].ID < events[b].ID
		}
		return events[a].Timestamp.Before(events[b].Timestamp)
	})
}

func SortIncidents(items []Incident) {
	sort.SliceStable(items, func(a, b int) bool {
		if items[a].FirstSeen.Equal(items[b].FirstSeen) {
			return items[a].ID < items[b].ID
		}
		return items[a].FirstSeen.Before(items[b].FirstSeen)
	})
}

func cloneStrings(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
