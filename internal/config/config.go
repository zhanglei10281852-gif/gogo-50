package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Multiline struct {
	Enabled       bool   `json:"enabled"`
	StartPattern  string `json:"start_pattern"`
	ContinueSpace bool   `json:"continue_space"`
	MaxLines      int    `json:"max_lines"`
}

type Input struct {
	Name             string            `json:"name"`
	Path             string            `json:"path"`
	Format           string            `json:"format"`
	Source           string            `json:"source"`
	TimeField        string            `json:"time_field"`
	LevelField       string            `json:"level_field"`
	SourceField      string            `json:"source_field"`
	MessageField     string            `json:"message_field"`
	TimestampLayouts []string          `json:"timestamp_layouts"`
	CSVColumns       []string          `json:"csv_columns"`
	StaticFields     map[string]string `json:"static_fields"`
	Multiline        Multiline         `json:"multiline"`
}

type Predicate struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"`
	Value  string   `json:"value"`
	Values []string `json:"values"`
	Negate bool     `json:"negate"`
}

type Rule struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Enabled      bool              `json:"enabled"`
	Severity     string            `json:"severity"`
	All          []Predicate       `json:"all"`
	Any          []Predicate       `json:"any"`
	GroupBy      []string          `json:"group_by"`
	Threshold    int               `json:"threshold"`
	Window       string            `json:"window"`
	Cooldown     string            `json:"cooldown"`
	ResolveAfter string            `json:"resolve_after"`
	Labels       map[string]string `json:"labels"`
}

type Retention struct {
	EventDays             int  `json:"event_days"`
	IncidentDays          int  `json:"incident_days"`
	Deduplicate           bool `json:"deduplicate"`
	SnapshotBeforeCompact bool `json:"snapshot_before_compact"`
}

type Config struct {
	Version   int       `json:"version"`
	Store     string    `json:"store"`
	Inputs    []Input   `json:"inputs"`
	Rules     []Rule    `json:"rules"`
	Retention Retention `json:"retention"`
}

func Default() Config {
	return Config{
		Version:   1,
		Store:     "./logpilot-data",
		Retention: Retention{EventDays: 30, IncidentDays: 90, Deduplicate: true, SnapshotBeforeCompact: true},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	if decoder.More() {
		return cfg, errors.New("decode config: multiple JSON values")
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return cfg, errors.New("decode config: trailing JSON value")
	}
	if err := cfg.Normalize(filepath.Dir(path)); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) Normalize(base string) error {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if c.Store == "" {
		return errors.New("store is required")
	}
	if !filepath.IsAbs(c.Store) {
		c.Store = filepath.Clean(filepath.Join(base, c.Store))
	}
	seenInputs := map[string]bool{}
	for i := range c.Inputs {
		input := &c.Inputs[i]
		input.Name = strings.TrimSpace(input.Name)
		if input.Name == "" {
			return fmt.Errorf("inputs[%d].name is required", i)
		}
		if seenInputs[input.Name] {
			return fmt.Errorf("duplicate input name %q", input.Name)
		}
		seenInputs[input.Name] = true
		input.Format = strings.ToLower(strings.TrimSpace(input.Format))
		switch input.Format {
		case "json", "jsonl", "csv":
		default:
			return fmt.Errorf("input %q has unsupported format %q", input.Name, input.Format)
		}
		if input.Path == "" {
			return fmt.Errorf("input %q path is required", input.Name)
		}
		if !filepath.IsAbs(input.Path) {
			input.Path = filepath.Clean(filepath.Join(base, input.Path))
		}
		if input.Source == "" {
			input.Source = input.Name
		}
		if input.TimeField == "" {
			input.TimeField = "timestamp"
		}
		if input.LevelField == "" {
			input.LevelField = "level"
		}
		if input.SourceField == "" {
			input.SourceField = "source"
		}
		if input.MessageField == "" {
			input.MessageField = "message"
		}
		if len(input.TimestampLayouts) == 0 {
			input.TimestampLayouts = []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05"}
		}
		if input.Multiline.MaxLines == 0 {
			input.Multiline.MaxLines = 100
		}
		if input.Multiline.MaxLines < 1 || input.Multiline.MaxLines > 10000 {
			return fmt.Errorf("input %q multiline.max_lines out of range", input.Name)
		}
		if input.Format == "csv" && len(input.CSVColumns) > 0 {
			columns := map[string]bool{}
			for _, column := range input.CSVColumns {
				if column == "" || columns[column] {
					return fmt.Errorf("input %q has invalid CSV columns", input.Name)
				}
				columns[column] = true
			}
		}
	}
	seenRules := map[string]bool{}
	for i := range c.Rules {
		rule := &c.Rules[i]
		rule.ID = strings.TrimSpace(rule.ID)
		if rule.ID == "" {
			return fmt.Errorf("rules[%d].id is required", i)
		}
		if seenRules[rule.ID] {
			return fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		seenRules[rule.ID] = true
		if rule.Title == "" {
			rule.Title = rule.ID
		}
		if rule.Severity == "" {
			rule.Severity = "ERROR"
		}
		if rule.Threshold == 0 {
			rule.Threshold = 1
		}
		if rule.Threshold < 1 {
			return fmt.Errorf("rule %q threshold must be positive", rule.ID)
		}
		if rule.Window == "" {
			rule.Window = "5m"
		}
		if _, err := time.ParseDuration(rule.Window); err != nil {
			return fmt.Errorf("rule %q window: %w", rule.ID, err)
		}
		if rule.Cooldown == "" {
			rule.Cooldown = "5m"
		}
		if _, err := time.ParseDuration(rule.Cooldown); err != nil {
			return fmt.Errorf("rule %q cooldown: %w", rule.ID, err)
		}
		if rule.ResolveAfter == "" {
			rule.ResolveAfter = "30m"
		}
		if _, err := time.ParseDuration(rule.ResolveAfter); err != nil {
			return fmt.Errorf("rule %q resolve_after: %w", rule.ID, err)
		}
		for j, predicate := range append(append([]Predicate{}, rule.All...), rule.Any...) {
			if err := validatePredicate(predicate); err != nil {
				return fmt.Errorf("rule %q predicate %d: %w", rule.ID, j, err)
			}
		}
	}
	if c.Retention.EventDays == 0 {
		c.Retention.EventDays = 30
	}
	if c.Retention.IncidentDays == 0 {
		c.Retention.IncidentDays = 90
	}
	if c.Retention.EventDays < 0 || c.Retention.IncidentDays < 0 {
		return errors.New("retention days cannot be negative")
	}
	return nil
}

func validatePredicate(p Predicate) error {
	if strings.TrimSpace(p.Field) == "" {
		return errors.New("field is required")
	}
	switch strings.ToLower(p.Op) {
	case "eq", "ne", "contains", "prefix", "suffix", "regex", "gt", "gte", "lt", "lte", "exists", "in":
	default:
		return fmt.Errorf("unsupported operation %q", p.Op)
	}
	if strings.EqualFold(p.Op, "regex") {
		if _, err := regexpCompile(p.Value); err != nil {
			return err
		}
	}
	if strings.EqualFold(p.Op, "in") && len(p.Values) == 0 {
		return errors.New("in operation requires values")
	}
	return nil
}

func regexpCompile(value string) (any, error) {
	if value == "" {
		return nil, errors.New("regular expression cannot be empty")
	}
	return regexp.Compile(value)
}

func Save(path string, cfg Config) error {
	copy := cfg
	base := filepath.Dir(path)
	if err := copy.Normalize(base); err != nil {
		return err
	}
	data, err := json.MarshalIndent(copy, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (c Config) Input(name string) (Input, bool) {
	for _, input := range c.Inputs {
		if input.Name == name {
			return input, true
		}
	}
	return Input{}, false
}

func (c Config) Rule(id string) (Rule, bool) {
	for _, rule := range c.Rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return Rule{}, false
}

func (c Config) EnabledRules() []Rule {
	var rules []Rule
	for _, rule := range c.Rules {
		if rule.Enabled {
			rules = append(rules, rule)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func (r Rule) WindowDuration() time.Duration { value, _ := time.ParseDuration(r.Window); return value }
func (r Rule) CooldownDuration() time.Duration {
	value, _ := time.ParseDuration(r.Cooldown)
	return value
}
func (r Rule) ResolveDuration() time.Duration {
	value, _ := time.ParseDuration(r.ResolveAfter)
	return value
}
