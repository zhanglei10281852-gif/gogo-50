package validate

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"LogPilot/internal/config"
)

type Finding struct {
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

type Result struct {
	Valid    bool      `json:"valid"`
	Errors   int       `json:"errors"`
	Warnings int       `json:"warnings"`
	Findings []Finding `json:"findings"`
}

func Config(cfg config.Config, checkFiles bool) Result {
	var findings []Finding
	add := func(severity, path, message string) {
		findings = append(findings, Finding{Severity: severity, Path: path, Message: message})
	}
	if strings.TrimSpace(cfg.Store) == "" {
		add("error", "store", "store path is required")
	}
	inputNames := map[string]bool{}
	for i, input := range cfg.Inputs {
		base := fmt.Sprintf("inputs[%d]", i)
		if input.Name == "" {
			add("error", base+".name", "name is required")
		}
		if inputNames[input.Name] {
			add("error", base+".name", "name must be unique")
		}
		inputNames[input.Name] = true
		switch input.Format {
		case "json", "jsonl", "csv":
		default:
			add("error", base+".format", "format must be json, jsonl, or csv")
		}
		if input.Path == "" {
			add("error", base+".path", "path is required")
		}
		if checkFiles {
			if info, err := os.Stat(input.Path); err != nil {
				add("error", base+".path", err.Error())
			} else if info.IsDir() {
				add("error", base+".path", "path is a directory")
			}
		}
		if input.Multiline.StartPattern != "" {
			if _, err := regexp.Compile(input.Multiline.StartPattern); err != nil {
				add("error", base+".multiline.start_pattern", err.Error())
			}
		}
		if input.Multiline.MaxLines < 1 {
			add("error", base+".multiline.max_lines", "must be positive")
		}
		if input.Format == "csv" && input.Multiline.Enabled {
			add("warning", base+".multiline", "multiline options do not apply to CSV")
		}
	}
	ruleIDs := map[string]bool{}
	for i, rule := range cfg.Rules {
		base := fmt.Sprintf("rules[%d]", i)
		if rule.ID == "" {
			add("error", base+".id", "id is required")
		}
		if ruleIDs[rule.ID] {
			add("error", base+".id", "id must be unique")
		}
		ruleIDs[rule.ID] = true
		if rule.Threshold < 1 {
			add("error", base+".threshold", "must be positive")
		}
		if len(rule.All) == 0 && len(rule.Any) == 0 {
			add("warning", base, "rule matches every event")
		}
		for j, predicate := range append(append([]config.Predicate{}, rule.All...), rule.Any...) {
			path := fmt.Sprintf("%s.predicates[%d]", base, j)
			if predicate.Field == "" {
				add("error", path+".field", "field is required")
			}
			switch strings.ToLower(predicate.Op) {
			case "eq", "ne", "contains", "prefix", "suffix", "gt", "gte", "lt", "lte", "exists", "in":
			case "regex":
				if _, err := regexp.Compile(predicate.Value); err != nil {
					add("error", path+".value", err.Error())
				}
			default:
				add("error", path+".op", "unsupported predicate operation")
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path == findings[j].Path {
			return findings[i].Message < findings[j].Message
		}
		return findings[i].Path < findings[j].Path
	})
	result := Result{Findings: findings}
	for _, finding := range findings {
		if finding.Severity == "error" {
			result.Errors++
		} else {
			result.Warnings++
		}
	}
	result.Valid = result.Errors == 0
	return result
}

func (r Result) Error() string {
	if r.Valid {
		return ""
	}
	parts := make([]string, 0, r.Errors)
	for _, finding := range r.Findings {
		if finding.Severity == "error" {
			parts = append(parts, finding.Path+": "+finding.Message)
		}
	}
	return strings.Join(parts, "; ")
}
