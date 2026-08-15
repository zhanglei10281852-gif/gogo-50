package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"LogPilot/internal/config"
	"LogPilot/internal/pipeline"
	"LogPilot/internal/query"
	"LogPilot/internal/report"
	"LogPilot/internal/store"
)

const version = "1.0.0"

type application struct {
	out io.Writer
	err io.Writer
	now func() time.Time
}

func main() {
	app := application{out: os.Stdout, err: os.Stderr, now: time.Now}
	if err := app.run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "logpilot:", err)
		os.Exit(1)
	}
}

func (a application) run(args []string) error {
	if len(args) == 0 {
		a.usage()
		return errors.New("command required")
	}
	command := args[0]
	rest := args[1:]
	switch command {
	case "validate":
		return a.validate(rest)
	case "ingest":
		return a.ingest(rest)
	case "query":
		return a.query(rest)
	case "detect":
		return a.detect(rest)
	case "compact":
		return a.compact(rest)
	case "verify":
		return a.verify(rest)
	case "report":
		return a.report(rest)
	case "version", "--version", "-version":
		fmt.Fprintln(a.out, version)
		return nil
	case "help", "--help", "-h":
		a.usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func (a application) validate(args []string) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(a.err)
	configPath := flags.String("config", "logpilot.json", "configuration file")
	checkFiles := flags.Bool("check-files", true, "check input files")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	result := validateConfig(cfg, *checkFiles)
	if *jsonOutput {
		return writeJSON(a.out, result)
	}
	if result.Valid {
		fmt.Fprintf(a.out, "valid: %d warning(s)\n", result.Warnings)
	} else {
		fmt.Fprintf(a.out, "invalid: %d error(s), %d warning(s)\n", result.Errors, result.Warnings)
	}
	for _, finding := range result.Findings {
		fmt.Fprintf(a.out, "%s %s: %s\n", strings.ToUpper(finding.Severity), finding.Path, finding.Message)
	}
	if !result.Valid {
		return errors.New("configuration validation failed")
	}
	return nil
}

func (a application) ingest(args []string) error {
	flags := flag.NewFlagSet("ingest", flag.ContinueOnError)
	flags.SetOutput(a.err)
	configPath := flags.String("config", "logpilot.json", "configuration file")
	inputNames := flags.String("inputs", "", "comma-separated input names")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, backend, err := loadBackend(*configPath)
	if err != nil {
		return err
	}
	_ = cfg
	result, err := backend.Ingest(splitList(*inputNames))
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(a.out, result)
	}
	fmt.Fprintf(a.out, "ingested=%d skipped=%d rejected=%d total=%d root=%s\n", result.Added, result.Skipped+result.Ingest.Stats.Duplicates, result.Ingest.Stats.Rejected, result.Total, result.RootDigest)
	return nil
}

func (a application) query(args []string) error {
	flags := flag.NewFlagSet("query", flag.ContinueOnError)
	flags.SetOutput(a.err)
	configPath := flags.String("config", "logpilot.json", "configuration file")
	format := flags.String("format", "text", "text, json, or csv")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	backend := store.New(cfg.Store)
	if err := backend.Init(); err != nil {
		return err
	}
	filter, err := query.Parse(flags.Args())
	if err != nil {
		return err
	}
	result, err := backend.Query(filter)
	if err != nil {
		return err
	}
	var data []byte
	switch strings.ToLower(*format) {
	case "text":
		data = report.EventText(result.Events)
	case "json":
		data, err = report.EventJSON(result.Events)
	case "csv":
		data = report.CSV(result.Events)
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
	if err != nil {
		return err
	}
	_, err = a.out.Write(data)
	return err
}

func (a application) detect(args []string) error {
	flags := flag.NewFlagSet("detect", flag.ContinueOnError)
	flags.SetOutput(a.err)
	configPath := flags.String("config", "logpilot.json", "configuration file")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	_, backend, err := loadBackend(*configPath)
	if err != nil {
		return err
	}
	result, err := backend.Detect()
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(a.out, result)
	}
	fmt.Fprintf(a.out, "incidents=%d open=%d resolved=%d root=%s\n", len(result.Detection.Incidents), result.Open, result.Resolved, result.RootDigest)
	for _, evaluation := range result.Detection.Evaluations {
		fmt.Fprintf(a.out, "rule=%s examined=%d matched=%d triggered=%d suppressed=%d\n", evaluation.Rule, evaluation.Examined, evaluation.Matched, evaluation.Triggered, evaluation.Suppressed)
	}
	return nil
}

func (a application) compact(args []string) error {
	flags := flag.NewFlagSet("compact", flag.ContinueOnError)
	flags.SetOutput(a.err)
	configPath := flags.String("config", "logpilot.json", "configuration file")
	snapshot := flags.String("snapshot", "", "snapshot name")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	_, backend, err := loadBackend(*configPath)
	if err != nil {
		return err
	}
	result, err := backend.Compact(*snapshot)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(a.out, result)
	}
	stats := result.Compaction.Stats
	fmt.Fprintf(a.out, "events=%d->%d incidents=%d->%d expired=%d duplicates=%d snapshot=%s root=%s\n", stats.BeforeEvents, stats.AfterEvents, stats.BeforeIncidents, stats.AfterIncidents, stats.ExpiredEvents, stats.DuplicateEvents, result.Snapshot.Name, result.RootDigest)
	return nil
}

func (a application) verify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(a.err)
	configPath := flags.String("config", "logpilot.json", "configuration file")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	_, backend, err := loadBackend(*configPath)
	if err != nil {
		return err
	}
	result := backend.Verify()
	if *jsonOutput {
		if err := writeJSON(a.out, result); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.out, "valid=%t manifest=%t audit=%t checked=%d root=%s\n", result.Valid, result.ManifestValid, result.AuditValid, result.Checked, result.RootDigest)
		for _, item := range result.Errors {
			fmt.Fprintln(a.out, "ERROR", item)
		}
	}
	if !result.Valid {
		return errors.New("integrity verification failed")
	}
	return nil
}

func (a application) report(args []string) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(a.err)
	configPath := flags.String("config", "logpilot.json", "configuration file")
	format := flags.String("format", "text", "text or json")
	title := flags.String("title", "LogPilot Report", "report title")
	bucketText := flags.String("bucket", "1h", "timeline bucket")
	top := flags.Int("top", 10, "top item count")
	output := flags.String("output", "", "output file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	bucket, err := report.ParseBucket(*bucketText)
	if err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	backend := store.New(cfg.Store)
	if err := backend.Init(); err != nil {
		return err
	}
	events, err := backend.LoadEvents()
	if err != nil {
		return err
	}
	incidents, err := backend.LoadIncidents()
	if err != nil {
		return err
	}
	summary := report.Build(events, incidents, report.Options{Bucket: bucket, Top: *top, Generated: a.now()})
	data, err := report.Render(summary, report.Options{Format: *format, Title: *title})
	if err != nil {
		return err
	}
	if *output == "" {
		_, err = a.out.Write(data)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		return err
	}
	return os.WriteFile(*output, data, 0o644)
}

func loadBackend(path string) (config.Config, *pipeline.Pipeline, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return cfg, nil, err
	}
	backend := pipeline.New(cfg)
	if err := backend.Initialize(); err != nil {
		return cfg, nil, err
	}
	return cfg, backend, nil
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}

func (a application) usage() {
	fmt.Fprintln(a.out, "LogPilot - offline log operations")
	fmt.Fprintln(a.out, "usage: logpilot <command> [options]")
	fmt.Fprintln(a.out, "commands: validate ingest query detect compact verify report version")
}

// Small adapters keep command handlers focused and make validation output stable.
type validationFinding struct{ Severity, Path, Message string }
type validationResult struct {
	Valid            bool
	Errors, Warnings int
	Findings         []validationFinding
}

func validateConfig(cfg config.Config, checkFiles bool) validationResult {
	result := validationResult{Valid: true}
	if cfg.Store == "" {
		result.Findings = append(result.Findings, validationFinding{"error", "store", "store is required"})
	}
	seenInputs := map[string]bool{}
	for i, input := range cfg.Inputs {
		path := fmt.Sprintf("inputs[%d]", i)
		if input.Name == "" {
			result.Findings = append(result.Findings, validationFinding{"error", path + ".name", "name is required"})
		}
		if seenInputs[input.Name] {
			result.Findings = append(result.Findings, validationFinding{"error", path + ".name", "duplicate name"})
		}
		seenInputs[input.Name] = true
		if checkFiles {
			if info, err := os.Stat(input.Path); err != nil {
				result.Findings = append(result.Findings, validationFinding{"error", path + ".path", err.Error()})
			} else if info.IsDir() {
				result.Findings = append(result.Findings, validationFinding{"error", path + ".path", "must be a file"})
			}
		}
	}
	for _, finding := range result.Findings {
		if finding.Severity == "error" {
			result.Errors++
		} else {
			result.Warnings++
		}
	}
	result.Valid = result.Errors == 0
	sort.Slice(result.Findings, func(i, j int) bool { return result.Findings[i].Path < result.Findings[j].Path })
	return result
}
