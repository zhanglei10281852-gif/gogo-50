package ingest

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"LogPilot/internal/config"
	"LogPilot/internal/model"
)

type Stats struct {
	Files           int       `json:"files"`
	Lines           int       `json:"lines"`
	Records         int       `json:"records"`
	Rejected        int       `json:"rejected"`
	MultilineJoined int       `json:"multiline_joined"`
	Duplicates      int       `json:"duplicates"`
	Bytes           int64     `json:"bytes"`
	First           time.Time `json:"first,omitempty"`
	Last            time.Time `json:"last,omitempty"`
}

type Rejection struct {
	Input  string `json:"input"`
	Line   int    `json:"line"`
	Reason string `json:"reason"`
	Raw    string `json:"raw"`
}

type Result struct {
	Events   []model.Event `json:"events"`
	Rejected []Rejection   `json:"rejected,omitempty"`
	Stats    Stats         `json:"stats"`
}

type Parser struct {
	Now  func() time.Time
	seen map[string]struct{}
}

func New() *Parser { return &Parser{Now: time.Now, seen: map[string]struct{}{}} }

func (p *Parser) ParseInputs(inputs []config.Input) (Result, error) {
	result := Result{}
	for _, input := range inputs {
		parsed, err := p.ParseFile(input)
		if err != nil {
			return result, err
		}
		mergeResult(&result, parsed)
	}
	model.SortEvents(result.Events)
	return result, nil
}

func (p *Parser) ParseFile(input config.Input) (Result, error) {
	file, err := os.Open(input.Path)
	if err != nil {
		return Result{}, fmt.Errorf("open input %q: %w", input.Name, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Result{}, err
	}
	var result Result
	switch input.Format {
	case "json":
		result, err = p.parseJSON(file, input)
	case "jsonl":
		result, err = p.parseJSONL(file, input)
	case "csv":
		result, err = p.parseCSV(file, input)
	default:
		return result, fmt.Errorf("input %q: unsupported format %q", input.Name, input.Format)
	}
	result.Stats.Files = 1
	result.Stats.Bytes = info.Size()
	if err != nil {
		return result, fmt.Errorf("parse input %q: %w", input.Name, err)
	}
	return result, nil
}

func (p *Parser) parseJSON(reader io.Reader, input config.Input) (Result, error) {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return Result{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Result{}, errors.New("JSON input contains trailing value")
	}
	trimmed := bytes.TrimSpace(raw)
	var objects []map[string]any
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := decodeStrict(trimmed, &objects); err != nil {
			return Result{}, err
		}
	} else {
		var object map[string]any
		if err := decodeStrict(trimmed, &object); err != nil {
			return Result{}, err
		}
		objects = []map[string]any{object}
	}
	result := Result{}
	for i, object := range objects {
		result.Stats.Lines++
		event, err := p.objectEvent(object, input, i+1)
		if err != nil {
			result.reject(input.Name, i+1, err.Error(), string(trimmed))
			continue
		}
		result.add(p.accept(event))
	}
	return result, nil
}

func (p *Parser) parseJSONL(reader io.Reader, input config.Input) (Result, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	result := Result{}
	line := 0
	var pending []string
	pendingLine := 0
	startExpression, err := compileOptional(input.Multiline.StartPattern)
	if err != nil {
		return result, fmt.Errorf("multiline start_pattern: %w", err)
	}
	flush := func() {
		if len(pending) == 0 {
			return
		}
		raw := strings.Join(pending, "\n")
		var object map[string]any
		if err := decodeStrict([]byte(raw), &object); err != nil {
			result.reject(input.Name, pendingLine, err.Error(), raw)
		} else {
			event, err := p.objectEvent(object, input, pendingLine)
			if err != nil {
				result.reject(input.Name, pendingLine, err.Error(), raw)
			} else {
				result.add(p.accept(event))
			}
		}
		if len(pending) > 1 {
			result.Stats.MultilineJoined += len(pending) - 1
		}
		pending = nil
		pendingLine = 0
	}
	for scanner.Scan() {
		line++
		result.Stats.Lines++
		text := scanner.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		if !input.Multiline.Enabled {
			pending, pendingLine = []string{text}, line
			flush()
			continue
		}
		starts := looksLikeJSONStart(text, startExpression)
		continues := input.Multiline.ContinueSpace && beginsSpace(text)
		if len(pending) == 0 {
			pending, pendingLine = []string{text}, line
			continue
		}
		if starts && !continues {
			flush()
			pending, pendingLine = []string{text}, line
			continue
		}
		if len(pending) >= input.Multiline.MaxLines {
			result.reject(input.Name, pendingLine, "multiline record exceeds max_lines", strings.Join(pending, "\n"))
			pending, pendingLine = []string{text}, line
			continue
		}
		pending = append(pending, text)
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	flush()
	return result, nil
}

func (p *Parser) parseCSV(reader io.Reader, input config.Input) (Result, error) {
	csvReader := csv.NewReader(reader)
	csvReader.ReuseRecord = false
	csvReader.FieldsPerRecord = -1
	csvReader.TrimLeadingSpace = false
	csvReader.LazyQuotes = false
	headers := append([]string(nil), input.CSVColumns...)
	result := Result{}
	line := 0
	if len(headers) == 0 {
		record, err := csvReader.Read()
		if err != nil {
			return result, fmt.Errorf("CSV header: %w", err)
		}
		line++
		result.Stats.Lines++
		headers = record
	}
	if err := validateHeaders(headers); err != nil {
		return result, err
	}
	for {
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line++
		result.Stats.Lines++
		if err != nil {
			result.reject(input.Name, line, err.Error(), "")
			continue
		}
		if len(record) != len(headers) {
			result.reject(input.Name, line, fmt.Sprintf("expected %d columns, got %d", len(headers), len(record)), strings.Join(record, ","))
			continue
		}
		object := make(map[string]any, len(headers))
		for i, header := range headers {
			object[header] = record[i]
		}
		event, err := p.objectEvent(object, input, line)
		if err != nil {
			result.reject(input.Name, line, err.Error(), strings.Join(record, ","))
			continue
		}
		result.add(p.accept(event))
	}
	return result, nil
}

func (p *Parser) objectEvent(object map[string]any, input config.Input, line int) (model.Event, error) {
	timeValue, ok := object[input.TimeField]
	if !ok {
		return model.Event{}, fmt.Errorf("missing timestamp field %q", input.TimeField)
	}
	timestamp, err := parseTimestamp(timeValue, input.TimestampLayouts)
	if err != nil {
		return model.Event{}, err
	}
	levelText, err := scalar(object[input.LevelField])
	if err != nil {
		return model.Event{}, fmt.Errorf("level field: %w", err)
	}
	level, err := model.ParseLevel(levelText)
	if err != nil {
		return model.Event{}, err
	}
	source := input.Source
	if value, ok := object[input.SourceField]; ok {
		parsed, err := scalar(value)
		if err != nil {
			return model.Event{}, fmt.Errorf("source field: %w", err)
		}
		if parsed != "" {
			source = parsed
		}
	}
	source = model.NormalizeSource(source)
	if source == "" {
		return model.Event{}, errors.New("normalized source is empty")
	}
	messageValue, ok := object[input.MessageField]
	if !ok {
		return model.Event{}, fmt.Errorf("missing message field %q", input.MessageField)
	}
	message, err := scalar(messageValue)
	if err != nil {
		return model.Event{}, fmt.Errorf("message field: %w", err)
	}
	message = model.NormalizeMessage(message)
	if message == "" {
		return model.Event{}, errors.New("message is empty")
	}
	fields := make(map[string]string)
	reserved := map[string]bool{input.TimeField: true, input.LevelField: true, input.SourceField: true, input.MessageField: true}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if reserved[key] {
			continue
		}
		value, err := scalar(object[key])
		if err != nil {
			return model.Event{}, fmt.Errorf("field %q: %w", key, err)
		}
		fields[key] = value
	}
	for key, value := range input.StaticFields {
		fields[key] = value
	}
	event := model.NewEvent(timestamp, level, source, message, fields)
	event.Input = input.Name
	event.Line = line
	event.IngestedAt = p.Now().UTC()
	return event, event.Validate()
}

func parseTimestamp(value any, layouts []string) (time.Time, error) {
	switch typed := value.(type) {
	case json.Number:
		return parseEpoch(string(typed))
	case float64:
		return parseEpoch(strconv.FormatFloat(typed, 'f', -1, 64))
	case string:
		text := strings.TrimSpace(typed)
		if text == "" {
			return time.Time{}, errors.New("timestamp is empty")
		}
		for _, layout := range layouts {
			if parsed, err := time.Parse(layout, text); err == nil {
				return parsed.UTC(), nil
			}
		}
		if _, err := strconv.ParseFloat(text, 64); err == nil {
			return parseEpoch(text)
		}
		return time.Time{}, fmt.Errorf("timestamp %q matches no configured layout", text)
	default:
		return time.Time{}, fmt.Errorf("timestamp has unsupported type %T", value)
	}
}

func parseEpoch(text string) (time.Time, error) {
	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid epoch timestamp %q", text)
	}
	seconds := int64(value)
	fraction := value - float64(seconds)
	if seconds > 1000000000000000 {
		seconds /= 1000000
	} else if seconds > 1000000000000 {
		seconds /= 1000
	}
	nanos := int64(fraction * float64(time.Second))
	parsed := time.Unix(seconds, nanos).UTC()
	if parsed.Year() < 1970 || parsed.Year() > 9999 {
		return time.Time{}, fmt.Errorf("epoch timestamp out of range")
	}
	return parsed, nil
}

func scalar(value any) (string, error) {
	switch typed := value.(type) {
	case nil:
		return "", nil
	case string:
		return typed, nil
	case json.Number:
		return string(typed), nil
	case float64:
		return strconv.FormatFloat(typed, 'g', -1, 64), nil
	case bool:
		return strconv.FormatBool(typed), nil
	default:
		return "", fmt.Errorf("expected scalar, got %T", value)
	}
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	return nil
}

func validateHeaders(headers []string) error {
	seen := map[string]bool{}
	for i, header := range headers {
		header = strings.TrimSpace(header)
		if header == "" {
			return fmt.Errorf("CSV header %d is empty", i+1)
		}
		if seen[header] {
			return fmt.Errorf("duplicate CSV header %q", header)
		}
		seen[header] = true
		headers[i] = header
	}
	return nil
}

func compileOptional(expression string) (*regexp.Regexp, error) {
	if expression == "" {
		return nil, nil
	}
	return regexp.Compile(expression)
}

func looksLikeJSONStart(text string, expression *regexp.Regexp) bool {
	if expression != nil {
		return expression.MatchString(text)
	}
	trimmed := strings.TrimSpace(text)
	return strings.HasPrefix(trimmed, "{")
}

func beginsSpace(text string) bool { return len(text) > 0 && (text[0] == ' ' || text[0] == '\t') }

func (p *Parser) accept(event model.Event) (model.Event, bool) {
	if _, exists := p.seen[event.Fingerprint]; exists {
		return event, false
	}
	p.seen[event.Fingerprint] = struct{}{}
	return event, true
}

func (r *Result) add(event model.Event, accepted bool) {
	if !accepted {
		r.Stats.Duplicates++
		return
	}
	r.Events = append(r.Events, event)
	r.Stats.Records++
	if r.Stats.First.IsZero() || event.Timestamp.Before(r.Stats.First) {
		r.Stats.First = event.Timestamp
	}
	if r.Stats.Last.IsZero() || event.Timestamp.After(r.Stats.Last) {
		r.Stats.Last = event.Timestamp
	}
}

func (r *Result) reject(input string, line int, reason, raw string) {
	if len(raw) > 4096 {
		raw = raw[:4096]
	}
	r.Rejected = append(r.Rejected, Rejection{Input: input, Line: line, Reason: reason, Raw: raw})
	r.Stats.Rejected++
}

func mergeResult(target *Result, source Result) {
	target.Events = append(target.Events, source.Events...)
	target.Rejected = append(target.Rejected, source.Rejected...)
	target.Stats.Files += source.Stats.Files
	target.Stats.Lines += source.Stats.Lines
	target.Stats.Records += source.Stats.Records
	target.Stats.Rejected += source.Stats.Rejected
	target.Stats.MultilineJoined += source.Stats.MultilineJoined
	target.Stats.Duplicates += source.Stats.Duplicates
	target.Stats.Bytes += source.Stats.Bytes
	if target.Stats.First.IsZero() || !source.Stats.First.IsZero() && source.Stats.First.Before(target.Stats.First) {
		target.Stats.First = source.Stats.First
	}
	if source.Stats.Last.After(target.Stats.Last) {
		target.Stats.Last = source.Stats.Last
	}
}
