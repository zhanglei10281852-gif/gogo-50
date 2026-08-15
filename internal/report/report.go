package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"LogPilot/internal/model"
)

type Summary struct {
	Generated       time.Time   `json:"generated"`
	From            time.Time   `json:"from,omitempty"`
	To              time.Time   `json:"to,omitempty"`
	Events          int         `json:"events"`
	Incidents       int         `json:"incidents"`
	OpenIncidents   int         `json:"open_incidents"`
	Levels          []Count     `json:"levels"`
	Sources         []Count     `json:"sources"`
	Rules           []Count     `json:"rules"`
	Timeline        []TimeCount `json:"timeline"`
	TopFingerprints []Count     `json:"top_fingerprints"`
}

type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type TimeCount struct {
	Time  time.Time `json:"time"`
	Count int       `json:"count"`
}

type Options struct {
	Format    string
	Title     string
	Bucket    time.Duration
	Top       int
	Generated time.Time
}

func Build(events []model.Event, incidents []model.Incident, options Options) Summary {
	if options.Bucket <= 0 {
		options.Bucket = time.Hour
	}
	if options.Top <= 0 {
		options.Top = 10
	}
	summary := Summary{Generated: options.Generated.UTC(), Events: len(events), Incidents: len(incidents)}
	levelCounts := map[string]int{}
	sourceCounts := map[string]int{}
	fingerprintCounts := map[string]int{}
	timeline := map[time.Time]int{}
	for _, event := range events {
		if summary.From.IsZero() || event.Timestamp.Before(summary.From) {
			summary.From = event.Timestamp
		}
		if summary.To.IsZero() || event.Timestamp.After(summary.To) {
			summary.To = event.Timestamp
		}
		levelCounts[event.Level.String()]++
		sourceCounts[event.Source]++
		fingerprintCounts[event.Fingerprint]++
		timeline[event.Timestamp.UTC().Truncate(options.Bucket)]++
	}
	ruleCounts := map[string]int{}
	for _, incident := range incidents {
		ruleCounts[incident.RuleID]++
		if incident.Status != model.IncidentResolved {
			summary.OpenIncidents++
		}
	}
	summary.Levels = counts(levelCounts, 0)
	summary.Sources = counts(sourceCounts, options.Top)
	summary.Rules = counts(ruleCounts, options.Top)
	summary.TopFingerprints = counts(fingerprintCounts, options.Top)
	for timestamp, count := range timeline {
		summary.Timeline = append(summary.Timeline, TimeCount{Time: timestamp, Count: count})
	}
	sort.Slice(summary.Timeline, func(i, j int) bool { return summary.Timeline[i].Time.Before(summary.Timeline[j].Time) })
	return summary
}

func Render(summary Summary, options Options) ([]byte, error) {
	switch strings.ToLower(options.Format) {
	case "json":
		return JSON(summary)
	case "text", "":
		return Text(summary, options.Title), nil
	default:
		return nil, fmt.Errorf("unsupported report format %q", options.Format)
	}
}

func JSON(summary Summary) ([]byte, error) {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func Text(summary Summary, title string) []byte {
	if title == "" {
		title = "LogPilot Report"
	}
	var buffer bytes.Buffer
	buffer.WriteString(title)
	buffer.WriteByte('\n')
	buffer.WriteString(strings.Repeat("=", len(title)))
	buffer.WriteString("\n\n")
	writer := tabwriter.NewWriter(&buffer, 0, 4, 2, ' ', 0)
	fmt.Fprintf(writer, "Generated:\t%s\n", summary.Generated.UTC().Format(time.RFC3339))
	fmt.Fprintf(writer, "Range:\t%s to %s\n", formatTime(summary.From), formatTime(summary.To))
	fmt.Fprintf(writer, "Events:\t%d\n", summary.Events)
	fmt.Fprintf(writer, "Incidents:\t%d\n", summary.Incidents)
	fmt.Fprintf(writer, "Open incidents:\t%d\n", summary.OpenIncidents)
	writer.Flush()
	writeCounts(&buffer, "Levels", summary.Levels)
	writeCounts(&buffer, "Sources", summary.Sources)
	writeCounts(&buffer, "Rules", summary.Rules)
	writeTimeline(&buffer, summary.Timeline)
	writeCounts(&buffer, "Top fingerprints", summary.TopFingerprints)
	return buffer.Bytes()
}

func EventText(events []model.Event) []byte {
	var buffer bytes.Buffer
	writer := tabwriter.NewWriter(&buffer, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "TIME\tLEVEL\tSOURCE\tMESSAGE\tID")
	for _, event := range events {
		message := strings.ReplaceAll(event.Message, "\n", "\\n")
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", event.Timestamp.UTC().Format(time.RFC3339Nano), event.Level.String(), event.Source, message, event.ID)
	}
	writer.Flush()
	return buffer.Bytes()
}

func EventJSON(events []model.Event) ([]byte, error) {
	copy := make([]model.Event, len(events))
	for i := range events {
		copy[i] = events[i].Clone()
	}
	model.SortEvents(copy)
	data, err := json.MarshalIndent(copy, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func IncidentText(incidents []model.Incident) []byte {
	copy := make([]model.Incident, len(incidents))
	for i := range incidents {
		copy[i] = incidents[i].Clone()
	}
	model.SortIncidents(copy)
	var buffer bytes.Buffer
	writer := tabwriter.NewWriter(&buffer, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "STATUS\tSEVERITY\tRULE\tGROUP\tCOUNT\tFIRST\tLAST\tID")
	for _, incident := range copy {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", incident.Status, incident.Severity.String(), incident.RuleID, incident.Group, incident.Count, formatTime(incident.FirstSeen), formatTime(incident.LastSeen), incident.ID)
	}
	writer.Flush()
	return buffer.Bytes()
}

func IncidentJSON(incidents []model.Incident) ([]byte, error) {
	copy := make([]model.Incident, len(incidents))
	for i := range incidents {
		copy[i] = incidents[i].Clone()
	}
	model.SortIncidents(copy)
	data, err := json.MarshalIndent(copy, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func CSV(events []model.Event) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("timestamp,level,source,message,id,fingerprint,fields\n")
	copy := make([]model.Event, len(events))
	copy = append(copy[:0], events...)
	model.SortEvents(copy)
	for _, event := range copy {
		fieldKeys := make([]string, 0, len(event.Fields))
		for key := range event.Fields {
			fieldKeys = append(fieldKeys, key)
		}
		sort.Strings(fieldKeys)
		fieldParts := make([]string, 0, len(fieldKeys))
		for _, key := range fieldKeys {
			fieldParts = append(fieldParts, key+"="+event.Fields[key])
		}
		values := []string{event.Timestamp.UTC().Format(time.RFC3339Nano), event.Level.String(), event.Source, event.Message, event.ID, event.Fingerprint, strings.Join(fieldParts, ";")}
		for i, value := range values {
			if i > 0 {
				buffer.WriteByte(',')
			}
			buffer.WriteString(csvQuote(value))
		}
		buffer.WriteByte('\n')
	}
	return buffer.Bytes()
}

func writeCounts(buffer *bytes.Buffer, title string, items []Count) {
	buffer.WriteString("\n" + title + "\n")
	buffer.WriteString(strings.Repeat("-", len(title)) + "\n")
	if len(items) == 0 {
		buffer.WriteString("(none)\n")
		return
	}
	writer := tabwriter.NewWriter(buffer, 0, 4, 2, ' ', 0)
	for _, item := range items {
		fmt.Fprintf(writer, "%s\t%d\n", item.Name, item.Count)
	}
	writer.Flush()
}

func writeTimeline(buffer *bytes.Buffer, items []TimeCount) {
	buffer.WriteString("\nTimeline\n--------\n")
	if len(items) == 0 {
		buffer.WriteString("(none)\n")
		return
	}
	writer := tabwriter.NewWriter(buffer, 0, 4, 2, ' ', 0)
	for _, item := range items {
		fmt.Fprintf(writer, "%s\t%d\n", formatTime(item.Time), item.Count)
	}
	writer.Flush()
}

func counts(source map[string]int, limit int) []Count {
	items := make([]Count, 0, len(source))
	for name, count := range source {
		items = append(items, Count{Name: name, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Name < items[j].Name
		}
		return items[i].Count > items[j].Count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func csvQuote(value string) string {
	if !strings.ContainsAny(value, ",\"\r\n") {
		return value
	}
	return "\"" + strings.ReplaceAll(value, "\"", "\"\"") + "\""
}

func ParseBucket(value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if duration <= 0 {
		return 0, fmt.Errorf("bucket must be positive")
	}
	return duration, nil
}

func Percent(part, total int) string {
	if total == 0 {
		return "0.0%"
	}
	return strconv.FormatFloat(float64(part)*100/float64(total), 'f', 1, 64) + "%"
}
