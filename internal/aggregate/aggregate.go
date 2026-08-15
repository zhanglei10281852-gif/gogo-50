package aggregate

import (
	"sort"
	"strings"
	"time"

	"LogPilot/internal/model"
)

type Key struct {
	Bucket time.Time `json:"bucket"`
	Source string    `json:"source"`
	Level  string    `json:"level"`
}

type Metric struct {
	Key                Key       `json:"key"`
	Count              int       `json:"count"`
	UniqueFingerprints int       `json:"unique_fingerprints"`
	First              time.Time `json:"first"`
	Last               time.Time `json:"last"`
	Bytes              int       `json:"bytes"`
}

type Series struct {
	Bucket  time.Duration `json:"bucket"`
	Metrics []Metric      `json:"metrics"`
	Total   int           `json:"total"`
}

type accumulator struct {
	metric       Metric
	fingerprints map[string]struct{}
}

func Build(events []model.Event, bucket time.Duration) Series {
	if bucket <= 0 {
		bucket = time.Hour
	}
	items := map[Key]*accumulator{}
	for _, event := range events {
		key := Key{Bucket: event.Timestamp.UTC().Truncate(bucket), Source: event.Source, Level: event.Level.String()}
		item := items[key]
		if item == nil {
			item = &accumulator{metric: Metric{Key: key, First: event.Timestamp, Last: event.Timestamp}, fingerprints: map[string]struct{}{}}
			items[key] = item
		}
		item.metric.Count++
		item.metric.Bytes += len(event.Message)
		if event.Timestamp.Before(item.metric.First) {
			item.metric.First = event.Timestamp
		}
		if event.Timestamp.After(item.metric.Last) {
			item.metric.Last = event.Timestamp
		}
		item.fingerprints[event.Fingerprint] = struct{}{}
	}
	series := Series{Bucket: bucket, Total: len(events)}
	for _, item := range items {
		item.metric.UniqueFingerprints = len(item.fingerprints)
		series.Metrics = append(series.Metrics, item.metric)
	}
	sort.Slice(series.Metrics, func(i, j int) bool {
		a, b := series.Metrics[i].Key, series.Metrics[j].Key
		if !a.Bucket.Equal(b.Bucket) {
			return a.Bucket.Before(b.Bucket)
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Level < b.Level
	})
	return series
}

func BySource(events []model.Event) map[string]int {
	result := map[string]int{}
	for _, event := range events {
		result[event.Source]++
	}
	return result
}

func ByLevel(events []model.Event) map[string]int {
	result := map[string]int{}
	for _, event := range events {
		result[event.Level.String()]++
	}
	return result
}

func ByField(events []model.Event, field string) map[string]int {
	result := map[string]int{}
	for _, event := range events {
		value, ok := event.Field(field)
		if !ok {
			value = "<missing>"
		}
		result[value]++
	}
	return result
}

func Rate(events []model.Event, window time.Duration) float64 {
	if len(events) == 0 || window <= 0 {
		return 0
	}
	first, last := events[0].Timestamp, events[0].Timestamp
	for _, event := range events[1:] {
		if event.Timestamp.Before(first) {
			first = event.Timestamp
		}
		if event.Timestamp.After(last) {
			last = event.Timestamp
		}
	}
	duration := last.Sub(first)
	if duration < window {
		duration = window
	}
	return float64(len(events)) / duration.Seconds()
}

func UniqueSources(events []model.Event) []string {
	seen := map[string]bool{}
	for _, event := range events {
		seen[event.Source] = true
	}
	result := make([]string, 0, len(seen))
	for source := range seen {
		result = append(result, source)
	}
	sort.Strings(result)
	return result
}

func SearchTerms(events []model.Event, minimum int) []string {
	counts := map[string]int{}
	for _, event := range events {
		seen := map[string]bool{}
		for _, word := range strings.Fields(strings.ToLower(event.Message)) {
			word = strings.Trim(word, "\"'.,:;!?()[]{}")
			if len(word) < 3 || seen[word] {
				continue
			}
			seen[word] = true
			counts[word]++
		}
	}
	var result []string
	for word, count := range counts {
		if count >= minimum {
			result = append(result, word)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if counts[result[i]] == counts[result[j]] {
			return result[i] < result[j]
		}
		return counts[result[i]] > counts[result[j]]
	})
	return result
}
