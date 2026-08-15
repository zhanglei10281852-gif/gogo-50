package ingest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"LogPilot/internal/config"
)

func TestStrictJSONLAndDeduplication(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	data := "{\"timestamp\":\"2025-01-01T00:00:00Z\",\"level\":\"error\",\"source\":\"API\",\"message\":\"failure 12\"}\n" +
		"{\"timestamp\":\"2025-01-01T00:01:00Z\",\"level\":\"ERROR\",\"source\":\"api\",\"message\":\"failure 99\"}\n" +
		"{bad json}\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	input := config.Input{Name: "app", Path: path, Format: "jsonl", Source: "default", TimeField: "timestamp", LevelField: "level", SourceField: "source", MessageField: "message", TimestampLayouts: []string{time.RFC3339}, Multiline: config.Multiline{MaxLines: 10}}
	parser := New()
	parser.Now = func() time.Time { return time.Unix(0, 0).UTC() }
	result, err := parser.ParseFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || result.Stats.Duplicates != 1 || result.Stats.Rejected != 1 {
		t.Fatalf("unexpected result: %+v", result.Stats)
	}
}
