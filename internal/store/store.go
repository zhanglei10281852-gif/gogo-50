package store

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"LogPilot/internal/model"
	"LogPilot/internal/query"
)

const schemaVersion = 1

type Metadata struct {
	Version    int       `json:"version"`
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`
	Events     int       `json:"events"`
	Incidents  int       `json:"incidents"`
	Earliest   time.Time `json:"earliest,omitempty"`
	Latest     time.Time `json:"latest,omitempty"`
	Generation int64     `json:"generation"`
}

type Store struct{ Root string }

type Snapshot struct {
	Name       string    `json:"name"`
	Created    time.Time `json:"created"`
	Generation int64     `json:"generation"`
	Events     int       `json:"events"`
	Incidents  int       `json:"incidents"`
	RootDigest string    `json:"root_digest"`
	Files      []string  `json:"files"`
}

type QueryResult struct {
	Events    []model.Event `json:"events"`
	Scanned   int           `json:"scanned"`
	Matched   int           `json:"matched"`
	Truncated bool          `json:"truncated"`
}

func New(root string) *Store { return &Store{Root: filepath.Clean(root)} }

func (s *Store) Init() error {
	for _, directory := range []string{s.Root, s.snapshotDir()} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return fmt.Errorf("create store: %w", err)
		}
	}
	for _, path := range []string{s.eventsPath(), s.incidentsPath(), s.indexPath()} {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(path, nil, 0o644); err != nil {
				return fmt.Errorf("initialize store file: %w", err)
			}
		} else if err != nil {
			return err
		}
	}
	if _, err := os.Stat(s.metadataPath()); errors.Is(err, os.ErrNotExist) {
		now := time.Now().UTC()
		return s.writeJSON(s.metadataPath(), Metadata{Version: schemaVersion, Created: now, Updated: now})
	} else if err != nil {
		return err
	}
	meta, err := s.Metadata()
	if err != nil {
		return err
	}
	if meta.Version != schemaVersion {
		return fmt.Errorf("unsupported store version %d", meta.Version)
	}
	return nil
}

func (s *Store) Metadata() (Metadata, error) {
	var metadata Metadata
	if err := s.readJSON(s.metadataPath(), &metadata); err != nil {
		return metadata, err
	}
	return metadata, nil
}

func (s *Store) LoadEvents() ([]model.Event, error) {
	var events []model.Event
	if err := readJSONL(s.eventsPath(), func(data []byte) error {
		var event model.Event
		if err := json.Unmarshal(data, &event); err != nil {
			return err
		}
		if err := event.Validate(); err != nil {
			return err
		}
		events = append(events, event)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("load events: %w", err)
	}
	model.SortEvents(events)
	return events, nil
}

func (s *Store) SaveEvents(events []model.Event) error {
	copy := make([]model.Event, len(events))
	seen := map[string]bool{}
	for i, event := range events {
		if err := event.Validate(); err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		if seen[event.ID] {
			return fmt.Errorf("duplicate event id %q", event.ID)
		}
		seen[event.ID] = true
		copy[i] = event.Clone()
	}
	model.SortEvents(copy)
	if err := writeJSONLAtomic(s.eventsPath(), copy); err != nil {
		return err
	}
	return s.refreshMetadata(copy, nil)
}

func (s *Store) AppendEvents(additions []model.Event) (int, int, error) {
	existing, err := s.LoadEvents()
	if err != nil {
		return 0, 0, err
	}
	byID := make(map[string]bool, len(existing))
	byFingerprint := make(map[string]bool, len(existing))
	for _, event := range existing {
		byID[event.ID], byFingerprint[event.Fingerprint] = true, true
	}
	added, skipped := 0, 0
	for _, event := range additions {
		if err := event.Validate(); err != nil {
			return added, skipped, err
		}
		if byID[event.ID] || byFingerprint[event.Fingerprint] {
			skipped++
			continue
		}
		existing = append(existing, event.Clone())
		byID[event.ID], byFingerprint[event.Fingerprint] = true, true
		added++
	}
	if added == 0 {
		return 0, skipped, nil
	}
	if err := s.SaveEvents(existing); err != nil {
		return 0, skipped, err
	}
	return added, skipped, nil
}

func (s *Store) LoadIncidents() ([]model.Incident, error) {
	var incidents []model.Incident
	if err := readJSONL(s.incidentsPath(), func(data []byte) error {
		var incident model.Incident
		if err := json.Unmarshal(data, &incident); err != nil {
			return err
		}
		if err := incident.Validate(); err != nil {
			return err
		}
		incidents = append(incidents, incident)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("load incidents: %w", err)
	}
	model.SortIncidents(incidents)
	return incidents, nil
}

func (s *Store) SaveIncidents(incidents []model.Incident) error {
	copy := make([]model.Incident, len(incidents))
	seen := map[string]bool{}
	for i, incident := range incidents {
		if err := incident.Validate(); err != nil {
			return fmt.Errorf("incident %d: %w", i, err)
		}
		if seen[incident.ID] {
			return fmt.Errorf("duplicate incident id %q", incident.ID)
		}
		seen[incident.ID] = true
		copy[i] = incident.Clone()
	}
	model.SortIncidents(copy)
	if err := writeJSONLAtomic(s.incidentsPath(), copy); err != nil {
		return err
	}
	return s.refreshMetadata(nil, copy)
}

func (s *Store) Query(filter query.Filter) (QueryResult, error) {
	events, err := s.LoadEvents()
	if err != nil {
		return QueryResult{}, err
	}
	result := QueryResult{Scanned: len(events)}
	allFilter := filter
	allFilter.Offset, allFilter.Limit = 0, 0
	all := query.Apply(events, allFilter)
	result.Matched = len(all)
	result.Events = query.Apply(events, filter)
	result.Truncated = filter.Limit > 0 && result.Matched > filter.Offset+len(result.Events)
	return result, nil
}

func (s *Store) EventByID(id string) (model.Event, bool, error) {
	events, err := s.LoadEvents()
	if err != nil {
		return model.Event{}, false, err
	}
	for _, event := range events {
		if event.ID == id {
			return event, true, nil
		}
	}
	return model.Event{}, false, nil
}

func (s *Store) IncidentByID(id string) (model.Incident, bool, error) {
	incidents, err := s.LoadIncidents()
	if err != nil {
		return model.Incident{}, false, err
	}
	for _, incident := range incidents {
		if incident.ID == id {
			return incident, true, nil
		}
	}
	return model.Incident{}, false, nil
}

func (s *Store) CreateSnapshot(name, rootDigest string) (Snapshot, error) {
	if err := validateSnapshotName(name); err != nil {
		return Snapshot{}, err
	}
	metadata, err := s.Metadata()
	if err != nil {
		return Snapshot{}, err
	}
	directory := filepath.Join(s.snapshotDir(), name)
	if _, err := os.Stat(directory); err == nil {
		return Snapshot{}, fmt.Errorf("snapshot %q exists", name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, err
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return Snapshot{}, err
	}
	files := []string{}
	for _, source := range []string{s.eventsPath(), s.incidentsPath(), s.metadataPath()} {
		if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return Snapshot{}, err
		}
		destination := filepath.Join(directory, filepath.Base(source))
		if err := copyFile(source, destination); err != nil {
			return Snapshot{}, err
		}
		files = append(files, filepath.Base(source))
	}
	sort.Strings(files)
	snapshot := Snapshot{Name: name, Created: time.Now().UTC(), Generation: metadata.Generation, Events: metadata.Events, Incidents: metadata.Incidents, RootDigest: rootDigest, Files: files}
	if err := s.writeJSON(filepath.Join(directory, "snapshot.json"), snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (s *Store) Snapshots() ([]Snapshot, error) {
	entries, err := os.ReadDir(s.snapshotDir())
	if errors.Is(err, os.ErrNotExist) {
		return []Snapshot{}, nil
	}
	if err != nil {
		return nil, err
	}
	var snapshots []Snapshot
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		var snapshot Snapshot
		if err := s.readJSON(filepath.Join(s.snapshotDir(), entry.Name(), "snapshot.json"), &snapshot); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].Name < snapshots[j].Name })
	return snapshots, nil
}

func (s *Store) RestoreSnapshot(name string) error {
	if err := validateSnapshotName(name); err != nil {
		return err
	}
	directory := filepath.Join(s.snapshotDir(), name)
	var snapshot Snapshot
	if err := s.readJSON(filepath.Join(directory, "snapshot.json"), &snapshot); err != nil {
		return err
	}
	for _, filename := range snapshot.Files {
		if filepath.Base(filename) != filename {
			return fmt.Errorf("unsafe snapshot file %q", filename)
		}
		if err := copyFile(filepath.Join(directory, filename), filepath.Join(s.Root, filename)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) refreshMetadata(events []model.Event, incidents []model.Incident) error {
	metadata, err := s.Metadata()
	if err != nil {
		return err
	}
	if events != nil {
		metadata.Events = len(events)
		metadata.Earliest, metadata.Latest = time.Time{}, time.Time{}
		if len(events) > 0 {
			metadata.Earliest, metadata.Latest = events[0].Timestamp, events[len(events)-1].Timestamp
		}
	}
	if incidents != nil {
		metadata.Incidents = len(incidents)
	}
	metadata.Updated = time.Now().UTC()
	metadata.Generation++
	return s.writeJSON(s.metadataPath(), metadata)
}

func (s *Store) RebuildIndex() error {
	events, err := s.LoadEvents()
	if err != nil {
		return err
	}
	type indexEntry struct {
		Time        time.Time `json:"time"`
		ID          string    `json:"id"`
		Source      string    `json:"source"`
		Level       string    `json:"level"`
		Fingerprint string    `json:"fingerprint"`
	}
	entries := make([]indexEntry, len(events))
	for i, event := range events {
		entries[i] = indexEntry{Time: event.Timestamp, ID: event.ID, Source: event.Source, Level: event.Level.String(), Fingerprint: event.Fingerprint}
	}
	return writeJSONLAtomic(s.indexPath(), entries)
}

func (s *Store) ValidateIndex() error {
	events, err := s.LoadEvents()
	if err != nil {
		return err
	}
	file, err := os.Open(s.indexPath())
	if errors.Is(err, os.ErrNotExist) && len(events) == 0 {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		if count >= len(events) {
			return errors.New("index has extra entries")
		}
		var entry struct {
			ID          string `json:"id"`
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return err
		}
		if entry.ID != events[count].ID || entry.Fingerprint != events[count].Fingerprint {
			return fmt.Errorf("index mismatch at entry %d", count)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count != len(events) {
		return fmt.Errorf("index has %d entries, expected %d", count, len(events))
	}
	return nil
}

func (s *Store) Digest() (string, error) {
	files := []string{s.eventsPath(), s.incidentsPath(), s.metadataPath(), s.indexPath()}
	type digestEntry struct{ name, digest string }
	var entries []digestEntry
	for _, filename := range files {
		data, err := os.ReadFile(filename)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		entries = append(entries, digestEntry{filepath.Base(filename), hex.EncodeToString(sum[:])})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	h := sha256.New()
	for _, entry := range entries {
		fmt.Fprintf(h, "%s\x00%s\n", entry.name, entry.digest)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Store) Paths() []string {
	return []string{s.eventsPath(), s.incidentsPath(), s.metadataPath(), s.indexPath()}
}
func (s *Store) eventsPath() string    { return filepath.Join(s.Root, "events.jsonl") }
func (s *Store) incidentsPath() string { return filepath.Join(s.Root, "incidents.jsonl") }
func (s *Store) metadataPath() string  { return filepath.Join(s.Root, "metadata.json") }
func (s *Store) indexPath() string     { return filepath.Join(s.Root, "index.jsonl") }
func (s *Store) snapshotDir() string   { return filepath.Join(s.Root, "snapshots") }

func (s *Store) readJSON(path string, destination any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return nil
}

func (s *Store) writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeAtomic(path, data)
}

func readJSONL(path string, consume func([]byte) error) error {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, 64*1024)
	line := 0
	for {
		data, err := reader.ReadBytes('\n')
		if len(bytes.TrimSpace(data)) > 0 {
			line++
			if consume(bytes.TrimSpace(data)) != nil {
				return fmt.Errorf("line %d: invalid record", line)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func writeJSONLAtomic[T any](path string, values []T) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	for _, value := range values {
		if err := encoder.Encode(value); err != nil {
			return err
		}
	}
	return writeAtomic(path, buffer.Bytes())
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".tmp-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	_ = os.Remove(path)
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func validateSnapshotName(name string) error {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "\\/:") {
		return fmt.Errorf("invalid snapshot name %q", name)
	}
	return nil
}
