package integrity

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
	"strings"
	"time"
)

type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Version    int       `json:"version"`
	Created    time.Time `json:"created"`
	Algorithm  string    `json:"algorithm"`
	RootDigest string    `json:"root_digest"`
	Entries    []Entry   `json:"entries"`
}

type AuditRecord struct {
	Sequence int64             `json:"sequence"`
	Time     time.Time         `json:"time"`
	Action   string            `json:"action"`
	Subject  string            `json:"subject"`
	Details  map[string]string `json:"details,omitempty"`
	Previous string            `json:"previous"`
	Digest   string            `json:"digest"`
}

type VerifyResult struct {
	Valid         bool     `json:"valid"`
	ManifestValid bool     `json:"manifest_valid"`
	AuditValid    bool     `json:"audit_valid"`
	RootDigest    string   `json:"root_digest"`
	Errors        []string `json:"errors,omitempty"`
	Checked       int      `json:"checked"`
}

func Build(root string, include []string, created time.Time) (Manifest, error) {
	paths, err := collect(root, include)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{Version: 1, Created: created.UTC(), Algorithm: "SHA-256"}
	for _, relative := range paths {
		absolute := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Stat(absolute)
		if err != nil {
			return manifest, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		digest, err := fileDigest(absolute)
		if err != nil {
			return manifest, err
		}
		manifest.Entries = append(manifest.Entries, Entry{Path: relative, Size: info.Size(), SHA256: digest})
	}
	manifest.RootDigest = RootDigest(manifest.Entries)
	return manifest, nil
}

func Write(path string, manifest Manifest) error {
	if err := validateManifest(manifest); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWrite(path, data)
}

func Read(path string) (Manifest, error) {
	var manifest Manifest
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	if err := validateManifest(manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func Verify(root, manifestPath, auditPath string) VerifyResult {
	result := VerifyResult{ManifestValid: true, AuditValid: true}
	manifest, err := Read(manifestPath)
	if err != nil {
		result.ManifestValid = false
		result.Errors = append(result.Errors, "manifest: "+err.Error())
	} else {
		result.RootDigest = manifest.RootDigest
		for _, entry := range manifest.Entries {
			result.Checked++
			path, err := safeJoin(root, entry.Path)
			if err != nil {
				result.ManifestValid = false
				result.Errors = append(result.Errors, err.Error())
				continue
			}
			info, err := os.Stat(path)
			if err != nil {
				result.ManifestValid = false
				result.Errors = append(result.Errors, entry.Path+": "+err.Error())
				continue
			}
			if info.Size() != entry.Size {
				result.ManifestValid = false
				result.Errors = append(result.Errors, fmt.Sprintf("%s: size %d, expected %d", entry.Path, info.Size(), entry.Size))
			}
			digest, err := fileDigest(path)
			if err != nil {
				result.ManifestValid = false
				result.Errors = append(result.Errors, entry.Path+": "+err.Error())
				continue
			}
			if digest != entry.SHA256 {
				result.ManifestValid = false
				result.Errors = append(result.Errors, entry.Path+": SHA-256 mismatch")
			}
		}
		if calculated := RootDigest(manifest.Entries); calculated != manifest.RootDigest {
			result.ManifestValid = false
			result.Errors = append(result.Errors, "manifest root digest mismatch")
		}
	}
	if auditPath != "" {
		if err := VerifyAudit(auditPath); err != nil {
			result.AuditValid = false
			result.Errors = append(result.Errors, "audit: "+err.Error())
		}
	}
	sort.Strings(result.Errors)
	result.Valid = result.ManifestValid && result.AuditValid
	return result
}

func RootDigest(entries []Entry) string {
	copy := append([]Entry(nil), entries...)
	sort.Slice(copy, func(i, j int) bool { return copy[i].Path < copy[j].Path })
	h := sha256.New()
	for _, entry := range copy {
		fmt.Fprintf(h, "%s\x00%d\x00%s\n", filepath.ToSlash(entry.Path), entry.Size, strings.ToLower(entry.SHA256))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func AppendAudit(path, action, subject string, details map[string]string, at time.Time) (AuditRecord, error) {
	last, err := LastAudit(path)
	if err != nil {
		return AuditRecord{}, err
	}
	record := AuditRecord{Sequence: last.Sequence + 1, Time: at.UTC(), Action: action, Subject: subject, Details: cloneMap(details), Previous: last.Digest}
	record.Digest = auditDigest(record)
	data, err := json.Marshal(record)
	if err != nil {
		return record, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return record, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return record, err
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return record, err
	}
	if err := file.Sync(); err != nil {
		return record, err
	}
	return record, nil
}

func LastAudit(path string) (AuditRecord, error) {
	var last AuditRecord
	err := scanAudit(path, func(record AuditRecord) error { last = record; return nil })
	return last, err
}

func VerifyAudit(path string) error {
	previous := ""
	sequence := int64(0)
	return scanAudit(path, func(record AuditRecord) error {
		sequence++
		if record.Sequence != sequence {
			return fmt.Errorf("sequence %d, expected %d", record.Sequence, sequence)
		}
		if record.Previous != previous {
			return fmt.Errorf("record %d previous digest mismatch", sequence)
		}
		if expected := auditDigest(record); record.Digest != expected {
			return fmt.Errorf("record %d digest mismatch", sequence)
		}
		previous = record.Digest
		return nil
	})
}

func AuditRecords(path string) ([]AuditRecord, error) {
	var records []AuditRecord
	err := scanAudit(path, func(record AuditRecord) error { records = append(records, record); return nil })
	return records, err
}

func auditDigest(record AuditRecord) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00%s\x00", record.Sequence, record.Time.UTC().Format(time.RFC3339Nano), record.Action, record.Subject, record.Previous)
	keys := make([]string, 0, len(record.Details))
	for key := range record.Details {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(h, "%s\x00%s\x00", key, record.Details[key])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func scanAudit(path string, consume func(AuditRecord) error) error {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		var record AuditRecord
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if err := consume(record); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
	}
	return scanner.Err()
}

func collect(root string, include []string) ([]string, error) {
	if len(include) > 0 {
		paths := make([]string, 0, len(include))
		seen := map[string]bool{}
		for _, item := range include {
			item = filepath.ToSlash(filepath.Clean(item))
			if item == "." || strings.HasPrefix(item, "../") || filepath.IsAbs(item) {
				return nil, fmt.Errorf("unsafe manifest path %q", item)
			}
			if !seen[item] {
				seen[item] = true
				paths = append(paths, item)
			}
		}
		sort.Strings(paths)
		return paths, nil
	}
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "manifest.json" || relative == "audit.jsonl" || strings.HasPrefix(relative, "snapshots/") {
			return nil
		}
		paths = append(paths, relative)
		return nil
	})
	sort.Strings(paths)
	return paths, err
}

func validateManifest(manifest Manifest) error {
	if manifest.Version != 1 {
		return fmt.Errorf("unsupported manifest version %d", manifest.Version)
	}
	if manifest.Algorithm != "SHA-256" {
		return fmt.Errorf("unsupported algorithm %q", manifest.Algorithm)
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		if entry.Path == "" || filepath.IsAbs(entry.Path) || strings.HasPrefix(filepath.ToSlash(entry.Path), "../") {
			return fmt.Errorf("unsafe path %q", entry.Path)
		}
		if seen[entry.Path] {
			return fmt.Errorf("duplicate path %q", entry.Path)
		}
		seen[entry.Path] = true
		if entry.Size < 0 {
			return fmt.Errorf("negative size for %q", entry.Path)
		}
		if len(entry.SHA256) != 64 {
			return fmt.Errorf("invalid SHA-256 for %q", entry.Path)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil {
			return fmt.Errorf("invalid SHA-256 for %q", entry.Path)
		}
	}
	if manifest.RootDigest != RootDigest(manifest.Entries) {
		return errors.New("invalid root digest")
	}
	return nil
}

func safeJoin(root, relative string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(relative))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe path %q", relative)
	}
	return filepath.Join(root, clean), nil
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func cloneMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o644); err != nil {
		return err
	}
	_ = os.Remove(path)
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}
