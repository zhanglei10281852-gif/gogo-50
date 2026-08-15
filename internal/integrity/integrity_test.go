package integrity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManifestAndAuditTamperDetection(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "events.jsonl"), []byte("record\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := Build(root, []string{"events.jsonl"}, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	auditPath := filepath.Join(root, "audit.jsonl")
	if err := Write(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := AppendAudit(auditPath, "ingest", manifest.RootDigest, nil, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if result := Verify(root, manifestPath, auditPath); !result.Valid {
		t.Fatalf("verification failed: %+v", result)
	}
	if err := os.WriteFile(filepath.Join(root, "events.jsonl"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if result := Verify(root, manifestPath, auditPath); result.Valid || result.ManifestValid {
		t.Fatalf("tampering was accepted")
	}
}
