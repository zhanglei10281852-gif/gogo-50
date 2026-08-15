package pipeline

import (
	"fmt"
	"sort"
	"time"

	"LogPilot/internal/aggregate"
	"LogPilot/internal/config"
	"LogPilot/internal/detect"
	"LogPilot/internal/ingest"
	"LogPilot/internal/integrity"
	"LogPilot/internal/model"
	"LogPilot/internal/retention"
	"LogPilot/internal/store"
)

type Pipeline struct {
	Config config.Config
	Store  *store.Store
	Now    func() time.Time
}

type IngestResult struct {
	Ingest     ingest.Result `json:"ingest"`
	Added      int           `json:"added"`
	Skipped    int           `json:"skipped"`
	Total      int           `json:"total"`
	RootDigest string        `json:"root_digest"`
}

type DetectResult struct {
	Detection  detect.Result `json:"detection"`
	Open       int           `json:"open"`
	Resolved   int           `json:"resolved"`
	RootDigest string        `json:"root_digest"`
}

type CompactResult struct {
	Compaction retention.Result `json:"compaction"`
	Snapshot   store.Snapshot   `json:"snapshot"`
	RootDigest string           `json:"root_digest"`
}

func New(cfg config.Config) *Pipeline {
	return &Pipeline{Config: cfg, Store: store.New(cfg.Store), Now: time.Now}
}

func (p *Pipeline) Initialize() error { return p.Store.Init() }

func (p *Pipeline) Ingest(selected []string) (IngestResult, error) {
	inputs, err := p.selectInputs(selected)
	if err != nil {
		return IngestResult{}, err
	}
	parser := ingest.New()
	parser.Now = p.Now
	parsed, err := parser.ParseInputs(inputs)
	if err != nil {
		return IngestResult{}, err
	}
	added, skipped, err := p.Store.AppendEvents(parsed.Events)
	if err != nil {
		return IngestResult{}, err
	}
	if err := p.Store.RebuildIndex(); err != nil {
		return IngestResult{}, err
	}
	manifest, err := p.updateIntegrity("ingest", fmt.Sprintf("added=%d", added))
	if err != nil {
		return IngestResult{}, err
	}
	metadata, err := p.Store.Metadata()
	if err != nil {
		return IngestResult{}, err
	}
	return IngestResult{Ingest: parsed, Added: added, Skipped: skipped, Total: metadata.Events, RootDigest: manifest.RootDigest}, nil
}

func (p *Pipeline) Detect() (DetectResult, error) {
	events, err := p.Store.LoadEvents()
	if err != nil {
		return DetectResult{}, err
	}
	existing, err := p.Store.LoadIncidents()
	if err != nil {
		return DetectResult{}, err
	}
	engine := detect.New(p.Config.EnabledRules())
	engine.Now = p.Now
	detection, err := engine.Detect(events, existing)
	if err != nil {
		return DetectResult{}, err
	}
	if err := p.Store.SaveIncidents(detection.Incidents); err != nil {
		return DetectResult{}, err
	}
	manifest, err := p.updateIntegrity("detect", fmt.Sprintf("incidents=%d", len(detection.Incidents)))
	if err != nil {
		return DetectResult{}, err
	}
	result := DetectResult{Detection: detection, RootDigest: manifest.RootDigest}
	for _, incident := range detection.Incidents {
		if incident.Status == model.IncidentResolved {
			result.Resolved++
		} else {
			result.Open++
		}
	}
	return result, nil
}

func (p *Pipeline) Compact(snapshotName string) (CompactResult, error) {
	events, err := p.Store.LoadEvents()
	if err != nil {
		return CompactResult{}, err
	}
	incidents, err := p.Store.LoadIncidents()
	if err != nil {
		return CompactResult{}, err
	}
	digest, err := p.Store.Digest()
	if err != nil {
		return CompactResult{}, err
	}
	var snapshot store.Snapshot
	if p.Config.Retention.SnapshotBeforeCompact {
		if snapshotName == "" {
			snapshotName = p.Now().UTC().Format("20060102T150405.000000000Z")
		}
		snapshot, err = p.Store.CreateSnapshot(snapshotName, digest)
		if err != nil {
			return CompactResult{}, err
		}
	}
	compactor := retention.New(p.Config.Retention)
	compactor.Now = p.Now
	compaction, err := compactor.Compact(events, incidents)
	if err != nil {
		return CompactResult{}, err
	}
	if err := p.Store.SaveEvents(compaction.Events); err != nil {
		return CompactResult{}, err
	}
	if err := p.Store.SaveIncidents(compaction.Incidents); err != nil {
		return CompactResult{}, err
	}
	if err := p.Store.RebuildIndex(); err != nil {
		return CompactResult{}, err
	}
	manifest, err := p.updateIntegrity("compact", fmt.Sprintf("expired=%d", compaction.Stats.ExpiredEvents))
	if err != nil {
		return CompactResult{}, err
	}
	return CompactResult{Compaction: compaction, Snapshot: snapshot, RootDigest: manifest.RootDigest}, nil
}

func (p *Pipeline) Metrics(bucket time.Duration) (aggregate.Series, error) {
	events, err := p.Store.LoadEvents()
	if err != nil {
		return aggregate.Series{}, err
	}
	return aggregate.Build(events, bucket), nil
}

func (p *Pipeline) updateIntegrity(action, summary string) (integrity.Manifest, error) {
	manifest, err := integrity.Build(p.Config.Store, []string{"events.jsonl", "incidents.jsonl", "metadata.json", "index.jsonl"}, p.Now())
	if err != nil {
		return manifest, err
	}
	if err := integrity.Write(p.manifestPath(), manifest); err != nil {
		return manifest, err
	}
	_, err = integrity.AppendAudit(p.auditPath(), action, manifest.RootDigest, map[string]string{"summary": summary}, p.Now())
	return manifest, err
}

func (p *Pipeline) Verify() integrity.VerifyResult {
	return integrity.Verify(p.Config.Store, p.manifestPath(), p.auditPath())
}

func (p *Pipeline) selectInputs(names []string) ([]config.Input, error) {
	if len(names) == 0 {
		return append([]config.Input(nil), p.Config.Inputs...), nil
	}
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[name] = true
	}
	var inputs []config.Input
	for _, input := range p.Config.Inputs {
		if wanted[input.Name] {
			inputs = append(inputs, input)
			delete(wanted, input.Name)
		}
	}
	if len(wanted) > 0 {
		missing := make([]string, 0, len(wanted))
		for name := range wanted {
			missing = append(missing, name)
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("unknown inputs: %v", missing)
	}
	return inputs, nil
}

func (p *Pipeline) manifestPath() string { return p.Config.Store + "/manifest.json" }
func (p *Pipeline) auditPath() string    { return p.Config.Store + "/audit.jsonl" }
