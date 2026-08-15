# LogPilot

LogPilot is an independent, original offline log-operations project. It is not affiliated with, endorsed by, sponsored by, or derived from any similarly named product, company, or organization.

LogPilot ingests strict JSON, JSONL, and CSV logs into a deterministic local store, normalizes records, detects thresholded conditions, tracks incident lifecycles, compacts retained data, verifies tamper-evident manifests and audit chains, and produces text or JSON reports. It uses only the Go standard library and makes no network requests.

## Features

- Strict JSON decoding with trailing-value rejection and scalar field validation.
- JSON arrays/objects, JSON Lines, and RFC 4180-style CSV ingestion.
- Configurable timestamp layouts plus seconds, milliseconds, and microseconds epochs.
- Canonical UTC timestamps, levels, source names, messages, and custom fields.
- Optional bounded multiline assembly for JSONL inputs.
- Stable event identifiers, normalized SHA-256 fingerprints, and deduplication.
- `all`/`any` predicates with equality, membership, text, regex, existence, and ordered comparisons.
- Sliding windows, thresholds, group keys, cooldown suppression, and automatic resolution.
- Durable JSONL event/incident files, metadata, deterministic index, filtering, and snapshots.
- Event/incident retention, duplicate pruning, reference cleanup, and pre-compaction snapshots.
- Per-file SHA-256 manifest plus a path/size/digest root and hash-chained audit log.
- Stable text, JSON, and event CSV output suitable for local automation.

## Build

Go 1.22.5 or newer in the 1.22 line is expected.

```powershell
go test ./... -count=1
go build ./...
go vet ./...
go build -o logpilot.exe ./cmd/logpilot
```

There are no external modules, services, or generated assets.

## Quick start

The sample configuration resolves paths relative to `samples/config.json`; its store is ignored at `runtime/`.

```powershell
go run ./cmd/logpilot validate -config samples/config.json
go run ./cmd/logpilot ingest -config samples/config.json
go run ./cmd/logpilot query -config samples/config.json level=ERROR order=asc
go run ./cmd/logpilot detect -config samples/config.json
go run ./cmd/logpilot verify -config samples/config.json
go run ./cmd/logpilot report -config samples/config.json -format text -bucket 1h
go run ./cmd/logpilot compact -config samples/config.json -snapshot before-demo
```

`query` accepts `key=value` terms after flags: `from`, `to`, `level`, `source`, `contains`, `field.<name>`, `offset`, `limit`, and `order`. Time values use RFC 3339, a date, or date-time. Output formats are text, JSON, and CSV.

## Configuration

The top-level JSON object has:

- `version`: currently `1`.
- `store`: local data directory, relative to the configuration file when not absolute.
- `inputs`: named input definitions. Formats are `json`, `jsonl`, and `csv`.
- `rules`: detection rules. Disabled rules are retained but not evaluated.
- `retention`: event/incident age, deduplication, and snapshot policy.

Unknown configuration fields are rejected. Each input names timestamp, level, source, and message fields. CSV can use its header row or an explicit `csv_columns` list. Static fields are merged into every input record. Multiline assembly is bounded by `max_lines` and can use a start expression or leading-space continuation.

Predicates access built-in fields (`id`, `timestamp`, `level`, `source`, `message`, `fingerprint`, `input`, `line`) or normalized custom fields. Supported operators are `eq`, `ne`, `contains`, `prefix`, `suffix`, `regex`, `gt`, `gte`, `lt`, `lte`, `exists`, and `in`; `negate` reverses a result.

## Store layout

- `events.jsonl`: sorted normalized events.
- `incidents.jsonl`: sorted incident state and transition history.
- `metadata.json`: schema version, counts, range, and generation.
- `index.jsonl`: deterministic local event lookup/index projection.
- `manifest.json`: integrity manifest for current store files.
- `audit.jsonl`: append-only hash-chained operation audit.
- `snapshots/<name>/`: point-in-time data and snapshot descriptor.

Writes use same-directory temporary files and atomic replacement. No file locks are taken, so one mutating LogPilot process should own a store at a time.

## Integrity definition

Every manifest entry is `(slash-normalized relative path, byte size, lowercase SHA-256 file digest)`. Entries are sorted by path. The manifest root digest is SHA-256 over the UTF-8 concatenation of each entry as:

```text
path NUL decimal-size NUL lowercase-file-digest LF
```

Audit records contain a sequence, UTC timestamp, action, subject, sorted detail map, previous record digest, and digest. The record digest is SHA-256 over the length-independent canonical field sequence implemented by `internal/integrity`. `verify` recalculates every file digest, the root digest, sequence continuity, prior links, and audit record digests.

## Determinism

Stored events and incidents use timestamp/ID ordering. Maps are converted to sorted sequences for reports and cryptographic roots. Text reports use UTC timestamps and fixed tabular columns. JSON reports use explicit ordered arrays for rankings. The report generation timestamp is the only expected time-dependent field.

## Commands

- `validate`: parse, normalize, and validate configuration and input paths.
- `ingest`: parse selected/all inputs, normalize, deduplicate, index, manifest, and audit.
- `query`: filter local events and render text, JSON, or CSV.
- `detect`: evaluate rules and reconcile open/resolved incidents.
- `compact`: snapshot, retain, deduplicate, reindex, manifest, and audit.
- `verify`: check manifest files/root and the audit chain.
- `report`: aggregate events/incidents into deterministic text or JSON.

Use `<command> -h` for command-specific flags.
