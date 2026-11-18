# Signal

A local-first finding ledger for application security work. Ingest a scanner export, verify findings with hashed evidence, and generate a self-contained HTML report.

Live: https://arrojchino.github.io/signal/
Source: https://github.com/arrojchino/signal

## Why it exists

Most small appsec tools stop at "we found something". Signal keeps the part that survives review: a stable identity for each finding, an explicit verification state, and evidence whose hash can be checked later. It is one job, done properly, rather than a pile of scripts.

## Design, borrowed from the best

The architecture was shaped by studying twelve of the most-starred open-source security projects. Four ideas carried over:

1. **Rules live in data.** `rules.json` holds severity order and schema version; adding a rule never means editing code. This is the Sherlock / SpiderFoot / CheatSheetSeries pattern.
2. **One versioned result envelope.** Every command returns the same shape with `schema_version`, `report_id`, counts, verification counts and findings. This is Trivy's `types.Report` idea at small scale.
3. **Verification is a state machine.** `unverified`, `confirmed`, `ruled_out`, `open_proof_gap`. "Could not verify" never silently becomes "clean" — the lesson from the AI pentesting tools.
4. **Evidence is hashed, not trusted.** Each attached file gets a SHA-256 and a timestamp. The model never decides whether evidence is authentic; it only records that it was seen.

The CLI is also importable as a library, following sqlmap's dual-use entrypoint.

## Layout

```
signal.py      CLI and library: normalize, ingest, verify, render
rules.json     declarative severity policy
tests/         deterministic unittest suite
README.md      this file
```

No external packages. No network calls. No credentials.

## Usage

```bash
python signal.py demo
python signal.py ingest findings.csv --out store.json
python signal.py verify store.json <fingerprint> confirmed --evidence proof.txt
python signal.py report store.json --out report.html
python -m unittest discover -s tests
```

`ingest` accepts common column variants (`Application`, `Severity`, `CWE`, `Status`). Fingerprints are the first 16 hex chars of SHA-256 over the canonical fields, so the same finding gets the same ID across runs.

## Report

The generated HTML is a single file with inline CSS, no CDN and no scripts. It shows severity counts, verification counts, the finding table, and truncated evidence hashes. States are printed verbatim so a reviewer can see what is still open.

## Limits

Signal does not scan code, exploit anything, or connect to a network. It organizes evidence and makes claims checkable. Findings are heuristics until a human verifies them; a hash proves that bytes did not change, not that the claim is true.
