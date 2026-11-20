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
5. **The preview touches nothing.** `demo` builds a synthetic store locally with no network calls and no credentials, following the sandbox-preview pattern used by authorized LAN scanners. Limits are stated explicitly rather than left implicit.

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
python signal.py report store.json --out results.sarif --format sarif
python -m unittest discover -s tests
```

`ingest` accepts common column variants (`Application`, `Severity`, `CWE`, `Status`). Fingerprints are the first 16 hex chars of SHA-256 over the canonical fields, so the same finding gets the same ID across runs.

### End-to-end example

Given `findings.csv`:

```csv
Application,Severity,CWE,Flaw Name,Filename,Finding Status
edge-gateway,High,CWE-89,SQL injection,gateway.py,open
auth-service,Medium,CWE-79,Reflected XSS,views.py,open
asset-api,Low,CWE-200,Verbose error,api.py,accepted
```

Ingest it, confirm one finding against a local evidence file, then render both outputs:

```bash
python signal.py ingest findings.csv --out store.json
python signal.py verify store.json 77995a79 confirmed --evidence proof.txt
python signal.py report store.json --out report.html
python signal.py report store.json --out results.sarif --format sarif
```

Real output from those commands:

```text
ingested 3 findings -> store.json
verified 77995a79 -> confirmed
wrote report.html (html)
wrote results.sarif (sarif)
```

The initial envelope has `report_id: 0fbbaa8f9bb9` and counts `High: 1, Medium: 1, Low: 1`. Fingerprints are stable across runs:

```text
77995a798e716a04 | High   | edge-gateway | SQL injection
04949a10e1b645c0 | Medium | auth-service | Reflected XSS
814237127c6694d9 | Low    | asset-api    | Verbose error
```

After `verify`, the envelope is rebuilt: `verification` becomes `confirmed: 1, unverified: 2`, `report_id` changes to `a06dd0abe9a8`, and the attached file is recorded by hash only (`580a79a6edfc856983c369120057677d43b8fadc32ee78daabdc0e56abf0a839`) with a timestamp. The SARIF output is version `2.1.0` with 3 rules and 3 results; each result carries the fingerprint and verification state under `properties`.

## Report

The generated HTML is a single file with inline CSS, no CDN and no scripts. It shows severity counts, verification counts, the finding table, and truncated evidence hashes. States are printed verbatim so a reviewer can see what is still open.

## Limits

Signal does not scan code, exploit anything, or connect to a network. It organizes evidence and makes claims checkable. Findings are heuristics until a human verifies them; a hash proves that bytes did not change, not that the claim is true.
