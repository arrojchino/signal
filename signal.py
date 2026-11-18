"""Signal: local-first appsec finding ledger and report generator.

Dual-use module and CLI. Stdlib only. All findings carry a stable fingerprint,
an explicit verification state, and hashed evidence references.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1
STATES = ("unverified", "confirmed", "ruled_out", "open_proof_gap")
CANONICAL = ("Application Name", "Severity", "CWE ID", "Flaw Name", "Filename/Class", "Finding Status")


def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def fingerprint(finding: dict) -> str:
    parts = [str(finding.get(k, "")) for k in CANONICAL]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]


def load_rules(path: Path) -> dict:
    rules = json.loads(path.read_text(encoding="utf-8"))
    if rules.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported rules schema")
    if not isinstance(rules.get("severity_order"), list) or not rules["severity_order"]:
        raise ValueError("rules.severity_order must be a non-empty list")
    return rules


def normalize(row: dict, rules: dict) -> dict:
    mapping = {
        "Application Name": row.get("Application") or row.get("Application Name") or "unknown",
        "Severity": row.get("Severity") or row.get("Custom Severity") or "Unspecified",
        "CWE ID": row.get("CWE") or row.get("CWE ID") or "-",
        "Flaw Name": row.get("Flaw Name") or row.get("Title") or "Unnamed finding",
        "Filename/Class": row.get("Filename") or row.get("Filename/Class") or "-",
        "Finding Status": row.get("Finding Status") or row.get("Status") or "open",
    }
    for k, v in mapping.items():
        mapping[k] = str(v).strip()
    mapping["Verification"] = "unverified"
    mapping["Evidence"] = []
    mapping["Severity Rank"] = rules["severity_order"].index(mapping["Severity"]) if mapping["Severity"] in rules["severity_order"] else 99
    mapping["Fingerprint"] = fingerprint(mapping)
    return mapping


def ingest(csv_path: Path, rules: dict) -> dict:
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    findings = [normalize(row, rules) for row in rows]
    return envelope(findings, rules)


def envelope(findings: list, rules: dict) -> dict:
    counts = {}
    for f in findings:
        counts[f["Severity"]] = counts.get(f["Severity"], 0) + 1
    states = {}
    for f in findings:
        states[f["Verification"]] = states.get(f["Verification"], 0) + 1
    payload = json.dumps({"findings": findings, "schema_version": SCHEMA_VERSION}, sort_keys=True)
    return {
        "schema_version": SCHEMA_VERSION,
        "report_id": hashlib.sha256(payload.encode()).hexdigest()[:12],
        "generated_at": utcnow(),
        "rules": rules["name"],
        "counts": counts,
        "verification": states,
        "findings": findings,
    }


def verify(store: dict, fp: str, state: str, evidence: Path | None) -> dict:
    if state not in STATES:
        raise ValueError("state must be one of " + ", ".join(STATES))
    hit = None
    for f in store["findings"]:
        if f["Fingerprint"].startswith(fp):
            hit = f
            break
    if hit is None:
        raise KeyError("no finding with fingerprint prefix " + fp)
    hit["Verification"] = state
    if evidence:
        if not evidence.is_file():
            raise FileNotFoundError(str(evidence))
        hit["Evidence"].append({
            "path": str(evidence),
            "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
            "recorded_at": utcnow(),
        })
    return envelope(store["findings"], {"name": store["rules"]})


REPORT_CSS = """
:root{color-scheme:dark;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;background:#080b09;color:#e8efe9}
*{box-sizing:border-box}body{margin:0;padding:34px 26px 60px;background:radial-gradient(800px 420px at 85% -10%,#12271a,#080b09 65%)}
header,main,footer{max-width:1000px;margin:0 auto}h1{font-size:clamp(30px,6vw,54px);letter-spacing:.14em;margin:0;color:#d8f0dc;font-weight:500}
.sub{color:#789184;font-size:11px;letter-spacing:.2em;text-transform:uppercase;margin-top:10px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:26px 0}
.card{border:1px solid #1d2c22;padding:15px 17px;background:#0b100d}.card .k{font-size:10px;letter-spacing:.16em;color:#7c9486;text-transform:uppercase}.card .v{font-size:28px;margin-top:8px;color:#b7e3bf}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;padding:9px 7px;border-bottom:1px solid #16231b}th{font-size:10px;letter-spacing:.12em;color:#688073;text-transform:uppercase}
.ok{color:#7fbf92}.warn{color:#d7b25a}.bad{color:#e58a6a}.muted{color:#7c9486}footer{border-top:1px solid #1d2c22;margin-top:30px;padding-top:16px;font-size:10px;letter-spacing:.12em;color:#5e7466}
"""


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def render_html(store: dict) -> str:
    cards = "".join(f'<div class="card"><div class="k">{esc(k)}</div><div class="v">{v}</div></div>' for k, v in store["counts"].items())
    vcards = "".join(f'<div class="card"><div class="k">{esc(k)}</div><div class="v">{v}</div></div>' for k, v in store["verification"].items())
    rows = []
    for f in store["findings"]:
        cls = "bad" if f["Severity Rank"] <= 1 else ("warn" if f["Severity Rank"] == 2 else "ok")
        ev = ", ".join(e["sha256"][:10] for e in f["Evidence"]) or "-"
        rows.append(
            f'<tr><td class="muted">{f["Fingerprint"]}</td><td class="{cls}">{esc(f["Severity"])}</td>'
            f'<td>{esc(f["Application Name"])}</td><td>{esc(f["CWE ID"])}</td>'
            f'<td>{esc(f["Flaw Name"])}</td><td>{esc(f["Verification"])}</td><td class="muted">{ev}</td></tr>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signal — finding ledger</title><style>{REPORT_CSS}</style></head><body>
<header><h1>SIGNAL</h1><div class="sub">Local finding ledger · report {esc(store['report_id'])}</div></header>
<main><div class="grid">{cards}</div><h2 class="sub">Verification</h2><div class="grid">{vcards}</div>
<h2 class="sub">Findings</h2><table><thead><tr><th>ID</th><th>Severity</th><th>Application</th><th>CWE</th><th>Finding</th><th>State</th><th>Evidence</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></main>
<footer>Schema {store['schema_version']} · rules {esc(store['rules'])} · generated {esc(store['generated_at'])} · evidence hashes are SHA-256 · states: confirmed / ruled_out / open_proof_gap</footer>
</body></html>"""


def render_sarif(store: dict) -> str:
    """SARIF 2.1.0 for CI consumers. Rules are keyed by CWE, results by fingerprint."""
    levels = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
    rules, seen = [], set()
    results = []
    for f in store["findings"]:
        rid = f["CWE ID"] if f["CWE ID"] != "-" else "SIGNAL-UNMAPPED"
        if rid not in seen:
            seen.add(rid)
            rules.append({
                "id": rid,
                "name": f["Flaw Name"],
                "shortDescription": {"text": f["Flaw Name"]},
                "defaultConfiguration": {"level": levels.get(f["Severity"], "note")},
            })
        results.append({
            "ruleId": rid,
            "level": levels.get(f["Severity"], "note"),
            "message": {"text": f"{f['Flaw Name']} in {f['Application Name']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["Filename/Class"]}}}],
            "partialFingerprints": {"signal/v1": f["Fingerprint"]},
            "properties": {
                "application": f["Application Name"],
                "verification": f["Verification"],
                "evidence": [e["sha256"] for e in f["Evidence"]],
            },
        })
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "signal", "version": "1.0.0", "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def main(argv=None):
    p = argparse.ArgumentParser(description="Signal: local appsec finding ledger")
    p.add_argument("--rules", default="rules.json", help="path to rules.json")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("ingest"); a.add_argument("csv"); a.add_argument("--out", default="store.json")
    v = sub.add_parser("verify"); v.add_argument("store"); v.add_argument("fingerprint"); v.add_argument("state", choices=STATES); v.add_argument("--evidence")
    r = sub.add_parser("report"); r.add_argument("store"); r.add_argument("--out", default="report.html"); r.add_argument("--format", choices=("html", "sarif"), default="html")
    sub.add_parser("demo")
    args = p.parse_args(argv)
    rules = load_rules(Path(args.rules))
    if args.cmd == "ingest":
        store = ingest(Path(args.csv), rules)
        Path(args.out).write_text(json.dumps(store, indent=2), encoding="utf-8")
        print(f"ingested {len(store['findings'])} findings -> {args.out}")
    elif args.cmd == "verify":
        store = json.loads(Path(args.store).read_text(encoding="utf-8"))
        store = verify(store, args.fingerprint, args.state, Path(args.evidence) if args.evidence else None)
        Path(args.store).write_text(json.dumps(store, indent=2), encoding="utf-8")
        print(f"verified {args.fingerprint} -> {args.state}")
    elif args.cmd == "report":
        store = json.loads(Path(args.store).read_text(encoding="utf-8"))
        text = render_html(store) if args.format == "html" else render_sarif(store)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({args.format})")
    elif args.cmd == "demo":
        rows = [
            {"Application":"edge-gateway","Severity":"High","CWE":"CWE-89","Flaw Name":"SQL injection","Filename":"gateway.py","Finding Status":"open"},
            {"Application":"auth-service","Severity":"Medium","CWE":"CWE-79","Flaw Name":"Reflected XSS","Filename":"views.py","Finding Status":"open"},
            {"Application":"asset-api","Severity":"Low","CWE":"CWE-200","Flaw Name":"Verbose error","Filename":"api.py","Finding Status":"accepted"},
        ]
        store = envelope([normalize(r, rules) for r in rows], rules)
        Path("demo_store.json").write_text(json.dumps(store, indent=2), encoding="utf-8")
        Path("demo_report.html").write_text(render_html(store), encoding="utf-8")
        print(f"demo: {len(store['findings'])} findings, report {store['report_id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
