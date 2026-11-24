#!/usr/bin/env python3
"""Render output/sdr/sdr.json and output/coverage.json as one local HTML page.

Self-contained and offline: no external scripts, fonts, images or network
requests, because the data describes real findings and stays on the laptop.
Every value is HTML-escaped (evidence can carry attacker-controlled text such
as PR titles). The only script is an inline filter for the KSI list.

Implementation state (how far the checks are) and result (what the latest
evaluation found) are separate signals, and neither implies the other.
"""
import argparse
import html
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULT_RE = re.compile(r"^(\S+): (passed|failed|inconclusive|not evaluated)")
# Worst first: a KSI's overall result is its worst method result.
RESULT_ORDER = ["failed", "inconclusive", "not evaluated", "passed"]
RESULT_GLYPH = {"failed": "✗", "inconclusive": "?", "not evaluated": "–", "passed": "✓", "no results": "·"}
STATE_ORDER = ["Not started", "In progress", "Covered", "SDR-ready"]


def e(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def slug(ksi_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "-", ksi_id)


def results_by_ar(sdr_entry: dict) -> dict:
    """AR ID -> result word, from the SDR evidence text (the SDR is the single source)."""
    out = {}
    for ev in sdr_entry.get("ksiEvidence", []):
        m = RESULT_RE.match(ev.get("evidenceText", ""))
        if m:
            out[m.group(1)] = m.group(2)
    return out


def overall_result(results: dict) -> str:
    for r in RESULT_ORDER:
        if r in results.values():
            return r
    return "no results"


def state_badge(state: str) -> str:
    return f'<span class="state state-{slug(state.lower())}" title="Implementation state">{e(state)}</span>'


def result_badge(result: str) -> str:
    return (f'<span class="result result-{slug(result)}" title="Latest evaluation result">'
            f'<span aria-hidden="true">{RESULT_GLYPH[result]}</span> {e(result)}</span>')


def statements(items: list, empty: str) -> str:
    if not items:
        return f'<p class="muted">{e(empty)}</p>'
    return "".join(f"<p>{e(i)}</p>" for i in items)


def render_methods(row: dict, results: dict) -> str:
    if not row["methods"]:
        return '<p class="muted">No mapped assessment requirement yet.</p>'
    rows = []
    for m in row["methods"]:
        sc = m["scope"]
        reached = "not run" if not sc["run"] else f"{sc['reached']}/{sc['total']}"
        missing = f'<br><span class="muted">missing: {e(", ".join(sc["missing"]))}</span>' if sc["missing"] else ""
        res = results.get(m["ar"], "not evaluated")
        rows.append(
            f"<tr><td>{e(m['ar'])}</td><td>{e(m['kind'] or '?')}</td><td>{e(m['executor'] or 'none')}</td>"
            f"<td>{'implemented' if m['implemented'] else 'not implemented'}</td>"
            f"<td>{'yes' if m['fixtures'] else 'no'}</td><td>{e(reached)}{missing}</td>"
            f"<td>{result_badge(res)}</td></tr>")
    return ("<table><thead><tr><th>AR</th><th>Kind</th><th>Evaluator</th><th>Method</th><th>Fixtures</th>"
            "<th>Targets reached</th><th>Latest result</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def render_controls(row: dict) -> str:
    c = row["controls"]
    parts = [f"<p>{row['controls_decided']}/{row['controls_total']} related controls decided.</p><ul>"]
    for label in ("addressed", "inherited", "not-applicable", "open"):
        if c[label]:
            parts.append(f"<li><strong>{e(label)}</strong>: {e(', '.join(c[label]))}</li>")
    parts.append("</ul>")
    return "".join(parts)


def render_ksi(row: dict, entry: dict) -> str:
    results = results_by_ar(entry or {})
    overall = overall_result(results)
    haystack = f"{row['id']} {row['name']} {row['family']}".lower()
    status = (entry or {}).get("ksiImplementationStatus", "")
    return f"""
<details class="ksi" id="ksi-{slug(row['id'])}" data-state="{e(row['state'])}" data-result="{e(overall)}" data-family="{e(row['family'])}" data-text="{e(haystack)}">
<summary><span class="id">{e(row['id'])}</span> <span class="name">{e(row['name'])}</span>
 <span class="signals">{state_badge(row['state'])} {result_badge(overall)}</span></summary>
<div class="body">
<p class="statement">{e(row['statement'])}</p>
<p class="muted">Type: {e(row['type'])} · SDR status: {e(status)} · Methods {min(row['methods_implemented'], 2)}/2</p>
<h4>Implementation</h4>{statements((entry or {}).get('ksiImplementation', []), 'Nothing documented yet.')}
<h4>Validation</h4>{statements((entry or {}).get('ksiValidation', []), 'Nothing documented yet.')}
<h4>Methods</h4>{render_methods(row, results)}
<h4>Latest evidence</h4>{statements([ev.get('evidenceText', '') for ev in (entry or {}).get('ksiEvidence', [])], 'No evidence yet.')}
<h4>Related controls</h4>{render_controls(row)}
<h4>Assessment</h4>{statements((entry or {}).get('ksiAssessment', []), 'No assessor content (assessment is independent).')}
</div></details>"""


def render_overview(coverage: dict, results: dict) -> str:
    fam = defaultdict(lambda: {"n": 0, "states": defaultdict(int), "m": 0, "results": defaultdict(int)})
    for row in coverage["ksis"]:
        f = fam[row["family"]]
        f["n"] += 1
        f["states"][row["state"]] += 1
        f["m"] += min(row["methods_implemented"], 2)
        f["results"][overall_result(results.get(row["id"], {}))] += 1
    head = "".join(f"<th>{e(s)}</th>" for s in STATE_ORDER)
    rows = []
    for name in sorted(fam):
        f = fam[name]
        cells = "".join(f"<td>{f['states'].get(s, 0)}</td>" for s in STATE_ORDER)
        res = ", ".join(f"{f['results'][r]} {r}" for r in RESULT_ORDER + ["no results"] if f["results"].get(r))
        rows.append(f"<tr><td>{e(name)}</td><td>{f['n']}</td>{cells}<td>{f['m']}/{f['n'] * 2}</td><td>{e(res)}</td></tr>")
    return (f"<table><thead><tr><th>Family</th><th>KSIs</th>{head}<th>Methods</th><th>Latest results</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>")


CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1b1f24;--muted:#5b6570;--line:#d0d7de;--warn:#fff4d6;--warnfg:#5c3d00}
@media (prefers-color-scheme:dark){:root{--bg:#14181d;--fg:#e6e9ec;--muted:#9aa5b1;--line:#2d343c;--warn:#3a2f10;--warnfg:#ffd98a}}
body{font:15px/1.5 system-ui,sans-serif;margin:0;background:var(--bg);color:var(--fg)}
main{max-width:1100px;margin:0 auto;padding:1rem 1.25rem 4rem}
.banner{background:var(--warn);color:var(--warnfg);padding:.6rem 1.25rem;font-weight:600;border-bottom:1px solid var(--line)}
table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{border-bottom:1px solid var(--line);padding:.3rem .5rem;text-align:left;vertical-align:top}
.muted{color:var(--muted)}.kpis{display:flex;gap:1.5rem;flex-wrap:wrap;margin:.5rem 0}.kpis div{font-size:1.4rem}.kpis span{display:block;font-size:.8rem;color:var(--muted)}
.filters{display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0}input,select{font:inherit;padding:.25rem .4rem;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:4px}
details.ksi{border:1px solid var(--line);border-radius:6px;margin:.4rem 0}details.ksi>summary{cursor:pointer;padding:.5rem .75rem;display:flex;gap:.75rem;align-items:baseline;flex-wrap:wrap}
.id{font-family:ui-monospace,monospace;font-weight:600}.signals{margin-left:auto;display:flex;gap:.5rem}.body{padding:0 1rem 1rem}
.state{border:1.5px solid var(--fg);border-radius:999px;padding:0 .6rem;font-size:.8rem}
.state-sdr-ready{border-width:3px}.state-not-started{border-style:dashed;color:var(--muted);border-color:var(--muted)}
.result{border-radius:4px;padding:0 .5rem;font-size:.8rem;border:1px solid var(--line);background:color-mix(in srgb,var(--fg) 6%,transparent)}
.result-failed{font-weight:700;background:color-mix(in srgb,#d1242f 22%,transparent);border-color:#d1242f}
.result-passed{background:color-mix(in srgb,#1a7f37 20%,transparent);border-color:#1a7f37}
h4{margin:1rem 0 .25rem}.hidden{display:none}
"""

JS = """
(function(){
  var q=document.getElementById('q'),st=document.getElementById('state'),rs=document.getElementById('result'),
      cards=[].slice.call(document.querySelectorAll('details.ksi')),n=document.getElementById('shown');
  function apply(){
    var t=q.value.toLowerCase(),shown=0;
    cards.forEach(function(c){
      var ok=(!t||c.dataset.text.indexOf(t)>-1)&&(!st.value||c.dataset.state===st.value)&&(!rs.value||c.dataset.result===rs.value);
      c.classList.toggle('hidden',!ok);if(ok)shown++;
    });
    n.textContent=shown+' of '+cards.length+' KSIs shown';
  }
  [q,st,rs].forEach(function(el){el.addEventListener('input',apply)});
  try{if(location.hash){var t=document.querySelector(location.hash);if(t&&t.tagName==='DETAILS')t.open=true}}catch(x){}
  apply();
})();
"""


def render(sdr: dict, coverage: dict) -> str:
    entries = {k["ksiId"]: k for k in sdr.get("keySecurityIndicators", [])}
    results = {kid: results_by_ar(ent) for kid, ent in entries.items()}
    s = coverage["summary"]
    options = lambda items: "".join(f'<option value="{e(i)}">{e(i)}</option>' for i in items)
    cards = "".join(render_ksi(row, entries.get(row["id"])) for row in coverage["ksis"])
    meta = sdr.get("metadata", {})
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ROSA Seaplane SDR (local run)</title><style>{CSS}</style></head>
<body>
<div class="banner">Local run. Not certification evidence.</div>
<main>
<h1>ROSA Seaplane Security Decision Record</h1>
<p class="muted">{e(meta.get('updateSource', ''))} · generated {e(meta.get('lastUpdated', ''))} · SDR version {e(meta.get('version', ''))}</p>
<div class="kpis">
 <div>{s['covered']}/{s['ksis']}<span>KSIs covered</span></div>
 <div>{s['sdr_ready']}/{s['ksis']}<span>SDR-ready</span></div>
 <div>{s['methods_implemented']}/{s['methods_required']}<span>automated methods</span></div>
 <div>{s['deferred_process']}<span>process KSIs deferred</span></div>
</div>
<p class="muted">State is how far the checks are implemented. Result is what the latest evaluation found. Neither implies the other.</p>
<h2>Overview by family</h2>
{render_overview(coverage, results)}
<h2>KSIs</h2>
<div class="filters">
 <input id="q" type="search" placeholder="Filter by ID, name or family" aria-label="Filter">
 <select id="state" aria-label="State"><option value="">Any state</option>{options(STATE_ORDER)}</select>
 <select id="result" aria-label="Result"><option value="">Any result</option>{options(RESULT_ORDER + ['no results'])}</select>
 <span id="shown" class="muted"></span>
</div>
{cards}
</main>
<script>{JS}</script>
</body></html>
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sdr", default=str(ROOT / "output/sdr/sdr.json"))
    ap.add_argument("--coverage", default=str(ROOT / "output/coverage.json"))
    ap.add_argument("--out", default=str(ROOT / "output/sdr/index.html"))
    args = ap.parse_args()
    for p in (args.sdr, args.coverage):
        if not Path(p).is_file():
            sys.exit(f"ERROR: {p} not found; run `make sdr` first.")
    page = render(json.loads(Path(args.sdr).read_text()), json.loads(Path(args.coverage).read_text()))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
