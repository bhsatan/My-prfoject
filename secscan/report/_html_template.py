"""Self-contained HTML template for the SecScan report.

No CDN links, no external resources, no network dependencies.
All CSS and SVG are inlined.
"""

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecScan Report — Score {{SCORE}}/100</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --text: #e2e8f0; --muted: #94a3b8;
    --pass: #22c55e; --fail: #ef4444; --unknown: #eab308;
    --sev-critical: #ef4444; --sev-high: #f97316;
    --sev-medium: #0ea5e9; --sev-low: #94a3b8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif;
         background: var(--bg); color: var(--text);
         max-width: 900px; margin: 0 auto; padding: 2rem 1rem; }
  .warning-banner {
    background: #422006; border: 1px solid #f97316; border-radius: 8px;
    padding: 0.75rem 1rem; margin-bottom: 1.5rem; color: #fed7aa;
    font-size: 0.9rem; text-align: center;
  }
  .header { text-align: center; margin-bottom: 2rem; }
  .header h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
  .header .time { color: var(--muted); font-size: 0.85rem; }

  /* Score gauge */
  .gauge { text-align: center; margin: 1.5rem 0; }
  .gauge svg { width: 180px; height: 100px; }
  .gauge .score-num { font-size: 2.5rem; font-weight: 700; }
  .gauge .grade { font-size: 1.2rem; color: var(--muted); }

  /* Summary cards */
  .summary { display: flex; gap: 1rem; justify-content: center;
             flex-wrap: wrap; margin-bottom: 2rem; }
  .card { background: var(--surface); border-radius: 8px; padding: 1rem 1.5rem;
          text-align: center; min-width: 100px; }
  .card .num { font-size: 1.8rem; font-weight: 700; }
  .card .label { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; }
  .card.pass .num { color: var(--pass); }
  .card.fail .num { color: var(--fail); }
  .card.unknown .num { color: var(--unknown); }

  /* Severity table */
  .sev-table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
  .sev-table td { padding: 0.4rem 0.5rem; }
  .sev-label { font-weight: 600; font-size: 0.8rem; width: 80px; text-align: right; }
  .bar-cell { width: 60%; }
  .bar-cell span { display: inline-block; height: 1.2rem; border-radius: 2px; }
  .bar-fail { background: var(--fail); }
  .bar-unknown { background: var(--unknown); }
  .bar-pass { background: var(--pass); }
  .sev-critical { color: var(--sev-critical); }
  .sev-high { color: var(--sev-high); }
  .sev-medium { color: var(--sev-medium); }
  .sev-low { color: var(--sev-low); }

  /* Findings */
  .section-title { font-size: 1.2rem; margin: 1.5rem 0 1rem;
                   padding-bottom: 0.3rem; border-bottom: 2px solid var(--surface); }
  .issues { color: var(--fail); }
  .passed-title { color: var(--pass); }
  .finding { background: var(--surface); border-radius: 8px; padding: 1rem;
             margin-bottom: 1rem; border-left: 4px solid var(--fail); }
  .finding.unknown { border-left-color: var(--unknown); }
  .finding-header { display: flex; align-items: center; gap: 0.5rem;
                    flex-wrap: wrap; margin-bottom: 0.5rem; }
  .finding-title { font-weight: 600; flex: 1; }
  .badge { font-size: 0.7rem; font-weight: 700; padding: 0.15rem 0.5rem;
           border-radius: 4px; text-transform: uppercase; }
  .badge.sev-critical { background: #7f1d1d; color: #fca5a5; }
  .badge.sev-high { background: #7c2d12; color: #fed7aa; }
  .badge.sev-medium { background: #0c4a6e; color: #bae6fd; }
  .badge.sev-low { background: #334155; color: #cbd5e1; }
  .badge.status-fail { background: #7f1d1d; color: #fca5a5; }
  .badge.status-unknown { background: #713f12; color: #fef08a; }
  .detail { color: var(--muted); font-size: 0.9rem; margin-bottom: 0.5rem; }
  .why { font-size: 0.9rem; margin-bottom: 0.5rem; }
  .fix { font-size: 0.9rem; margin-bottom: 0.5rem; }
  .fix ol { padding-left: 1.5rem; margin-top: 0.3rem; }
  .fix li { margin-bottom: 0.2rem; }
  .meta { font-size: 0.8rem; color: var(--muted); }
  .passed-list { list-style: none; padding: 0; }
  .passed-list li { padding: 0.3rem 0; color: var(--pass); font-size: 0.95rem; }

  .footer { text-align: center; margin-top: 2rem; padding-top: 1rem;
            border-top: 1px solid var(--surface); color: var(--muted);
            font-size: 0.8rem; }
</style>
</head>
<body>

<div class="warning-banner">
  ⚠ This report contains sensitive information about your system's security.
  Do not share it publicly.
</div>

<div class="header">
  <h1>SecScan Security Posture Report</h1>
  <div class="time">Generated: {{SCAN_TIME}}</div>
</div>

<div class="gauge">
  <svg viewBox="0 0 180 100">
    <path d="M 20 90 A 70 70 0 0 1 160 90" fill="none" stroke="#334155"
          stroke-width="12" stroke-linecap="round"/>
    <path d="M 20 90 A 70 70 0 0 1 160 90" fill="none" stroke="{{SCORE_COLOUR}}"
          stroke-width="12" stroke-linecap="round"
          stroke-dasharray="{{SCORE}},1000"
          style="transform-origin:center;"/>
  </svg>
  <div class="score-num" style="color:{{SCORE_COLOUR}}">{{SCORE}}</div>
  <div class="grade">Grade {{GRADE}}</div>
</div>

<div class="summary">
  <div class="card pass"><div class="num">{{PASSED}}</div><div class="label">Passed</div></div>
  <div class="card fail"><div class="num">{{FAILED}}</div><div class="label">Failed</div></div>
  <div class="card unknown"><div class="num">{{UNKNOWN}}</div><div class="label">Unknown</div></div>
  <div class="card"><div class="num">{{TOTAL}}</div><div class="label">Total</div></div>
</div>

{{SEVERITY_CHART}}

{{FINDINGS}}

<div class="footer">
  SecScan v{{VERSION}} · Generated: {{SCAN_TIME}}
</div>

</body>
</html>
"""
