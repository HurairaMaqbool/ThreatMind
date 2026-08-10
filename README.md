# KQL Detection Engine — v2 (six-agent architecture)

Turns security-blog write-ups into **validated Microsoft Defender Advanced Hunting
(KQL) detections**, end to end, with a Streamlit dashboard to browse them.

It runs **fully offline in demo mode** — no API key, no network — so you can try
everything immediately. In live mode it fetches real feeds and uses Claude.

---

## What's new in v2

The pipeline was rebuilt into **six specialised agents** (was a single
analyze→generate pass):

```
            ┌─────────┐
 raw post → │ TRIAGE  │  huntable? (drop vendor news / opinion / no-behavior)
            └────┬────┘
                 │ huntable
            ┌────▼────┐
            │ DEDUP   │  post-level: never reprocess a blog already seen (SQLite)
            └────┬────┘
            ┌────▼──────────┐
            │ EXTRACTION    │  every behavior → MITRE ATT&CK + rich artifacts
            └────┬──────────┘     (processes, command_lines, registry, lolbins, network…)
            ┌────▼──────────┐
            │ COVERAGE      │  THE BRAIN (separate from the generator):
            │ PLANNER       │  Pyramid-of-Pain tier × Defender table → detection angles
            └────┬──────────┘
            ┌────▼──────────┐
            │ GENERATOR     │  one schema-grounded KQL per angle (fan-out)
            └────┬──────────┘
            ┌────▼──────────┐     ┌─────────── tools (code, not prompts) ───────────┐
            │ VALIDATOR     │ ◄──►│ kql_lint · schema_check (vs authoritative schema) │
            │ (retry loop)  │     │ · dry_run.  Rewrites on failure, caps at N iters. │
            └────┬──────────┘     └───────────────────────────────────────────────────┘
            ┌────▼──────────┐
            │ ENRICH        │  evasion · resilience · operationalization · Sigma rule
            └────┬──────────┘
            ┌────▼──────────┐
            │ COVERAGE      │  "did we cover everything?" gap report per threat
            │ CRITIC        │
            └────┬──────────┘
            ┌────▼──────────┐
            │ DEDUP QUERIES │  similarity search (Jaccard) vs a persistent query library
            └───────────────┘
```

Plus:
- **Authoritative Defender schema registry** (`app/schema.py`) grounds the generator
  and validator — hallucinated columns like `CommandLineText` are rejected.
- **Two dedup guarantees**: posts (so a blog is never reprocessed) **and** queries
  (so the same detection isn't promoted twice).
- **Streamlit dashboard** with a detailed **Queries** tab (metric cards, charts,
  filterable table, per-query copy/download).

---

## Quick start (offline demo — recommended first run)

```bash
pip install -r requirements.txt

# 1) generate detections from the bundled sample posts (no key/network needed)
python run.py --reset --demo

# 2) open the dashboard
streamlit run dashboard/app.py        # → http://localhost:8501
```

In the dashboard: **Scanner** runs the pipeline, **Queries** is the detection
browser, **Downloads** exports `.kql`/Sigma/JSON, **History** lists past scans.

> You can also just click **▶ Run scan** on the Scanner tab — you don't have to use
> the CLI at all.

### Legacy/bonus web dashboard (FastAPI)

```bash
python run.py --demo --serve          # → http://localhost:8000
```

---

## Live mode (real feeds + Claude)

```bash
export ANTHROPIC_API_KEY=sk-ant-...    # optional: without it, live falls back to the rule engine
python run.py                          # fetches the 10 configured blogs
streamlit run dashboard/app.py
```

Live mode uses the verbatim agent prompts in `app/prompts.py`. If a model call
fails, that single item falls back to the offline engine, so a run never crashes.

---

## CLI

```
python run.py --demo            # offline run on bundled sample posts
python run.py                   # live run (fetch the 10 feeds)
python run.py --serve           # launch the FastAPI dashboard (:8000)
python run.py --reset           # wipe persistent stores (seen_index + query library)
python run.py --demo --embed    # bake results into web/index.html (standalone file)
python run.py --port 9000 --serve
```

---

## Assumed data schema (`results.json`)

The dashboard reads this file (written after every scan). Shape:

```jsonc
{
  "generated_at": "ISO-8601",
  "mode": "demo|live",
  "sources": ["BleepingComputer", ...],
  "pipeline": {                       // headline counts
    "collected", "huntable", "new", "duplicates", "behaviors", "angles",
    "queries", "valid", "rewritten_by_loop", "flagged_for_review",
    "duplicate_queries_vs_library", "seen_index_size", "query_library_size"
  },
  "coverage_summary": {
    "threats", "threats_with_behavioral_query",
    "threats_without_behavioral_query", "platforms_covered", "overall"
  },
  "messages": [ { "agent": "...", "detail": "..." } ],   // agent trace
  "threats": [ {                       // one per huntable post (nested view)
    "threat_id", "source", "url", "title", "published", "summary",
    "threat_type", "severity", "triage": {...}, "iocs": {...}, "cves": [...],
    "behaviors": [ { "behavior_id", "description", "attack_technique",
                     "attack_tactic", "artifacts": {...} } ],
    "angles":    [ { "angle_id", "behavior_id", "tier", "durability",
                     "target_table", "detection_idea", "expected_false_positives" } ],
    "queries":   [ <query> ],
    "coverage_critic": { "behaviors_without_behavioral_detection": [...],
                         "uncovered_data_sources": [...], "skipped_behaviors": [...],
                         "overall_coverage": "complete|partial" }
  } ],
  "queries": [ <query> ]               // FLAT list — this is what the Queries tab renders
}
```

Each **`<query>`** (the unit the dashboard table shows):

```jsonc
{
  "query_id", "angle_id", "behavior_id", "threat_id", "threat_name",
  "title", "platform",            // platform = Defender product (Endpoint / Office 365 / Identity)
  "target_table",                 // the Advanced Hunting table
  "technique", "tactic",
  "tier",                         // Pyramid of Pain: behavioral | tool_artifact | indicator
  "durability", "severity",       // severity derived from the ATT&CK tactic
  "kql", "sigma", "detection_idea", "expected_false_positives",
  "validation": { "status", "valid", "iterations", "changes", "lint",
                  "schema_errors", "dry_run" },
  "evasion": [...], "resilience": [...], "operationalization": {...},
  "duplicate", "duplicate_of"
}
```

If a query ever lacks `tier`, the dashboard derives it from the KQL content
(`tools.classify_tier`).

---

## Dashboard — Queries tab (component layout)

```
┌───────────────────────────────────────────────────────────────────────┐
│  [ Total queries ] [ Platforms ] [ Threats w/ behavioral ] [ Gaps ]     │  ← metric cards
├───────────────────────────────────────┬───────────────────────────────┤
│  Bar: queries by PLATFORM             │  Bar: queries by PYRAMID TIER  │  ← two charts
├───────────────────────────────────────┴───────────────────────────────┤
│  Filters:  Platform ▾  Tier ▾  Severity ▾  Technique ▾  [search]  □dupes│  ← combine
├───────────────────────────────────────────────────────────────────────┤
│  ▸ [TIER] Threat name · platform · Txxxx · severity · status            │  ← expandable rows
│      └ KQL (st.code, copy icon) · ⬇download · evasion/resilience · Sigma│
│  ▸ … (paginated)                                                        │
└───────────────────────────────────────────────────────────────────────┘
```

The Queries tab is a **drop-in module** (`dashboard/queries_tab.py`). Wire it into
any Streamlit tab bar with one line:

```python
from dashboard.queries_tab import render_queries_tab
with tab_queries:
    render_queries_tab()
```

---

## Project layout

```
kql-detection-engine/
├── run.py                     # CLI entrypoint
├── requirements.txt
├── README.md
├── results.json               # written by each run; the dashboards read this
├── app/                       # the engine
│   ├── schema.py              #   authoritative Defender Advanced Hunting schema
│   ├── prompts.py             #   the six agent prompts + enrichment prompt
│   ├── state.py               #   LangGraph state
│   ├── agents.py              #   the six nodes + validator retry loop
│   ├── graph.py                #   linear graph wiring + results assembly
│   ├── tools.py               #   IOC/ATT&CK + lint/schema_check/dry_run/tier/dedup
│   ├── demo_engine.py         #   offline brain (all six stages, schema-valid KQL)
│   ├── persistence.py         #   seen_index, query library, results, history
│   ├── llm.py                 #   Anthropic client (live mode)
│   ├── config.py              #   sources, feeds, thresholds, severity map
│   └── server.py              #   FastAPI app (legacy/bonus UI + JSON API)
├── dashboard/                 # Streamlit app (primary UI)
│   ├── app.py                 #   tab bar: Scanner · Queries · Downloads · History · Chat
│   └── queries_tab.py         #   the Queries dashboard (self-contained module)
├── web/index.html             # legacy single-file dashboard (auto-adapts to v2 schema)
└── data/
    ├── sample_posts.json      # 4 bundled write-ups for demo mode
    ├── seen.sqlite3           # persistent post-dedup store (created on first run)
    └── query_library.json     # persistent query-dedup store (created on first run)
```

---

## Notes

- **Demo vs live**: demo uses hand-authored, deterministic case knowledge + the real
  IOCs extracted from each article. Live uses Claude with the same prompts. Both pass
  the same lint + schema check.
- **The validator loop** rewrites a failing query (fix hallucinated fields, add a time
  bound, tighten cost) and re-runs the checks, capped at `VALIDATOR_MAX_ITERS` (default 3);
  anything still failing is flagged `needs_human_review` rather than silently dropped.
- **Coverage is honestly reported**: an indicator-only behavior (e.g. C2 by domain) is
  surfaced as a gap by the Coverage-Critic, not hidden.

---

## Author / Contact

**Huraira Maqbool** — AI Engineer (LLMs, RAG systems, agentic AI pipelines & multi-agent architectures)

- GitHub: [github.com/HurairaMaqbool](https://github.com/HurairaMaqbool)
- LinkedIn: [linkedin.com/in/huraira-maqbool-b696a5277](https://www.linkedin.com/in/huraira-maqbool-b696a5277/)
- Email: [hurairac37@gmail.com](mailto:hurairac37@gmail.com)

Feel free to connect, open an issue, or reach out for collaboration.
