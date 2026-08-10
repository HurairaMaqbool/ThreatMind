# 🛡️ ThreatMind — Autonomous Cyber Threat Intelligence Pipeline

![Python](https://img.shields.io/badge/python-3.11-blue)
![LangGraph](https://img.shields.io/badge/LangGraph-1.0-purple)
![Groq](https://img.shields.io/badge/LLM-Groq_Llama_3-orange)
![FastAPI](https://img.shields.io/badge/API-FastAPI-009688)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B)
![Docker](https://img.shields.io/badge/Deploy-Docker_Compose-2496ED)

ThreatMind is an 11-agent LangGraph pipeline that continuously watches security
blogs and advisories, decides what's actually worth hunting for, and turns it into
validated, multi-platform SIEM detections — with zero manual triage.

It runs as a standing service: a scheduler crawls threat-intel feeds on an interval,
runs every huntable article through the full pipeline, and pushes finished
detections into a SOC-style dashboard and REST API, with Slack/email alerts for
anything severe.

### Contents
- [Pipeline architecture](#pipeline-architecture)
- [What makes this different](#what-makes-this-different-from-a-single-shot-llm-writes-kql-script)
- [Quick start](#quick-start)
- [Configuration](#configuration-env)
- [REST API](#rest-api-apimainpy)
- [Dashboard](#dashboard-dashboardapppy)
- [Project layout](#project-layout)
- [Notes](#notes)
- [Author / Contact](#author--contact)

---

## Pipeline architecture

```
 RSS feed → new article
     │
     ▼
┌─────────────┐
│ 0· TRIAGE   │  is this article huntable? (drops vendor news / opinion / no real behavior)
└──────┬──────┘
       │ huntable
┌──────▼──────┐
│ 1· DISCOVERY│  fetches the article HTML (retries on failure)
└──────┬──────┘
┌──────▼──────┐
│ 2· EXTRACTION│ strips boilerplate → clean article text, title, published date
└──────┬──────┘
┌──────▼──────────┐
│ 3· THREAT INTEL  │  LLM extracts behaviors (mapped to MITRE ATT&CK) + IOCs
└──────┬───────────┘
┌──────▼──────────────┐
│ 4· COVERAGE PLANNER  │  behaviors → detection angles (Pyramid-of-Pain tier × Sentinel table)
└──────┬───────────────┘
┌──────▼──────┐
│ 5· RAG      │  ChromaDB: pulls schema snippets, similar past threats, historical KQL
└──────┬──────┘
┌──────▼──────────┐
│ 6· REASONING     │  chain-of-thought pass: detection strategy + relevant columns
└──────┬───────────┘
┌──────▼──────────────┐
│ 7· KQL GENERATOR     │  schema-grounded KQL per detection angle
└──────┬───────────────┘
┌──────▼──────────────┐     ┌── retry loop (max 3 attempts, min validation score 70) ──┐
│ 8· VALIDATOR         │ ◄──►│ auto-fixes known wrong column names (e.g. CommandLine →  │
│                       │     │ ProcessCommandLine) before re-scoring                    │
└──────┬───────────────┘     └───────────────────────────────────────────────────────────┘
       │ passed / max retries reached
┌──────▼──────────────┐
│ 9· COVERAGE CRITIC   │  assigns severity, flags gaps, verdicts overall coverage
└──────┬───────────────┘
┌──────▼──────┐
│ 10· REPORT  │  final report + multi-platform conversion, persisted to ChromaDB & SQLite
└─────────────┘
```

Routing is conditional, not just linear: Agent 0 can end the run early on a
non-huntable article, and Agent 8 loops back to Agent 7 to regenerate any query
that fails validation, up to `MAX_VALIDATION_RETRIES` (default 3).

---

## What makes this different from a single-shot "LLM writes KQL" script

- **A dedicated Coverage Planner**, separate from the generator, decides *what*
  to detect (behavioral vs. tool-artifact vs. indicator-only) before any KQL is
  written — so detections are prioritized by durability, not just generated
  wherever an IOC exists.
- **RAG-grounded generation**: the generator isn't working from the LLM's
  memory of Sentinel/Defender schema — it's grounded against an authoritative
  schema file (`config/sentinel_schema.yaml`) via ChromaDB retrieval, plus
  historical KQL and similar past threats for context.
- **A real validator, not a linter**: known wrong-but-plausible column names
  (`CommandLine`, `ParentProcessName`, etc.) are auto-corrected against the
  actual Advanced Hunting schema, then re-scored — not just flagged.
- **Honest coverage reporting**: the Coverage Critic reports gaps (e.g. an
  IOC-only behavior with no durable behavioral detection) instead of silently
  dropping them.
- **Multi-platform output**: validated KQL is converted to Sigma and then to
  Splunk, QRadar, Elasticsearch, and CrowdStrike via pySigma backends, plus
  Wazuh and SentinelOne via LLM conversion — so one pipeline run produces
  detections for six SIEM platforms, not just Microsoft Sentinel.
- **It's a service, not a script**: a scheduler crawls on a fixed interval,
  dedupes already-seen URLs (ChromaDB), and pushes Slack/email alerts for
  anything above LOW severity — this is built to run unattended.

---

## Quick start

### Local

```bash
pip install -r requirements.txt
cp .env.example .env      # add your GROQ_API_KEY at minimum

# Run the API + scheduler
uvicorn api.main:app --host 0.0.0.0 --port 8000

# In a separate terminal, run the dashboard
streamlit run dashboard/app.py     # → http://localhost:8501
```

### Docker

```bash
docker compose up --build
# API      → http://localhost:8000
# Dashboard → http://localhost:8501
```

`docker-compose.yml` runs the scheduler and API together in one container and
the Streamlit dashboard in another, sharing the ChromaDB store and logs as
mounted volumes.

---

## Configuration (`.env`)

Key variables (see `.env.example` for the full list):

| Variable | Purpose |
|---|---|
| `GROQ_API_KEY` | Required. All agents run on Groq (Llama 3.1 8B for most agents, Llama 3.3 70B for reasoning-heavy ones) |
| `CRAWL_INTERVAL_HOURS` | How often the scheduler polls the configured feeds (default 6) |
| `MAX_ARTICLES_PER_CYCLE` | Cap on articles processed per crawl cycle (default 3) |
| `MIN_VALIDATION_SCORE` | Minimum score for a KQL query to pass validation (default 70) |
| `MAX_VALIDATION_RETRIES` | Cap on the Agent 7 ↔ Agent 8 retry loop (default 3) |
| `ENABLE_MULTI_PLATFORM` | Toggle Sigma/multi-SIEM conversion in Agent 10 |
| `SLACK_WEBHOOK_URL` / `SMTP_*` | Alerting for HIGH/CRITICAL findings |

Feeds are configured in `config/feeds.yaml` — currently 10 sources, including
Microsoft Security Blog, CISA Advisories, Unit 42, CrowdStrike, Krebs on
Security, SANS ISC, Mandiant, BleepingComputer, The Hacker News, and Schneier
on Security.

---

## REST API (`api/main.py`)

| Endpoint | Purpose |
|---|---|
| `GET /health`, `GET /ready` | Liveness/readiness for container orchestration |
| `GET /threats` | List processed threats |
| `GET /threats/{threat_id}` | Full detail for one threat |
| `GET /queries` | List validated KQL queries |
| `GET /kql/{angle_id}` | Single detection by angle |
| `POST /trigger` | Manually trigger a pipeline run for a given URL |
| `GET /stats` | Pipeline/query statistics |

Rate-limited per IP; supports an optional `AUTOTHREAT_API_KEY` for auth.

---

## Dashboard (`dashboard/app.py`)

A Streamlit "SOC Command Center" with five pages: **Live Feed**, **Threat
Detail**, **KQL Library**, **Queries**, and **Statistics** — pulling live
status from the scheduler and rendering results straight from ChromaDB/SQLite.

---

## Project layout

```
ThreatMind/
├── agents/                      # the 11 pipeline agents + shared prompts
│   ├── agent_00_triage.py
│   ├── agent_01_discovery.py
│   ├── agent_02_extraction.py
│   ├── agent_03_threat_intel.py
│   ├── agent_04_coverage_planner.py
│   ├── agent_05_rag.py
│   ├── agent_06_reasoning.py
│   ├── agent_07_kql_generator.py
│   ├── agent_08_validator.py
│   ├── agent_09_coverage_critic.py
│   ├── agent_10_report.py
│   └── prompts.py
├── pipeline/                    # LangGraph wiring
│   ├── graph.py                 #   builds & compiles the 11-node graph
│   ├── router.py                #   conditional routing (triage gate, retry loop)
│   └── state.py                 #   shared ThreatState schema
├── memory/                      # persistence + retrieval
│   ├── chromadb_client.py       #   threat reports, KQL library, processed-URL dedup
│   ├── sqlite_client.py         #   query storage/stats
│   ├── rag_retriever.py         #   schema/similar-threat/historical-KQL retrieval
│   ├── embeddings.py
│   └── migrations.py
├── scheduler/
│   ├── scheduler.py             #   APScheduler: interval crawl + startup run
│   └── crawler.py               #   per-article pipeline invocation + dedup
├── alerts/
│   ├── slack_alert.py
│   └── email_alert.py
├── api/
│   └── main.py                  #   FastAPI app: health, threats, queries, trigger, stats
├── dashboard/                    # Streamlit SOC dashboard
│   ├── app.py
│   ├── ui.py
│   ├── page_live_feed.py
│   ├── page_threat_detail.py
│   ├── page_kql_library.py
│   ├── page_queries.py
│   └── page_statistics.py
├── utils/
│   ├── groq_client.py           #   Groq API wrapper w/ retry + JSON parsing
│   ├── validation.py
│   ├── platform_converter.py    #   KQL → Sigma → Splunk/QRadar/Elastic/CrowdStrike/Wazuh/SentinelOne
│   ├── health.py
│   ├── system_status.py
│   ├── ids.py
│   ├── json_parser.py
│   └── logger.py
├── config/
│   ├── feeds.yaml                #   the 10 monitored RSS sources
│   ├── sentinel_schema.yaml      #   authoritative Advanced Hunting schema
│   └── settings.py
├── scripts/
│   ├── migrate_db.py
│   └── preflight.py
├── tests/                        # unittest suite: pipeline, agents, API, validator, migrations
├── examples/
│   └── foundation_prototype.py
├── Dockerfile
├── docker-compose.yml            #   api + dashboard services, shared ChromaDB volume
└── requirements.txt
```

---

## Notes

- **Model**: every agent runs on Groq — `llama-3.1-8b-instant` by default,
  with `llama-3.3-70b-versatile` reserved for the reasoning-heavy agents
  (extraction, coverage planning, reasoning, KQL generation). No Anthropic/OpenAI
  dependency for the core pipeline.
- **The validator loop** doesn't just reject bad KQL — it auto-corrects known
  wrong-but-plausible column names against the real schema, re-scores, and
  only escalates to a retry (regenerate from Agent 7) if that's not enough.
  Anything still failing after `MAX_VALIDATION_RETRIES` is surfaced, not
  silently dropped.
- **Coverage is honestly reported**: the Coverage Critic flags indicator-only
  behaviors (e.g. C2 by domain) as a gap rather than hiding them behind a
  "complete" verdict.
- **Deduplication happens at the URL level** via ChromaDB, so the scheduler
  never reprocesses an article it's already crawled.

---

## Author / Contact

**Huraira Maqbool** — AI Engineer (LLMs, RAG systems, agentic AI pipelines & multi-agent architectures)

- GitHub: [github.com/HurairaMaqbool](https://github.com/HurairaMaqbool)
- LinkedIn: [linkedin.com/in/huraira-maqbool-b696a5277](https://www.linkedin.com/in/huraira-maqbool-b696a5277/)
- Email: [hurairac37@gmail.com](mailto:hurairac37@gmail.com)

Feel free to connect, open an issue, or reach out for collaboration.
