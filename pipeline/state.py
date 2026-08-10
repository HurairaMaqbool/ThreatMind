from typing import TypedDict, List, Dict, Any

class ThreatState(TypedDict):
    # Input fields
    blog_url: str
    raw_html: str

    # Agent 0 output (Triage)
    huntable: bool
    triage_reason: str
    primary_actor: str
    triage_confidence: str  # "high" | "medium" | "low"

    # Agent 1 output (Discovery)
    clean_text: str
    article_title: str
    published_date: str

    # Agent 2 output (Behavior Extraction)
    behaviors: List[Dict[str, Any]]

    # Agent 3 output (Threat Intel)
    iocs: Dict[str, Any]

    # Agent 4 output (Coverage Planner)
    detection_angles: List[Dict[str, Any]]

    # Agent 5 output (RAG)
    similar_threats: List[Any]
    historical_kqls: List[Any]
    schema_snippets: Dict[str, Any]
    rag_context: str

    # Agent 6 output (Reasoning)
    cot_reasoning: str
    detection_strategy: str
    sentinel_tables: List[str]
    relevant_columns: Dict[str, List[str]]

    # Agent 7 output (KQL Generation)
    generated_queries: List[Dict[str, Any]]

    # Agent 8 output (Validation)
    validated_queries: List[Dict[str, Any]]
    failed_queries: List[Dict[str, Any]]
    validation_scores: Dict[str, int]
    retry_counts: Dict[str, int]

    # Agent 9 output (Coverage Critic)
    coverage_gaps: List[Dict[str, Any]]
    overall_coverage: str  # "complete" | "partial"

    # Agent 10 output (Report)
    final_report: str
    severity_level: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    alert_sent: bool
    threat_id: str
    coverage_report: Dict[str, Any]

    # Upgrade 1 / Section 5A new fields
    sigma_rules: list
    pipeline_run_id: str
    pipeline_start_time: str
    auto_fixed_columns: list
    validation_threshold_used: int
    
    # New Architecture fields
    platform_queries: List[Dict]
    evasion_analysis: List[Dict]
    resilience_improvements: List[Dict]
    operationalization_notes: List[Dict]
    missed_behaviors: List[Dict]
    completeness_verdict: str
