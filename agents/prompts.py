"""Centralized LLM prompts with few-shot examples for consistent, accurate outputs."""

# ── Agent 0: Triage ──────────────────────────────────────────────────────────

TRIAGE_FEW_SHOTS = """
EXAMPLE 1 (huntable):
URL: https://www.microsoft.com/en-us/security/blog/2024/01/15/nation-state-actor-exploits-vpn/
Output: {"huntable": true, "reason": "Security blog threat report with CVE exploitation and TTPs."}

EXAMPLE 2 (not huntable):
URL: https://www.crowdstrike.com/pricing/
Output: {"huntable": false, "reason": "Commercial pricing page — no attack behaviors or IOCs."}

EXAMPLE 3 (huntable):
URL: https://unit42.paloaltonetworks.com/ransomware-campaign-analysis/
Output: {"huntable": true, "reason": "Malware campaign analysis with behaviors, IOCs, and MITRE mapping."}
"""


def triage_prompt(url: str) -> str:
    return f"""You are a senior CTI analyst. Decide if a URL points to a huntable threat intelligence article.
Huntable = contains attacker behaviors, TTPs, or technical IOCs usable for detection engineering.
Not huntable = marketing, pricing, careers, generic news without technical threat detail.

{TRIAGE_FEW_SHOTS}

NOW ANALYZE:
URL: {url}

Respond ONLY with JSON: {{"huntable": true/false, "reason": "one sentence"}}"""


# ── Agent 3: Threat Intel ────────────────────────────────────────────────────

BEHAVIORS_FEW_SHOTS = """
EXAMPLE INPUT: "Attackers used PowerShell with -enc flag to download Cobalt Strike from evil.com"
EXAMPLE OUTPUT:
{"behaviors":[{"behavior_id":"B1","description":"PowerShell downloads payload via encoded command","attack_technique":"T1059.001","attack_tactic":"Execution","artifacts":{"processes":["powershell.exe"],"command_lines":["-enc","DownloadString"],"file_paths":[]},"affected_products":["Windows"]},{"behavior_id":"B2","description":"Outbound C2 connection to malicious domain","attack_technique":"T1071.001","attack_tactic":"Command and Control","artifacts":{"processes":[],"command_lines":[],"file_paths":[]},"affected_products":["Windows"]}]}

EXAMPLE INPUT: "Threat actor dumped LSASS memory using comsvcs.dll"
EXAMPLE OUTPUT:
{"behaviors":[{"behavior_id":"B1","description":"Credential dumping via comsvcs.dll MiniDump","attack_technique":"T1003.001","attack_tactic":"Credential Access","artifacts":{"processes":["rundll32.exe"],"command_lines":["comsvcs.dll","MiniDump"],"file_paths":["%TEMP%\\*.dmp"]},"affected_products":["Windows"]}]}
"""


def behaviors_prompt(text: str) -> str:
    return f"""You are a CTI analyst. Extract attacker behaviors from the report and map each to MITRE ATT&CK.
Rules: max 5 behaviors, use valid technique IDs (e.g. T1059.001), be specific, only extract stated facts.

{BEHAVIORS_FEW_SHOTS}

REPORT:
{text}

Respond ONLY with JSON: {{"behaviors": [...]}}"""


IOCS_FEW_SHOTS = """
EXAMPLE OUTPUT:
{"ip_addresses":["185.220.101.45"],"domains":["evil-c2.com"],"file_hashes":["a1b2c3d4e5f6..."],"cve_numbers":["CVE-2024-1234"],"file_names":["payload.dll"],"malware_name":"Cobalt Strike","threat_actor":"APT29","target_industry":"Government","attack_method":"Spear-phishing with macro-enabled document","affected_platforms":["Windows"],"pyramid_tier":"behavioral"}
"""


def iocs_prompt(text: str) -> str:
    return f"""Extract IOC context from this threat report. Only include values explicitly mentioned or strongly implied.
Use "Unknown" for actor/malware if not stated. pyramid_tier = highest durable indicator type found.

{IOCS_FEW_SHOTS}

REPORT:
{text}

Respond ONLY with JSON matching the example schema."""


# ── Agent 4: Coverage Planner ────────────────────────────────────────────────

COVERAGE_FEW_SHOTS = """
EXAMPLE:
Input behavior: B1 | T1059.001 | PowerShell encoded download
Output angle:
{"angle_id":"B1-behavioral-DeviceProcessEvents","behavior_id":"B1","tier":"behavioral","target_table":"DeviceProcessEvents","detection_idea":"powershell.exe spawned with -enc or DownloadString in ProcessCommandLine","expected_fps":"IT automation scripts, software deployment"}

EXAMPLE:
Input behavior: B2 | T1071.001 | C2 over HTTPS
Output angle:
{"angle_id":"B2-network_artifact-DeviceNetworkEvents","behavior_id":"B2","tier":"network_artifact","target_table":"DeviceNetworkEvents","detection_idea":"InitiatingProcessFileName is script interpreter connecting to rare external IP on 443","expected_fps":"Cloud SaaS, CDN traffic"}
"""


def coverage_planner_prompt(behavior_summary: str) -> str:
    return f"""You are a Detection Engineer. Create detection angles using the Pyramid of Pain.
Tiers: behavioral > tool_artifact > network_artifact > indicator
Tables: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, IdentityLogonEvents
Create 1-2 angles per behavior. angle_id format: {{behavior_id}}-{{tier}}-{{target_table}}

{COVERAGE_FEW_SHOTS}

BEHAVIORS:
{behavior_summary}

Respond ONLY with JSON: {{"angles": [...]}}"""


# ── Agent 6: Reasoning ───────────────────────────────────────────────────────

REASONING_FEW_SHOT = """
EXAMPLE OUTPUT:
The attack begins with a malicious document spawning PowerShell (T1059.001), which downloads a payload from an external domain (T1071.001). Detection should focus on parent-child process chains in DeviceProcessEvents — Office apps spawning powershell.exe with encoded commands — and correlate with outbound connections in DeviceNetworkEvents. This approach targets durable behavioral patterns rather than ephemeral IOCs.
"""


def reasoning_prompt(behavior_summary: str, ioc_summary: str, angle_summary: str) -> str:
    return f"""You are a Threat Hunter validating detection strategy for Microsoft Defender for Endpoint KQL.

{REASONING_FEW_SHOT}

NOW ANALYZE (3-5 sentences, under 200 words):
Behaviors: {behavior_summary}
IOCs: {ioc_summary}
Angles: {angle_summary}

Confirm attack narrative and that chosen tables/columns will detect the behavior with acceptable false positives."""


# ── Agent 7: KQL Generator ───────────────────────────────────────────────────

KQL_FEW_SHOTS = """
EXAMPLE 1 — PowerShell execution:
{"angle_id":"B1-behavioral-DeviceProcessEvents","blocked":false,"notes":"Detects encoded PowerShell","kql_detection":"DeviceProcessEvents\\n| where TimeGenerated >= ago(1d)\\n| where FileName =~ \\"powershell.exe\\"\\n| where ProcessCommandLine has_any (\\"-enc\\", \\"DownloadString\\", \\"IEX\\")\\n| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine","kql_hunting":"DeviceProcessEvents\\n| where TimeGenerated >= ago(7d)\\n| where FileName =~ \\"powershell.exe\\"\\n| summarize EventCount=count() by bin(TimeGenerated, 1h), DeviceName, AccountName"}

EXAMPLE 2 — Network C2:
{"angle_id":"B2-network_artifact-DeviceNetworkEvents","blocked":false,"notes":"Rare external HTTPS from script host","kql_detection":"DeviceNetworkEvents\\n| where TimeGenerated >= ago(1d)\\n| where RemotePort == 443\\n| where InitiatingProcessFileName in~ (\\"powershell.exe\\", \\"cmd.exe\\", \\"wscript.exe\\")\\n| summarize ConnectionCount=count() by DeviceName, RemoteIP, InitiatingProcessFileName\\n| where ConnectionCount < 5\\n| project TimeGenerated, DeviceName, RemoteIP, InitiatingProcessFileName","kql_hunting":"DeviceNetworkEvents\\n| where TimeGenerated >= ago(7d)\\n| summarize count() by bin(TimeGenerated, 1h), DeviceName, RemoteIP"}
"""


def kql_generator_prompt(angle_id: str, angle_json: str, target_table: str, schema_json: str, reasoning: str) -> str:
    return f"""You are an expert Microsoft Sentinel KQL writer. Generate detection + hunting queries.

RULES:
1. ONLY use columns from Schema Snippet — never invent columns
2. BANNED: CommandLine→ProcessCommandLine, ParentProcess→InitiatingProcessFileName, User→AccountName, Hash→SHA256
3. MUST include TimeGenerated filter: detection ago(1d), hunting ago(7d)
4. Detection ends with: | project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName
5. Hunting ends with: | summarize count() by bin(TimeGenerated, 1h), DeviceName

{KQL_FEW_SHOTS}

ANGLE: {angle_json}
SCHEMA ({target_table}): {schema_json}
REASONING: {reasoning[:600]}

Respond ONLY with JSON for angle_id="{angle_id}"."""


# ── Agent 9: Coverage Critic ─────────────────────────────────────────────────

CRITIC_FEW_SHOTS = """
EXAMPLE 1 — Nation-state CVE exploitation, 3 behavioral detections:
{"severity_level":"CRITICAL","overall_coverage":"GOOD","coverage_report":{"gaps":["No registry persistence detection"],"strengths":["PowerShell execution","Network C2","Credential access covered"]}}

EXAMPLE 2 — Commodity phishing, 1 indicator-only detection:
{"severity_level":"MEDIUM","overall_coverage":"POOR","coverage_report":{"gaps":["No behavioral coverage, only hash IOCs"],"strengths":["Known malware hash blocked"]}}

EXAMPLE 3 — Targeted credential theft, 2 behavioral + 1 tool:
{"severity_level":"HIGH","overall_coverage":"GOOD","coverage_report":{"gaps":["Lateral movement not covered"],"strengths":["LSASS dump detection","Suspicious logon patterns"]}}
"""


def coverage_critic_prompt(behaviors_json: str, angles_json: str, validated_count: int, iocs_json: str) -> str:
    return f"""You are a Cybersecurity Manager scoring threat severity and detection coverage.

SEVERITY: CRITICAL=nation-state/active CVE/ransomware | HIGH=targeted APT/credential theft | MEDIUM=commodity malware | LOW=weak indicators
COVERAGE: EXCELLENT=>80% behavioral | GOOD=60-80% | PARTIAL=40-60% | POOR=<40%

{CRITIC_FEW_SHOTS}

DATA:
Behaviors: {behaviors_json}
Angles: {angles_json}
Validated queries: {validated_count}
IOCs: {iocs_json}

Respond ONLY with JSON: {{"severity_level":"...","overall_coverage":"...","coverage_report":{{"gaps":[],"strengths":[]}}}}"""


# ── Agent 10: Report ─────────────────────────────────────────────────────────

REPORT_FEW_SHOT = """
EXAMPLE STRUCTURE:
# 1. Executive Summary
North Korean actor Diamond Sleet exploited CVE-2023-42793 in JetBrains TeamCity to deploy a custom backdoor. Severity: CRITICAL. 4 detection queries generated across process and network telemetry.

# 2. Threat Actor Profile
Diamond Sleet (ZINC) — state-sponsored, targets technology and defense sectors.

# 3. Attack Chain narrative
Initial access via CVE exploitation → web shell deployment → PowerShell payload → credential theft.

# 4. MITRE ATT&CK Coverage table
| Technique | Tactic | Covered |
| T1190 | Initial Access | Yes |
| T1059.001 | Execution | Yes |

# 5. Detection Summary
4 validated KQL queries targeting behavioral and network tiers.

# 6. IOCs list
- CVE-2023-42793
- IP: 185.220.101.45

# 7. Recommendations
Patch TeamCity immediately. Deploy generated detections to Sentinel.

# 8. Analyst Notes
Coverage gap: no persistence detection for scheduled tasks.
"""


def report_prompt(title: str, severity: str, behavior_count: int, ip_count: int, hash_count: int, gaps: list) -> str:
    return f"""You are a Lead Threat Intelligence Analyst writing a SOC-ready Markdown report.
Be factual, concise, professional. Use only provided data — do not invent IOCs.

{REPORT_FEW_SHOT}

THREAT DATA:
Title: {title}
Severity: {severity}
Behaviors: {behavior_count}
IOCs: {ip_count} IPs, {hash_count} hashes
Coverage gaps: {gaps}

Write the full report with exactly these 8 headings. Include a MITRE table with Technique, Tactic, Covered columns."""
