import json
from pipeline.state import ThreatState
from agents.agent_09_coverage_critic import agent_9
from agents.agent_10_report import agent_10

def run_test():
    print("="*60)
    print(" STARTING MODULE 9 TEST: COVERAGE CRITIC & REPORT GENERATOR")
    print("="*60)
    
    # Mock end-of-pipeline state
    state: ThreatState = {
        "article_title": "Diamond Sleet exploits TeamCity CVE-2023-42793",
        "blog_url": "https://microsoft.com/security/blog",
        "published_date": "2023-10-18",
        "clean_text": "Diamond Sleet is a North Korean nation-state actor actively exploiting CVE-2023-42793.",
        "behaviors": [
            {"behavior_id": "B1", "description": "Attacker downloads payload using PowerShell", "attack_technique": "T1059.001", "attack_tactic": "Execution"},
            {"behavior_id": "B2", "description": "Attacker steals AD credentials", "attack_technique": "T1003.001", "attack_tactic": "Credential Access"}
        ],
        "iocs": {
            "threat_actor": "Diamond Sleet",
            "cve_numbers": ["CVE-2023-42793"],
            "ip_addresses": ["192.168.1.100"]
        },
        "detection_angles": [
            {"angle_id": "B1-behavioral-DeviceProcessEvents", "behavior_id": "B1", "tier": "behavioral", "target_table": "DeviceProcessEvents"}
        ],
        "validated_queries": [
            {
                "angle_id": "B1-behavioral-DeviceProcessEvents",
                "kql_detection": "DeviceProcessEvents | where FileName == 'powershell.exe'",
                "kql_hunting": "DeviceProcessEvents | where FileName == 'powershell.exe' | count",
                "blocked": False,
                "needs_review": False
            }
        ],
        "failed_queries": [],
        "cot_reasoning": "The attacker gets in via CVE, then uses PowerShell, then steals creds."
    }
    
    print("\n[Running Agent 9 - Coverage Critic]")
    state = agent_9(state)
    
    print("\n[Running Agent 10 - Report Generator]")
    state = agent_10(state)
    
    print("\n" + "="*60)
    print(f" SEVERITY LEVEL: {state.get('severity_level')}")
    print(f" OVERALL COVERAGE: {state.get('overall_coverage')}")
    print("="*60)
    print("\n" + state.get("final_report", ""))

if __name__ == "__main__":
    run_test()
