import json
from pipeline.state import ThreatState
from agents.agent_06_reasoning import agent_6
from agents.agent_07_kql_generator import agent_7

def run_test():
    print("="*60)
    print(" STARTING MODULE 7 TEST: REASONING + KQL GENERATION")
    print("="*60)
    
    # Mock data from previous agents (Agent 2, 3, 4, 5)
    state: ThreatState = {
        "clean_text": "APT29 uses a malicious document to spawn PowerShell which downloads a Cobalt Strike payload.",
        "behaviors": [{"behavior_id": "B1", "description": "PowerShell execution via malicious document", "attack_technique": "T1059.001", "attack_tactic": "Execution"}],
        "iocs": {"ip_addresses": ["192.168.1.100"]},
        "detection_angles": [
            {
                "angle_id": "B1-behavioral-DeviceProcessEvents",
                "behavior_id": "B1",
                "tier": "behavioral",
                "durability": "high",
                "target_table": "DeviceProcessEvents",
                "detection_idea": "PowerShell spawned from Office app with encoded command",
                "expected_fps": "IT admin scripts, software deployment tools"
            }
        ],
        "schema_snippets": {
            "DeviceProcessEvents": [
                {"column": "FileName", "type": "string", "desc": "name of the process"},
                {"column": "ProcessCommandLine", "type": "string", "desc": "full command line"},
                {"column": "InitiatingProcessFileName", "type": "string", "desc": "parent process name"},
                {"column": "TimeGenerated", "type": "datetime", "desc": "event timestamp"},
                {"column": "AccountName", "type": "string", "desc": "running account"},
                {"column": "DeviceName", "type": "string", "desc": "hostname"},
                {"column": "SHA256", "type": "string", "desc": "process hash"}
            ]
        },
        "similar_threats": []
    }
    
    print("\n[Running Agent 6 - Reasoning]")
    state = agent_6(state)
    
    print("\n[Running Agent 7 - KQL Generation]")
    state = agent_7(state)
    
    print("\n" + "="*60)
    print(" FINAL STATE OUTPUT")
    print("="*60)
    
    print("\n--- REASONING (Agent 6) ---")
    print(state.get("cot_reasoning", "No reasoning found."))
    
    print("\n--- GENERATED KQL (Agent 7) ---")
    queries = state.get("generated_queries", [])
    for q in queries:
        print(f"\nANGLE: {q.get('angle_id')}")
        print(f"BLOCKED: {q.get('blocked')}")
        if not q.get('blocked'):
            print("--- DETECTION QUERY ---")
            print(q.get('kql_detection'))
            print("--- HUNTING QUERY ---")
            print(q.get('kql_hunting'))
        else:
            print(f"NOTES: {q.get('notes')}")

if __name__ == "__main__":
    run_test()
