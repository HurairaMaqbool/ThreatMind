import json
from pipeline.state import ThreatState
from pipeline.router import route_after_agent_8
from agents.agent_08_validator import agent_8
from agents.agent_07_kql_generator import agent_7

def run_test():
    print("="*60)
    print(" STARTING MODULE 8 TEST: SELF-HEALING VALIDATION LOOP")
    print("="*60)
    
    # Setup mock state with an INTENTIONALLY BROKEN KQL query 
    # (Using "CommandLine" instead of "ProcessCommandLine")
    state: ThreatState = {
        "detection_angles": [
            {
                "angle_id": "TEST-1",
                "target_table": "DeviceProcessEvents",
                "detection_idea": "PowerShell downloaded something"
            }
        ],
        "generated_queries": [
            {
                "angle_id": "TEST-1",
                "kql_detection": "DeviceProcessEvents | where FileName == 'powershell.exe' | where CommandLine has '-enc'",
                "kql_hunting": "DeviceProcessEvents | where FileName == 'powershell.exe' | where CommandLine has '-enc' | count",
                "blocked": False
            }
        ],
        "schema_snippets": {
            "DeviceProcessEvents": [
                {"column": "FileName", "type": "string", "desc": "name of the process"},
                {"column": "ProcessCommandLine", "type": "string", "desc": "full command line"},
                {"column": "TimeGenerated", "type": "datetime", "desc": "event timestamp"}
            ]
        },
        "validation_scores": {},
        "retry_counts": {},
        "validated_queries": [],
        "failed_queries": []
    }
    
    # LOOP SIMULATION
    max_loops = 4
    for i in range(max_loops):
        print(f"\n[LOOP ITERATION {i+1}]")
        
        # 1. Run Validator
        state = agent_8(state)
        
        # 2. Check Router Decision
        decision = route_after_agent_8(state)
        if decision == "agent_9":
            break
            
        # 3. If routed back, run Agent 7 to fix it
        print("\n--- Triggering Agent 7 to fix errors ---")
        state = agent_7(state)

if __name__ == "__main__":
    run_test()
