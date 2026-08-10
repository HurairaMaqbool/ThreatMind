import json
from pipeline.state import ThreatState
from agents.agent_04_coverage_planner import agent_4

def run_test():
    # 1. Create mock behaviors (simulating Agent 2 output)
    mock_behaviors = [
        {
            "behavior_id": "B1",
            "description": "Attacker uses PowerShell to download and execute a payload in memory",
            "attack_technique": "T1059.001",
            "attack_tactic": "Execution",
            "artifacts": {
                "processes": ["powershell.exe"],
                "command_lines": ["-enc", "IEX(New-Object Net.WebClient).DownloadString"],
                "file_paths": [],
                "registry_keys": [],
                "named_pipes": [],
                "scheduled_tasks": [],
                "services": [],
                "lolbins": ["powershell.exe"],
                "network": []
            },
            "affected_products": ["Windows"]
        }
    ]

    # 2. Create mock IOCs (simulating Agent 3 output)
    mock_iocs = {
        "ip_addresses": ["192.168.1.100", "45.33.22.11"],
        "domains": ["malicious-c2-server.com"],
        "file_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "cve_numbers": [],
        "file_names": [],
        "registry_keys": [],
        "email_addresses": [],
        "malware_name": "Unknown",
        "threat_actor": "Unknown",
        "target_industry": "Multiple",
        "attack_method": "PowerShell memory execution",
        "affected_platforms": ["Windows"],
        "pyramid_tier": "behavioral"
    }

    # 3. Setup ThreatState
    state: ThreatState = {
        "behaviors": mock_behaviors,
        "iocs": mock_iocs
    }

    print("="*60)
    print(" STARTING MODULE 5 TEST: COVERAGE PLANNER (AGENT 4)")
    print("="*60)

    # 4. Run Agent 4
    updated_state = agent_4(state)

    # 5. Print results
    print("\n" + "="*60)
    print(" FINAL STATE OUTPUT (Detection Angles)")
    print("="*60)
    
    angles = updated_state.get("detection_angles", [])
    print(json.dumps(angles, indent=2))

if __name__ == "__main__":
    run_test()
