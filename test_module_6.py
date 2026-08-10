from pipeline.state import ThreatState
from memory.chromadb_client import store_threat_report, store_kql_query
from agents.agent_05_rag import agent_5

def run_test():
    print("="*60)
    print(" STARTING MODULE 6 TEST: RAG AND CHROMADB MEMORY")
    print("="*60)
    
    # 1. Pre-populate some fake data to test retrieval
    print("Pre-populating ChromaDB with a fake historical threat...")
    store_threat_report(
        url="https://fake-url.com/apt29",
        text="This is a test report about APT29 using PowerShell to download a payload.",
        metadata={"url": "https://fake-url.com/apt29", "title": "APT29 Test", "date": "2024-01-01", "severity": "HIGH", "threat_actor": "APT29"}
    )
    
    store_kql_query(
        angle_id="B1-behavioral-DeviceProcessEvents",
        kql="DeviceProcessEvents | where FileName == 'powershell.exe' | where ProcessCommandLine has '-enc'",
        score=95,
        behavior_description="Detect powershell.exe launched with encoded command flags like -enc",
        metadata={"angle_id": "B1-behavioral-DeviceProcessEvents", "table": "DeviceProcessEvents", "technique": "T1059.001", "score": 95, "tier": "behavioral"}
    )

    # 2. Setup mock state that Agent 4 would have produced
    state: ThreatState = {
        "clean_text": "Another report mentioning attackers using PowerShell encoded commands.",
        "detection_angles": [
            {
                "angle_id": "TEST-1",
                "behavior_id": "B1",
                "target_table": "DeviceProcessEvents",
                "detection_idea": "Detect powershell.exe launched with encoded command flags like -enc"
            },
            {
                "angle_id": "TEST-2",
                "behavior_id": "B2",
                "target_table": "DeviceNetworkEvents",
                "detection_idea": "Detect connection to malicious IP"
            }
        ]
    }

    # 3. Run Agent 5
    updated_state = agent_5(state)

    # 4. Print results
    print("\n" + "="*60)
    print(" FINAL STATE OUTPUT (RAG Context)")
    print("="*60)
    
    print("\n" + updated_state.get("rag_context", ""))

if __name__ == "__main__":
    run_test()
