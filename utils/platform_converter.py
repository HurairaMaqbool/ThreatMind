"""
Converts a validated KQL query into multi-platform SIEM formats.
Uses pySigma for Splunk/QRadar/Elastic/CrowdStrike.
Uses Groq LLM for Wazuh and SentinelOne.
"""
try:
    from sigma.collection import SigmaCollection
except ImportError:
    SigmaCollection = None

try:
    from sigma.backends.splunk import SplunkBackend
except ImportError:
    SplunkBackend = None


try:
    from sigma.backends.qradar import QradarBackend
except ImportError:
    QradarBackend = None

try:
    from sigma.backends.elasticsearch import LuceneBackend as ElasticsearchBackend
except ImportError:
    ElasticsearchBackend = None

try:
    from sigma.backends.crowdstrike import LogScaleBackend as CrowdstrikeBackend
except ImportError:
    try:
        from sigma.backends.crowdstrike import CrowdstrikeBackend
    except ImportError:
        CrowdstrikeBackend = None
from utils.logger import logger
from utils.groq_client import call_groq_with_retry, GROQ_MODEL_LIGHT

SIGMA_FEW_SHOT = """
EXAMPLE Sigma YAML for PowerShell detection:
title: Suspicious Encoded PowerShell
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - 'DownloadString'
  condition: selection
level: high
"""

def convert_to_all_platforms(
    kql_query: str,
    angle_id: str,
    technique: str,
    behavior_description: str,
    groq_client=None
) -> dict:
    
    result = {
        "angle_id": angle_id,
        "sentinel": kql_query,
        "splunk": None,
        "qradar": None,
        "elastic": None,
        "crowdstrike": None,
        "wazuh": None,
        "sentinelone": None
    }
    
    sigma_prompt = f"""Convert this Sentinel KQL into valid Sigma YAML. Follow the example format exactly.

{SIGMA_FEW_SHOT}

KQL to convert:
{kql_query}
Behavior: {behavior_description}
Technique: {technique}
angle_id: {angle_id}

Output strict YAML only. No markdown fences."""
    
    sigma_yaml = None
    try:
        resp = call_groq_with_retry("platform_converter_sigma", sigma_prompt, model=GROQ_MODEL_LIGHT)
        if resp.startswith("```yaml"):
            sigma_yaml = resp.split("```yaml")[1].split("```")[0].strip()
        else:
            sigma_yaml = resp.strip()
            
        if SigmaCollection and sigma_yaml:
            rules = SigmaCollection.from_yaml(sigma_yaml)

        
        try:
            if SplunkBackend:
                result["splunk"] = SplunkBackend().convert(rules)[0]
        except Exception as e:
            logger.info(f"Splunk conversion failed for {angle_id}: {e}")
            
        try:
            if QradarBackend:
                result["qradar"] = QradarBackend().convert(rules)[0]
        except Exception as e:
            logger.info(f"QRadar conversion failed for {angle_id}: {e}")
            
        try:
            if ElasticsearchBackend:
                result["elastic"] = ElasticsearchBackend().convert(rules)[0]
        except Exception as e:
            logger.info(f"Elastic conversion failed for {angle_id}: {e}")
            
        try:
            if CrowdstrikeBackend:
                result["crowdstrike"] = CrowdstrikeBackend().convert(rules)[0]
        except Exception as e:
            logger.info(f"CrowdStrike conversion failed for {angle_id}: {e}")
            
    except Exception as e:
        logger.info(f"Sigma conversion failed for {angle_id}: {e}")
        
    wazuh_prompt = f"""Convert KQL to Wazuh XML rule. Example format:
<rule id="100001" level="10">
  <description>PowerShell encoded command detected</description>
  <field name="win.eventdata.commandLine">\\.\\-enc|DownloadString</field>
</rule>

KQL: {kql_query}
Behavior: {behavior_description}
Output XML only."""
    try:
        resp = call_groq_with_retry("platform_converter_wazuh", wazuh_prompt, model=GROQ_MODEL_LIGHT)
        if resp.startswith("```xml"):
            result["wazuh"] = resp.split("```xml")[1].split("```")[0].strip()
        elif resp.startswith("```"):
            result["wazuh"] = resp.split("```")[1].split("```")[0].strip()
        else:
            result["wazuh"] = resp.strip()
    except Exception as e:
        logger.info(f"Wazuh conversion failed for {angle_id}: {e}")
        
    s1_prompt = f"""Convert KQL to SentinelOne Deep Visibility query. Example:
EventType = "Process Creation" AND SrcProcessName contains "powershell" AND TgtProcessCmdLine contains "-enc"

KQL: {kql_query}
Behavior: {behavior_description}
Output query string only."""
    try:
        resp = call_groq_with_retry("platform_converter_s1", s1_prompt, model=GROQ_MODEL_LIGHT)
        result["sentinelone"] = resp.strip().strip("`")
    except Exception as e:
        logger.info(f"SentinelOne conversion failed for {angle_id}: {e}")
        
    return result
