import os
import re

agents_dir = os.path.join(os.path.dirname(__file__), 'agents')
for filename in os.listdir(agents_dir):
    if not filename.endswith('.py'): continue
    
    filepath = os.path.join(agents_dir, filename)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    agent_name = filename[:-3]
    
    if 'safe_parse_json(' in content:
        if filename == 'agent_04_coverage_planner.py':
            content = content.replace('safe_parse_json(resp_text)', f'safe_parse_json(resp_text, expected_type="list", agent_name="{agent_name}")')
        else:
            content = content.replace('safe_parse_json(resp_text)', f'safe_parse_json(resp_text, agent_name="{agent_name}")')
            
    if 'call_groq_with_retry(' in content:
        content = content.replace('call_groq_with_retry(', f'call_groq_with_retry(agent_name="{agent_name}", ')
        
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
print('Refactored all agents!')
