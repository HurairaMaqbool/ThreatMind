import os
import re

def process_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    if "print(" not in content:
        return

    # Add import at the top if not there
    if "from utils.logger import logger" not in content:
        # Find first non-empty line
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if line.strip() and not line.startswith('#'):
                lines.insert(i, "from utils.logger import logger")
                break
        content = '\n'.join(lines)
    
    # Replace print( with logger.info(
    # Simple replace is usually fine for these scripts
    content = content.replace("print(", "logger.info(")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Refactored {filepath}")

base_dir = os.path.dirname(__file__)
dirs = [os.path.join(base_dir, "agents"), os.path.join(base_dir, "scheduler"), os.path.join(base_dir, "pipeline")]
for d in dirs:
    for root, _, files in os.walk(d):
        for file in files:
            if file.endswith(".py"):
                process_file(os.path.join(root, file))
