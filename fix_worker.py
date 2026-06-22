import os
import re

filepath = r"C:\Users\duggyt\DevOps\syswarden\src\core\syswarden-core\telemetry\worker.go"
with open(filepath, 'r', encoding='utf-8') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "fmt.Sscanf" in line:
        lines[i] = re.sub(r'^.*fmt\.Sscanf', '\t\t_, _ = fmt.Sscanf', line)

with open(filepath, 'w', encoding='utf-8') as f:
    f.writelines(lines)
print("Fixed worker.go")
