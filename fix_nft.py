import os
import re

filepath = r"C:\Users\duggyt\DevOps\syswarden\src\core\syswarden-cli\pkg\firewall\nftables.go"
with open(filepath, 'r', encoding='utf-8') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "nftRules.WriteString" in line and not "fmt.Fprintf" in line:
        # Match lines that end with nftRules.WriteString("something")
        # Just replace the prefix up to nftRules.WriteString
        lines[i] = re.sub(r'^.*nftRules\.WriteString', '\t_, _ = nftRules.WriteString', line)

with open(filepath, 'w', encoding='utf-8') as f:
    f.writelines(lines)
print("Fixed nftables.go")
