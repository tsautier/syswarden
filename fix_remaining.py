import os
import re

def process_file(filepath):
    if not os.path.exists(filepath): return
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified = False
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        
        # 1, 2, 3: os.WriteFile
        if stripped.startswith("os.WriteFile("):
            lines[i] = line.replace("os.WriteFile(", "_ = os.WriteFile(", 1)
            modified = True
            
        # 4, 5, 6: resp.Body.Close
        if stripped.startswith("resp.Body.Close()"):
            lines[i] = line.replace("resp.Body.Close()", "_ = resp.Body.Close()", 1)
            modified = True
            
        # 7: l.file.Close
        if stripped.startswith("l.file.Close()"):
            lines[i] = line.replace("l.file.Close()", "_ = l.file.Close()", 1)
            modified = True
            
        # 8, 9: s.conn.Close
        if stripped.startswith("s.conn.Close()"):
            lines[i] = line.replace("s.conn.Close()", "_ = s.conn.Close()", 1)
            modified = True

        # 10, 11, 12: nftRules.WriteString(fmt.Sprintf(...))
        if "nftRules.WriteString(fmt.Sprintf(" in line:
            lines[i] = line.replace("nftRules.WriteString(fmt.Sprintf(", "fmt.Fprintf(&nftRules, ")
            # remove one closing parenthesis from the end
            lines[i] = lines[i].replace("))\n", ")\n")
            modified = True

    if modified:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        print(f"Fixed {filepath}")

def main():
    repo = r"C:\Users\duggyt\DevOps\syswarden"
    files = [
        r"src\core\syswarden-cli\cmd\config_cmd.go",
        r"src\core\syswarden-cli\pkg\firewall\lists.go",
        r"src\core\syswarden-cli\pkg\network\downloader.go",
        r"src\core\syswarden-core\logger\logger.go",
        r"src\core\syswarden-core\network\uds.go",
        r"src\core\syswarden-cli\pkg\firewall\nftables.go"
    ]
    for f in files:
        process_file(os.path.join(repo, f))

if __name__ == "__main__":
    main()
