import os
import re

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified = False
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        
        # fix wg.Wait()
        if stripped.startswith("_ = wg.Wait()"):
            spaces = len(line) - len(stripped)
            lines[i] = (" " * spaces) + "wg.Wait()\n"
            modified = True
            
        # fix WriteString
        if stripped.startswith("_ = ") and ".WriteString(" in stripped:
            lines[i] = line.replace("_ = ", "_, _ = ", 1)
            modified = True
            
        # fix Sscanf
        if stripped.startswith("_ = fmt.Sscanf("):
            lines[i] = line.replace("_ = fmt.Sscanf(", "_, _ = fmt.Sscanf(", 1)
            modified = True

    if modified:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        print(f"Fixed {filepath}")

def main():
    for root, dirs, files in os.walk(r"C:\Users\duggyt\DevOps\syswarden\src\core"):
        for file in files:
            if file.endswith(".go"):
                process_file(os.path.join(root, file))

if __name__ == "__main__":
    main()
