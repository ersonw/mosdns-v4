#!/usr/bin/env python3
import sys
import os

# ========== Default Configuration ==========
DEFAULT_DOMAIN_FILE = "/etc/mosdns/rule/cn_domains.txt"
# =========================================

def load_domains(file_path):
    """
    Load all valid domains from file.
    Skip empty lines and comment lines (starting with #).
    Returns a set for fast deduplication.
    """
    domains = set()
    if not os.path.exists(file_path):
        return domains

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                domains.add(line)
    except Exception as e:
        print(f"Error reading file: {str(e)}", file=sys.stderr)
        sys.exit(1)

    return domains

def save_domains(file_path, domain_set):
    """
    Save domain set to file, sorted alphabetically for readability.
    """
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    sorted_domains = sorted(domain_set)
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            for d in sorted_domains:
                f.write(d + "\n")
    except Exception as e:
        print(f"Error writing file: {str(e)}", file=sys.stderr)
        sys.exit(1)

def parse_input_domains():
    """
    Parse domains from stdin (pipe input), one per line.
    Returns cleaned list of valid domain strings.
    """
    raw = sys.stdin.read()
    results = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        results.append(line)
    return results

def print_usage():
    print("Usage:")
    print("  # Default action: add (no need to specify add)")
    print("  python3 domain_manage.py [file_path] domain1 [domain2 ...]")
    print("  cat domain_list.txt | python3 domain_manage.py [file_path]")
    print("")
    print("  # Explicit action")
    print("  python3 domain_manage.py add|del [file_path] domain1 [domain2 ...]")
    print("  cat domain_list.txt | python3 domain_manage.py add|del [file_path]")
    print("")
    print("Arguments:")
    print("  add/del    : optional action, default = add")
    print("  file_path  : optional, default: " + DEFAULT_DOMAIN_FILE)
    print("  domainN    : one or more domains, or pass via stdin pipe")
    print("")
    print("Examples:")
    print("  python3 domain_manage.py google.com                 # add, default file")
    print("  python3 domain_manage.py add google.com             # explicit add")
    print("  python3 domain_manage.py del google.com             # delete")
    print("  python3 domain_manage.py /path/to/file.txt google.com  # specify file")
    print("  cat list.txt | python3 domain_manage.py             # batch add via pipe")
    print("  cat list.txt | python3 domain_manage.py del         # batch delete via pipe")

def main():
    if len(sys.argv) < 2 and sys.stdin.isatty():
        print_usage()
        sys.exit(1)

    # Parse action and shift arguments
    args = sys.argv[1:]
    action = "add"  # default action: add

    if args and args[0].lower() in ("add", "del"):
        action = args.pop(0).lower()

    # Parse file path and domain list
    file_path = DEFAULT_DOMAIN_FILE
    arg_domains = []

    if args:
        first = args[0].strip()
        # Heuristic: if arg contains "/" or ends with .txt/.conf, it's a file path
        if "/" in first or first.endswith(".txt") or first.endswith(".conf"):
            file_path = first
            arg_domains = args[1:]
        else:
            arg_domains = args

    # Read from stdin if no domain arguments and stdin has data (pipe mode)
    input_domains = []
    if arg_domains:
        input_domains = [d.strip() for d in arg_domains if d.strip()]
    else:
        if not sys.stdin.isatty():
            input_domains = parse_input_domains()

    if not input_domains:
        print("Error: no domains provided via arguments or stdin", file=sys.stderr)
        print_usage()
        sys.exit(1)

    # Load existing domains
    existing = load_domains(file_path)
    original_count = len(existing)

    # Execute action
    changed = 0
    if action == "add":
        for d in input_domains:
            if d not in existing:
                existing.add(d)
                changed += 1
    else:  # del
        for d in input_domains:
            if d in existing:
                existing.remove(d)
                changed += 1

    # Only write file if there are actual changes
    if changed > 0:
        save_domains(file_path, existing)

    # Print summary
    print(f"File   : {file_path}")
    print(f"Action : {action}")
    print(f"Input  : {len(input_domains)} entries")
    print(f"Changed: {changed} entries")
    print(f"Total  : {len(existing)} entries")

if __name__ == "__main__":
    main()
