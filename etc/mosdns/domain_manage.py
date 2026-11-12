#!/usr/bin/env python3
"""Add, delete or clean domains in a plain-text list.

Input is messy by nature: URLs, wildcards, ports, trailing notes and pasted
chat lines. Every line is reduced to bare lower-case domains first, validated
against DNS label rules, then merged into the file as a sorted set.

Without a file path the normalized list goes to stdout, so it can feed a
pipe; the summary goes to stderr. With a file path the list is edited in
place.

Examples:
  cat messy.txt | python3 domain_manage.py            # clean to stdout
  cat messy.txt | python3 domain_manage.py -o clean.txt  # clean to a new file
  python3 domain_manage.py 'https://foo.com/x'        # one domain to stdout
  python3 domain_manage.py /etc/mosdns/rule/oversea_domains.txt google.com
  python3 domain_manage.py del /etc/mosdns/rule/oversea_domains.txt foo.com
  python3 domain_manage.py clean /etc/mosdns/rule/oversea_domains.txt
"""

import ipaddress
import os
import re
import stat
import sys
import tempfile

# A DNS name candidate. The lookarounds keep it from matching a suffix of a
# longer broken token such as "foo_bar.com" or "foo..bar.com".
_DOMAIN_RE = re.compile(
    r"(?<![a-z0-9_.-])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?![a-z0-9_-])",
    re.IGNORECASE,
)


def normalize_domain(candidate):
    """Return a bare valid domain or None.

    Drops the trailing dot, lower-cases, rejects IP literals, single labels,
    empty labels, labels over 63 bytes and a numeric TLD. IDN input has to be
    punycode already, because the regex only accepts ASCII.
    """
    if not candidate:
        return None
    domain = candidate.strip().strip(".").lower()
    if not domain or len(domain) > 253:
        return None
    labels = domain.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not 1 <= len(label) <= 63:
            return None
        if label[0] == "-" or label[-1] == "-":
            return None
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return None
    # A numeric TLD is never a domain, and this also rejects IPv4 literals.
    if not any(ch.isalpha() for ch in labels[-1]):
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    return domain


def extract_domains(line):
    """Pull domains out of one raw line.

    A URL contributes only its host, so a query string carrying another
    domain does not leak into the list. Free-form lines (wildcards, ports,
    trailing notes) fall back to scanning every domain-like token.
    """
    text = line.strip().lstrip("\ufeff")
    if not text or text.startswith("#"):
        return []
    # "*.example.com" is not a valid name for mosdns' subdomain matcher: the
    # "*" becomes a literal label, so the pattern never matches. Strip it and
    # keep example.com, which matches the exact host and all subdomains.
    text = re.sub(r"\*\.", "", text)

    host = None
    if "://" in text:
        try:
            from urllib.parse import urlsplit

            host = urlsplit(text.split()[0]).hostname
        except ValueError:
            host = None
    if host:
        domain = normalize_domain(host)
        if domain:
            return [domain]

    found = []
    for match in _DOMAIN_RE.finditer(text):
        domain = normalize_domain(match.group(0))
        if domain:
            found.append(domain)
    return found


def load_domains(path):
    """Read the file and normalize every entry.

    Returns (domains, cleaned, dropped, raw). cleaned counts lines that were
    not already a bare domain (URL, wildcard, duplicate); dropped counts lines
    with no usable domain at all; raw is the number of non-comment lines.
    """
    domains = set()
    cleaned = 0
    dropped = 0
    raw = 0
    if not os.path.exists(path):
        return domains, cleaned, dropped, raw
    if os.path.isdir(path):
        raise SystemExit(f"Error: {path} is a directory")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            raw += 1
            found = extract_domains(text)
            if not found:
                dropped += 1
                cleaned += 1
                continue
            if len(found) != 1 or text.lower().rstrip(".") != found[0]:
                cleaned += 1
            for domain in found:
                if domain in domains:
                    cleaned += 1
                domains.add(domain)
    return domains, cleaned, dropped, raw


def save_domains(path, domains):
    """Write a sorted list atomically, keeping the original file mode."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".domain_manage.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for domain in sorted(domains):
                f.write(domain + "\n")
        try:
            os.chmod(tmp, stat.S_IMODE(os.stat(path).st_mode))
        except FileNotFoundError:
            os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


USAGE = """Usage:
  python3 domain_manage.py [-o out_file] [file_path] domain1 [domain2 ...]
  python3 domain_manage.py add|del [file_path] domain1 [domain2 ...]
  python3 domain_manage.py clean [file_path]
  cat domain_list.txt | python3 domain_manage.py [-o out_file] [add|del]

Action defaults to add. Without file_path the sorted domains are printed to
stdout, or to -o out_file when given; -o never reads the output file, so it
is for "extract and save", not for merging. With file_path the list is edited
in place. Only the summary goes to stderr in stream mode.
URLs, wildcards, ports and trailing notes are reduced to bare domains."""


def parse_args(argv):
    """Parse action / optional file / domains without argparse.

    argparse cannot accept an optional path before the domains, and the old
    script allowed exactly that ("script /path/file.txt domain").
    """
    args = list(argv)
    if args and args[0] in ("-h", "--help"):
        print(USAGE)
        raise SystemExit(0)

    # Pull -o/--output out before the positional interpretation: its value
    # may look like a path or a domain.
    output = None
    rest = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-o", "--output"):
            if i + 1 >= len(args):
                print("Error: -o needs a file name", file=sys.stderr)
                raise SystemExit(1)
            output = args[i + 1]
            i += 2
            continue
        if arg.startswith("--output="):
            output = arg.split("=", 1)[1]
            i += 1
            continue
        rest.append(arg)
        i += 1
    args = rest

    action = "add"
    if args and args[0].lower() in ("add", "del", "clean"):
        action = args.pop(0).lower()

    path = None
    if args:
        first = args[0].strip()
        if first == "-":
            args.pop(0)
        elif not first.lower().startswith(("http://", "https://")) and (
            "/" in first or first.lower().endswith((".txt", ".conf", ".list"))
        ):
            path = args.pop(0)

    if output == "-":
        output = None
    if output is not None and path is not None:
        print("Error: -o and an in-place file path are mutually exclusive",
              file=sys.stderr)
        raise SystemExit(1)

    return action, path, args, output


def main(argv=None):
    action, path, inputs, output = parse_args(
        sys.argv[1:] if argv is None else argv
    )

    # Pipe mode only when nothing was passed as positional domains. A file
    # clean never reads stdin; stream mode always does.
    read_stdin = not inputs and not sys.stdin.isatty()
    if read_stdin and (path is None or action != "clean"):
        raw_text = sys.stdin.read()
        inputs = raw_text.splitlines()

    valid = []
    skipped = 0
    for line in inputs:
        found = extract_domains(line)
        if not found:
            skipped += 1
            continue
        valid.extend(found)

    unique_input = set(valid)
    duplicate_input = len(valid) - len(unique_input)

    # No file: write the normalized set to -o, or print it to stdout.
    if path is None:
        if action == "del":
            print("Error: del needs a file path", file=sys.stderr)
            return 1
        if not unique_input:
            print("Error: no valid domain found in input", file=sys.stderr)
            return 1
        if output is not None:
            save_domains(output, unique_input)
        else:
            for domain in sorted(unique_input):
                print(domain)
        print(
            f"Input: {len(inputs)} lines, {len(unique_input)} valid, "
            f"{duplicate_input} duplicate, {skipped} skipped",
            file=sys.stderr,
        )
        return 0

    existing, cleaned, dropped, raw = load_domains(path)
    original = len(existing)

    if action != "clean" and not unique_input:
        print("Error: no valid domain found in input", file=sys.stderr)
        return 1

    changed = 0
    if action == "add":
        for domain in unique_input:
            if domain not in existing:
                existing.add(domain)
                changed += 1
    elif action == "del":
        for domain in unique_input:
            if domain in existing:
                existing.discard(domain)
                changed += 1

    # clean rewrites even when only the existing entries needed fixing.
    if changed > 0 or (action == "clean" and cleaned > 0):
        save_domains(path, existing)

    print(f"File     : {path}")
    print(f"Action   : {action}")
    print(f"Input    : {len(inputs)} lines, {len(unique_input)} valid"
          f", {duplicate_input} duplicate, {skipped} skipped")
    print(f"Existing : {raw} lines, {original} entries, {cleaned} normalized/dropped"
          f" ({dropped} with no domain)")
    print(f"Changed  : {changed} entries")
    print(f"Total    : {len(existing)} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
