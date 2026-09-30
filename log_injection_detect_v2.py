#!/usr/bin/env python3
"""
Log injection detector v2.

Idea: the application only ever writes ONE kind of line:
    [YYYY-MM-DD HH:MM:SS] Login attempt: <username>
so anything that does not fit that format, or that looks odd inside it,
is evidence of tampering. This is an allow-list approach instead of
searching for individual bad strings.

Usage: python3 log_injection_detect_v2.py [logfile]
"""

import os
import re
import sys
from datetime import datetime

TS = r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]"
VALID_LINE = re.compile(rf"^(\[[^\]]+\]) Login attempt: (.*)$")
TS_ONLY = re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]")
SUSPICIOUS_IN_USERNAME = re.compile(
    r"\[|\]|fake|deleted|admin (login|action)|%0a|%0d|\\n|\\r", re.IGNORECASE
)


def analyze(path):
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return 1

    with open(path, "r") as f:
        lines = f.read().splitlines()

    findings = []  # (line_no, severity, reason, text)
    latest = None  # latest timestamp seen so far

    for n, line in enumerate(lines, 1):
        # 1. Blank line: a legitimate write never produces one
        if line.strip() == "":
            findings.append((n, "HIGH", "Blank line (possible injected newline)", line))
            continue

        # 2. More than one timestamp on a single line
        if len(re.findall(TS, line)) > 1:
            findings.append((n, "HIGH", "Multiple timestamps on one line", line))

        m = VALID_LINE.match(line)

        # 3. Line does not match the format the app writes (orphan / forged line)
        if not m:
            if TS_ONLY.match(line):
                findings.append(
                    (n, "HIGH", "Timestamped line that is not a login attempt "
                                "(app never writes this; forged entry)", line)
                )
            else:
                findings.append(
                    (n, "HIGH", "Line with no timestamp (orphan line, "
                                "injected via newline)", line)
                )
            # still check timestamp order below if there is one
        else:
           
            username = m.group(2)
            # 4. Empty username
            if username.strip() == "":
                findings.append((n, "LOW", "Empty username", line))
            # 5. Suspicious content inside the username field
            elif SUSPICIOUS_IN_USERNAME.search(username):
                findings.append(
                    (n, "MEDIUM", "Suspicious content inside username "
                                  "(attempted injection, may have been neutralised)", line)
                )

        # 6. Timestamps must not go backwards in an append-only log
        t = TS_ONLY.match(line)
        if t:
            ts = datetime.strptime(t.group(1), "%Y-%m-%d %H:%M:%S")
            if latest and ts < latest:
                findings.append(
                    (n, "HIGH", f"Timestamp goes backwards (earlier than {latest}); "
                                "likely forged/backdated entry", line)
                )
            else:
                latest = ts

    # ---- report ----
    print("=" * 60)
    print(f"LOG ANALYSIS v2: {path}")
    print("=" * 60)
    print(f"Total lines: {len(lines)}   File size: {os.path.getsize(path)} bytes")

    if not findings:
        print("\nNo anomalies found.")
        print("=" * 60)
        return 0

    findings.sort(key=lambda x: x[0])
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    print(f"\nFound {len(findings)} findings:\n")
    for n, sev, reason, text in findings:
        counts[sev] += 1
        shown = text if text else "(empty line)"
        print(f"  Line {n:>3} [{sev}] {reason}")
        print(f"           > {shown[:90]}")
    print(f"\nSummary: {counts['HIGH']} high, {counts['MEDIUM']} medium, "
          f"{counts['LOW']} low")
    print("=" * 60)
    return 2


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "c:/uni/s2/ISEC3004/ISEC3004_Assignment/Vulnerabilities Log Injection/access.log"
    sys.exit(analyze(target))
