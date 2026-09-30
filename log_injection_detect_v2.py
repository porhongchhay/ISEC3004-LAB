#!/usr/bin/env python3
"""
Purpose: the log only records lines in the following format:
    [YYYY-MM-DD HH:MM:SS] Login attempt: <username>
    Anything that doesn't fit the above format is evidence of tampering.

Usage: python3 log_injection_detect_v2.py [logfile]
""" 

# imports
import os
import re
import sys
from datetime import datetime

TIMESTAMP = r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]"
VALID_LINE =  re.compile(rf"^({TIMESTAMP}) Login attempt: (.*)$")
TIMESTAMP_ONLY =  re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]")
SUSPICIOUS_IN_USERNAME = re.compile(r"\[|\]|fake|deleted|admin (login|action)|%0a|%0d|\\n|\\r", re.IGNORECASE)

def analyze_log(log_file):
    # check if log file exists
    if not os.path.exists(log_file):
        print(f"File not found: {log_file}")
        return 1

    # open log file
    with open(log_file, "r") as f: 
        lines = f.read().splitlines()

    suspicious = [] # format: (line_no, reason, text)
    latest_timestamp = None # used to record the latest timestamp

    for i, line in enumerate(lines, 1):
        # 1. Blank line - a legitimate log never produces a blank line
        if line.strip() == "":
            suspicious.append((i, "Blank line: possible injected newline", line))
            continue

        # 2. multiple timestamps on a single line
        if len(re.findall(TIMESTAMP, line)) > 1:
            suspicious.append((i, "Multiple timestamps on one line", line))

        match_line = VALID_LINE.match(line)

        # 3. Line does not match the format the app writes
        if not match_line: 
            # only timestamps
            if TIMESTAMP_ONLY.match(line):
                    suspicious.append((i, "Timestamped line that is not a login attempt", line))
            # line without a timestamp
            else:
                suspicious.append((i, "Line with no timestamp", line))
        else: 
             # get username of each line
            username = match_line.group(2)
            # 4. check if username is empty
            if username.strip() == "":
                suspicious.append((i, "log with empty username", line))
            # 5. suspicious content inside username
            elif SUSPICIOUS_IN_USERNAME.search(username):
                suspicious.append((i, "Suspicious content inside username", line))

        # 6. timestamps must not go backwards in time
        match_timestamp = TIMESTAMP_ONLY.match(line)

        if match_timestamp:
            get_timestamp = datetime.strptime(match_timestamp.group(1), "%Y-%m-%d %H:%M:%S")
            if latest_timestamp and get_timestamp < latest_timestamp:
                suspicious.append((i, f"Timestamp goes backwards (earlier than {latest_timestamp})", line))
            else:
                latest_timestamp = get_timestamp 

    # analysis report
    print("=" * 65)
    print(f"LOG ANALYSIS: {log_file}")
    print("=" * 65)
    print(f"\n* Statistics:")
    print(f"   Total lines: {len(lines)}")
    print(f"   File size: {os.path.getsize(log_file)} bytes")


    if not suspicious:
        print("\nNo suspicious entries found")
        print("=" * 50)
        return 0

    suspicious.sort(key=lambda x: x[0])
    print(f"\nFound {len(suspicious)} suspicious entries:\n")
    for i, reason, text in suspicious:
        if text:
            shown = text 
        else: 
            shown = "empty line"
        print(f"Line {i:>3} {reason}")
        print(f"        * {shown[:90]}")
    print("=" * 65)
    return 2

if __name__ == "__main__":
    if len(sys.argv) > 1:
        log_file = sys.argv[1] 
    else:
        log_file = "access.log"

    analyze_log(log_file)