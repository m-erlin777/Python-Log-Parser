"""Parse Linux authentication logs for SSH login attempts.

This module provides a CLI tool to read an auth log (e.g., /var/log/auth.log),
extract failed and successful SSH login attempts using regular expressions, and
export results to JSON for downstream analysis.

Usage:
    python log_parser.py --logfile /path/to/auth.log

Outputs:
    - failed_logins.json: list of dicts with keys: 'user', 'ip', 'raw'
    - successful_logins.json: list of dicts with keys: 'user', 'ip', 'raw'

Notes:
    - Designed to be authored on Windows (VSCode) and run on Linux if desired.
    - Paths are handled with pathlib; no OS-specific hardcoding.
"""
import re
import json
from pathlib import Path
import argparse

def parse_auth_log(log_path: Path) -> tuple[list[dict], list[dict]]:
    """Parse SSH authentication log for failed and successful login attempts.

    Args:
        log_path (Path): Path to the SSH authentication log file.

    Returns:
        tuple[list[dict], list[dict]]:
            - failed_logins: list of dicts with keys 'user', 'ip', 'raw'
            - successful_logins: list of dicts with keys 'user', 'ip', 'raw'
    """  
    # Regex patterns for failed and successful SSH login attempts
    failed_pattern = re.compile(
        r'Failed password for (invalid user )?(\w+) from ([\d\.]+) port \d+ ssh2'
    )

    success_pattern = re.compile(
        r'Accepted password for (\w+) from ([\d\.]+) port \d+ ssh2'
    )

    failed_logins = []
    successful_logins = []

    # Open the log file safely
    with log_path.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Check for failed logins
            failed_match = failed_pattern.search(line)
            if failed_match:
                user = failed_match.group(2)
                ip = failed_match.group(3)
                failed_logins.append({
                    'user': user,
                    'ip': ip,
                    'raw': line.strip()
                })
                continue  # Skip success check for failed login

            # Check for successful logins
            success_match = success_pattern.search(line)
            if success_match:
                user = success_match.group(1)
                ip = success_match.group(2)
                successful_logins.append({
                    'user': user,
                    'ip': ip,
                    'raw': line.strip()
                })

    return failed_logins, successful_logins


def main():
    """CLI entry point for parsing Linux auth logs for SSH login attempts.

    Uses argparse to receive the --logfile argument, runs parse_auth_log(),
    prints results to the terminal, and writes failed and successful login
    attempts to JSON files in the same directory as the log.
    """
    parser = argparse.ArgumentParser(description='Parse Linux auth logs for SSH login attempts')
    parser.add_argument(
        '--logfile', type=Path, required=True,
        help='Path to the auth log file to parse'
    )
    args = parser.parse_args()

    log_path = args.logfile
    if not log_path.exists():
        print(f'Error: Log file does not exist: {log_path}')
        return
     
    failed_logins, successful_logins = parse_auth_log(log_path)

    print(f"Failed login attempts found: {len(failed_logins)}")
    for attempt in failed_logins:
        print(f"User: {attempt['user']}, IP: {attempt['ip']}")

    print(f"\nSuccessful login attempts found: {len(successful_logins)}")
    for attempt in successful_logins:
        print(f"User: {attempt['user']}, IP: {attempt['ip']}")

    # Save to JSON
    failed_file = log_path.parent / 'failed_logins.json'
    success_file = log_path.parent / 'successful_logins.json'

    with failed_file.open('w', encoding='utf-8') as f:
        json.dump(failed_logins, f, indent=2)
    with success_file.open('w', encoding='utf-8') as f:
        json.dump(successful_logins, f, indent=2)

        print(f"\nParsed data saved to:\n   {failed_file}\n {success_file}")

if __name__ == '__main__':
    main()
