import argparse
import os
from utils.scanner_engine import Scanner
from utils.logger import Logger

def main():
    parser = argparse.ArgumentParser(description="DeepVulnScan - XSS & SQLi Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--target', help='Single target URL to scan')
    group.add_argument('-T', '--targets-file', help='File with list of target URLs (one per line)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    logger = Logger()
    scanner = Scanner(logger)

    targets = []
    if args.target:
        targets.append(args.target)
    else:
        if not os.path.isfile(args.targets_file):
            print(f"Targets file not found: {args.targets_file}")
            return
        with open(args.targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

    for target in targets:
        if args.verbose:
            print(f"[+] Scanning: {target}")
        try:
            scanner.scan(target)
        except Exception as e:
            print(f"[!] Error scanning {target}: {e}")

if __name__ == '__main__':
    main()
