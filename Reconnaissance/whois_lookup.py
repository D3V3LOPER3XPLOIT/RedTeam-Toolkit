#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WHOIS Lookup Tool
Created by: Syed Ashir
Description: Fetch registrar, creation date, and expiry date (with optional save).
"""

import sys
import re
import argparse
import json
from datetime import datetime

# Optional colors
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    C_OK = Fore.GREEN + Style.BRIGHT
    C_WARN = Fore.YELLOW + Style.BRIGHT
    C_ERR = Fore.RED + Style.BRIGHT
    C_INFO = Fore.CYAN + Style.BRIGHT
    C_DIM = Style.DIM
    C_RESET = Style.RESET_ALL
except Exception:
    # Fallback if colorama isn't installed
    C_OK = C_WARN = C_ERR = C_INFO = C_DIM = C_RESET = ""

# WHOIS lib
try:
    import whois
except Exception:
    print("\n" + "!"*68)
    print(" The package 'python-whois' is required.")
    print(" Install it with:  pip install python-whois")
    print("!"*68 + "\n")
    sys.exit(1)

BANNER = rf"""{C_INFO}
 __        __   _    _ _     _       _                 _             
 \ \      / /__| | _(_) |__ | | ___ | |__   ___   ___ | | _____ _ __ 
  \ \ /\ / / _ \ |/ / | '_ \| |/ _ \| '_ \ / _ \ / _ \| |/ / _ \ '__|
   \ V  V /  __/   <| | |_) | | (_) | | | | (_) | (_) |   <  __/ |   
    \_/\_/ \___|_|\_\_|_.__/|_|\___/|_| |_|\___/ \___/|_|\_\___|_|   
{C_RESET}{C_DIM}                Whois Lookup Tool
                 This tool is created by Syed Ashir
{C_RESET}"""

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)

def valid_domain(s: str) -> bool:
    """Basic domain validator (not for URLs)."""
    s = s.strip().lower()
    # Strip protocol and path if mistakenly included
    s = re.sub(r"^https?://", "", s).split("/")[0]
    return bool(DOMAIN_REGEX.match(s))

def normalize_date(val):
    """WHOIS can return a single datetime or a list; return ISO string or empty."""
    if isinstance(val, list):
        # pick the earliest non-null value
        vals = [v for v in val if v]
        if not vals:
            return ""
        try:
            return sorted(vals)[0].isoformat()
        except Exception:
            try:
                return str(sorted(vals)[0])
            except Exception:
                return ""
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val) if val else ""

def clean_domain(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"^https?://", "", s).split("/")[0]
    return s

def lookup(domain: str) -> dict:
    """Run whois lookup and extract key fields."""
    w = whois.whois(domain)
    data = {
        "domain": domain,
        "registrar": getattr(w, "registrar", "") or "",
        "creation_date": normalize_date(getattr(w, "creation_date", "")),
        "expiration_date": normalize_date(getattr(w, "expiration_date", "")),
        "updated_date": normalize_date(getattr(w, "updated_date", "")),
        "status": getattr(w, "status", ""),
        "name_servers": getattr(w, "name_servers", []),
        "raw": getattr(w, "text", None) or ""  # raw text if available
    }
    # Normalize name servers to list of strings
    if isinstance(data["name_servers"], (set, tuple)):
        data["name_servers"] = list(data["name_servers"])
    if isinstance(data["name_servers"], str):
        data["name_servers"] = [data["name_servers"]]
    # Convert statuses if set
    if isinstance(data["status"], (set, tuple)):
        data["status"] = list(data["status"])
    return data

def print_result(res: dict):
    print(f"\n{C_OK}[✓] Domain:{C_RESET} {res['domain']}")
    print(f"{C_INFO}Registrar:{C_RESET} {res.get('registrar') or 'N/A'}")
    print(f"{C_INFO}Created On:{C_RESET} {res.get('creation_date') or 'N/A'}")
    print(f"{C_INFO}Expires On:{C_RESET} {res.get('expiration_date') or 'N/A'}")
    print(f"{C_INFO}Updated On:{C_RESET} {res.get('updated_date') or 'N/A'}")
    ns_list = res.get("name_servers") or []
    if ns_list:
        print(f"{C_INFO}Name Servers:{C_RESET} " + ", ".join(sorted(ns_list)))
    status = res.get("status")
    if status:
        if isinstance(status, list):
            print(f"{C_INFO}Status:{C_RESET} " + ", ".join(status))
        else:
            print(f"{C_INFO}Status:{C_RESET} {status}")

def save_results(results, path: str, fmt: str):
    fmt = fmt.lower()
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    elif fmt == "csv":
        # Minimal CSV: domain, registrar, creation, expiration
        import csv
        fields = ["domain", "registrar", "creation_date", "expiration_date", "updated_date"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in results:
                w.writerow({k: r.get(k, "") for k in fields})
    else:
        raise ValueError("Unsupported save format. Use json or csv.")

def parse_args():
    p = argparse.ArgumentParser(
        description="WHOIS Lookup Tool — Created by Syed Ashir",
        epilog="Examples:\n"
               "  python whois_lookup.py example.com\n"
               "  python whois_lookup.py -f domains.txt -o out.json -F json\n"
               "  python whois_lookup.py google.com github.com -o out.csv -F csv",
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument("domains", nargs="*", help="Domain(s) to query (space-separated)")
    p.add_argument("-f", "--file", help="Path to a file containing domains (one per line)")
    p.add_argument("-o", "--output", help="Path to save results (e.g., results.json or results.csv)")
    p.add_argument("-F", "--format", choices=["json", "csv"], help="Save format if --output is used")
    p.add_argument("--no-raw", action="store_true", help="Exclude raw WHOIS text from saved JSON")
    return p.parse_args()

def main():
    print(BANNER)
    args = parse_args()

    domains = []
    # CLI domains
    for d in args.domains:
        domains.append(clean_domain(d))
    # File domains
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    s = clean_domain(line.strip())
                    if s:
                        domains.append(s)
        except FileNotFoundError:
            print(f"{C_ERR}[!] File not found:{C_RESET} {args.file}")
            sys.exit(1)

    # Interactive if none provided
    if not domains:
        user_in = input(f"{C_WARN}Enter a domain (e.g., example.com): {C_RESET}").strip()
        if user_in:
            domains = [clean_domain(user_in)]

    if not domains:
        print(f"{C_ERR}[!] No domains provided.{C_RESET}")
        sys.exit(1)

    # Deduplicate while keeping order
    seen = set()
    unique_domains = []
    for d in domains:
        if d not in seen:
            unique_domains.append(d)
            seen.add(d)

    results = []
    for d in unique_domains:
        if not valid_domain(d):
            print(f"{C_ERR}[x] Invalid domain skipped:{C_RESET} {d}")
            continue
        try:
            res = lookup(d)
            print_result(res)
            results.append(res)
        except Exception as e:
            print(f"{C_ERR}[x] Lookup failed for {d}:{C_RESET} {e}")

    # Save if requested
    if args.output:
        if not args.format:
            # Infer format from extension
            if args.output.lower().endswith(".json"):
                fmt = "json"
            elif args.output.lower().endswith(".csv"):
                fmt = "csv"
            else:
                print(f"{C_ERR}[!] Please specify --format json|csv or use .json/.csv extension.{C_RESET}")
                sys.exit(1)
        else:
            fmt = args.format

        to_save = results
        if fmt == "json" and args.no_raw:
            # strip raw to reduce file size
            cleaned = []
            for r in results:
                r2 = dict(r)
                r2.pop("raw", None)
                cleaned.append(r2)
            to_save = cleaned

        try:
            save_results(to_save, args.output, fmt)
            print(f"\n{C_OK}[✓] Saved {len(results)} result(s) to:{C_RESET} {args.output}")
        except Exception as e:
            print(f"{C_ERR}[x] Failed to save results:{C_RESET} {e}")

if __name__ == "__main__":
    main()
