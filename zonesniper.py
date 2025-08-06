import subprocess
import argparse
import threading
import time
import sys
import os
import requests
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Banner
BANNER = r"""

     +--^----------,--------,-----,--------^-,       
     | |||||||||   `--------'     |          O       
     `+---------------------------^----------|       
       `\_,---------,---------,--------------'       
         / XXXXXX /'|       /'                        
        / XXXXXX /  `\    /'                         
       / XXXXXX /`-------'                          
      / XXXXXX /                                    
     / XXXXXX /                                     
    (________(                By NK             
     `------'                                       

┌──────────────────────────────────────────────┐
│  🎯 ZONE TRANSFER VULNERABILITY SNIPER       │
└──────────────────────────────────────────────┘

"""

stop_spinner = False
vulnerable_results = []
verbose_mode = False

def spinner():
    while not stop_spinner:
        for cursor in '|/-\\':
            sys.stdout.write(f'\r\033[94m[🔎] Scanning... {cursor}\033[0m')
            sys.stdout.flush()
            time.sleep(0.1)

def show_banner():
    for char in BANNER:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.0003)
    print("\n\033[92mSniping misconfigured DNS servers...\033[0m")
    print("-" * 70)

def send_discord_webhook(domain, ns, zone_data, webhook_url):
    if not webhook_url:
        return
    message = f"🚨 **Zone Transfer Detected**\n**Domain:** {domain}\n**Nameserver:** {ns}\n```\n{zone_data[:1800]}\n...truncated\n```"
    try:
        response = requests.post(webhook_url, json={"content": message})
        if response.status_code != 204:
            print(f"[!] Failed to send webhook: {response.status_code} {response.text}")
    except Exception as e:
        print(f"[!] Exception sending webhook: {e}")

def dig_zone_transfer(domain, webhook_url=None):
    try:
        ns_lookup = subprocess.run(["dig", domain, "NS", "+short"], capture_output=True, text=True, timeout=5)
        nameservers = [line.strip() for line in ns_lookup.stdout.splitlines() if line.strip()]
    except Exception:
        return

    vulnerable = False
    for ns in nameservers:
        try:
            axfr = subprocess.run(["dig", f"@{ns}", domain, "AXFR"], capture_output=True, text=True, timeout=10)
            output = axfr.stdout.strip().lower()

            if any(err in output for err in [
                "connection timed out", "transfer failed",
                "communications error", "no servers could be reached"
            ]):
                continue

            if len(output.splitlines()) > 3:
                print(f"\n\033[91m[VULNERABLE]\033[0m {domain} → AXFR allowed on: {ns}")
                zone_data = axfr.stdout.strip()
                vulnerable_results.append((domain, ns, zone_data))
                send_discord_webhook(domain, ns, zone_data, webhook_url)
                vulnerable = True
                return
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue

    if verbose_mode and not vulnerable:
        print(f"\033[94m[NOT VULNERABLE]\033[0m {domain}")

def clean_domain(line):
    line = line.strip().replace("http://", "").replace("https://", "").split("/")[0]
    return line if "." in line else None

def write_html_report(results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = f"zonetransfer_report_{timestamp}"
    os.makedirs(report_dir, exist_ok=True)
    report_file = os.path.join(report_dir, "report.html")

    with open(report_file, "w") as f:
        f.write("<html><head><title>Zone Transfer Report</title>")
        f.write("<style>body { font-family: Arial; background: #111; color: #eee; } h1 { color: #f33; } table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #444; padding: 8px; text-align: left; } tr:nth-child(even) { background-color: #222; }</style>")
        f.write("</head><body>")
        f.write("<h1>Zone Transfer Vulnerability Report</h1>")
        f.write(f"<p>Scanned at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        f.write("<table><tr><th>Domain</th><th>Nameserver</th><th>AXFR Output (Truncated)</th></tr>")
        for domain, ns, zone_data in results:
            f.write(f"<tr><td>{domain}</td><td>{ns}</td><td><pre>{zone_data[:500]}...</pre></td></tr>")
        f.write("</table></body></html>")

    print(f"\n\033[92m[✔] HTML report saved to: {report_file}\033[0m\n")

def main():
    global stop_spinner, verbose_mode

    parser = argparse.ArgumentParser(description="Zone Transfer Sniper by NK")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Check a single domain")
    group.add_argument("-l", "--list", help="File containing domains to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show non-vulnerable domains too")
    parser.add_argument("--webhook", help="Discord webhook URL for notifications")

    args = parser.parse_args()
    verbose_mode = args.verbose
    webhook_url = args.webhook

    show_banner()

    if not verbose_mode:
        spinner_thread = threading.Thread(target=spinner)
        spinner_thread.start()

    try:
        if args.domain:
            domain = clean_domain(args.domain)
            if domain:
                dig_zone_transfer(domain, webhook_url)

        elif args.list:
            try:
                with open(args.list, "r") as f:
                    raw = [clean_domain(line) for line in f if clean_domain(line)]
                with ThreadPoolExecutor(max_workers=50) as executor:
                    executor.map(lambda domain: dig_zone_transfer(domain, webhook_url), raw)
            except FileNotFoundError:
                print(f"\n\033[91m[ERROR]\033[0m File not found: {args.list}")
    finally:
        stop_spinner = True
        if not verbose_mode:
            spinner_thread.join()
            print("\n\033[92m[✔] Scan completed.\033[0m\n")

        if vulnerable_results:
            write_html_report(vulnerable_results)
        else:
            print("\033[93m[!] No vulnerable domains found.\033[0m")

if __name__ == "__main__":
    main()
