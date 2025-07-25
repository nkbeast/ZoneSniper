<h1 align="center">💣 ZoneSniper - DNS AXFR Vulnerability Scanner</h1>

<p align="center">
  <a href="https://github.com/nkbeast/ZoneSniper"><img src="https://raw.githubusercontent.com/nkbeast/ZoneSniper/refs/heads/main/banner.png" width="600" alt="zonesniper-banner"></a>
</p>

<h4 align="center">🔫 DNS Zone Transfer vulnerability scanner (AXFR) with multi-threading, bulk input, verbose mode & HTML reporting.</h4>
<br>

---

## 🧾 Description

**ZoneSniper** is a blazing-fast, fully automated scanner that detects misconfigured DNS servers allowing AXFR (zone transfer). Ideal for bug bounty hunters, penetration testers, and red teamers, it handles large input lists with multi-threaded precision and exports clean vulnerability reports in HTML.

---

## ✨ Features

- 🎯 Scans for AXFR (zone transfer) vulnerabilities
- 📂 Bulk input support using `--list`
- ⚡ Multi-threaded scanning with `--threads`
- 🤫 Silent/Verbose mode with `--verbose`
- 📄 HTML Report generation
  
---

## 🚀 Installation And Usage

```bash
# Installation
git clone https://github.com/nkbeast/ZoneSniper.git

cd Zonesnipher

pip install dnspython

# Scan a single domain
python3 zonesniper.py --domain zonetransfer.me

# Bulk domain scan from file
python3 zonesniper.py --list domains.txt

# Use verbose mode to see full results
python3 zonesniper.py --list domains.txt --verbose

# Set custom thread count (default is 10)
python3 zonesniper.py --list domains.txt --threads 30

```

## OUTPUT

<p align="center">
  <a href="https://github.com/nkbeast/ZoneSniper"><img src="https://raw.githubusercontent.com/nkbeast/ZoneSniper/refs/heads/main/zonesnipher2.png" width="600" alt="zonesniper-banner2"></a>
</p>
