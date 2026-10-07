<h1 align="center">Security Suite</h1>

<p align="center">
  <em>single-file offensive security toolkit i built for my cybersecurity exam</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white">
  <img alt="Lines" src="https://img.shields.io/badge/lines-~2400-ff69b4?style=for-the-badge">
  <img alt="Dependencies" src="https://img.shields.io/badge/optional%20deps-6-9cf?style=for-the-badge">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey?style=for-the-badge">
  <img alt="Status" src="https://img.shields.io/badge/exam%20project-%E2%9C%94%20submitted-success?style=for-the-badge">
</p>

---

## hello

#### this is my exam project for **Network Security & Ethical Hacking** — i had about six weeks to design, build, and document a penetration-testing toolkit from scratch, and this is what came out of it. everything lives in one `main.py` file (~2,400 lines) because the exam rules required a single submission artifact, but i tried to keep the internals clean with clear section banners and layered modules.

#### i really wanted it to feel like a *real* pentest toolkit — not just a script that scans ports and prints pretty colours — so i added proper CVE enrichment, async scanning, TLS deep-probing, web fuzzing, and a whole bunch of little quality-of-life touches. i hope you enjoy reading through it as much as i enjoyed building it.

> [!WARNING]
> **only use this on systems you own or have written permission to test.** i put an authorization prompt in front of every active scan for a reason — don't make me regret it

---

## What it can do

#### a quick tour of every feature. the CLI has **29 menu options**, and each one is also available as a one-shot `--scan` command for scripting.

### Password intelligence
- Shannon-style **entropy estimation** with a per-character-class breakdown
- Scored strength rating (`VERY WEAK` → `VERY STRONG`) with written feedback
- Suggestions for improving weak passwords
- **Password policy auditor** — enforce min length, character classes, and a banned list

### Network scanning
- **Synchronous TCP port scanner** with `ThreadPoolExecutor` and nmap-style port specs (`22,80,443,8000-8100`)
- **Asynchronous TCP scanner** using `asyncio.open_connection` (great for sweeping /16s)
- **UDP scanner** with ICMP-based state inference
- **ARP discovery** for local subnets (batched, so it doesn't spawn 254 scapy loops)
- **ICMP ping** with scapy + system-`ping` fallback
- **Service fingerprinting** from banners (OpenSSH, nginx, Apache, Redis, MongoDB, Docker, Kubernetes, …)

### TLS/SSL
- Full certificate parsing via `cryptography` (subject, issuer, SANs, expiry, signature algorithm)
- **Passive** (verified) and **aggressive** (unverified) modes — and the aggressive mode actually returns a real certificate now, which took me an embarrassing amount of time to get right
- **Deep scan**: probes TLS 1.0 → 1.3 and tries 3DES / RC4 / NULL / EXPORT ciphers to flag weak crypto
- Automatic findings for expired certs, weak protocols, and low cipher strength

### DNS & reconnaissance
- Enumeration of A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, SRV, DNSKEY, PTR
- **DMARC** record discovery
- **AXFR zone transfer** detection against every nameserver
- **Subdomain brute force** with a bundled default list and full seclists support
- **WHOIS** lookup with clean field extraction

### Web application testing
- Security header grading (A–F) against nine modern headers (including COOP, CORP, COEP)
- Cookie security audit (Secure, HttpOnly, SameSite)
- Technology fingerprinting (WordPress, Drupal, Next.js, Nuxt, React, Vue, Shopify, …)
- **SQL injection** — error-based detection plus optional time-based blind probing
- **Reflected XSS** detection
- **Path traversal** (Linux `/etc/passwd` and Windows `win.ini` signatures)
- **Open redirect** detection
- **HTTP methods** probe (TRACE / PUT / DELETE / OPTIONS)
- **Directory brute force** with a bundled wordlist and `.php/.html/.bak/.zip/.tar.gz/.json/.xml` extension sweep
- **Parameter fuzzing** for anomaly-based discovery

### Crypto & tokens
- **JWT inspection** with `alg=none` and missing-`exp` findings
- **Hash identification** for 14 formats (MD5, NTLM, bcrypt, argon2, sha{1,224,256,384,512}, crypt variants, MySQL4, CRC32)
- **Dictionary cracker** with mangling rules (`capitalize`, `upper`, `reverse`, numeric/`!` suffixes)
- **RSA keypair generation** and **self-signed certificate** creation

### Reporting & storage
- Findings severity-sorted: `CRITICAL > HIGH > MEDIUM > LOW > INFO`
- Reports stored in **SQLite (WAL mode)**
- Export to **JSON**, **Markdown**, **HTML** (styled severity table), and **CSV**
- Every finding carries `evidence`, optional `CVE`, optional `CVSS`, and a `category`

### CVE enrichment
- Queries the **NVD 2.0 API** for fingerprinted services
- Extracts CVSS v3.1 / v3.0 / v2 severity and base score
- Optional API key support (avoids the 5-requests-per-30s anonymous limit)
- Per-keyword caching so repeated lookups are free

---

## Quick start

```bash
1. clone / save the file
git clone https://github.com/xaet/security-suite.git
cd securitysuite

2. (optional) install the extras
pip install requests cryptography dnspython python-whois scapy rich

3. run it
python main.py
```
#### the tool degrades gracefully — if requests isn't installed, the web features are disabled but everything else still works, and so on. you only need cryptography if you want certificate parsing and RSA / cert generation
---
## Interactive mode
#### just run python main.py and you'll get a little ASCII banner and a numbered menu. everything is guided, so you can't really get lost.
---
## One-shot mode (for scripting)
#### every menu option has a matching --scan sub-command:
```bash
quick port scan
python main.py --scan port --target 10.0.0.5 --ports 22,80,443,8000-8100

async sweep for a full /16
python main.py --scan async-port --target 10.0.0.5 --ports 1-65535

full assessment with HTML/MD/CSV exports
python main.py --scan full --target example.com --output ./reports

web deep scan
python main.py --scan web-deep --target https://example.com

crack an MD5 hash against rockyou
python main.py --scan crack --target 5f4dcc3b5aa765d61d8327deb882cf99 \
  --wordlist /usr/share/wordlists/rockyou.txt
  ```
---
## With a config file
#### i made it read JSON or TOML — whichever you prefer
```
rate_limit_rps   = 150.0
max_threads      = 300
async_concurrency = 800
aggressive_sqli  = true
use_nvd          = true
nvd_api_key      = "nvd-key-here"
report_dir       = "reports"
```
```bash
python main.py --config secsuite.toml
```
---
## Project layout
#### even though it's one file, it's organised into clear sections:
```
main.py
├── Logging                     colored, verbose-aware
├── Optional dependencies       soft-imports for requests/crypto/scapy/dns/whois/rich
├── Utilities                   retry, RateLimiter, parse_ports, helpers
├── Config                      validated dataclass, JSON/TOML loader
├── Dataclasses                 PortResult, Finding, ScanReport
├── Signature databases         hashes, banners, headers, ports, payloads
├── PasswordIntel               entropy, scoring, policy audit
├── Storage                     SQLite WAL, findings + assets tables
├── NetworkScanner              TCP/async/UDP/ARP + banner grabbing
├── TLSAnalyzer                 cert parsing, deep scan, weak-cipher probe
├── DNSAnalyzer / WhoisAnalyzer DNS enums, AXFR, subdomains, WHOIS
├── WebScanner                  headers, cookies, SQLi, XSS, traversal, dirs
├── HashTools / JWTTools        identification + cracking + JWT inspection
├── CryptoTools                 RSA + self-signed cert generation
├── CVELookup                   NVD 2.0 client with caching
├── SecuritySuite               the orchestrator
├── CLI                         interactive menu + rich rendering
└── main()                      argparse + one-shot dispatcher
```
---
## Things i tested it on
#### small lab i set up in VMs — no real targets
|Environment|What I tested|
|-------------|:-------------:|
|Kali → Metasploitable2|Port scan, banner grab, vuln map, CVE enrichment|
|Kali → DVWA (low/medium)|SQLi, XSS, traversal, dir brute force|
|Kali → OWASP Juice Shop|Header grading, cookie audit, tech fingerprint|
|Kali → example.com|TLS deep scan, DNS enum, WHOIS, subdomain brute|
|Kali → localhost|Crypto (RSA + self-signed), hash cracking, JWT inspection|

#### everything in the full_assessment pipeline produced a clean report and exported neatly to JSON/MD/HTML/CSV
---
## Requirements
|Package|Required for|
| ------------- |:-------------:|
|requests|Web scanning, CVE lookups|
|cryptography|Cert parsing, keygen|
|dnspython|DNS enumeration, subdomains, AXFR|
|python-whois|WHOIS lookups|
|scapy|ARP discovery, ICMP ping (falls back to **ping**)|
|rich|Coloured output, progress bars, tables|
#### All of them are optional — the tool tells you at startup what's available.
---
## Ethics & authorization
#### i want to be really clear about this part
#### this tool is designed for authorized security testing only — CTFs, your own lab, bug-bounty programs where you've read the scope, or client engagements with a signed contract. every active scan in the interactive menu is gated behind a confirmation prompt, and the one-shot mode assumes you know what you're doing
#### if you're not sure whether you're allowed to test a target: you're not. don't use this.
---
## License
```
MIT License

Copyright (c) 2026 XAET/RIRI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
---
## Thanks for reading!
#### if you found a bug, have a suggestion — please open an issue or add me on discord. i'd love to hear what you think, and honestly, this project taught me more than any single lecture did
