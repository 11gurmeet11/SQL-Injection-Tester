🎯 SQL Injection Testing Tool v2.1
=================================

👨‍💻 Author: gurmeet kaur 🔐 License: MIT

🆕 What’s new in v2.1
----------------------
✅ Auto-detect every GET/POST parameter (no manual FUZZ needed).
✅ Bulk scan via --url-file (supports comments, blank lines).
✅ Zero warnings: disables SSL warnings, handles all network errors.
✅ Self-testing: unit test suite runs when launched with no arguments.
✅ Clean & color-coded output (optional with --color).

📦 Installation
----------------
1. 📁 Clone or download this repository:
   ```bash
   git clone https://github.com/yourname/sql-injection-tester.git
   cd sql-injection-tester
   ```

2. 🐍 Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. 📦 Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *(If `requirements.txt` is not available, install manually:)*
   ```bash
   pip install requests colorama urllib3
   ```

🚀 Usage Examples
-----------------
🔎 Auto‑detect SQLi on one URL
    python sql_injection_tester.py -u "https://tld/items.php?id=1&cat=2" -A -v

📝 POST Form auto-detect
    python sql_injection_tester.py -u "https://tld/login.php" -X POST -d "u=admin&p=123" -A

📂 Scan many targets from file (30 threads)
    python sql_injection_tester.py --url-file targets.txt -A -t 30

🧪 Auto Unit Test
    python sql_injection_tester.py

📌 Parameters
-------------
-u, --url         → Single target URL (FUZZ optional if -A)
--url-file        → File containing URLs (one per line)
-X, --method      → HTTP verb (GET/POST)
-d, --data        → POST body string
-H, --header      → Add custom headers (repeatable)
-w, --wordlist    → Custom payload wordlist
-t, --threads     → Concurrent threads (default 10)
-A, --auto-detect → Auto-inject into each param
--color           → Optional color output
-v, --verbose     → Verbose scanning output

🧯 Output Example
-----------------
```bash
[*] Scanning 6 variant(s) × 12 payloads …
[+] Potential SQL injection indicators:
    https://target.com/item.php?id=FUZZ | ' OR '1'='1        → 200 1532B 0.31s
```
⚖️ Legal Disclaimer
-------------------
Use this tool only on systems you **own** or are authorized to test. Unauthorized testing is illegal.

