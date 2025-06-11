````markdown
# 🛡️ VulnScanner – Web Security Scanner (XSS, SQLi, Header Checks)

A lightweight Python-based scanner that detects common web vulnerabilities:

- 💥 Reflected XSS
- 💉 SQL Injection
- 🛠 Missing security headers

Ideal for students, bug bounty hunters, or anyone learning web security.

---

## 🚀 Features

- CLI support with `argparse`
- Colorized terminal output using `colorama`
- Markdown report generation (GitHub-friendly)
- Timestamped scan logs
- Lightweight and beginner-friendly

---

## 🧪 Example Usage

Basic scan:

```bash
python vulnscan.py --url "https://example.com/page.php?id=1&search=test"
```
````

Save output as Markdown:

```bash
python vulnscan.py --url "https://example.com/page.php?id=1" --output reports/vuln_report.md
```

---

## ✅ Sample Output

```text
[XSS] Found reflected XSS on parameter 'search' using payload: <script>alert(1)</script>
[SQLi] Found vulnerability on parameter 'id' using payload: ' OR 1=1 --
[Headers] Missing: Content-Security-Policy, Strict-Transport-Security
```

---

## 📂 Project Structure

```
vulnscanner/
├── vulnscan.py
├── requirements.txt
├── reports/
│   └── vuln_report.md
├── README.md
├── LICENSE
```

---

## 📦 Installation

```bash
pip install -r requirements.txt
```

**requirements.txt**

```
requests
colorama
```

---

## ⚠️ Legal & Ethical Notice

This tool is for **educational and ethical** purposes only.
❗ Do NOT scan targets you don’t own or don’t have explicit permission to test.
