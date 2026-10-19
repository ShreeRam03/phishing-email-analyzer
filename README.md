# Phishing Email Analyzer

A command-line tool that triages a suspicious email (`.eml` file) the way a SOC analyst would: it reads the headers, links and attachments, checks them against common phishing indicators, and gives a risk score with the reasons behind it.

Built with the Python standard library only. VirusTotal lookups are optional.

## What it checks

| Area | Indicators |
|---|---|
| Authentication | SPF, DKIM and DMARC results from the `Authentication-Results` header |
| Sender | `Reply-To` / `Return-Path` on a different domain from `From`; a brand name (PayPal, Microsoft, SBI…) in the display name but not in the sender domain |
| Links | Raw IP address URLs, URL shorteners, punycode look-alike domains, plain HTTP, `@` tricks in URLs, link text that shows one domain but points to another |
| Attachments | Risky file types (`.exe`, `.js`, `.iso`, macro documents…), double extensions like `invoice.pdf.exe`, SHA-256 hash of every file |
| Content | Urgency and pressure language ("account suspended", "within 24 hours") |
| VirusTotal (optional) | Looks up links and attachment hashes with the VirusTotal v3 API |

Each indicator adds points; the total (capped at 100) gives the verdict:

- **0–29** Low risk
- **30–59** Suspicious – review before trusting
- **60–100** High risk – likely phishing

## Example

```
$ python -m phish_analyzer samples/phish_paypal_lookalike.eml --no-vt

Subject:  Action required: your account is suspended
From:     PayPal Security <security@paypa1-support.example>
Links:    2   Attachments: 1

Findings:
  [+25] Authentication SPF = fail
  [+25] Authentication DMARC = fail
  [+20] Sender         Reply-To (help-desk@freemail-box.example) differs from From
  [+25] Sender         Display name mentions 'paypal' but sender domain is paypa1-support.example
  [+20] Link           URL uses a raw IP address: http://198.51.100.23/login/paypal/verify.php
  [+30] Link           Link text shows www.paypal.com but goes to 198.51.100.23
  [+10] Link           URL shortener hides the destination: https://bit.ly/3xYzAbC
  [+25] Attachment     Risky file type .exe: Invoice_Oct2026.pdf.exe
  [+20] Attachment     Double extension: Invoice_Oct2026.pdf.exe
  ...
Risk score: 100/100  ->  HIGH RISK - likely phishing
```

The genuine sample (`samples/legit_newsletter.eml`) scores 0/100.

## Usage

Requires Python 3.9+.

```bash
git clone https://github.com/ShreeRam03/phishing-email-analyzer.git
cd phishing-email-analyzer

python -m phish_analyzer path/to/email.eml            # analyze one email
python -m phish_analyzer *.eml --json report.json     # several emails, save JSON
python -m phish_analyzer email.eml --no-vt            # skip VirusTotal
```

To save an email as `.eml`: in Gmail open the message, **⋮ → Download message**; in Outlook, **File → Save As**.

### VirusTotal (optional)

Get a free API key at virustotal.com and set it as an environment variable. Never put the key in the code.

```bash
# Windows PowerShell
$env:VT_API_KEY = "your-key"
# Linux / macOS
export VT_API_KEY="your-key"
```

The free API allows 4 lookups a minute, so the tool checks at most 4 items per email.

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

## Project layout

```
phish_analyzer/
  parser.py      reads the .eml: headers, links (incl. <a> text), attachments + SHA-256
  checks.py      phishing indicators and scoring
  virustotal.py  optional VirusTotal v3 lookups
  __main__.py    command-line interface and report
samples/         one phishing and one genuine test email (fake domains)
tests/           unit tests
```

## Limitations

- It reads the `Authentication-Results` header written by the receiving mail server; it does not re-run SPF/DKIM checks itself.
- Scores are rule-based, not machine learning. A clean score does not prove an email is safe.
- The sample emails use reserved `.example` domains and a harmless text file as the "attachment".

## Author

Shreeram Perumalla · [LinkedIn](https://www.linkedin.com/in/shreeram-perumalla) · [Blog](https://shreeram03.github.io)
