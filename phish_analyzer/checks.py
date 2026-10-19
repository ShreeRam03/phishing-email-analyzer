"""Phishing indicators. Each check returns a list of Finding objects."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy"}
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".iso", ".img",
                    ".hta", ".lnk", ".docm", ".xlsm", ".jar", ".zip", ".rar", ".7z", ".html", ".htm"}
URGENT_WORDS = ["urgent", "immediately", "suspended", "verify your account", "password expires",
                "unusual activity", "action required", "final notice", "within 24 hours", "locked"]
BRANDS = ["paypal", "microsoft", "office365", "amazon", "apple", "netflix", "sbi", "hdfc", "icici"]


@dataclass
class Finding:
    category: str
    detail: str
    score: int  # how much this adds to the risk score


def _domain(addr_or_url):
    if "@" in addr_or_url and "://" not in addr_or_url:
        return addr_or_url.rsplit("@", 1)[-1].lower()
    return (urlparse(addr_or_url).hostname or "").lower()


def _base_domain(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def check_authentication(email):
    """SPF, DKIM and DMARC verdicts from the receiving server's Authentication-Results header."""
    findings = []
    results = email.auth_results.lower()
    if not results:
        return [Finding("Authentication", "No Authentication-Results header (SPF/DKIM/DMARC unknown)", 10)]
    for mech in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mech}=(\w+)", results)
        verdict = match.group(1) if match else "none"
        if verdict in ("fail", "softfail", "permerror"):
            findings.append(Finding("Authentication", f"{mech.upper()} = {verdict}", 25))
        elif verdict in ("none", "neutral", "temperror"):
            findings.append(Finding("Authentication", f"{mech.upper()} = {verdict}", 10))
    return findings


def check_sender(email):
    findings = []
    from_domain = _domain(email.from_addr)
    for label, addr in (("Reply-To", email.reply_to), ("Return-Path", email.return_path)):
        if addr and _base_domain(_domain(addr)) != _base_domain(from_domain):
            findings.append(Finding("Sender", f"{label} ({addr}) differs from From ({email.from_addr})", 20))
    name = email.from_name.lower()
    for brand in BRANDS:
        if brand in name and brand not in from_domain:
            findings.append(Finding("Sender", f"Display name mentions '{brand}' but sender domain is {from_domain}", 25))
    return findings


def check_links(email):
    findings = []
    for link in email.links:
        host = _domain(link.url)
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
            findings.append(Finding("Link", f"URL uses a raw IP address: {link.url}", 20))
        except ValueError:
            pass
        if host in SHORTENERS:
            findings.append(Finding("Link", f"URL shortener hides the destination: {link.url}", 10))
        if "xn--" in host:
            findings.append(Finding("Link", f"Punycode domain (possible look-alike): {host}", 20))
        if link.url.lower().startswith("http://"):
            findings.append(Finding("Link", f"Link is not HTTPS: {link.url}", 5))
        if "@" in urlparse(link.url).netloc:
            findings.append(Finding("Link", f"'@' in URL hides the real host: {link.url}", 20))
        text = link.text.lower().strip()
        shown = ""
        if text.startswith(("http://", "https://")):
            shown = _domain(text)
        elif text.startswith("www."):
            shown = text.split("/")[0]
        if shown and _base_domain(shown) != _base_domain(host):
            findings.append(Finding("Link", f"Link text shows {shown} but goes to {host}", 30))
    return findings


def check_attachments(email):
    findings = []
    for att in email.attachments:
        name = att.filename.lower()
        ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        if ext in RISKY_EXTENSIONS:
            findings.append(Finding("Attachment", f"Risky file type {ext}: {att.filename}", 25))
        if name.count(".") >= 2 and ext in RISKY_EXTENSIONS:
            findings.append(Finding("Attachment", f"Double extension: {att.filename}", 20))
    return findings


def check_content(email):
    text = (email.subject + " " + email.body_text).lower()
    hits = [w for w in URGENT_WORDS if w in text]
    if hits:
        return [Finding("Content", "Urgency / pressure language: " + ", ".join(hits), min(5 * len(hits), 20))]
    return []


ALL_CHECKS = [check_authentication, check_sender, check_links, check_attachments, check_content]


def run_all(email):
    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(email))
    return findings


def verdict(score):
    if score >= 60:
        return "HIGH RISK - likely phishing"
    if score >= 30:
        return "SUSPICIOUS - review before trusting"
    return "LOW RISK - no strong phishing signs"
