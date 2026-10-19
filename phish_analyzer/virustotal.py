"""Optional VirusTotal v3 lookups. Only runs when VT_API_KEY is set."""

import base64
import json
import os
import urllib.error
import urllib.request

API = "https://www.virustotal.com/api/v3"


def _get(path, key):
    req = urllib.request.Request(f"{API}/{path}", headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return None  # VirusTotal has never seen it
        raise


def _stats(report):
    if not report:
        return None
    return report["data"]["attributes"]["last_analysis_stats"]


def lookup_url(url, key):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return _stats(_get(f"urls/{url_id}", key))


def lookup_hash(sha256, key):
    return _stats(_get(f"files/{sha256}", key))


def enrich(email, findings, finding_cls, max_lookups=4):
    """Adds findings for URLs/attachments that VirusTotal engines flag.

    The free API allows 4 requests a minute, so lookups are capped.
    """
    key = os.environ.get("VT_API_KEY")
    if not key:
        return "skipped (set VT_API_KEY to enable)"
    targets = [("url", link.url) for link in email.links] + \
              [("file", att.sha256) for att in email.attachments]
    for kind, value in targets[:max_lookups]:
        stats = lookup_url(value, key) if kind == "url" else lookup_hash(value, key)
        if stats and stats.get("malicious", 0) >= 2:
            findings.append(finding_cls(
                "VirusTotal", f"{stats['malicious']} engines flag {kind}: {value}", 40))
    return f"checked {min(len(targets), max_lookups)} of {len(targets)} items"
