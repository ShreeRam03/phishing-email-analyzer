"""Command line: python -m phish_analyzer suspicious.eml [--json report.json]"""

import argparse
import json
import sys
from dataclasses import asdict

from . import checks, virustotal
from .parser import parse_eml


def build_report(path, use_vt=True):
    email = parse_eml(path)
    findings = checks.run_all(email)
    vt_status = virustotal.enrich(email, findings, checks.Finding) if use_vt else "disabled"
    score = min(sum(f.score for f in findings), 100)
    return {
        "file": path,
        "subject": email.subject,
        "from": f"{email.from_name} <{email.from_addr}>",
        "reply_to": email.reply_to,
        "links": [asdict(link) for link in email.links],
        "attachments": [asdict(att) for att in email.attachments],
        "virustotal": vt_status,
        "findings": [asdict(f) for f in findings],
        "score": score,
        "verdict": checks.verdict(score),
    }


def print_report(report):
    print(f"\nFile:     {report['file']}")
    print(f"Subject:  {report['subject']}")
    print(f"From:     {report['from']}")
    print(f"Links:    {len(report['links'])}   Attachments: {len(report['attachments'])}")
    print(f"VirusTotal: {report['virustotal']}\n")
    if report["findings"]:
        print("Findings:")
        for f in report["findings"]:
            print(f"  [+{f['score']:>2}] {f['category']:<14} {f['detail']}")
    else:
        print("Findings: none")
    print(f"\nRisk score: {report['score']}/100  ->  {report['verdict']}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="phish_analyzer", description="Triage a suspicious .eml email.")
    ap.add_argument("eml", nargs="+", help="one or more .eml files")
    ap.add_argument("--json", help="also write the report(s) to this JSON file")
    ap.add_argument("--no-vt", action="store_true", help="skip VirusTotal lookups")
    args = ap.parse_args(argv)

    reports = [build_report(path, use_vt=not args.no_vt) for path in args.eml]
    for report in reports:
        print_report(report)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2)
        print(f"Saved JSON report to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
