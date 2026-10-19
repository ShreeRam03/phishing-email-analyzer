"""Read a .eml file and pull out the parts an analyst looks at."""

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)


@dataclass
class Link:
    url: str
    text: str = ""  # visible text of an <a> tag, empty for plain-text links


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    subject: str
    from_addr: str
    from_name: str
    reply_to: str
    return_path: str
    auth_results: str
    received: list = field(default_factory=list)
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    body_text: str = ""


class _AnchorCollector(HTMLParser):
    """Collects (href, visible text) pairs from HTML bodies."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append(Link(self._href.strip(), "".join(self._text).strip()))
            self._href = None


def _email_only(header_value):
    return parseaddr(header_value or "")[1].lower()


def parse_eml(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    from_name, from_addr = parseaddr(msg.get("From", ""))
    parsed = ParsedEmail(
        subject=str(msg.get("Subject", "")),
        from_addr=from_addr.lower(),
        from_name=from_name,
        reply_to=_email_only(msg.get("Reply-To")),
        return_path=_email_only(msg.get("Return-Path")),
        auth_results=" ".join(str(h) for h in msg.get_all("Authentication-Results", [])),
        received=[str(h) for h in msg.get_all("Received", [])],
    )

    text_parts = []
    plain_parts = []  # bare URLs are only searched for in text/plain parts
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename or part.get_content_disposition() == "attachment":
            parsed.attachments.append(Attachment(
                filename=filename or "(no name)",
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            ))
            continue
        charset = part.get_content_charset() or "utf-8"
        content = payload.decode(charset, errors="replace")
        if part.get_content_type() == "text/html":
            collector = _AnchorCollector()
            collector.feed(content)
            parsed.links.extend(collector.links)
        elif part.get_content_type() == "text/plain":
            plain_parts.append(content)
        text_parts.append(content)

    parsed.body_text = "\n".join(text_parts)
    known = {link.url for link in parsed.links}
    for url in URL_RE.findall("\n".join(plain_parts)):
        if url not in known:
            parsed.links.append(Link(url))
            known.add(url)
    return parsed
