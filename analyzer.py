"""PhishGuard AI - Phase 1 email analysis engine.

This module performs static email inspection. It does not open URLs or execute
attachments. VirusTotal lookups are optional and require VT_API_KEY in .env.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import re
import ipaddress
from dataclasses import dataclass, asdict
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
VT_TIMEOUT = float(os.getenv("VT_TIMEOUT", "12"))
MAX_URL_CHECKS = int(os.getenv("MAX_URL_CHECKS", "5"))

SUSPICIOUS_PHRASES = [
    "verify your account", "verify your identity", "account suspended",
    "account suspension", "within 24 hours", "immediately", "urgent action",
    "confirm your password", "update your payment", "unusual activity",
    "unauthorized access", "security alert", "click here to verify",
    "restore access", "permanently suspended", "limited access",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly",
    "cutt.ly", "rebrand.ly", "rb.gy",
}

RISKY_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta",
    ".jar", ".msi", ".iso", ".img", ".lnk", ".docm", ".xlsm",
}

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class AnchorExtractor(HTMLParser):
    """Extract href values from HTML without rendering or opening them."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for key, value in attrs:
                if key.lower() == "href" and value:
                    self.urls.append(value.strip())


def _decode_part(part: Message) -> str:
    """Decode a MIME text part safely using its declared charset when possible."""
    try:
        content = part.get_content()
        return content if isinstance(content, str) else str(content)
    except Exception:
        payload = part.get_payload(decode=True)
        if not payload:
            return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            return payload.decode("utf-8", errors="replace")


def extract_email_content(message: Message) -> tuple[str, str, list[dict[str, str]]]:
    """Return plain text, HTML text and attachment metadata (never execute files)."""
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, str]] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        content_type = part.get_content_type()

        if filename or disposition == "attachment":
            attachments.append({
                "filename": filename or "unnamed_attachment",
                "content_type": content_type,
            })
            continue

        if content_type == "text/plain":
            plain_parts.append(_decode_part(part))
        elif content_type == "text/html":
            html_parts.append(_decode_part(part))

    return "\n".join(plain_parts), "\n".join(html_parts), attachments


def extract_urls(*contents: str) -> list[str]:
    """Extract visible URLs and HTML anchor targets, removing duplicates."""
    found: set[str] = set()
    for content in contents:
        if not content:
            continue
        for match in URL_PATTERN.findall(content):
            found.add(match.rstrip(".,);]}!?:"))
        parser = AnchorExtractor()
        try:
            parser.feed(content)
            found.update(parser.urls)
        except Exception:
            pass
    return sorted(url for url in found if url)


def normalize_url(raw_url: str) -> str:
    value = html.unescape(raw_url.strip())
    if value.lower().startswith("www."):
        value = "http://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return ""
    # Remove URL fragments for reputation lookups; preserve path and query.
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def extract_ip_candidates(message: Message) -> list[str]:
    """Return public IP candidates from Received headers; these are not proof of origin."""
    candidates: list[str] = []
    for header in message.get_all("Received", []):
        for match in IP_PATTERN.findall(str(header)):
            try:
                address = ipaddress.ip_address(match)
                if address.version == 4 and address.is_global and match not in candidates:
                    candidates.append(match)
            except ValueError:
                continue
    return candidates


def _email_addresses(header_value: str) -> list[str]:
    return [address.lower() for _, address in getaddresses([header_value]) if address]


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(".>") if "@" in address else ""


def _display_name(message: Message) -> str:
    from_value = str(message.get("From", ""))
    match = re.match(r"\s*([^<]+?)\s*<", from_value)
    return match.group(1).strip(' "') if match else ""


def analyze_authentication(message: Message) -> dict[str, Any]:
    """Read Authentication-Results headers; this does not independently verify DNS/signatures."""
    results = " ".join(str(x) for x in message.get_all("Authentication-Results", []))
    checks: dict[str, str] = {}
    for name in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{name}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", results, re.I)
        checks[name] = match.group(1).lower() if match else "not_provided"
    return {"reported_results": checks, "raw_header_present": bool(results),
            "note": "These are reported header results, not independently verified by this tool."}


def check_virustotal(ioc: str, ioc_type: str = "url") -> dict[str, Any]:
    """Look up an IP or URL. Unknown/error is kept distinct from zero detections."""
    if not VT_API_KEY:
        return {"status": "skipped", "malicious": None, "message": "VT_API_KEY is not configured."}

    if ioc_type == "ip":
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(ioc.encode("utf-8")).decode("ascii").rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        return {"status": "unsupported", "malicious": None, "message": "Unsupported indicator type."}

    try:
        response = requests.get(endpoint, headers={"x-apikey": VT_API_KEY}, timeout=VT_TIMEOUT)
        if response.status_code == 404:
            return {"status": "not_found", "malicious": None, "message": "Indicator not found in VirusTotal."}
        if response.status_code == 429:
            return {"status": "rate_limited", "malicious": None, "message": "VirusTotal rate limit reached."}
        response.raise_for_status()
        payload = response.json()
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious")
        if malicious is None:
            return {"status": "incomplete", "malicious": None, "message": "No analysis statistics returned."}
        return {"status": "checked", "malicious": int(malicious), "stats": stats}
    except requests.RequestException as exc:
        return {"status": "error", "malicious": None, "message": str(exc)}
    except (ValueError, TypeError, AttributeError) as exc:
        return {"status": "error", "malicious": None, "message": f"Unexpected API response: {exc}"}


def _inspect_url(raw_url: str, perform_reputation: bool = True) -> dict[str, Any]:
    normalized = normalize_url(raw_url)
    result: dict[str, Any] = {"url": raw_url, "normalized_url": normalized, "indicators": []}
    if not normalized:
        result["indicators"].append("URL is not a standard HTTP/HTTPS link")
        result["reputation"] = {"status": "skipped", "malicious": None}
        return result

    parts = urlsplit(normalized)
    host = (parts.hostname or "").lower()
    if host in SHORTENER_DOMAINS:
        result["indicators"].append("URL uses a known link-shortening domain")
    if host.startswith("xn--") or ".xn--" in host:
        result["indicators"].append("Domain contains punycode")
    try:
        ipaddress.ip_address(host)
        result["indicators"].append("URL uses an IP address instead of a domain name")
    except ValueError:
        pass
    if "@" in parts.netloc:
        result["indicators"].append("URL contains an @ symbol in its authority section")
    # Flag common brand-name impersonation patterns, without treating the
    # presence of a brand word alone as proof of phishing.
    trusted_brand_domains = {
        "github": ("github.com",),
        "microsoft": ("microsoft.com", "live.com", "office.com"),
        "google": ("google.com", "google.co.in", "gmail.com"),
        "apple": ("apple.com", "icloud.com"),
        "paypal": ("paypal.com",),
    }
    for brand, trusted_domains in trusted_brand_domains.items():
        if brand in host and not any(host == domain or host.endswith("." + domain) for domain in trusted_domains):
            result["indicators"].append(f"Domain contains '{brand}' but is not a recognized {brand} domain")
            break

    result["domain"] = host
    result["reputation"] = check_virustotal(normalized, "url") if perform_reputation else {
        "status": "disabled", "malicious": None
    }
    return result


def _score_findings(findings: list[dict[str, Any]], url_results: list[dict[str, Any]],
                    ip_results: list[dict[str, Any]], attachments: list[dict[str, str]],
                    auth: dict[str, Any]) -> tuple[int, str, list[str]]:
    """Transparent heuristic score; weights are initial project rules, not calibrated probabilities."""
    score = 0
    reasons: list[str] = []

    for finding in findings:
        score += finding["points"]
        reasons.append(finding["reason"])

    for item in url_results:
        if item.get("indicators"):
            score += min(10, 5 * len(item["indicators"]))
            reasons.extend(item["indicators"])
        vt = item.get("reputation", {})
        if vt.get("status") == "checked" and (vt.get("malicious") or 0) > 0:
            score += 25
            reasons.append(f"VirusTotal flagged URL ({vt['malicious']} malicious engines)")

    for item in ip_results:
        vt = item.get("reputation", {})
        if vt.get("status") == "checked" and (vt.get("malicious") or 0) > 0:
            score += 20
            reasons.append(f"VirusTotal flagged IP {item['ip']} ({vt['malicious']} malicious engines)")

    for attachment in attachments:
        suffix = Path(attachment["filename"]).suffix.lower()
        if suffix in RISKY_ATTACHMENT_EXTENSIONS:
            score += 15
            reasons.append(f"Potentially risky attachment type: {attachment['filename']}")

    auth_results = auth["reported_results"]
    failed = [name.upper() for name, value in auth_results.items() if value in {"fail", "softfail", "permerror"}]
    if failed:
        score += min(15, 5 * len(failed))
        reasons.append("Reported email authentication failure: " + ", ".join(failed))

    score = min(100, score)
    if score >= 60:
        label = "Likely Phishing"
    elif score >= 30:
        label = "Suspicious"
    else:
        label = "Low Risk"
    return score, label, sorted(set(reasons))


def analyze_email(filepath: str | Path, check_reputation: bool = True) -> dict[str, Any]:
    """Analyze an .eml file and return a structured result suitable for Flask/JSON."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Email file not found: {path.resolve()}")

    with path.open("rb") as file_handle:
        message = BytesParser(policy=policy.default).parse(file_handle)

    plain_text, html_text, attachments = extract_email_content(message)
    body_text = plain_text or re.sub(r"<[^>]+>", " ", html_text)
    body_lower = html.unescape(body_text).lower()

    from_header = str(message.get("From", ""))
    reply_header = str(message.get("Reply-To", ""))
    from_addresses = _email_addresses(from_header)
    reply_addresses = _email_addresses(reply_header)
    from_domain = _domain(from_addresses[0]) if from_addresses else ""
    reply_domain = _domain(reply_addresses[0]) if reply_addresses else ""

    findings: list[dict[str, Any]] = []
    if reply_addresses and from_addresses and reply_domain != from_domain:
        findings.append({"code": "REPLY_TO_DOMAIN_MISMATCH", "points": 20,
                         "reason": f"Reply-To domain ({reply_domain}) differs from sender domain ({from_domain})."})

    display_name = _display_name(message).lower()
    if display_name and from_domain and any(brand in display_name for brand in ("github", "microsoft", "google", "apple", "paypal", "bank")):
        brand = next(brand for brand in ("github", "microsoft", "google", "apple", "paypal", "bank") if brand in display_name)
        if brand not in from_domain:
            findings.append({"code": "DISPLAY_NAME_DOMAIN_MISMATCH", "points": 20,
                             "reason": f"Display name mentions {brand}, but sender domain is {from_domain}."})

    matched_phrases = [phrase for phrase in SUSPICIOUS_PHRASES if phrase in body_lower]
    if matched_phrases:
        findings.append({"code": "URGENT_OR_CREDENTIAL_LANGUAGE", "points": min(15, 5 + len(matched_phrases) * 2),
                         "reason": "Urgent or account-verification language detected: " + ", ".join(matched_phrases[:6])})

    urls = extract_urls(plain_text, html_text)
    url_results: list[dict[str, Any]] = []
    for raw_url in urls:
        should_check = check_reputation and len(url_results) < MAX_URL_CHECKS
        item = _inspect_url(raw_url, perform_reputation=should_check)
        if check_reputation and not should_check and item.get("normalized_url"):
            item["reputation"] = {"status": "skipped_limit", "malicious": None}
        url_results.append(item)

    ip_candidates = extract_ip_candidates(message)
    ip_results: list[dict[str, Any]] = []
    for ip in ip_candidates[:3]:
        reputation = check_virustotal(ip, "ip") if check_reputation else {"status": "disabled", "malicious": None}
        ip_results.append({"ip": ip, "note": "Candidate extracted from Received headers; not guaranteed to be the original sender.",
                           "reputation": reputation})

    authentication = analyze_authentication(message)
    if not check_reputation:
        # URL reputation is already skipped above; IP reputation is disabled above.
        pass
    score, classification, reasons = _score_findings(findings, url_results, ip_results, attachments, authentication)

    date_value = str(message.get("Date", ""))
    try:
        parsed_date = parsedate_to_datetime(date_value).isoformat() if date_value else None
    except (TypeError, ValueError, OverflowError):
        parsed_date = None

    return {
        "file_name": path.name,
        "email": {
            "from": from_header,
            "reply_to": reply_header or None,
            "to": str(message.get("To", "")),
            "subject": str(message.get("Subject", "")),
            "date": date_value or None,
            "parsed_date": parsed_date,
            "message_id": str(message.get("Message-ID", "")) or None,
        },
        "sender_analysis": {
            "from_domain": from_domain or None,
            "reply_to_domain": reply_domain or None,
            "ip_candidates": ip_candidates,
        },
        "authentication": authentication,
        "content_analysis": {
            "body_text": body_text[:12000],
            "urls_found": urls,
            "url_analysis": url_results,
            "attachments": attachments,
            "suspicious_phrases": matched_phrases,
        },
        "ip_analysis": ip_results,
        "rule_findings": findings,
        "risk": {"score": score, "classification": classification, "reasons": reasons,
                 "scoring_note": "Initial heuristic score for triage; not a calibrated probability."},
        "meta": {"virustotal_configured": bool(VT_API_KEY), "reputation_checks_enabled": check_reputation},
    }


def print_report(result: dict[str, Any]) -> None:
    email_info = result["email"]
    risk = result["risk"]
    print("\n========== PHISHGUARD AI: EMAIL ANALYSIS ==========")
    print(f"File           : {result['file_name']}")
    print(f"From           : {email_info['from']}")
    print(f"Reply-To       : {email_info['reply_to'] or 'Not provided'}")
    print(f"Subject        : {email_info['subject']}")
    print(f"Risk score     : {risk['score']}/100")
    print(f"Classification : {risk['classification']}")
    print("\nReasons:")
    if risk["reasons"]:
        for reason in risk["reasons"]:
            print(f" - {reason}")
    else:
        print(" - No configured warning rules were triggered.")
    print("\nURLs:")
    if result["content_analysis"]["url_analysis"]:
        for item in result["content_analysis"]["url_analysis"]:
            rep = item.get("reputation", {})
            print(f" - {item['url']} | VirusTotal: {rep.get('status')} | malicious: {rep.get('malicious')}")
    else:
        print(" - No URLs found.")
    print("\nNote: Low risk does not guarantee that an email is safe. Never open suspicious links or attachments.")
    print("===================================================\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze an .eml file with PhishGuard AI.")
    parser.add_argument("email_file", nargs="?", default="./email.eml", help="Path to the .eml file")
    parser.add_argument("--no-reputation", action="store_true", help="Skip VirusTotal lookups")
    parser.add_argument("--json", dest="json_path", help="Save complete analysis as JSON")
    args = parser.parse_args()

    try:
        result = analyze_email(args.email_file, check_reputation=not args.no_reputation)
        print_report(result)
        if args.json_path:
            output = Path(args.json_path)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"JSON report saved to: {output.resolve()}")
    except (OSError, ValueError) as exc:
        raise SystemExit(f"[ERROR] {exc}") from exc


if __name__ == "__main__":
    main()
