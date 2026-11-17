# PhishGuard AI - Phase 1

Phase 1 upgrades the original command-line email analyzer into a reusable analysis engine.

## Features
- Parses `.eml` files, including multipart plain-text and HTML messages.
- Extracts sender, Reply-To, subject, date, URLs, public IP candidates and attachment metadata.
- Detects Reply-To/domain mismatch, selected brand display-name mismatches and urgent language.
- Reads reported SPF/DKIM/DMARC results from `Authentication-Results` headers (does not independently verify them).
- Optionally checks URLs and IPs with VirusTotal.
- Produces a transparent initial heuristic score and JSON output.
- Does not open links or execute attachments.

## Setup (Windows PowerShell)

```powershell
cd PhishGuard-AI
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and add your own VirusTotal API key if you have one. VirusTotal checks are skipped if no key is configured.

## Run

```powershell
python analyzer.py path\to\email.eml --no-reputation
```

With VirusTotal enabled (requires a valid key in `.env`):

```powershell
python analyzer.py path\to\email.eml
```

Save a JSON report:

```powershell
python analyzer.py path\to\email.eml --no-reputation --json reports\analysis.json
```

If no file path is supplied, the program looks for `./email.eml`.

## Important limitations
- This phase is rule-based, not machine learning. ML is a later phase.
- A low score is not proof that an email is safe.
- IP addresses extracted from `Received` headers are candidates, not guaranteed origin IPs.
- SPF/DKIM/DMARC values are read from existing `Authentication-Results` headers; they are not verified independently.
- VirusTotal may return no record, rate-limit requests or report an error. These states are kept separate from zero detections.
- Use only emails you are authorized to analyze. Keep API keys and private email content secure.
