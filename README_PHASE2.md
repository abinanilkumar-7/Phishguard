# PhishGuard AI - Phase 2

## Run locally (Windows PowerShell)

1. Open this folder in VS Code.
2. Activate your existing virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks activation, use:
   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```
3. Install requirements:
   ```powershell
   python -m pip install -r requirements.txt
   ```
4. Start the web app:
   ```powershell
   python app.py
   ```
5. Open `http://127.0.0.1:5000` in your browser.
6. Upload an `.eml` file and click **Analyze email**.

## Features

- Dark responsive Flask dashboard
- `.eml` upload and validation (maximum 5 MB)
- Uses the Phase 1 `analyzer.py` engine
- Optional VirusTotal lookups (requires `VT_API_KEY` in `.env`)
- Risk score and reasons
- URL, sender, authentication and attachment summaries
- SQLite history stores summary metadata only; raw uploaded email files are removed after analysis

## Important

- Copy `.env.example` to `.env` and configure a new VirusTotal API key if needed.
- Never commit `.env` or API keys to Git.
- The risk score is an initial heuristic triage score, not a calibrated probability.
- Authentication-Results headers are displayed as reported evidence; the tool does not independently validate SPF/DKIM/DMARC.
- Do not open suspicious links or execute attachments.
- This Flask development server is for local testing only. Do not expose it to the public internet.
