# 🛡️ PhishGuard AI

> **A local-first phishing URL detection platform for safer link analysis.**  
> Built with React, Vite, FastAPI, URL intelligence, and an explainable machine-learning pipeline.

---

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=20232A)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-6-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vite.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-129%20passing-2ea44f?style=for-the-badge)](#testing)
[![Security](https://img.shields.io/badge/security-local--first-0f766e?style=for-the-badge)](#security-and-privacy)

</div>

---

## ✨ Features

| Feature | Description |
| :--- | :--- |
| **🔎 URL inspection** | Validates HTTP/HTTPS URLs and extracts lexical structure without opening the destination. |
| **🤖 Local ML scoring** | Uses the checked-in pure-Python model to produce a risk estimate, clearly separated from the final verdict. |
| **🧠 Explainable results** | Shows observed structural indicators, model context, evidence sources, and limitations. |
| **🗃️ Local threat snapshot** | Checks the bundled phishing snapshot for normalized URL and hostname matches. |
| **🌐 Optional threat intelligence** | Consent-gated VirusTotal, Google Safe Browsing, and URLhaus integrations with honest provider states. |
| **🌍 Domain intelligence** | Optional hostname-only DNS/RDAP enrichment with unavailable and redacted fields represented explicitly. |
| **🎨 Verdict themes** | Full-page calm, warning, alert, and neutral diagnostic themes driven by the real API verdict. |
| **🔐 Safe defaults** | Redirect following is disabled by default, provider keys stay on the backend, and submitted pages are not automatically visited. |
| **📱 Responsive UI** | React interface with keyboard focus states, reduced-motion support, mobile layouts, loading states, and API error handling. |
| **🚀 Deployment ready** | Includes Netlify frontend, Render backend, environment examples, and Windows startup/stop launchers. |

## 🧭 Verdict semantics

The backend decision engine is the authoritative source of the final verdict:

- **`PHISHING`** — a configured threat source confirmed a match.
- **`HIGH RISK`** — the model risk estimate crossed the high-risk threshold; this is not confirmed threat intelligence.
- **`SUSPICIOUS`** — elevated model risk or multiple structural indicators require caution.
- **`NO THREAT DETECTED`** — completed available checks found no known match. This is **not** a safety guarantee.
- **`INCONCLUSIVE`** — required evidence was unavailable, skipped, failed, or insufficient.

Unavailable, disabled, pending, and unconfigured providers never become clean results.

## 🏗️ Architecture

```text
React + Vite frontend
        │
        │ POST /api/scan
        ▼
FastAPI backend
  ├── URL validation and normalization
  ├── 18 URL-only lexical features
  ├── checked-in pure-Python model
  ├── local phishing snapshot
  ├── optional external providers
  ├── optional hostname-only DNS/RDAP intelligence
  └── authoritative decision engine
        │
        ▼
Structured verdict, evidence, provider statuses, and limitations
```

## 🚀 Quick start

### Prerequisites

- Windows 10/11
- Python 3.10 or newer
- Node.js 18 or newer
- npm

### Install

From the project directory:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
Set-Location frontend
npm install
Set-Location ..
```

If the included virtual environment is unavailable:

```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Configure

Copy the backend template:

```powershell
Copy-Item .env.example .env
```

Keep `.env` private. All provider keys are optional:

```ini
VIRUSTOTAL_API_KEY=
GSB_API_KEY=
URLHAUS_AUTH_KEY=
PHISHTANK_API_KEY=
ENABLE_REDIRECT_CHECKER=false
DEBUG_MODE=false
PHISHGUARD_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

The frontend only needs the public backend URL. For local Vite development,
the default proxy works without a frontend environment file:

```ini
VITE_API_BASE_URL=http://127.0.0.1:8000
```

Never place provider secrets in `VITE_*` variables.

### Start on Windows

The easiest option is:

```powershell
.\START_PHISHGUARD.bat
```

Or run the services manually in two terminals:

```powershell
# Terminal 1 — backend
.\venv\Scripts\python.exe -m uvicorn backend.main:app --reload --port 8000
```

```powershell
# Terminal 2 — frontend
Set-Location frontend
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

Stop both local services with:

```powershell
.\STOP_PHISHGUARD.bat
```

## 🔌 Optional providers

External URL checks are disabled by default and require explicit user consent
in the interface. When enabled, the backend may send the normalized submitted
URL to configured providers. Do not submit URLs containing passwords, tokens,
private data, or sensitive query strings.

- **VirusTotal** — URL submission and multi-engine analysis through API v3.
- **Google Safe Browsing** — URL threat lookup through the v4 Lookup API.
- **URLhaus** — malware-URL intelligence, not a complete phishing feed; the
  selected community endpoint requires an `Auth-Key`.
- **PhishTank/local snapshot** — local snapshot operation does not require an
  API key.

Provider states include `MATCH`, `NO_MATCH`, `NOT_CONFIGURED`, `NOT_ENABLED`,
`PENDING`, `UNAVAILABLE`, `ERROR`, and `NOT_CHECKED`. Review each provider's
current terms, quotas, eligibility, and permitted use before deployment.

## 🧪 Testing

Run the complete backend suite:

```powershell
.\venv\Scripts\python.exe -m pytest tests -q
```

Run Python syntax checks:

```powershell
.\venv\Scripts\python.exe -m py_compile backend\main.py decision_engine.py feature_extraction.py pure_ml.py threat_checker.py redirect_checker.py domain_intelligence.py train_model.py
```

Build the frontend:

```powershell
Set-Location frontend
npm run build
```

Tests use safe fixtures and mocked provider/DNS/RDAP responses. They do not
contact live malicious URLs.

## 🔐 Security and privacy

- Submitted pages are not opened, rendered, downloaded, or executed.
- External URL submission is opt-in.
- Provider API keys remain backend-only.
- Redirect tracing is disabled by default.
- Hostname intelligence does not fetch the submitted page.
- Private, loopback, link-local, reserved, and malformed addresses are filtered
  during hostname enrichment.
- Requests use bounded timeouts and redirects are not followed for provider or
  RDAP lookups.
- “No threat detected” never means guaranteed safe.
- Model scores are estimates, not calibrated probabilities.

This is an educational security project, not a replacement for browser
security controls, domain reputation services, incident response, or expert
analysis.

## ☁️ Deployment

### Netlify

The repository includes [netlify.toml](netlify.toml). Netlify builds the
`frontend` directory with `npm run build` and publishes `frontend/dist`.
Configure:

```text
VITE_API_BASE_URL=https://your-render-service.onrender.com
```

### Render

The repository includes [render.yaml](render.yaml). Configure the backend
secrets and set `PHISHGUARD_ALLOWED_ORIGINS` to the exact Netlify origin.
Never add provider keys to Netlify or frontend `VITE_*` variables.

## 📁 Project structure

```text
backend/main.py          FastAPI application and scan adapter
frontend/src/main.jsx    React interface and API client
frontend/src/styles.css  Responsive verdict-driven visual system
decision_engine.py       Authoritative verdict rules
feature_extraction.py    URL validation and lexical features
pure_ml.py               Runtime-compatible pure-Python model engine
threat_checker.py        Local snapshot and optional providers
domain_intelligence.py   Safe hostname-only DNS/RDAP enrichment
redirect_checker.py      Opt-in redirect safeguards
models/                  Checked-in JSON model artifacts
dataset/                 Local threat snapshot and supporting data
tests/                   Backend regression and safety tests
START_PHISHGUARD.bat     One-click Windows startup
STOP_PHISHGUARD.bat      Windows shutdown helper
```

## 📄 License

No license file is currently included. Add a license before distributing or
reusing this project outside its intended educational context.

---

<div align="center">

Made with 🛡️ for safer link analysis and responsible security education.

</div>
