# 🛡️ AegisPost | Website Security Posture & Phishing Detector

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.x-emerald.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Security-Passive%20Audit%20Only-green.svg)](#)

A sleek, modern cybersecurity dashboard and passive posture assessment platform. Analyze any public website's defensive signals in seconds—featuring **Google Safe Browsing phishing intelligence**, **cryptographic TLS verification**, **HTTP security header grading**, and **automated remediation advice powered by free-tier AI (Google Gemini 1.5 Flash / Groq Cloud)**.

---

## ✨ Features & Overhaul Highlights

### 🎨 1. Premium Cyber UI/UX Dashboard
- **Sleek Cyber Aesthetic:** Deep slate canvas (`#070A11`), glassmorphic cards, and high-visibility neon accents (**Emerald** for safe, **Amber** for warning, **Crimson** for threats, **Cyan** for info).
- **Glanceable Security Trust Badge & Gauge:** Dynamic radial SVG circular gauge (0–100) with instant posture classification: `Safe Posture`, `Needs Attention`, or `High Risk`.
- **4-Pillar Breakdown Cards:**
  1. **SSL/TLS Encryption Posture:** HTTPS enforcement, certificate presentation, and mixed-content detection.
  2. **Phishing & Threat Intelligence:** Real-time query against Google Safe Browsing's global malicious URL database.
  3. **Defensive HTTP Headers:** Content-Security-Policy (CSP), HSTS, X-Content-Type-Options, Referrer-Policy, and Framing (Clickjacking) protection.
  4. **Cookie & Identity Hardening:** Secure, HttpOnly, and SameSite attribute verification.
- **Interactive Multi-Step Radar Scanner:** Animated progressive scanner giving real-time feedback across DNS resolution, TLS handshakes, header parsing, and threat intel.
- **Beginner-Friendly Micro-Copy:** Plain-English explanations and real-world analogies ("Explain this simply") so non-technical stakeholders understand risks.

### 🤖 2. Free-Tier AI Security Advisor
- **Google Gemini API Integration:** Seamlessly queries Google's generous free-tier `gemini-1.5-flash` (15 requests/min with zero credit card required).
- **Groq Cloud Integration:** High-speed free-tier alternative using `llama-3.3-70b-versatile` or `llama-3.1-8b-instant`.
- **Zero-Config Smart Heuristic Fallback:** If no API key is supplied, a built-in heuristic security engine analyzes missing controls and provides prioritized remediation advice out-of-the-box.
- **Interactive Server Fix Generator:** One-click copy-paste configuration snippets for **Nginx**, **Apache**, **Cloudflare Workers**, **Node.js (Express/Helmet)**, and **HTML `<meta>`** tags.

### 🔒 3. Defensive Security Best Practices
- **Strict SSRF & DNS-Rebinding Defense:** Validates URL syntax, IDNA hostname encoding, resolves IP addresses, and unconditionally blocks loopback (`127.0.0.1`), RFC 1918 private subnets (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), link-local, and multicast addresses.
- **Environment Decoupling:** All sensitive API keys and port configurations are managed via `.env` with a structured `.env.example` template.
- **Streaming In-Memory PDF Reports:** Generates executive PDF audit reports on-the-fly via ReportLab with zero file persistence.

---

## 🏗️ Clean Modular Architecture

```
sample 01/
├── app.py                  # Primary Flask controller & unified API routes
├── config.py               # Decoupled environment loader & scanner constraints
├── .env.example            # Environment variables configuration template
├── .env                    # Local secrets (git-ignored)
├── requirements.txt        # Pinned Python package dependencies
├── test_app.py             # Comprehensive test suite (25 test cases)
│
├── scanner/                # Security scanner engine
│   ├── __init__.py
│   ├── validator.py        # SSRF defense, IP address resolution & URL sanitation
│   ├── core.py             # Bounded HTTP requester, TLS & header parser
│   ├── threat.py           # Google Safe Browsing API v5 client
│   └── scorer.py           # Weighted posture scoring & category matrix
│
├── ai/                     # AI security advisor
│   ├── __init__.py
│   └── advisor.py          # Gemini, Groq, OpenAI & offline smart engine
│
├── reports/                # Report generation
│   ├── __init__.py
│   └── pdf.py              # In-memory ReportLab PDF generator
│
└── public/                 # Modern frontend assets
    ├── index.html          # Cyber dashboard UI
    └── static/
        ├── styles.css      # Dark cyber theme & animations
        └── app.js          # Interactive frontend controller
```

---

## 🚀 Quickstart & Local Setup

### Prerequisites
- **Python 3.10** or higher
- `git` and `pip`

### Step 1: Clone & Navigate
```bash
git clone <your-repo-url>
cd "sample 01"
```

### Step 2: Create and Activate Virtual Environment

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**On macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
# Windows
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```

*(Note: The app runs with zero configuration friction using the built-in Smart Heuristic Advisor. To activate live Google Gemini AI and Google Safe Browsing, see the key instructions below).*

### Step 5: Start the Development Server
```bash
python app.py
```

Open your browser to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 🔑 Obtaining Free API Keys

### 1. Google Gemini AI API (Recommended Free LLM)
1. Visit **[Google AI Studio](https://aistudio.google.com/app/apikey)**.
2. Sign in with your Google Account and click **"Create API Key"**.
3. Copy your key and add it to `.env`:
   ```env
   GEMINI_API_KEY=AIzaSy...
   GEMINI_MODEL=gemini-1.5-flash
   ```

### 2. Groq Cloud API (Optional High-Speed Free Alternative)
1. Visit **[Groq Console](https://console.groq.com/keys)**.
2. Sign up and click **"Create API Key"**.
3. Add it to `.env`:
   ```env
   GROQ_API_KEY=gsk_...
   GROQ_MODEL=llama-3.3-70b-versatile
   ```

### 3. Google Safe Browsing API (Phishing & Malware Threat Intel)
1. Go to the **[Google Cloud Console](https://console.cloud.google.com/)**.
2. Create a project and search for **"Safe Browsing API"**.
3. Enable the API, then go to **APIs & Services → Credentials → Create Credentials → API Key**.
4. Add it to `.env`:
   ```env
   GOOGLE_SAFE_BROWSING_API_KEY=AIzaSy...
   ```

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `GET /` | `GET` | Serves the interactive cybersecurity dashboard |
| `GET /health` | `GET` | Health check endpoint and provider configuration status |
| `POST /api/check` | `POST` | Runs a passive posture audit (`{"url": "https://example.com"}`) |
| `POST /api/advice` | `POST` | Generates AI remediation advice from Gemini, Groq, or Smart Engine |
| `POST /api/fix-snippet`| `POST` | Generates Nginx, Apache, Cloudflare, or Express server snippets |
| `POST /api/explain` | `POST` | Provides beginner-friendly analogies for technical concepts |
| `POST /api/report.pdf` | `POST` | Returns a downloadable in-memory executive PDF audit report |

---

## 🧪 Running Automated Unit Tests

All network requests in the test suite are mocked with strict unit tests verifying SSRF protection, URL sanitation, redirect limits, header parsing, and LLM advice generation:

```bash
python -m unittest -v
```

Expected result:
```
----------------------------------------------------------------------
Ran 25 tests in 0.065s

OK
```

---

## ⚠️ Limitations & Ethical Use Notice

- **Passive Only:** This tool conducts passive observations of public responses only. It never crawls, scans ports, executes exploits, or bruteforces credentials.
- **Defense in Depth:** A 100/100 score indicates that all checked public headers and cryptographic signals are present. It is not a warranty against internal application logic flaws.
- **Authorization:** Only audit websites you own or have explicit authorization to assess.
