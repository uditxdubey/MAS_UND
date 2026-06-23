![Python](https://img.shields.io/badge/python-3.9+-blue)
![License](https://img.shields.io/badge/license-Proprietary-red)
![Tests](https://img.shields.io/badge/tests-40%20passed-brightgreen)
![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Compliant-blue)
🛡️ Sovereign Shield

Real-time EU AI Act compliance for AI agents. Runs locally. Zero cloud dependency.

Sovereign Shield is a runtime interception layer that sits between your AI agents
and the internet. Every outbound HTTP request is inspected before execution —
blocked if it violates EU AI Act requirements, logged if it passes.

Built in Erlangen, Germany. Designed for German Mittelstand and European enterprise.

---

## The Problem

AI agents (LangChain, AutoGen, CrewAI) call external APIs freely.
A single misconfigured agent can:

- Send customer PII to a server in China — **€35M fine (EU AI Act Art. 53)**
- Leak IBAN or Steuer-ID in an outbound payload — **Art. 10 violation**
- Leave no audit trail of what data was sent where — **Art. 13 violation**

Your compliance team has no visibility. Your legal team has no evidence trail.
Your AI agents have no guardrails.

---

## The Solution

Sovereign Shield intercepts every `requests.post()` call at the Python level —
before the packet leaves the machine.
```python
# This is all you add to your agent bootstrap
from sovereign_shield.interceptor import activate
from sovereign_shield.symbolic.shield_policy import ShieldPolicy

activate(ShieldPolicy.german_mittelstand())

# From this point — every requests.post() in your entire process
# is intercepted, inspected, and blocked if non-compliant.
# Zero changes to your existing agent code required.
```

---

## What It Enforces

| EU AI Act Article | Enforcement |
|---|---|
| **Art. 10** — Data Governance | Blocks outbound requests containing PII (email, IBAN, Steuer-ID, passport, phone) |
| **Art. 13** — Transparency | Writes append-only JSONL audit trail for every request |
| **Art. 17** — Quality Management | Verifier agent cross-checks every decision |
| **Art. 53** — Data Sovereignty | Blocks requests to non-EU-adequate countries |

---

## How It Works
```
AI Agent calls requests.post(url, json={...})
         │
         ▼
┌─────────────────────────────┐
│  GeoGuard (Art. 53)         │  Resolves destination IP
│  Checks country allowlist   │  HALT if not EU-adequate
└──────────────┬──────────────┘
               │ PASS
               ▼
┌─────────────────────────────┐
│  PIIGuard (Art. 10)         │  Scans payload for PII
│  Regex pattern matching     │  HALT if PII detected
└──────────────┬──────────────┘
               │ PASS
               ▼
┌─────────────────────────────┐
│  AuditorAgent               │  Maps decision to EU AI Act article
│  VerifierAgent              │  Cross-checks for legal defensibility
└──────────────┬──────────────┘
               │
               ▼
   Audit log written (JSONL)
               │
               ▼
   Original request executes
```
WATCH A DEMO VIDEO:: https://www.linkedin.com/posts/udit-dubey-9aa0b9284_sovereign-eu-ai-ugcPost-7440418036613931008-OYjQ/?utm_source=share&utm_medium=member_desktop&rcm=ACoAAEUR_VIBkF8voJhgsbRnGX53gvQYevXJM28


**Decision time: < 2ms. Latency added to legitimate requests: < 2ms.**

---

## Installation
```bash
# Clone the repository
git clone https://github.com/uditxdubey/MAS_UND.git
cd MAS_UND

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install -e .

# Download GeoIP database (free, MaxMind)
# Register at https://www.maxmind.com/en/geolite2/signup
# Download GeoLite2-Country.mmdb → place in ./data/
```

---

## Usage

### EU Standard (all EC adequacy countries)
```python
from sovereign_shield.interceptor import activate
activate()
```

### German Mittelstand (DACH + core EU only — strictest)
```python
from sovereign_shield.interceptor import activate
from sovereign_shield.symbolic.shield_policy import ShieldPolicy

activate(ShieldPolicy.german_mittelstand())
```

### What a HALT looks like
```python
import requests
from sovereign_shield.interceptor import activate
from sovereign_shield.symbolic.shield_policy import ShieldPolicy
from sovereign_shield.symbolic.geo_guard import DataSovereigntyViolation

activate(ShieldPolicy.german_mittelstand())

try:
    requests.post("https://api.chinese-server.com", json={"data": "report"})
except DataSovereigntyViolation as e:
    print(f"BLOCKED: {e.country} — {e.reason}")
    # BLOCKED: CN — Destination country not in EU adequacy allowlist (Art.53)
```

---

## Audit Log

Every request produces a structured JSON entry:
```json
{
  "shield": "sovereign-shield",
  "version": "1.0",
  "ts_utc": "2026-03-14T19:57:08.913787+00:00",
  "verdict": "HALT",
  "guard": "GeoGuard",
  "url": "https://api.chinese-server.com",
  "reason": "Destination country not in EU adequacy allowlist (Art.53)",
  "article": "Art.53  — Data Sovereignty & Cross-Border Transfer",
  "severity": "CRITICAL",
  "country": "CN"
}
```

The audit log is append-only and never modified after writing.
It is your legal evidence trail under EU AI Act Art. 13.

---

## Supported PII Patterns (Art. 10)

| Pattern | Description |
|---|---|
| `email` | Email addresses |
| `iban` | International Bank Account Numbers |
| `phone_de` | German mobile and landline numbers |
| `steuer_id` | German Steueridentifikationsnummer |
| `sozialversicherung` | German Sozialversicherungsnummer |
| `passport` | Passport numbers |

---

## Country Allowlist (Art. 53)

**EU Standard preset** — All 27 EU member states + EEA + EC adequacy decisions:
Switzerland, United Kingdom, Japan, South Korea, Canada, New Zealand, Israel,
Uruguay, Argentina.

**German Mittelstand preset** — DACH region + core EU partners only:
DE, AT, CH, IS, LI, NO, BE, NL, FR, SE.

---

## Verification
```bash
# Run full test suite — 40 formally verified enforcement rules
pytest tests/ -v

# Expected output:
# 40 passed in 0.14s
```

---

## Project Structure
```
sovereign_shield/
├── interceptor.py          # Entry point — wraps requests.post()
├── symbolic/
│   ├── geo_guard.py        # Art.53 — geographic enforcement
│   ├── pii_guard.py        # Art.10 — PII detection
│   ├── shield_policy.py    # Policy presets
│   ├── sovereignty.py      # Country allowlist
│   └── pii_policy.py       # PII pattern config
├── agents/
│   ├── auditor.py          # EU AI Act article mapping
│   └── verifier.py         # Decision cross-verification
├── audit/
│   └── logger.py           # Append-only JSONL audit trail
└── neural/
    └── advisor.py          # Local LLM risk classification (Phase 2)
```

---

## Roadmap

- [x] Art. 53 geo-blocking (GeoGuard)
- [x] Art. 10 PII detection (PIIGuard)
- [x] Art. 13 audit logging
- [x] Art. 17 decision verification
- [x] German Mittelstand policy preset
- [x] 40/40 formally verified tests
- [ ] Audit log encryption (AES-256)
- [ ] Local LLM risk classification (Llama 3)
- [ ] `requests.get()` interception
- [ ] `httpx` library support
- [ ] LangChain native integration
- [ ] Compliance dashboard

---

## License

MIT-License

---

*Built in Erlangen, Germany — for European AI compliance.*
