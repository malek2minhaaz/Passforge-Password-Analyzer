# PassForge — Password Intelligence Platform

> Real-time password strength analyzer with entropy scoring, crack time estimates, breach checking, and secure password generation.

---

## Quick Start

```bash
cd passforge
python server.py
# Browser opens at http://localhost:7777
```

No pip installs needed — uses Python standard library only.

---

## Features

### Analyzer
- **Real-time analysis** as you type (250ms debounce)
- **Entropy calculation** based on charset and length
- **Pattern detection** — keyboard walks, leet speak, repeated chars, years, sequential runs
- **Crack time estimates** across 6 attack scenarios (online throttled → GPU cluster)
- **Character composition** breakdown with visual bars
- **Strength arc** with grade (A+ → F) and label (FORTRESS → CRITICAL)
- **Personalized suggestions** based on detected weaknesses
- **HaveIBeenPwned breach check** via k-anonymity API (your full password is never sent)

### Generator
- **Random** — cryptographically secure (secrets module), configurable charset
- **Passphrase** — 4+ random words separated by a symbol
- **Memorable** — consonant/vowel alternating, pronounceable
- **PIN** — numeric only
- One-click **Copy** or **Use** (loads into analyzer)

### History
- Last 50 analyses, masked by default
- Click to reveal/hide password
- One-click re-analyze

### Security Tips
- 12 essential password security principles

---

## Project Structure

```
passforge/
├── server.py          ← Run this: python server.py
├── index.html         ← Full PassForge UI
├── README.md
└── modules/
    ├── __init__.py
    ├── analyzer.py    ← Entropy, patterns, crack times, scoring
    └── generator.py   ← Cryptographically secure password generation
```

---

## Privacy

- All analysis happens **locally** on your machine
- Breach check uses **k-anonymity**: only the first 5 characters of a SHA-1 hash are sent to the HaveIBeenPwned API — your actual password is never transmitted
- No data is stored or logged beyond your browser session
