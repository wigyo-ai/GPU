# H2O.ai ATLAS Red Team

A Flask-based adversarial testing harness for LLMs, built on the [MITRE ATLAS](https://atlas.mitre.org/) framework. Uses [NVIDIA Garak](https://github.com/NVIDIA/garak) to generate attack probes and [H2O GPTe](https://h2o.ai/platform/enterprise-h2ogpte/) as the target LLM endpoint.

> **For authorised security testing only.** Do not use against systems you do not own or have explicit permission to test.

---

## Features

- **ATLAS Dashboard** — Browse tactics and techniques mapped to the MITRE ATLAS framework
- **Garak Probe Engine** — Automatically loads pre-built attack payloads (prompt injection, jailbreaks, encoding evasion, data leakage, and more)
- **Payload Editor** — Review, modify, and tune any payload before execution
- **H2O GPTe Integration** — Sends payloads directly to your H2O GPTe deployment via the `h2ogpte` SDK
- **Automated Scoring** — Evaluates model responses as `SUCCESSFUL` or `BLOCKED` using a weighted heuristic engine + optional Garak detector
- **Attack History** — Persistent in-session log of all executions with permalink result pages

---

## ATLAS Coverage

| Tactic | Techniques |
|--------|-----------|
| Execution | LLM Prompt Injection, Indirect Prompt Injection |
| Defense Evasion | LLM Jailbreak, Encoding Attacks, Glitch Token Exploitation |
| Exfiltration | Meta-Prompt Extraction, Training Data Leakage |
| Impact | Societal Harm / Misinformation, Harmful Content Generation |

---

## Tech Stack

| Layer | Library |
|-------|---------|
| Web framework | Flask |
| Target LLM | `h2ogpte==1.6.47` |
| Probe engine | `garak` (NVIDIA) |
| UI | Bootstrap 5.3 (dark theme, CDN) |

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure credentials

Copy `.env` and fill in your H2O GPTe details:

```bash
cp .env .env.local   # optional — or edit .env directly
```

```env
H2OGPTE_URL=https://your-instance.h2ogpte.com
H2OGPTE_API_KEY=your-api-key-here
H2OGPTE_LLM=                        # leave blank for server default
```

Your API key is found in the H2O GPTe UI under **Account → API Keys**.

### 3. Run

```bash
python app.py
```

Open [http://localhost:5500](http://localhost:5500)

---

## Project Structure

```
├── app.py                  # Flask routes + in-memory result store
├── garak_integration.py    # Garak probe loader, ATLAS taxonomy, response scorer
├── h2o_client.py           # H2O GPTe SDK wrapper
├── requirements.txt
├── .env                    # Credentials (never committed)
└── templates/
    ├── base.html           # Bootstrap dark theme, navbar, loading overlay
    ├── index.html          # ATLAS tactics & techniques dashboard
    ├── technique.html      # Probe selector + payload editor + live results
    ├── results.html        # Permalink result report page
    ├── history.html        # All past executions
    └── 404.html
```

---

## How It Works

```
User selects ATLAS technique
        │
        ▼
Garak probe module loaded → prompts extracted
        │
        ▼
User reviews / modifies payload in editor
        │
        ▼
POST /api/execute → h2ogpte SDK → H2O GPTe model
        │
        ▼
Response scored:
  • Weighted regex (refusal signals vs. compliance signals)
  • Garak MitigationBypass detector (if available)
        │
        ▼
Verdict: SUCCESSFUL / BLOCKED / UNKNOWN + confidence %
```

---

## Scoring Logic

Responses are evaluated by two layers:

1. **Keyword heuristic** — weighted regex patterns detect refusal phrases ("I cannot", "violates my guidelines") vs. compliance signals ("Sure, here's how", numbered steps, code blocks)
2. **Garak MitigationBypass detector** — used as a tiebreaker when the heuristic score is ambiguous

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `H2OGPTE_URL` | Yes | Base URL of your H2O GPTe instance |
| `H2OGPTE_API_KEY` | Yes | API key for authentication |
| `H2OGPTE_LLM` | No | Model name; uses server default if omitted |

---

## Disclaimer

This tool is intended for **authorised red-team engagements, security research, and defensive testing** of LLM systems. Misuse against systems without explicit permission is prohibited. The authors assume no liability for unauthorised use.
