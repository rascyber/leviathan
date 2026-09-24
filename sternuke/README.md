# sternuke

**Local, AI-assisted vulnerability assessment framework** — part of the Leviathan toolkit.

sternuke is a high-speed asynchronous scanner and autonomous agent that runs
**entirely on infrastructure you control**. It requires no commercial APIs,
license keys, or paid cloud feeds. All AI processing happens through a *local*
Ollama / vLLM server, and all scan signatures are parsed locally.

> ⚠️ **Authorised use only.** sternuke is an assessment tool. Use it exclusively
> against systems and source code that you own or have explicit written
> permission to test. Concurrency and request-rate limits are enforced by
> `ScanPolicy` so the scanner behaves as an assessment tool, not a flooder.

## Architecture

| Module | Role | Responsibilities |
|--------|------|------------------|
| `engine.py`   | The muscle | Async networking (`aiohttp`), token-bucket rate limiting, local rule execution/matching, filesystem crawler. |
| `ai_agent.py` | The brain  | Static Solidity/Rust structural analysis, web context building, local model orchestration, rule synthesis. |
| `cli.py`      | CLI        | `click` interface (argparse fallback) with `--target`, `--mode`, `--model`, `--ai`, throttle flags. |
| `gui.py`      | GUI        | `customtkinter` interface (tkinter fallback): target box, config selectors, live log, findings dashboard. |
| `main.py`     | Entry      | Stitches everything together. |

## Installation

```bash
pip install -r sternuke/requirements.txt
```

Only `aiohttp` and `PyYAML` are strictly required; `click` and `customtkinter`
gracefully fall back to the standard library when absent.

### Local model (optional)

For AI-assisted rule synthesis, run a local model server exposing the standard
OpenAI-compatible endpoint, e.g. [Ollama](https://ollama.com):

```bash
ollama serve
ollama pull deepseek-coder      # or llama3
```

sternuke talks to `http://localhost:11434/v1` by default. If the model is
unreachable, the agent falls back to deterministic built-in heuristics.

## Usage

### CLI

Web assessment with the built-in ruleset:

```bash
python -m sternuke.main scan \
    --target https://example.test \
    --mode web \
    --rules sternuke/rules \
    --output ./sternuke-out
```

AI-assisted, static-only blockchain assessment of a local repo:

```bash
python -m sternuke.main scan \
    --target ./my-contracts \
    --mode blockchain \
    --ai --model deepseek-coder \
    --output ./sternuke-out
```

Key switches: `--target`, `--mode web|blockchain`, `--model`, `--base-url`,
`--rules`, `--ai/--no-ai`, `--concurrency`, `--rps`, `--rule-format yaml|json`,
`-v/--verbose`.

### GUI

```bash
python -m sternuke.main            # no args -> GUI
python -m sternuke.main gui        # explicit
```

## Rule format

Rules are Nuclei-inspired and parsed **entirely locally** (YAML or JSON):

```yaml
id: exposed-dotenv
info:
  name: Exposed .env file
  severity: high
  description: A .env environment file is publicly readable.
  remediation: Block access to dotfiles at the web server.
  tags: [web, exposure]
requests:
  - method: GET
    path: ["/.env"]
    matchers:
      - type: regex
        regex: ["(?i)(APP_KEY|DB_PASSWORD|SECRET)="]
```

Matchers support `word`, `regex` and `status` types over `body`, `header` or
`all` parts, with `and`/`or` conditions and a `negative` flag. The AI agent
writes synthesised rules in this same schema so they can be replayed and audited.

## Outputs

Each scan writes to the `--output` directory:

* `findings.json` — all findings (severity, name, location, evidence).
* `blueprint.json` — the architectural model (blockchain mode).
* `*-synth-*.yaml|json` — AI-synthesised rule files.
