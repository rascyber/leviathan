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
| `state_engine.py` | Stateful chaining | Session state manager, dependency-graph explorer (Step A output → Step B input), and the bounded self-correction ("refusal to fail") loop. |
| `memory.py`   | Case-based reasoning | Zero-heavy-dependency local vector memory (hashing embedder + cosine recall) seeded with generic weakness-class knowledge; provides "strategic intuition". |
| `cognitive.py` | Cognitive modules | Web business-logic mutation planner (param pollution / authz bypass / race) and blockchain cross-contract reentrancy analyzer. |

## Cognitive layer (v1.1)

Beyond stateless signature scanning, sternuke can reason across a *sequence* of
interactions and recall relevant prior cases:

* **Stateful chaining** — `StatefulChainEngine` threads cookies, tokens and
  captured variables through a dependency-ordered chain, piping outputs of one
  step into the parameters of the next (`{{variable}}` templating).
* **Case-based memory** — before probing, `VectorMemory.strategic_intuition()`
  matches the target's technology profile against remembered weakness classes to
  prioritise testing. New footprints are remembered for next time.
* **Business-logic mutation loop** — `BusinessLogicMutator.plan()` turns a single
  endpoint into a stateful sequence testing negative/zero/duplicated parameters,
  authorization bypass, and race conditions.
* **Cross-contract analysis** — `CrossContractAnalyzer` maps external calls
  (`call`/`delegatecall`/sends, Solana CPIs) and flags state writes that occur
  *after* an external transfer (checks-effects-interactions violation → the
  reentrancy / flash-loan-preparation footprint). Purely static.
* **Self-correction** — when a benign probe is rejected (403/400/reverted),
  `SelfCorrectionLoop` re-encodes the *same* input a bounded number of times to
  distinguish "actually safe" from "input filter", staying within `ScanPolicy`.

### New commands

```bash
# Query local case-based memory
python -m sternuke.main intel "checkout race condition coupon" --domain web

# Run a stateful business-logic chain against one endpoint (authorised targets only)
python -m sternuke.main chain --target https://app.test \
    --path /api/v1/cart/checkout --param quantity=1 --param item_id=9
```

Blockchain scans now also emit `call_graph.json` and cross-contract findings
automatically.

## Fuzzing subsystem (v1.2)

`sternuke/fuzzing/` adds an automated payload-mutation engine with three domain
drivers over a shared mutation core (`ByteMutator`, `TypedMutator`, `Corpus`,
`CrashBucket`). **Every driver is local-by-default** (`fuzzing/guards.py`): it
refuses non-local targets unless you pass `--allow-remote` to explicitly accept
authorization for a system you are permitted to test.

* **Web/API** — `WebFuzzer` mutates request parameters (structural, encoding,
  type-confusion, byte-havoc) and flags anomalies: reflected error signatures
  (SQL/stack traces), 5xx, and large response-size deltas. Runs under the
  engine's `ScanPolicy` throttles.
* **Smart contract** — `ContractFuzzer` does ABI-aware, property/invariant-based
  fuzzing against a **local** node (anvil/hardhat). Keccak-256 and ABI encoding
  are implemented locally (no web3 dependency); it fuzzes state-changing
  functions and reports when an `echidna_*`/`invariant_*`/`prop_*` boolean view
  that held at baseline later returns false or reverts.
* **Binary** — `BinaryFuzzer` runs a bounded, black-box mutational campaign
  against a **local** executable (stdin or `@@` file arg), triaging crashes by
  signal + sanitizer signature and de-duplicating them into unique defects with
  saved reproducers. (Black-box, not coverage-guided — pair with AFL++/libFuzzer
  for coverage; use this for triage.)

### Fuzzing commands

```bash
# Web parameter fuzzing (local target; --allow-remote to opt into an authorised remote)
python -m sternuke.main fuzz --mode web --target "http://127.0.0.1:8080/search?q=x"

# Binary fuzzing of a local executable, feeding stdin
python -m sternuke.main fuzz --mode binary --binary ./parser \
    --max-execs 5000 --seconds 120 --seed-dir ./corpus

# Property-based contract fuzzing against a local node
python -m sternuke.main fuzz --mode contract --rpc http://127.0.0.1:8545 \
    --address 0xYourContract --sig "setRate(uint256)" --sig "prop_solvency()"
```

Crashes are written to `<output>/crashes/`; all findings land in `findings.json`.

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
