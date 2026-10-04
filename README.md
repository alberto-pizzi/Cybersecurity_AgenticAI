# Agentic AI Pentesting & Reporting Automation System through MCP

Platform for **authorized web assessments**: shared discovery, scanners integrated via MCP, authentication, **Deterministic** or **Agentic** orchestration, and **JSON, HTML, and PDF** reporting.

> ⚠️ **Use only on your own targets or ones you are explicitly authorized to test.**

The system does **not** take benchmarks or endpoint lists as input: the surface must be discovered at runtime on the authorized target.

---

## 🚀 Quick start

> **There are only two core steps:**
> 1. **`initScript.py`** → prepares the environment (one time only).
> 2. **`assessmentRunner.py`** → runs the assessment in the chosen mode (**agentic** or **deterministic**) with the desired `--config`.
>
> `--dry-run` and `--auth-only` are **not** steps of their own: they are only optional checks to run before step 2.

### Step 1 — Preparation (`initScript.py`)

```bash
cd ~/Cybersecurity_AgenticAI
python initScript.py              # installs/verifies dependencies, scanners, Chromium, preflight
python initScript.py --with-lab   # adds the local lab and the AI backends
```

Requirements: **Python 3.13** on a Debian VM, network access to the authorized target, disk space for scanners and reports.

To prepare an AI backend together with the lab:

```bash
python initScript.py --with-lab --prepare-ai snap4city   # or: llama / qwen
```

> Snap4City uses provider credentials **separate** from the target's.

### Step 2 — Assessment (`assessmentRunner.py`)

This is the only step that repeats: run `assessmentRunner.py` choosing the **mode** and **config**.

> 💡 *Optional check (recommended before long runs):* add `--dry-run` to validate config, scope, and jobs **without** launching scanners, or `--auth-only` to test only login and session.
>
> ```bash
> python assessmentRunner.py --config configs/dashboard-test.json \
>   --orchestrator agentic --mode balanced --max-rounds 2 --require-ai --dry-run --authorized
> ```

```bash
# Agentic (AI planning)
python assessmentRunner.py --config configs/dashboard-test.json \
  --orchestrator agentic --mode balanced --max-rounds 2 --require-ai --authorized

# Deterministic (reproducible baseline)
python assessmentRunner.py --config configs/dashboard-test.json \
  --orchestrator deterministic --mode balanced --authorized
```

---

## 🧩 Architecture

| Component | Role |
| --- | --- |
| `assessmentRunner.py` | Expands the config, prepares the jobs, and launches the orchestrator. |
| `orchestratorShared.py` | Discovery, scope, rate, request contract, sessions, and common helpers. |
| `orchestratorDeterministic.py` | Fixed, reproducible pipeline. |
| `orchestratorAgentic.py` / `orchestratorAgenticCore.py` | AI planner, rounds, execution, verification, and final analysis. |
| `servers/` | MCP wrappers and checks developed in the project. |
| `servers/reporting/` | Normalization, coverage, and report rendering. |
| `initScript.py` / `setupTools.py` | Initialization, operator guide, and tool preflight. |

**Deterministic** and **Agentic** share discovery, sessions, scope, scanners, and reporting. Only **how** actions are chosen differs.

---

## 🧰 Available tools

The first ones are **third-party open source** with MCP wrappers; the last ones are **checks developed in the project**. Docker changes the runtime, not the tool's origin.

| Tool | Type | Integration |
| --- | --- | --- |
| **FFUF** | Discovery (content) | `ffufServer.py` |
| **Arjun** | Discovery (parameters) | `arjunServer.py` |
| **ZAP** | Proxy, spider, DAST | `zapServer.py`, `zapVerification.py` |
| **Nuclei** | Template scanning and DAST | `nucleiServer.py` |
| **Nikto** | Web server assessment | `niktoServer.py` |
| **SQLMap** | SQL injection | `sqlmapServer.py` |
| **Dalfox** | XSS | `dalfoxServer.py` |
| **Commix** | Command injection | `commixServer.py` |
| **Interactsh** | OAST | `interactshServer.py` |
| **IDOR Forge** | IDOR / BOLA | `idorForgeServer.py` (+ native fallback) |
| **Traversal** | Traversal / LFI | `traversalServer.py` *(project)* |
| **Authorization** | Access control | `authorizationServer.py` *(project)* |
| **Browser** | Client-side verification | `browserServer.py` *(project, Playwright)* |
| **Workflow** | Multi-step flows | `workflowServer.py` *(project)* |
| **Session** | Session security | `sessionServer.py` *(project)* |
| **JWT** | Token analysis | `jwtServer.py` *(project, PyJWT)* |

**Tool-driven discovery:** FFUF, Arjun, and ZAP can add new surface to the request graph. In the Agentic path they must still be **selected by the model**.

---

## 🔒 Scope and authorization

- The default scope is **same-origin** (protocol + hostname + port).
- `allow_same_host_ports=true` → authorizes HTTP/HTTPS on **other ports of the exact same hostname**.
- `discover_same_host_services=true` → enables proactive discovery of same-host web services (requires the option above).
- **Neither one authorizes sibling hostnames.** Redirects are followed only if the destination stays in scope.
- `allow_state_changes=false` blocks destructive or unnecessary requests.

---

## ⚙️ Profiles, rate, and budgets

**BALANCED is the recommended default.** TEST is diagnostic only; FAST/BALANCED/DEEP are coverage profiles.

The **operating rate** is **10 request starts/s** (a maximum, not a minimum). The pacer is shared cross-process: two runs by the same user do not multiply the rate. Parallelism exploits I/O without increasing the request peak.

```json
{ "execution": { "request_rate": 10 } }
```

| Phase | TEST | FAST | BALANCED | DEEP |
| --- | ---: | ---: | ---: | ---: |
| Operational execution | 1.5 h | 16 h | 48 h | 96 h |
| Verification | 10 min | 60 min | 120 min | 240 min |
| AI analysis | 10 min | 120 min | 360 min | 720 min |
| Reporting | 20 min | 60 min | 120 min | 240 min |
| Hard watchdog | 3 h | 24 h | 66 h | 128 h |

> The watchdog is a safety net against hangs, not an expected duration.

---

## 📝 Configuration

Copy the example and edit a copy:

```bash
cp configs/platform.example.json configs/my-target.json
```

Set `authorization.confirmed=true` **only after** verifying real authorization. The parser requires `schema_version`, `platform`, at least one `asset` with a service, and the `execution` section.

Minimal valid example:

```json
{
  "schema_version": 1,
  "platform": {"name": "example-target"},
  "authorization": {
    "confirmed": true,
    "reference": "authorization reference",
    "allow_same_host_ports": false,
    "discover_same_host_services": false
  },
  "assets": [{
    "id": "webhost",
    "host": "target.example",
    "services": [{
      "id": "http-main",
      "url": "http://target.example/",
      "auth_only": false,
      "allow_state_changes": false
    }]
  }],
  "execution": {
    "orchestrator": "agentic",
    "mode": "balanced",
    "request_rate": 10,
    "model": "snap4city",
    "max_rounds": 2,
    "require_ai": true,
    "allow_state_changes": false
  }
}
```

### Authenticated target

**Passwords do not go in the JSON**: reference environment variable names instead.

```json
"credentials": {
  "user": {
    "kind": "browser_oidc",
    "cookie_env": "SECOPS_TARGET_COOKIE",
    "username_env": "SECOPS_TARGET_USERNAME",
    "password_env": "SECOPS_TARGET_PASSWORD",
    "login_path": "/", "validation_path": "/", "optional": true
  }
}
```

In the service, use `"credential_ref": "user"` (or `credential_refs` for multiple identities), then export the variables:

```bash
export SECOPS_TARGET_USERNAME='user'
export SECOPS_TARGET_PASSWORD='password'
```

Verify login and session before a long run with `--auth-only`.

---

## 🎛️ Main `assessmentRunner` options

| Option | Effect |
| --- | --- |
| `--config FILE` / `--target URL` | Multi-asset config or direct target. |
| `--orchestrator agentic\|deterministic` | Chooses the path. |
| `--mode test\|fast\|balanced\|deep` | Chooses the profile. |
| `--model snap4city\|llama\|qwen` | AI backend (Agentic). |
| `--max-rounds 1\|2\|3` | Number of Agentic rounds. |
| `--require-ai` / `--no-require-ai` | Makes AI planning/analysis mandatory (or optional). |
| `--auth-only` | Runs only the authenticated profiles. |
| `--authorized` | Confirms authorization for non-local targets. |
| `--dry-run` | Validates the plan without launching scanners. |

Full list: `python assessmentRunner.py --help` · install/preflight: `python initScript.py --help`.

---

## 📊 Reports and results

Each assessment produces **JSON** (complete dataset), **HTML** (consultation), and **PDF** (delivery summary). If the PDF fails, valid JSON and HTML are preserved.

The report separates three levels: **security findings**, **tool execution status**, and **surface coverage**.

> `candidate` = an issue **still to be verified**; `vulnerability` = a **confirmed** finding. A timeout does not mean no vulnerabilities; zero findings with many untested endpoints does **not** mean the target is secure.

Artifacts are saved in `reports/`. To download them:

```bash
scp debian@<host>:/home/debian/Cybersecurity_AgenticAI/reports/<file> .
```

Monitoring a long run:

```bash
mkdir -p logs
LOG="logs/balanced_$(date +%Y%m%d_%H%M%S).log"
python assessmentRunner.py --config configs/dashboard-test.json \
  --orchestrator agentic --mode balanced --max-rounds 2 --require-ai --authorized > "$LOG" 2>&1
tail -n 300 -F "$LOG"     # on long SSH sessions use tmux
```

---

## 🩺 Troubleshooting

| Problem | Check |
| --- | --- |
| Login failed | Credentials, OIDC redirects, and auth logs. |
| Many failed auth prechecks | Session valid for the specific application root. |
| Discovery with residual queue | Limits, slow pages, queue still producing new endpoints. |
| Planner failed | Provider, AI budget, and batch diagnostics. |
| Tool partial | Diagnostic code and timeout before re-running. |
| Missing PDF | Use HTML/JSON and check the renderer diagnostics. |
| Rate below 10 req/s | Normal with slow pages or serial tools: the rate is a **maximum**. |

---

## 🛡️ Operational security

- Use **only** your own targets or ones you are explicitly authorized to test.
- Avoid concurrent assessments on the same target (they duplicate work and scanner state).
- Do not enable state-changing probes without an explicit need.
- Do not interpret zero findings as the absence of vulnerabilities without checking coverage and limitations.
