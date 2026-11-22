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
> `--dry-run` and `--auth-only` are **not** separate steps: the former validates the plan, while the latter runs the assessment on authenticated profiles only.

### Step 1 — Preparation (`initScript.py`)

```bash
cd ~/Cybersecurity_AgenticAI
python initScript.py              # installs/verifies dependencies, scanners, Chromium, preflight
python initScript.py --with-lab   # adds the local lab and prepares all supported AI backends
```

Requirements: **Python 3.13** on a Debian VM, network access to the authorized target, disk space for scanners and reports.

With `--with-lab`, if neither `--prepare-ai` nor `--agentic-model` is specified, the initializer prepares **all supported AI backends** and the Agentic default is **Snap4City**. Use `--prepare-ai snap4city|llama|qwen` only when you want to restrict preparation to one backend. Snap4City is remote, so it is configured/prepared rather than downloaded locally.

> Snap4City uses provider credentials **separate** from the target's.

### Step 2 — Assessment (`assessmentRunner.py`)

This is the only step that repeats: run `assessmentRunner.py` choosing the **mode** and **config**.

> 💡 *Optional execution flags:* use `--dry-run` to validate config, scope, and jobs **without** launching scanners (recommended before long runs), or `--auth-only` to assess **authenticated profiles only** (scanners still run).
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

📄 **`init.txt`** is the operator's technical guide: a quick reference of every command and option for `initScript.py` and `assessmentRunner.py`.

---

## 🧩 Architecture

| Component | Role |
| --- | --- |
| `assessmentRunner.py` | Expands the config, prepares the jobs, and launches the orchestrator. |
| `orchestratorShared.py` | Discovery, scope, rate, request contract, sessions, and common helpers. |
| `orchestratorDeterministic.py` | Fixed, reproducible pipeline. |
| `orchestratorAgentic.py` | Agentic entry point and LangGraph wiring. |
| `orchestratorAgenticCore.py` | AI planner, rounds, execution, verification, and final analysis. |
| `utils.py` | Shared low-level utilities, request-rate policy/pacing, process coordination, runtime helpers, and safe parsing. |
| `servers/` | MCP wrappers and checks developed in the project. |
| `servers/secopsServer.py` | Unified MCP listener, source fingerprint and Docker runtime self-test. |
| `servers/reporting/` | Normalization, coverage, and report rendering. |
| `initScript.py` | Initializes the environment and generates the operator guide. |
| `setupTools.py` | Installs/verifies scanners, dependencies, and preflight requirements. |
| `setupLab.py` | Creates/verifies the optional local Docker lab and its session. |

**Deterministic** and **Agentic** share discovery, sessions, scope, scanners, and reporting. Deterministic uses a fixed 10-node pipeline (including FFUF/Arjun cross-discovery and a bounded incremental GET pass); Agentic uses a 6-node graph with AI-selected concrete actions, feedback rounds, and a final AI analysis. Scope and safety remain enforced by Python.

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

The default `execution.request_rate` is **10 request starts/s**, but the JSON configuration accepts any **integer from 1 to 50**. Invalid values fall back to the default 10 rather than being silently clamped. The pacer is shared cross-process, so parallel workers do not multiply the configured rate. A lower configured rate expands target-traffic-dependent time budgets so coverage is not reduced only because requests are intentionally slower. The values below are the base ceilings at the default rate of 10.

```json
{ "execution": { "request_rate": 10 } }
```

| Phase / limit | TEST | FAST | BALANCED | DEEP |
| --- | ---: | ---: | ---: | ---: |
| Planner nominal per round | 5 min | 6 h | 30 h | 48 h |
| Planner nominal cumulative accounting | 5 min | 12 h | 60 h | 144 h |
| Operational execution | 2 h | 32 h | 96 h | 192 h |
| Verification | 10 min | 60 min | 120 min | 240 min |
| Final AI analysis nominal reserve | 20 min | 4 h | 12 h | 24 h |
| Reporting | 20 min | 60 min | 120 min | 240 min |
| Internal target/finalization guard | 4 h | 44 h | 128 h | 256 h |
| Fixed parent-process cutoff | disabled | disabled | disabled | disabled |

The table uses each profile's default round count (TEST 1, FAST 2, BALANCED 2, DEEP 3). Planner and final-AI values are **nominal sizing/accounting values in normal profile mode, not aggregate wall-clock stop conditions**. Every started planner or analysis batch gets its complete provider-call watchdog, and fast responses return immediately. Measured planner/analysis control-plane time is excluded from the fixed target-execution/finalization guard, so a healthy but slow model does not consume scanner or report time. The assessment runner does not impose an additional fixed Agentic parent-process timeout; provider/tool calls retain their own bounded timeouts. `--max-rounds` still scales target-work/finalization reserves as before.

Important per-action/tool timeouts at the default rate of 10:

| Tool | TEST | FAST | BALANCED | DEEP |
| --- | ---: | ---: | ---: | ---: |
| FFUF | 10 s | 1 h | 2 h | 4 h |
| Commix | 10 s | 180 s | 300 s | 480 s |
| Browser | 10 s | 120 s | 240 s | 360 s |
| Authorization | 10 s | 90 s | 120 s | 180 s |

In Deterministic, the combined **FFUF + Arjun + recrawl** discovery window is **25 s / 180 s / 480 s / 900 s** (TEST / FAST / BALANCED / DEEP), shared across active profiles. Per profile, 32% is allocated to FFUF, 43% to Arjun, 15% to recrawl and 10% is reserved for Arjun follow-up on newly observed ZAP routes. The shared deadline may shorten an individual allocation; unrun cases are recorded as skipped. Specialist case quotas use bounded adaptive overflow and a reserved allowance for routing/traversal cases.

Agentic reference action capacities per round are **24 / 180 / 480 / 720**. In FAST/BALANCED/DEEP the admission capacity can grow with remaining eligible work; the AI still selects actions, with an optional AI-requested extension up to 12.5%. The global round cap is shared fairly across active profiles and tools.

For standalone FFUF actions, the profile timeout is the global action budget. Its compact general phase may use the time still remaining after the earlier FFUF phases. Planner provider calls have a 20 s transport floor and a generous per-call watchdog (BALANCED: **1800 s / 30 min**). A malformed-plan retry is a new provider call and receives a fresh full 1800 s allocation. The total number of batches never divides that timeout; in normal mode there is no aggregate planner wall-clock cutoff, so batches are not rejected merely because their worst-case sum exceeds a nominal cumulative value. Batches split only when the actual prompt exceeds model context or the provider explicitly reports context overflow. Final AI analysis is also completion-driven: every BALANCED provider call gets **1800 s**; context-split children, malformed-response recovery children and singleton rescue calls each get a fresh full 1800 s provider allowance rather than sharing a shrinking parent deadline. There is no aggregate final-analysis wall-clock admission cap. If a full 1800 s call itself times out, that is recorded as an AI/provider timeout; scanner/verifier evidence is still retained and reporting continues. The remaining scanners retain their existing profile timeout settings.

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

With `--auth-only`, the **full assessment** runs on authenticated profiles only; it is not a login-only diagnostic. A stale cookie is revalidated and, when permitted and configured credentials are available, the session can be restored through the existing browser/OIDC flow. Conclusive credential rejection is scoped to the identity, application root and origin/port; other authorized applications and anonymous work remain eligible. Verified replacement cookies are persisted to a source JSON only for explicitly managed credentials.

---

## 🎛️ Main `assessmentRunner` options

| Option | Effect |
| --- | --- |
| `--config FILE` / `--target URL` | Multi-asset config or direct target. |
| `--orchestrator agentic\|deterministic` | Chooses the path. |
| `--mode test\|fast\|balanced\|deep` | Chooses the profile. |
| `--model snap4city\|llama\|qwen` | AI backend (Agentic, default: Snap4City). |
| `--max-rounds 1\|2\|3` | Maximum Agentic rounds. Increasing it also expands the round-dependent budget/watchdog envelopes. |
| `--require-ai` / `--no-require-ai` | With `--require-ai`, attack selection never falls back to a deterministic plan. If AI control-plane work cannot complete, collected evidence is finalized and the incomplete AI coverage is reported instead of discarding the run. |
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

### 📁 Output files and naming

All files are written to `reports/`. Every job report shares one **base name**:

```text
SecOps_Assessment_<stamp>_j<NNN>           # Deterministic orchestrator
SecOps_Agentic_Assessment_<stamp>_j<NNN>   # Agentic orchestrator
```

- `<stamp>` = `YYYYMMDD_HHMMSS_<microseconds>_<pid>_<8 hex chars>` (UTC), shared by all jobs of the same assessment.
- `j<NNN>` = job index (`j001`, `j002`, …).
- `<platform>` = `platform.name` from the config, with non-alphanumeric characters replaced by `_`.

| File | What it is |
|---|---|
| `<base>.json` | Technical report data: all normalized findings, coverage and redacted scanner results. |
| `<base>.review.json` | Review snapshot, used to rebuild the report without a new scan. |
| `<base>.html` / `<base>.pdf` | **Full** report: complete technical report (interactive HTML / PDF deliverable). |
| `<base>_reduced.html` / `.pdf` | **Reduced** report: every finding, with detail trimmed by severity. |
| `<base>_summary.html` / `.pdf` | **Summary** report: tests performed plus critical/high issues only. |
| `Assessment_Results_Data_<ref>.json` | Dataset of the whole assessment: redacted config, rate policy, outcome of every job and report data. |
| `<platform>_<stamp>_aggregate.json` / `.review.json` / `.html` / `.pdf` | Single report merging all jobs (only with `reporting.aggregate_report=true` and at least 2 jobs). |
| `supporting/<platform>_<stamp>/` | Job JSON, snapshot, HTML and PDF moved here when `reporting.keep_job_reports=false`. |
| `<base>_Emergency_<YYYYMMDD>_<HHMMSS>.json` / `.html` | Raw emergency dump, only if the report server failed with nothing recoverable. |
| `<report_id>_from_json.*` | Reports rebuilt with `--report-from-json` (same files as a job). |
| `<report_id>_revision.*` | Reports rebuilt with `rerenderReport.py`. |

Notes:

- `<ref>` is the report base name when the assessment produced a single report, the aggregate report name when the aggregate report is enabled, and `<platform>_<stamp>` otherwise.
- A successful job produces **8 files** (`.json`, `.review.json`, full/reduced/summary in HTML and PDF), plus one `Assessment_Results_Data_*.json` per assessment.
- If the full PDF fails, only `.json`, `.review.json` and `.html` remain, and no reduced/summary report is produced.


### 🔁 Regenerate reports from an existing JSON (no pentest)

Without `--report-from-json`, `assessmentRunner.py` runs the pentest and builds the report from the evidence it collects. As an **optional** alternative, `--report-from-json` rebuilds the **HTML and PDF** deliverables (full **report** + the companion **list** reports — *reduced* and *summary*) from a JSON **already produced** by a previous run, **without launching any scanner against the target**.

Accepted inputs:

- the **technical report JSON** (`<report_id>.json`),
- the **review snapshot** (`<report_id>.review.json`),
- the **results-data dataset** (`Assessment_Results_Data_*.json`).

```bash
# Rebuild report + list (HTML/PDF) from an external JSON, no pentest
python assessmentRunner.py --report-from-json reports/SecOps_Assessment_XXXX.json

# Optional cover-page overrides and a custom output base name
python assessmentRunner.py --report-from-json reports/SecOps_Assessment_XXXX.json \
  --output-name MyClient_rev2 --client-name "ACME" --assessor "Team" --assessment-type "Web app" --report-version 1.1
```

> `--report-from-json` is mutually exclusive with `--config`/`--target`, and `--authorized` is **not** required because no target traffic is generated. Scanner results in these JSON files are already redacted, so the regenerated report carries no secrets.

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
| Nikto/Docker access denied | Check Docker from the **MCP process**, not only from the SSH shell; verify its runtime identity and service isolation. `initScript.py` checks Docker through the live MCP and does not restart unrelated services. |
| Many failed auth prechecks | Session valid for the specific application root. |
| Discovery with residual queue | Limits, slow pages, queue still producing new endpoints. |
| Planner incomplete | Provider/contract errors, per-call watchdogs, and context diagnostics. Normal profile mode has no aggregate planner time cutoff; collected evidence still reaches final reporting. |
| Tool partial | Diagnostic code and timeout before re-running. |
| Missing PDF | Use HTML/JSON and check the renderer diagnostics. |
| Effective rate below the configured value | Normal with slow pages or serial tools: `execution.request_rate` is a **maximum**, not a minimum. |

---

## 🛡️ Operational security

- Use **only** your own targets or ones you are explicitly authorized to test.
- Avoid concurrent assessments on the same target (they duplicate work and scanner state).
- Do not enable state-changing probes without an explicit need.
- Do not interpret zero findings as the absence of vulnerabilities without checking coverage and limitations.
