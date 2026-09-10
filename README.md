# Agentic AI Pentesting & Reporting Automation System through MCP 

Automated web-application security assessment platform: one unified FastMCP Streamable HTTP
server (`servers/secopsServer.py`) imports the external-tool wrappers and project-specific checks
and exposes their tools through a single `/mcp` endpoint. Two orchestrators drive the same tool
catalogue against a target and produce PDF/HTML/JSON reports plus a redacted review snapshot. A platform-level
assessment configuration can expand multiple authorized HTTP/HTTPS services into the same existing orchestrators;
direct orchestrator commands remain supported. Full command reference: `init.txt`.

## Start here: recommended workflow

If this is the first time you open the repository, use this sequence.

1. **Initialize the environment** from the repository root.

   ```powershell
   python .\initScript.py --with-lab
   ```

   On Linux/macOS use `python3 ./initScript.py --with-lab`. The initializer verifies the project dependencies, scanners,
   Playwright/Chromium and the selected AI backends. With `--with-lab` it also prepares the local DVWA lab. At the end it
   prints ready-to-copy commands.

2. **Run the first baseline with Deterministic in `balanced` mode on DVWA.** The execution order is fixed, so this is the
   easiest run to inspect and reproduce. After the baseline works, use Agentic in `balanced` mode when you want adaptive
   action selection and AI evidence analysis.

3. **Choose how to describe the new target.**
   - Use `assessmentRunner.py --target <URL>` for a single starting URL when the run is anonymous or when you already have
     a valid cookie that can be passed with `--cookies`.
   - Use `assessmentRunner.py --config <FILE>` when you only have the target username/password and the session must be
     created through browser/OIDC login. Direct `--target` mode does not accept target username/password and does not run
     the `snap4city_oidc` login workflow.
   - Also use `--config` when the authorized scope contains several hosts, ports, base paths, identities or explicit entry
     URLs that must all be tested.

4. **Do not list every internal URL unless the scope requires specific entry URLs.** For a normal application, give the
   root URL or the relevant base path and let discovery expand the authorized surface. Exact same-origin URLs are always
   in scope; additional origins are followed only when they match an explicit `authorization.allowed_origins` or
   `authorization.allowed_host_suffixes` entry. Discovery follows HTML links/forms, extracts GET/POST request contracts
   and JavaScript endpoint hints, and observes dynamic `document`, `xhr` and `fetch` requests with Chromium. If several
   supplied URLs must each be guaranteed as starting points, declare them as separate services in the configuration.

5. **Validate a new configuration before scanning it.**

   ```powershell
   python .\assessmentRunner.py --config .\configs\platform.example.json --orchestrator deterministic --mode balanced --dry-run
   ```

   `--dry-run` validates and expands the configuration without starting scanners.

6. **Use `balanced` unless you need a different trade-off.** `fast` is intended for smoke tests and short diagnostics.
   `deep` increases discovery and scanner budgets, so use it after the target, authentication and scope have been checked.

7. **Watch the terminal during the assessment.** Deterministic reports the fixed pipeline stages. Agentic also reports
   planner rounds and selected actions. Execution status and coverage remain separate from security findings.

8. **Read the final artifacts from `reports/`.** PDF and HTML are the human-readable reports. The report JSON contains the
   technical report data. `.review.json` is the redacted rerender snapshot. When `assessmentRunner.py` is used,
   `Assessment_Results_Data_<ID>.json` is the preferred redacted dataset for audit and later analysis. The runner prints
   the exact paths under `Assessment final artifacts`.

### Authentication: direct target or configuration?

This distinction is important:

- `--target` mode accepts `--cookies`. It can therefore run anonymously or reuse an authenticated session that already exists.
- `--target` mode has no target `--username` or `--password` option. It does not create an OIDC session from account credentials.
- If you only have the username/password of the assessed application, use a JSON configuration with a credential such as
  `kind: "snap4city_oidc"`. `assessmentRunner.py` performs the browser login and passes the resulting cookies to the existing orchestrators.
- When an OIDC credential has `optional: true`, missing credentials or a failed login fall back to the anonymous profile.
  `--auth-only` is different: it requires a valid authenticated session, so the job is blocked if login cannot provide one.

### What should I normally choose?

| Need | Recommended choice |
| --- | --- |
| First run / reproducible baseline | `assessmentRunner.py` or `orchestratorDeterministic.py`, `--mode balanced` |
| Single target, anonymous or cookie already available | `assessmentRunner.py --target <URL>` |
| Only target username/password available | `assessmentRunner.py --config <FILE>` with a supported login credential such as `snap4city_oidc` |
| Multiple hosts / ports / base paths / identities | `assessmentRunner.py --config <FILE>` starting from `configs/platform.example.json` |
| Several exact entry URLs that must all be covered | declare one enabled service per supplied URL in the config |
| Check a configuration without scanning | add `--dry-run` |
| Adaptive tool selection and AI evidence analysis | Agentic + `--model <model>`; add `--require-ai` when AI completion is mandatory |
| Quick smoke test | `--mode fast` |
| Normal assessment | `--mode balanced` |
| Broader bounded assessment after validation | `--mode deep` |
| Debug one scanner/request manually | Deterministic isolated `--tool ...` mode described in `init.txt` |

For non-local targets, keep state-changing checks disabled unless the authorized scope explicitly permits them. An explicit
`allow_state_changes=false` in the configuration or `--no-allow-state-changes` on the CLI is binding. The planner cannot
bypass this shared Python gate. The flag applies only to the project paths documented below and is not a universal switch
for every external scanner.

## Credential and token terminology (legend)

This document uses the word "token" for two unrelated access-credential concepts. Every later
mention of "token" in this file is tagged with one of the two markers below, so it is always clear
which access is meant:

- **(1) AI-token** — Snap4City access/refresh tokens that authenticate to the remote LLM API (the AI
  backend used by the Agentic planner). Managed by the Snap4City `TokenManager`, cached in
  `token_stored.json`, and completely unrelated to any assessed target.
- **(2) Target-token** — Target cookies, target JWTs and anti-CSRF tokens (for example `--cookies`,
  `--jwt-token`, or the `dashboard_session` login) belonging to the application being assessed. Never
  Snap4City credentials, never shared with the AI provider.

## How the core files work

### Initialization

- `initScript.py`: Installs/verifies dependencies, scanners, Docker images and Playwright. Chromium is a verified default dependency: unless `--skip-browser` is explicitly used, initialization installs the Playwright Chromium build (and Linux host dependencies) and fails if a headless launch cannot be completed. With `--with-lab` it sets up
the local training lab and ZAP and prepares the selected AI backends. If neither `--prepare-ai` nor `--agentic-model` is
specified, it prepares all three choices: it pulls/verifies `llama3.1:8b` and `qwen2.5:7b` in the project Ollama container
and authenticates/verifies the remote Snap4City `llama4-agentic-inference` endpoint. Snap4City is remote and therefore is
not downloaded. `--prepare-ai snap4city|llama|qwen` prepares only one backend. If `--agentic-model` is specified without
`--prepare-ai`, the initializer automatically prepares only that selected model. If both options are supplied, they must
be coherent: `--prepare-ai all` accepts any Agentic model, while a single-backend `--prepare-ai` must match
`--agentic-model`. The Agentic commands printed at the end use Snap4City when all backends are prepared; when one backend
is prepared, that backend becomes the default. The initializer writes
`.secops_runtime.json`, used by preflight checks and both orchestrators. `--commands-only` prints the `init.txt` command reference.

- `init.txt`: Canonical operational cheat sheet stored in the repository and printed by `initScript.py --commands-only`.
  The initializer reads the existing file and does not overwrite it during normal initialization, so documentation updates remain stable.

### Orchestrators

Then, there are mainly **2 orchestrators** that are responsible for directing the pipeline:

- `orchestratorDeterministic.py`: Fixed, reproducible LangGraph pipeline: discovery → broad scan → parameter scan →
authorization → browser/workflow → specialist checks → final Chromium verification → report. The baseline engine.

- `orchestratorAgentic.py`: Same discovery and validators as Deterministic, but a selectable AI planner chooses
discovery-derived actions each round. Before the AI analysis, the same final deterministic Chromium stage retries unresolved XSS candidates when a compatible request contract is available. Supported aliases are `snap4city` (Snap4City `llama4-agentic-inference`),
`llama` (Ollama `llama3.1:8b`) and `qwen` (Ollama `qwen2.5:7b`). After execution, the same selected provider/model
performs a separate evidence-grounded risk assessment, including potential consequences and recovery/restoration guidance,
while scanner evidence and confirmation status remain immutable.

The other files support the previous ones, as shared logic or support files.

### Platform assessment configuration

- `assessmentConfig.py`: validates a platform scope containing multiple assets, credential references and web targets expressed either as an absolute per-service `url`, or as asset host/IP plus service port/protocol/base path. When only host/IP and port are supplied, port 443 infers HTTPS and other ports infer HTTP unless `protocol` is explicitly set.
- `assessmentRunner.py`: accepts either a platform JSON configuration or a direct `--target`/`--cookies` invocation, then delegates
  each HTTP/HTTPS job to the existing Deterministic or Agentic orchestrator. Direct mode consumes an already available cookie session;
  target username/password login is configuration-driven. Non-web protocols may be inventoried but are explicitly recorded as unsupported
  by the current web-assessment orchestrators rather than being silently treated as tested.
- `configs/dvwa.example.json`: non-secret placeholder that shows the exact DVWA configuration structure without containing a usable session.
- `configs/dvwa.generated.json`: generated by `initScript.py --with-lab` from the fresh DVWA session and immediately usable.
- `configs/dashboard-test.json`: definition for the authorized `192.168.1.81` / `dashboard-test` test; HTTP/80 with base path `/` is enabled while HTTPS/443 remains disabled until verified. Its authorization block also declares `snap4city.org` as an allowed host suffix, so related Snap4City origins discovered at runtime can enter the assessment without any site-specific crawler rule. Its `dashboard_session` credential can reuse `DASHBOARD_TEST_COOKIE` when an existing session is supplied, otherwise it performs the Snap4City/Keycloak browser login with `DASHBOARD_TEST_USERNAME` and `DASHBOARD_TEST_PASSWORD`. Cookies obtained for the primary target are never copied automatically to sibling origins.
- `configs/tourist-dashboard.json`: complete Snap4City tourism-dashboard configuration for the eight supplied HTTPS views. Each view is an explicit service URL so every entry point is assessed. `TOURIST_DASHBOARD_COOKIE` can reuse an existing session. Otherwise `TOURIST_DASHBOARD_USERNAME` and `TOURIST_DASHBOARD_PASSWORD` are used by the optional `snap4city_oidc` browser login. If login is unavailable or fails, the jobs continue anonymously unless `--auth-only` is requested. State-changing checks remain explicitly disabled.
- `configs/platform.example.json`: example of a larger multi-host scope that explicitly demonstrates both supported web-target forms: one service uses an absolute `service.url`, while other services use asset host/IP plus port/protocol/base path. It also shows two web identities and a non-web service kept only as inventory. Environment-variable credential references are preferred for reusable configurations.

The runner is an optional layer above the orchestrators, not a replacement for them. Existing direct commands such as
`python orchestratorDeterministic.py --target ...` and `python orchestratorAgentic.py --target ...` continue to work unchanged.

In the Agentic planner, the optional breadth review is a sparse-plan recovery pass. It runs only when the first plan selected at most roughly one third of the executable candidates and can add at most 4 actions in `fast`, 10 in `balanced` or 16 in `deep`. This expands coverage without turning the first round into an indiscriminate checklist.

### Profile breadth budgets

The profiles increase both discovery breadth and scanner execution ceilings. Limits are deliberately applied after relevance ranking and route-shape deduplication, so a larger budget is spent preferentially on distinct API/form/request surfaces rather than repeated calendar pages, archives, static assets or equivalent query-value variants. ZAP and Nuclei limits are request-contract/target ceilings, not HTTP request counts.

| Coverage bound | fast | balanced | deep |
| --- | ---: | ---: | ---: |
| HTTP crawler pages per profile | 35 | 90 | 180 |
| Chromium navigations per profile | 12 | 45 | 90 |
| JavaScript assets inspected | 12 | 36 | 72 |
| ZAP request contracts considered | 10 | 32 | 60 |
| Nuclei focused/static targets | 8 | 30 | 80 |
| Nuclei DAST request contracts | 0 | 18 | 48 |
| SQLMap cases | 3 | 10 | 18 |
| Dalfox cases | 3 | 10 | 18 |
| Commix cases | 3 | 8 | 14 |
| Traversal cases | 3 | 10 | 18 |
| Browser cases | 3 | 10 | 20 |
| Workflow cases | 3 | 10 | 20 |
| IDOR cases | 1 | 4 | 8 |
| Authorization cases | 2 | 6 | 12 |
| Arjun endpoints | 3 | 10 | 18 |
| Interactsh actions | 1 | 2 | 3 |
| Final Chromium XSS candidates | 2 | 10 | 20 |
| Agentic breadth-review additions | 4 | 10 | 16 |
| Agentic maximum actions per round | 16 | 40 | 64 |

Broad scanner timeout ceilings are `zap` 120/540/900s, `nuclei` 150/660/1200s, `nikto` 60/150/240s and `ffuf` 50/120/210s in fast/balanced/deep. Main specialist ceilings are SQLMap 75/180/300s, Dalfox 45/120/210s, Commix 50/120/180s, Traversal 35/75/120s, Browser 45/120/210s and Workflow 40/105/180s. Agentic planner ceilings are 900/1800/3000s with context windows 6144/8192/12288 and output budgets 800/1300/1800 tokens. These are upper bounds; completed tools return immediately.

Nuclei accepts up to 8/30/80 focused targets and 0/18/48 DAST request contracts. DAST stays disabled in `fast`; balanced/deep retain bounded fuzz aggression and global time/concurrency/rate controls. GET and POST contracts are both eligible when compatible with the template/input mode. ZAP considers up to 10/32/60 ranked request contracts for targeted/prioritized/full active modes.

### Discovery and scanner coverage

Discovery combines an HTTP crawler, JavaScript endpoint extraction and a bounded Playwright/Chromium queue. Exact same-origin URLs are always eligible; cross-origin URLs are admitted only when they match an explicit authorized origin or DNS suffix. There is no domain-name special case in the discovery code. The crawler uses profile budgets of 35/90/180 HTML pages, Chromium uses 12/45/90 navigations and JavaScript inspection uses 12/36/72 assets in fast/balanced/deep. A route signature based on origin, path and parameter names deduplicates value-only variants; per-origin quotas and generic relevance scoring favor APIs, forms, account/management/search/configuration surfaces and observed XHR/fetch traffic while deprioritizing static/vendor/chunk assets, archive/calendar/pagination-like routes and repeated low-value variants.

GET and POST are first-class request contracts. HTML forms, query strings, JavaScript `fetch`/XHR/axios hints and browser-observed requests preserve method, body, content type and nested JSON parameter paths. Discovery itself remains non-mutating: Chromium aborts non-GET/HEAD/OPTIONS navigation requests before transmission and destructive routes are blocked, but the observed POST body can still become a contract for later compatible scanners. `allow_state_changes=false` therefore prevents unsafe discovery submissions without deleting POST coverage from the assessment. Cookies remain origin-confined: the primary target cookie is used only on its exact origin; explicitly authorized sibling origins are scanned without that cookie unless separately configured.

Observed sibling origins are not merely inventoried. Deterministic and Agentic can schedule ZAP, Nuclei and Nikto against a bounded set of discovered authorized sibling origins, with each sibling treated as its own scanner target and with primary-origin cookies stripped. Specialist request-case selectors also accept explicitly authorized scoped URLs where safe. Authentication/session probes intentionally remain exact-origin because session validity must not be inferred across hosts. The resulting contracts are shared by both orchestrators and drive ranking instead of inventing endpoints or parameters.

ZAP active mode is selected from the scan profile rather than from whether the current profile has a cookie: `fast` uses bounded targeted active scanning, `balanced` prioritized active scanning and `deep` the broader bounded mode; `diagnostic_only` remains passive. Scanner inventory is read through the Python API and retried through the raw ZAP JSON API; if metadata is unavailable, a curated set of known injection/path-traversal rule IDs is used as a compatibility fallback. Static assets are excluded from active-case selection. If semantic request classification still yields no native plan, safe dynamic/API-like parameterized GET request shapes may receive the bounded generic active-rule union; distinct application endpoints are retained and executed sequentially until the global ZAP time budget is exhausted. Equivalent requests with the same method, path and parameter set are still deduplicated. Planned, attempted, started and completed native cases are counted separately; ZAP reports complete active coverage only when all four counts agree with the planned case count. A planned case that cannot start, remains incomplete, or is not attempted therefore makes the bounded ZAP result partial instead of allowing the completed subset to be reported as complete. The fallback starts from cross-product rules such as reflected XSS, generic SQL injection and traversal instead of wasting the balanced budget on stored-XSS or DBMS-specific rules without evidence. Rule IDs are enabled one by one and the wrapper records which IDs ZAP actually accepted, so a theoretical plan cannot be reported as an effective active scan. Only when no safe case/rule can be enabled does the wrapper return `partial/no_active_scan_rules_enabled`.

Nuclei consumes discovered request contracts for DAST checks in both `balanced` and `deep`; the initializer now requires a DAST-capable current Nuclei runtime (minimum v3.11.1), verifies the official `nuclei-templates/dast` subtree and performs a template-load DAST runtime check before assessments start. The DAST phase explicitly selects that directory. Request-shaped Proxify JSONL is attempted first; if the engine rejects it, the same GET/POST request contracts are serialized to the other officially supported Proxify YAML MultiDoc input mode; only if both request-shaped modes fail does the wrapper fall back to a plain URL list for compatible GET cases. Every attempt and stderr excerpt remains in coverage diagnostics. Balanced uses `-fa medium` with `fuzz-param-frequency=100`; deep uses `-fa high` with `fuzz-param-frequency=1000`. `-fm single` is retained so one parameter is mutated at a time and evidence remains attributable; it is not a low payload-count cap. SQLMap/Dalfox/other parameter scanners rank API/data-oriented contracts, meaningful identifier/query parameters, method and observed JSON/network evidence ahead of navigation-only parameters. After the scanner phases, both orchestrators perform a candidate-driven Chromium verification pass: at most 2 unresolved XSS candidates in `fast`, 10 in `balanced` and 20 in `deep` are sent to the browser verifier when a compatible request contract exists. The final action is restricted to the exact source parameter and is matched to the closest request context using the other query parameters, so two candidates on the same path/parameter but with different application context are verified separately. The source context is preserved through reconciliation and final finding deduplication, so a browser outcome cannot be reassigned to or merged with a different XSS context on the same route. The Browser server exports the parameters actually exercised so reconciliation remains deterministic even if nested diagnostics are lost in transport. Confirmed execution upgrades the source candidate and sets high verification confidence. An unexecuted browser reflection keeps the candidate's potential severity unchanged but limits confidence to medium; a successful exact-parameter bounded non-reproduction likewise preserves severity while setting confidence to low. Severity therefore expresses potential impact if the weakness is real, while confidence expresses how strongly the collected evidence supports its existence. For findings without a browser ceiling, the validated AI confidence becomes the final finding confidence. The subsequent AI analysis may enrich wording and reassess severity from impact evidence, but it cannot raise confidence above the deterministic browser ceiling (MEDIUM for reflection without execution, LOW for bounded non-reproduction). Static assets such as CSS, JavaScript, images and fonts are excluded as Browser-XSS targets. Deterministic skips an exact URL/method/parameter case already exercised successfully by its earlier browser/workflow phase; Agentic performs the same bounded verification before AI analysis.

Nikto is reported as `partial` when its process exits successfully but neither request metrics nor a structured report are sufficient to verify scan coverage. Parsed console findings are preserved, but unverified coverage is never presented as a complete successful scan.

Terminal logging keeps long request URLs compact: when an URL exceeds the configured display threshold, only the endpoint plus parameter/query metadata are printed (for example parameter count and query length). The complete unmodified URL remains stored in scanner results, JSON artifacts and reports. The threshold can be adjusted with `SECOPS_TERMINAL_URL_MAX`.

### Session-lifecycle logout verification

Logout handling is profile-aware and intentionally separate from generic fuzzing. Anonymous discovery does not spend scanner budget on logout/signout/logoff endpoints because there is no authenticated session to invalidate. Authenticated discovery may retain a logout request contract, including a POST form, but does not execute it during ordinary crawling or specialist scanning. After the remaining authenticated checks and final browser verification have completed, the session verifier executes one bounded logout flow and replays the pre-logout cookie against the protected session probe. If the old cookie still provides authenticated access, the result is a deterministically confirmed session-invalidation vulnerability (CWE-613); if the old cookie is rejected, logout invalidation is verified; if the response cannot be distinguished reliably, the check remains partial rather than creating a vulnerability. Login/SSO/OIDC routing is the inverse: those routes remain testable in the anonymous profile but are not sent to SQLMap/Dalfox/Commix/Traversal from an already authenticated profile.

## Requirements

- Python 3.12+
- Docker
- Ollama only for local `llama`/`qwen` Agentic models. `initScript.py --with-lab` provisions both by default;
  `--prepare-ai snap4city` does not provision or require Ollama because no local model is requested.
- The Snap4City AI model/provider requires network access plus `snap4city_model_credentials.json` or interactive model credentials. This file is unrelated to the account used to log in to the assessed dashboard. The provider is remote and is verified during initialization rather than downloaded. Token (1) endpoint calls use bounded HTTP timeouts; transport or JSON failures fall back through the normal cached-token/refresh/user-credential sequence (1) and cannot block indefinitely.

## Detailed initialization and run options 

The recommended complete local-lab initialization is:

```powershell
python .\initScript.py --with-lab
```

With neither `--prepare-ai` nor `--agentic-model`, this prepares all three supported AI choices:

1. Ollama + `llama3.1:8b`;
2. Ollama + `qwen2.5:7b`;
3. Snap4City + `llama4-agentic-inference` (remote readiness/authentication check, no model download).

If only `--agentic-model` is supplied, that model is also the only AI backend prepared. For example:

```powershell
python .\initScript.py --with-lab --agentic-model qwen
python .\initScript.py --with-lab --agentic-model snap4city --run agentic --mode balanced
```

To prepare exactly one:

```powershell
python .\initScript.py --with-lab --prepare-ai snap4city
python .\initScript.py --with-lab --prepare-ai llama
python .\initScript.py --with-lab --prepare-ai qwen
```

To initialize and immediately run an orchestrator:

```powershell
python .\initScript.py --with-lab --run deterministic --mode balanced
python .\initScript.py --with-lab --run agentic --mode balanced
python .\initScript.py --with-lab --prepare-ai snap4city --run agentic --mode balanced
python .\initScript.py --with-lab --prepare-ai qwen --run agentic --mode balanced
```

When all backends are prepared, the default Agentic model is Snap4City. When exactly one backend is prepared, that backend
becomes the Agentic default. `initScript.py` has no `--model` option. `--prepare-ai` explicitly chooses what is prepared;
`--agentic-model` chooses what Agentic uses and, when `--prepare-ai` is absent, also implicitly chooses what is prepared.
If both are present, `--prepare-ai all --agentic-model <model>` is valid, while mismatched single-backend selections are rejected.

The repository also contains `configs/dvwa.example.json`, which is only a readable placeholder and must not be used as a real authenticated session.
After step 1 succeeds, `initScript.py` writes `configs/dvwa.generated.json` with the fresh DVWA cookie and `auth_only=false`, then prints
ready-to-copy `assessmentRunner.py` commands for fast, balanced and deep Deterministic/Agentic runs. Those generated commands therefore
run both anonymous and authenticated profiles by default; add `--auth-only` when only the authenticated profile is wanted. It also prints one
direct `orchestratorAgentic.py` command so the original manual workflow remains immediately available. In addition, every non-example JSON
under `configs/` receives exactly one Deterministic BALANCED and one Agentic BALANCED command; files whose names contain `example`, `sample`
or `template`, and the already-covered `dvwa.generated.json`, are excluded. The additional commands use `--authorized` explicitly and the
verified Agentic model selected by initialization when available. The same dynamic list is printed by `--commands-only`.

If Snap4City authentication succeeds but its configured remote model/endpoint cannot be prepared, initialization reports the
Snap4City error and continues. A verified local Ollama model is used as the Agentic fallback when one is already available;
otherwise the initializer attempts to provision `llama3.1:8b`. Failure of that recovery path is reported without discarding the
rest of the completed initialization.

The complete operational reference is in `init.txt`.

## Configuration-driven assessments

Validate a configuration without launching scanners:

```powershell
python .\assessmentRunner.py --config .\configs\dvwa.generated.json --orchestrator deterministic --mode balanced --dry-run
```

Configuration values for `orchestrator`, `mode` and `model` are normalized to lowercase during validation, so equivalent case variants cannot pass validation and then fail later at the orchestrator CLI.

Run the generated DVWA configuration. Because the generated file contains a fresh cookie and `auth_only=false`, the default is
anonymous + authenticated; add `--auth-only` only when the anonymous profile must be skipped:

```powershell
python .\assessmentRunner.py --config .\configs\dvwa.generated.json --orchestrator deterministic --mode balanced
python .\assessmentRunner.py --config .\configs\dvwa.generated.json --orchestrator deterministic --mode balanced --auth-only
python .\assessmentRunner.py --config .\configs\dvwa.generated.json --orchestrator agentic --model snap4city --max-rounds 2 --mode balanced --require-ai
```

The runner can also be used without a JSON file. `--config` and `--target` are alternatives. Direct-target mode accepts the same
primary and secondary cookie headers used by the orchestrators. With a cookie and no `--auth-only`, both anonymous and authenticated
profiles are executed. With `--auth-only`, only the authenticated profile is executed. Without a cookie, the run is anonymous only.
Direct-target mode does **not** accept target username/password and does not execute the OIDC browser-login resolver. If account
credentials are all you have, use a configuration with `kind: "snap4city_oidc"` or obtain an authorized cookie separately.
For example:

```powershell
python .\assessmentRunner.py --target http://127.0.0.1 --cookies "PHPSESSID=<SESSION>; security=low" --orchestrator deterministic --mode balanced
python .\assessmentRunner.py --target http://127.0.0.1 --cookies "PHPSESSID=<SESSION>; security=low" --orchestrator deterministic --mode balanced --auth-only
python .\assessmentRunner.py --target http://127.0.0.1 --orchestrator deterministic --mode balanced
python .\assessmentRunner.py --target http://127.0.0.1 --cookies "PHPSESSID=<SESSION>; security=low" --orchestrator agentic --model snap4city --max-rounds 2 --mode balanced --require-ai
```

`--orchestrator`, `--mode`, `--model`, `--max-rounds`, `--auth-only`, `--require-ai`/`--no-require-ai`,
`--authorized`, `--allow-state-changes` and `--no-allow-state-changes` override only the current run and do not rewrite the source JSON. For local Ollama
models, `assessmentRunner.py` requires the exact requested model to be already installed and passes `--no-model-pull` to the
Agentic orchestrator; initialize the chosen model first instead of silently substituting another model.

For the authorized microX test, first map the supplied name in the assessment VM:

```text
192.168.1.81 dashboard-test
```

Use `getent hosts dashboard-test`, `curl -v http://dashboard-test/` and `curl -vk https://dashboard-test/` when you want to
revalidate the mapping and exposed services. The current `configs/dashboard-test.json` already enables the HTTP/80 service confirmed
by the 2026-09-03 run and keeps HTTPS/443 disabled. The configuration declares `dashboard_session` as a Snap4City OIDC browser-login credential.
The preferred reusable form is:

```bash
export DASHBOARD_TEST_USERNAME='authorized-user'
export DASHBOARD_TEST_PASSWORD='authorized-password'
```

If either variable is missing and the runner has an interactive terminal, it asks only for the missing value in console and hides password input.
These two variables are credentials of the **assessed dashboard account** and are unrelated to `snap4city_model_credentials.json`, which authenticates the
Snap4City AI provider used by the Agentic planner. Chromium opens `/dashboardSmartCity/`; if the anonymous landing page is shown, it activates the visible `login` control, then follows the Keycloak/OIDC flow, submits the supplied account, returns to the dashboard, verifies that the anonymous login control is no longer present, and extracts the target cookies in memory. Those cookies are then passed to the existing orchestrators exactly like a
manual `--cookies` session, so both anonymous and authenticated discovery/scanners run because `auth_only=false`. The credentials and resulting
cookie are not written to the configuration or Results Data. `DASHBOARD_TEST_COOKIE='PHPSESSID=<SESSION>; ...'` remains a manual override: when
present it is used directly and the browser login is skipped. If no account/session is available, leaving the console values empty keeps the
optional job anonymous; `--auth-only` instead blocks because an authenticated session is required. An authenticated profile is eligible for scanner planning only while discovery has not conclusively marked that session ineffective; an invalid supplied cookie therefore cannot be reported as authenticated coverage or suppress the corresponding anonymous coverage. After initialization, `dashboard-test.json` is included automatically in the generic per-config command list: it receives one Deterministic BALANCED command and one Agentic BALANCED command using `--max-rounds 2 --mode balanced --require-ai` and the effective Agentic model (Snap4City or the verified local fallback). The initializer no longer depends on a hardcoded dashboard-test command and no longer prints the isolated ZAP diagnostic command.


### Tourist dashboard configuration

`configs/tourist-dashboard.json` contains the eight supplied Snap4City dashboard-view URLs as eight enabled HTTPS service jobs. They share
one optional target credential named `tourist_session`:

```bash
export TOURIST_DASHBOARD_USERNAME='authorized-user'
export TOURIST_DASHBOARD_PASSWORD='authorized-password'
```

An existing session can be supplied instead:

```bash
export TOURIST_DASHBOARD_COOKIE='PHPSESSID=<SESSION>; ...'
```

The cookie has priority over username/password. Otherwise Chromium performs the Snap4City/Keycloak OIDC login once and the resulting
session is reused for the service jobs. Because `optional=true` and `auth_only=false`, a missing account or failed login does not cancel the
assessment: the affected jobs continue with the anonymous profile. If `--auth-only` is added, a valid authenticated session becomes mandatory.
To force an **anonymous-only** service from configuration, remove its `credential_ref` (or leave it empty). `auth_only=false` by itself does not
disable authentication; it only means that an available credential may be used in addition to the anonymous profile.
The recommended validation command is:

```powershell
python .\assessmentRunner.py --config .\configs\tourist-dashboard.json --orchestrator deterministic --mode balanced --dry-run --authorized
```

After the dry-run is correct, remove `--dry-run` or select Agentic as required by the assessment.

## Agentic AI models

Model aliases map to providers as follows:

- `snap4city` -> Snap4City remote endpoint `llama4-agentic-inference`;
- `llama` -> local Ollama model `llama3.1:8b`;
- `qwen` -> local Ollama model `qwen2.5:7b`.

The two local aliases share the same Ollama readiness path: the requested model tag is checked explicitly and is warmed before Agentic planning. Model selection is exact; `llama` and `qwen` do not replace each other automatically.

With all backends available, the generated `assessmentRunner.py` commands select Snap4City by default and use strict AI
execution. Direct Agentic commands remain valid for manual/debug use; for example:

```powershell
python .\orchestratorAgentic.py --target http://127.0.0.1 --cookies "PHPSESSID=<SESSION>; security=low" --auth-only --model snap4city --max-rounds 2 --mode balanced --require-ai
```

Local alternatives use the same planner and prompt contract:

```powershell
python .\orchestratorAgentic.py --target http://127.0.0.1 --cookies "PHPSESSID=<SESSION>; security=low" --auth-only --model llama --max-rounds 2 --mode balanced --require-ai
python .\orchestratorAgentic.py --target http://127.0.0.1 --cookies "PHPSESSID=<SESSION>; security=low" --auth-only --model qwen --max-rounds 2 --mode balanced --require-ai
```

`orchestratorAgentic.py --model` accepts exactly `snap4city`, `llama` and `qwen`. There is no public `--ai-provider`
option: the transport/provider is an internal implementation detail inferred from the selected model. `snap4city` uses the
remote Snap4City endpoint, while `llama` and `qwen` use local Ollama. Snap4City uses the Snap4City `TokenManager` (1) and keeps its authentication priority: a valid access
token (1) already cached in `token_stored.json` is reused first; when it is expired, a cached refresh token (1) is tried; real
username/password from `snap4city_model_credentials.json` are the normal final credential step. If the JSON is missing or still contains
placeholders, those placeholder strings are never sent to Snap4City: the wrapper first tries the cached access/refresh token (1) and
asks for username/password in an interactive console only when neither token (1) can be used. Credentials entered interactively stay
in memory for that process; the password is not echoed and `snap4city_model_credentials.json` is not rewritten automatically. The repository `.gitignore` excludes `snap4city_model_credentials.json`, `token_stored.json`, generated reports and Python caches to reduce accidental commits of runtime secrets/artifacts.

`--require-ai` disables the planner fallback: a planning or AI-analysis failure stops the Agentic run. Without it, planning
errors can fall back to a small deterministic discovery-derived plan of at most three safe actions. During a running
`orchestratorAgentic.py` assessment, a failed AI backend never automatically switches provider or local model. The only
backend substitution introduced here is the explicit initialization-time recovery described above when Snap4City preparation
fails before an assessment starts.

## What is produced

If all steps are completed successfully, **4 report artifacts are produced**:

- JSON
- HTML
- PDF (obtained from the conversion and adaptation of HTML)
- `.review.json`, a redacted evidence snapshot for later review/regeneration

JSON is the complete, untruncated dataset (every deduplicated finding); HTML and PDF render a readable, size-capped subset of it for browsing.
The review snapshot retains redacted scanner results, normalized findings, assessment context, planner audit and AI-analysis metadata so a later
revision can be rendered without repeating the security scan. Use `python .\rerenderReport.py --snapshot <REPORT.review.json>`.

For confirmed findings, Deterministic reporting adds conservative potential-consequence and recovery/restoration guidance when the tool does
not provide those fields. Agentic reporting asks the selected AI to produce the same fields from immutable scanner evidence. When a scanner
already supplied description, impact, consequence, recovery or remediation text, the original value remains available in the existing
"Original scanner assessment" audit area if the final Agentic wording differs. No report colors, card layout or visual styling are changed.

Reports produced land in `reports/` .

When execution is started through `assessmentRunner.py`, the runner also writes a redacted, self-contained machine-readable dataset named `Assessment_Results_Data_<REFERENCE_ID>.json`. For a single generated report, `<REFERENCE_ID>` is exactly that report's `report_id` (for example `SecOps_Agentic_Assessment_20260903_191426`); for a multi-job or dry-run test it is the generated `test_id`. The old `Assessment_Batch_*.manifest.json` name is no longer produced.

`Assessment_Results_Data_*` is the preferred input for future automated analysis because it embeds the assessment evidence instead of acting only as an artifact index. Schema version 4 stores redacted configuration/job metadata, artifact paths and a `reports_data` entry for every generated report. Each embedded report contains the normalized summary and coverage, readable and raw findings, complete redacted scanner results, assessment context, discovery, diagnostics, planner notes/audit, the recorded operational `reasoning_summary` and breadth-review reasoning, Agentic decision metadata and final AI-analysis summary plus the per-finding AI rationale/confidence metadata already attached to normalized findings. When there is exactly one report, the main `assessment_results`, `assessment_context`, `discovery`, `diagnostics`, `agentic_decisions` and `ai_analysis` sections are also copied to the top level for direct access. The technical report JSON and `.review.json` remain separate artifacts for compatibility and report regeneration.

At the end of `assessmentRunner.py`, the `Assessment final artifacts` block prints both every PDF path and the exact `Assessment_Results_Data_<REFERENCE_ID>.json` path.

Example shape:

```json
{
  "schema_version": 4,
  "dataset_type": "secops-assessment-results-data",
  "reference_id": "SecOps_Agentic_Assessment_20260903_191426",
  "test_id": "microx-dashboard_20260903_191000",
  "report_id": "SecOps_Agentic_Assessment_20260903_191426",
  "assessment_results": {
    "summary": {},
    "coverage": {},
    "findings": [],
    "all_findings": [],
    "scanner_results": {}
  },
  "discovery": {},
  "diagnostics": {},
  "agentic_decisions": {
    "planner_source": "ai",
    "planner_rounds": 2,
    "planner_notes": [],
    "planner_audit": [],
    "reasoning_summaries": [],
    "breadth_review_reasoning": []
  },
  "ai_analysis": {"summary": {}, "findings": []},
  "report_artifacts": [
    {
      "job_id": "microx-dashboard/http-80",
      "report_id": "SecOps_Agentic_Assessment_20260903_191426",
      "pdf_path": "/.../SecOps_Agentic_Assessment_20260903_191426.pdf",
      "json_path": "/.../SecOps_Agentic_Assessment_20260903_191426.json",
      "html_path": "/.../SecOps_Agentic_Assessment_20260903_191426.html",
      "review_snapshot_path": "/.../SecOps_Agentic_Assessment_20260903_191426.review.json"
    }
  ],
  "reports_data": [
    {
      "report_id": "SecOps_Agentic_Assessment_20260903_191426",
      "assessment_results": {},
      "assessment_context": {},
      "discovery": {},
      "diagnostics": {},
      "agentic_decisions": {},
      "ai_analysis": {"summary": {}, "findings": []},
      "artifacts": {}
    }
  ]
}
```

## Common flags

- `--authorized` for any non-local target.
- `--authorized-origin https://api.example.org` adds one exact HTTP/HTTPS origin to the authorized discovery/scanner scope; repeat as needed.
- `--authorized-host-suffix example.org` adds the suffix itself and its subdomains to the authorized scope; repeat as needed. It never authorizes lookalike hosts such as `notexample.org`.
- `--allow-state-changes` explicitly enables the bounded checks that intentionally submit potentially persistent/state-changing requests.
- `--no-allow-state-changes` explicitly disables those checks, including on a local laboratory target.
- `--skip-browser` is an initializer-only opt-out. Without it, `initScript.py` treats a launchable Playwright Chromium as required and installs Linux browser dependencies automatically when needed.

The state-changing safety gate is centralized in `orchestratorShared.state_changing_tests_allowed()` and uses three states. An explicit `true`/`--allow-state-changes` always enables the bounded checks; an explicit `false`/`--no-allow-state-changes` always disables them. Only when the setting is omitted does the automatic default apply: targets whose hostname is exactly `127.0.0.1`, `localhost` or `::1` are treated as local laboratories and enable the bounded checks, while every other hostname or address, including private/LAN targets such as `dashboard-test` / `192.168.1.81`, keeps them disabled. A service-level `allow_state_changes` value overrides the execution-level value in an assessment JSON. Deterministic and Agentic execution both pass through the same Python gate, so the Agentic planner cannot bypass it.

The flag is not a universal no-write switch for every third-party scanner: in the current implementation it is passed specifically to the following active verification paths. SQLMap, Commix, ZAP, Nuclei and the other scanner wrappers do not read this flag; their own bounded/safety behavior remains separate.

Actual POST transmission is separate from discovery. Chromium discovery records non-GET request shapes but aborts them before transmission; later scanners may send POST requests only from discovered/derived request contracts. Arjun may probe a selected POST contract; ZAP may replay/seed and actively scan selected POST cases; Nuclei consumes POST contracts in DAST for `balanced`/`deep` (`fast` DAST remains disabled); SQLMap, Commix, Traversal and the external Dalfox process can test selected POST contracts. Browser sends its stored-XSS POST only when state changes are allowed. Workflow can still perform its bounded three-invalid-attempt authentication observation on a POST login form, while active CSRF, upload and CAPTCHA mutation checks require state changes to be allowed. IDOR-Forge and the Authorization differential remain GET-only. An authenticated logout POST is reserved for the final session-lifecycle check rather than ordinary fuzzing.

The flag currently affects these active verification paths:

- **Dalfox wrapper (`dalfoxServer.py`)**: the additional bounded reflection verifier may submit a POST only when state changes are allowed. GET-based checks and the external Dalfox scan are not globally disabled by this flag.
- **Browser verifier (`browserServer.py`)**: the stored-XSS check may submit a harmless marker and revisit the page to verify persistence only when state changes are allowed; DOM/reflected browser checks that do not require persistent submission can still run.
- **Workflow verifier (`workflowServer.py`)**: active POST validation for anti-CSRF enforcement, the bounded harmless file-upload marker check and the CAPTCHA-field-removal request require state changes to be allowed. Structural/form-only observations can still be reported without sending those verification requests. Setup/reset/delete routes remain excluded independently of this flag. Logout/signout/logoff is not a normal workflow fuzzing target: anonymous runs ignore it, while an authenticated logout contract is reserved for the final session-lifecycle verifier so invalidating the session cannot break earlier scanner actions.

