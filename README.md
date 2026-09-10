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
   `Assessment_Results_Data_<ID>.json` is the preferred redacted dataset for audit and later analysis. It embeds both per-tool coverage and the endpoint coverage matrix, together with scanner results, discovery and diagnostics. The runner prints
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

- `orchestratorAgentic.py`: Same discovery and validators as Deterministic. Broad baseline capabilities and JWT analysis when applicable are selected deterministically; a selectable AI planner chooses the complementary discovery-derived capability groups each round. Before the AI analysis, the same final deterministic Chromium stage retries unresolved XSS candidates when a compatible request contract is available. Supported aliases are `snap4city` (Snap4City `llama4-agentic-inference`),
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
- `configs/tourist-dashboard.json`: complete anonymous-only Snap4City tourism-dashboard configuration for the eight supplied public HTTPS views. Each view is an explicit service URL so every entry point is assessed, but no `credential_ref` is configured and the runner therefore never prompts for target credentials. The eight jobs are treated as entry points of one logical target: `reporting.aggregate_report=true` creates one primary aggregate report and `keep_job_reports=false` moves the per-entry artifacts under `reports/supporting/<assessment-id>/`. State-changing checks remain explicitly disabled.
- `configs/platform.example.json`: example of a larger multi-host scope that explicitly demonstrates both supported web-target forms: one service uses an absolute `service.url`, while other services use asset host/IP plus port/protocol/base path. It also shows two web identities and a non-web service kept only as inventory. Environment-variable credential references are preferred for reusable configurations.

The runner is an optional layer above the orchestrators, not a replacement for them. Existing direct commands such as
`python orchestratorDeterministic.py --target ...` and `python orchestratorAgentic.py --target ...` continue to work unchanged.

For configurations where several service URLs are entry points of one logical application, the optional top-level `reporting` block can request one assessment report across all jobs: `aggregate_report=true` merges the per-entry scanner results, coverage and discovery context after every job has finished. `keep_job_reports=false` keeps those per-entry artifacts only as supporting evidence under `reports/supporting/<assessment-id>/`, while the root `reports/` directory exposes one primary aggregate PDF/HTML/JSON/review snapshot. This is reporting aggregation only: every configured URL is still executed as its own bounded job, so no entry point loses scanner coverage. The aggregate report preserves finding provenance explicitly: each finding card shows the scanner tool(s), the affected URL, and the source entry point/job that produced the evidence; when semantically duplicate findings are merged, all contributing entry points and jobs remain attached to the merged finding.

The Agentic planner works at **profile/tool capability-group level**, not at individual-request level. Python first builds and validates all concrete discovery-derived actions, groups them by `(profile, tool)`, and exposes compact groups such as `anonymous/sqlmap`, `authenticated/browser` or `authenticated/zap` to the AI. Broad baseline groups (`ffuf`, `zap`, `nuclei`, `session`, `nikto`) and the cheap local `jwt` analysis are selected deterministically whenever they are eligible, so the model cannot accidentally omit baseline coverage. The AI therefore spends its decision budget on complementary specialist/workflow capabilities rather than on individual SQLMap URLs or on deciding whether basic broad coverage exists. Once a group is selected, Python expands it back into the exact request contracts using the same deterministic ranking, compatibility checks and adaptive specialist ceilings used by Deterministic. Expansion is round-robin across selected tool groups inside each profile so a large SQLMap/ZAP group cannot starve the other selected capabilities.

Anonymous and authenticated planning budgets are **independent**. Each active profile receives its own tool-group ceiling of 12/16/18 in fast/balanced/deep. Concrete execution is also per-profile and per-round, with a soft base of 48/144/288 actions and an adaptive emergency ceiling of 80/240/480. The upper ceiling is deliberately higher than the sum of the current per-tool maxima in each profile (65/214/463), so under the present registry it normally does not truncate valid per-tool selections merely because other tools used concrete slots. Python grows above the base only while already selected groups still contain distinct validated actions; the AI cannot change that ceiling. A concrete action is one scanner invocation/request contract, not one form field: the same SQLMap/Commix/etc. action can carry several parameters of that request. Distinct parameter, file, token and form-field name sets are part of the Agentic action identity, so contracts on the same route are not collapsed merely because their URL and method match. Any generated and validated actions left beyond a round ceiling remain eligible for the next round unless they become duplicate, unsupported or otherwise invalid.

The compact group catalog shown to the AI is capped at 32/40/48 groups overall and is populated fairly across profiles; with the current registry this is sufficient to expose all profile/tool groups even when anonymous and authenticated are both active. The optional breadth review is also profile-local: when the AI has selected too few **non-baseline** capabilities for one profile, it may add at most 3/6/8 groups in fast/balanced/deep while remaining inside that profile's 12/16/18 total group ceiling. Mandatory baseline groups do not make a profile look artificially complete for this sparse-plan test. The console and planner audit report the concrete pool, group pool, deterministic baseline groups, discretionary AI groups, breadth-review groups, validated concrete actions, base/adaptive concrete capacity and any selected-group actions deferred to a later round. Authorized sibling-origin broad scans do not duplicate work under both profile labels: because the primary cookie is never forwarded to a sibling origin, an identical no-cookie ZAP/Nuclei/Nikto scan is scheduled only under `anonymous` when that profile exists.

Coverage policies that are not inherently planner-specific are shared by both orchestrators and by every active profile: authorized-scope checks and cookie isolation, useful-page handling of HTTP 404/410, Chromium discovery limits, deterministic specialist ranking and adaptive specialist overflow, ZAP request seeding/active fallback, Nuclei input handling and final Chromium XSS verification. Final XSS verification now uses a per-profile base/adaptive ceiling of 8/12, 40/64 and 120/180 candidates in fast/balanced/deep, not one shared total; JWT analysis allows 16/64/192 unique tokens per profile. IDOR and Authorization also use the same adaptive specialist mechanism as the other request-oriented tools. Agentic-only group/action budgets are not copied into Deterministic because Deterministic has no planner-level global action quota: it already iterates each profile and executes the deterministic per-tool selections directly.

### Who decides request priority

There is no separate ranking service and the AI does not assign request importance. Ranking is implemented in `orchestratorShared.py`. Discovery first builds normalized `request_cases` from HTTP crawl links/forms, JavaScript endpoint extraction and Playwright network observations. Python then applies compatibility/safety filters and computes a different score for each specialist. `_tool_case_priority()` handles SQLMap, Dalfox, Commix, Traversal and IDOR; `_browser_case_priority()`, `_workflow_case_priority()` and `_authorization_case_priority()` handle their dedicated classes; Arjun uses its own endpoint score. The generic `_risk_terms()` component gives small weights to security-relevant words in the path and parameter names, while each specialist adds much larger class-specific weights.

For example, SQLMap receives higher priority for SQL/data/search routes, SQL-relevant parameter names, POST/JSON contracts, live Playwright-observed requests and successful 2xx/3xx browser responses. Dalfox rewards XSS/search/comment/message inputs and live browser traffic; Commix rewards command/exec routes and `cmd`/`host`-like parameters; Traversal rewards file/download/template/path inputs; IDOR accepts only GET cases with numeric object-reference parameters; Browser strongly rewards client-side source/sink evidence; Workflow prioritizes upload, authentication, CAPTCHA, CSRF/token and other stateful form shapes; Authorization prioritizes read-only identity/object/resource identifiers and privileged-resource routes. Incompatible methods, logout/destructive routes, static resources, oversized generated requests and observed 404/410 cases are rejected or heavily penalized before budget selection.

The resulting cases are sorted by score, then bounded by route-shape deduplication so changing only an input value cannot occupy the whole budget. The fixed specialist base is filled first. Only after that, `_select_with_adaptive_specialist_budget()` may admit high-value deferred cases whose score is at least 75% of the base cutoff and whose request contains evidence specific to that vulnerability class. Deterministic consumes these ranked selections directly. Agentic uses exactly the same ranked concrete pool, groups it by `(profile, tool)`, and lets the model choose complementary tool groups; the model does not change individual-request scores or decide which SQLMap/IDOR/etc. URL ranks above another.

### Profile breadth budgets

The profiles increase both discovery breadth and scanner execution ceilings. Limits are deliberately applied after relevance ranking and route-shape deduplication, so a larger budget is spent preferentially on distinct API/form/request surfaces rather than repeated calendar pages, archives, static assets or equivalent query-value variants. ZAP and Nuclei limits are request-contract/target ceilings, not HTTP request counts. Specialist rows written as `base / adaptive max` use bounded adaptive overflow: `orchestratorShared.py` deterministically ranks the request contracts for the vulnerability class, fills the fixed base first, and can admit deferred cases only when the base is saturated, the deferred score is at least 75% of the base cutoff score and strong class-relevant evidence is present. For discretionary Agentic capability groups the model may choose among the eligible actions, but it cannot change the scores, threshold, scope or adaptive ceiling; baseline broad/JWT groups are selected by Python.

| Coverage bound | fast | balanced | deep |
| --- | ---: | ---: | ---: |
| HTTP crawler pages per profile | 35 | 90 | 180 |
| Chromium navigations per profile | 16 | 60 | 120 |
| JavaScript assets inspected | 12 | 36 | 72 |
| ZAP request contracts considered | 10 | 32 | 60 |
| ZAP passive observations retained | 60 | 220 | 450 |
| ZAP generic GET active-fallback pages | 1 | 2 | 3 |
| Nuclei focused/static targets | 8 | 30 | 80 |
| Nuclei DAST request contracts | 0 | 18 | 48 |
| SQLMap cases (base / adaptive max) | 3 / 4 | 10 / 14 | 18 / 24 |
| Dalfox cases (base / adaptive max) | 3 / 4 | 10 / 14 | 18 / 24 |
| Commix cases (base / adaptive max) | 3 / 4 | 8 / 11 | 14 / 19 |
| Traversal cases (base / adaptive max) | 3 / 4 | 10 / 14 | 18 / 24 |
| Browser cases (base / adaptive max) | 3 / 4 | 10 / 14 | 20 / 26 |
| Workflow cases (base / adaptive max) | 3 / 4 | 10 / 14 | 20 / 26 |
| IDOR cases (base / adaptive max) | 3 / 4 | 10 / 14 | 20 / 28 |
| Authorization cases (base / adaptive max) | 4 / 5 | 12 / 16 | 24 / 32 |
| Arjun endpoints (base / adaptive max) | 3 / 4 | 10 / 14 | 18 / 24 |
| Interactsh actions | 1 | 2 | 3 |
| JWT tokens analyzed per profile | 16 | 64 | 192 |
| Final Chromium XSS candidates per profile (base / adaptive max) | 8 / 12 | 40 / 64 | 120 / 180 |
| Agentic tool-group catalog shown to AI | 32 | 40 | 48 |
| Agentic tool-group budget per profile | 12 | 16 | 18 |
| Agentic breadth-review additions per sparse profile | 3 | 6 | 8 |
| Agentic concrete actions per round/profile (base / adaptive max) | 48 / 80 | 144 / 240 | 288 / 480 |

Broad scanner timeout ceilings are `zap` 120/540/900s, `nuclei` 150/660/1200s, `nikto` 60/150/240s and `ffuf` 50/120/210s in fast/balanced/deep. Main specialist ceilings are SQLMap 75/180/300s, Dalfox 45/120/210s, Commix 50/120/180s, Traversal 35/75/120s, Browser 45/120/210s and Workflow 40/105/180s. Agentic planner ceilings are 900/1800/3000s with context windows 6144/8192/12288 and output budgets 800/1300/1800 tokens. These are upper bounds; completed tools return immediately.

JWT analysis is profile-local and bounded at 16/64/192 unique discovered tokens in fast/balanced/deep. The bound is intentionally high because the verifier only decodes and inspects token structure/claims locally and does not perform a network attack; different tokens can represent different issuers, audiences or roles. In Agentic, the JWT capability is baseline-selected whenever tokens exist, while raw token values remain local and are not exposed in the compact planner view.

Final Chromium XSS verification uses a separate adaptive stage shared by Deterministic and Agentic. It ranks only unresolved XSS candidates that have a compatible safe request contract, selects a per-profile base of 8/40/120 in fast/balanced/deep, and can extend to 12/64/180 when the base is saturated and deferred candidates remain at least 75% of the base cutoff score. Context match, an exact source parameter, client-side source/sink evidence, observed live browser traffic and existing scanner evidence raise this deterministic priority; the AI does not decide the overflow.

Before the base/adaptive cut is applied, request-oriented specialist selectors also bound value-only variants of the same `(origin + path + method + parameter-name set)` to 2/3/4 in fast/balanced/deep. For example, `/user?id=1`, `/user?id=2` and `/user?id=3` do not each consume unrelated specialist capacity just because the identifier value changes; distinct routes or distinct input-name sets remain independently eligible. This generic anti-saturation rule is shared by Deterministic and Agentic, including IDOR/Authorization.

Adaptive specialist overflow is deliberately separate from timeout growth: it allows more distinct high-value request contracts to be tested without extending the time allowance of each individual run. Strong evidence requires at least one vulnerability-class-specific signal, such as a relevant parameter or route, numeric/object identifiers for IDOR, identity/privileged-resource signals for Authorization, browser source/sink evidence, or workflow-specific form/token/upload/authentication metadata; POST/JSON shape, observed XHR/fetch traffic, a live 2xx/3xx browser response and high-value application/API routing strengthen that decision but do not grant overflow by themselves. Selected overflow cases are tagged in the deterministic selection summaries and in the Agentic action catalog for auditability.

Nuclei accepts up to 8/30/80 focused targets and 0/18/48 DAST request contracts. DAST stays disabled in `fast`; balanced/deep retain bounded fuzz aggression and global time/concurrency/rate controls. GET and POST contracts are both eligible when compatible with the template/input mode. ZAP considers up to 10/32/60 ranked request contracts for targeted/prioritized/full active modes.

### Discovery and scanner coverage

Discovery combines an HTTP crawler, JavaScript endpoint extraction and a bounded Playwright/Chromium queue. Exact same-origin URLs are always eligible; cross-origin URLs are admitted only when they match an explicit authorized origin or DNS suffix. There is no domain-name special case in the discovery code. The crawler uses profile budgets of 35/90/180 HTML pages, Chromium uses 16/60/120 navigations and JavaScript inspection uses 12/36/72 assets in fast/balanced/deep. A route signature based on origin, path and parameter names deduplicates value-only variants; per-origin quotas and generic relevance scoring favor APIs, forms, account/management/search/configuration surfaces and observed XHR/fetch traffic while deprioritizing static/vendor/chunk assets, archive/calendar/pagination-like routes and repeated low-value variants. HTTP 404 and 410 responses remain recorded as crawl diagnostics, but they do not consume the useful crawl-page quota and are not admitted to `html_urls`, so dead links cannot displace valid pages from Chromium/ZAP seeding. A separate attempt ceiling of 1.5x the useful-page budget (with the same bounded per-origin principle) prevents broken-link-heavy applications from causing unbounded extra requests. If HTML pages are available but Chromium records zero successful navigations, the console emits an explicit browser warning and prioritizes Playwright/runtime/navigation errors ahead of ordinary 404/410 messages. Deterministic discovery invokes the synchronous Playwright crawler in a worker thread, so it never runs the Playwright Sync API inside LangGraph's active `asyncio` loop. Agentic normally reaches discovery from a synchronous graph invocation, but it uses the shared `discover_target_sync_safe()` guard as well: if that code is ever invoked while an asyncio loop is already active, discovery is moved to a worker thread before the Playwright Sync API is entered. When Chromium reaches the configured navigation ceiling, the console reports the exact `used/budget` saturation so the next run can distinguish a real breadth limit from an ordinary completion.

GET and POST are first-class request contracts. HTML forms, query strings, JavaScript `fetch`/XHR/axios hints and browser-observed requests preserve method, body, content type and nested JSON parameter paths. Discovery itself remains non-mutating: Chromium aborts non-GET/HEAD/OPTIONS navigation requests before transmission and destructive routes are blocked, but the observed POST body can still become a contract for later compatible scanners. `allow_state_changes=false` therefore prevents unsafe discovery submissions without deleting POST coverage from the assessment. Cookies remain origin-confined: the primary target cookie is used only on its exact origin; explicitly authorized sibling origins are scanned without that cookie unless separately configured.

Observed sibling origins are not merely inventoried. Deterministic and Agentic can schedule ZAP, Nuclei and Nikto against a bounded set of discovered authorized sibling origins, with each sibling treated as its own scanner target and with primary-origin cookies stripped. Specialist request-case selectors also accept explicitly authorized scoped URLs where safe. Authentication/session probes intentionally remain exact-origin because session validity must not be inferred across hosts. The resulting contracts are shared by both orchestrators and drive ranking instead of inventing endpoints or parameters.

ZAP active mode is selected from the scan profile rather than from whether the current profile has a cookie: `fast` uses bounded targeted active scanning, `balanced` prioritized active scanning and `deep` the broader bounded mode; `diagnostic_only` remains passive. Scanner inventory is read through the Python API and retried through the raw ZAP JSON API; if metadata is unavailable, a curated set of known injection/path-traversal rule IDs is used as a compatibility fallback. Static assets are excluded from active-case selection. Parameterized request contracts remain the preferred insertion points. If semantic classification produces no compatible parameterized native plan, ZAP now performs a second bounded fallback on at most 1/2/3 safe GET application pages in fast/balanced/deep, with `recurse=False` and a small curated set of installed reflected-XSS, generic-SQLi, traversal and command-injection rules. This allows active coverage on a discovered sibling origin even when its current contracts have no query/body parameters, without turning the fallback into an unbounded recursive active spider. Distinct application endpoints are retained while equivalent request shapes are deduplicated. Planned, attempted, started and completed native cases are counted separately; ZAP reports complete active coverage only when all four counts agree with the planned case count. A planned case that cannot start, remains incomplete, or is not attempted therefore makes the bounded ZAP result partial. Rule IDs are enabled one by one and the wrapper records which IDs ZAP actually accepted. `partial/no_active_scan_rules_enabled` is therefore reserved for the case where neither a compatible parameterized plan nor a safe generic GET fallback with an installed curated rule can be constructed/enabled. Passive observations are retained up to 60/220/450 in fast/balanced/deep so a saturated observation cap is not mistaken for a complete inventory; security findings are kept separately from that observation ceiling.

Nuclei consumes discovered request contracts for DAST checks in both `balanced` and `deep`; the initializer now requires a DAST-capable current Nuclei runtime (minimum v3.11.1), verifies the official `nuclei-templates/dast` subtree and performs a template-load DAST runtime check before assessments start. The DAST phase explicitly selects that directory. Request-shaped Proxify JSONL is attempted first; if the engine rejects it, the same GET/POST request contracts are serialized to the other officially supported Proxify YAML MultiDoc input mode; only if both request-shaped modes fail does the wrapper fall back to a plain URL list for compatible GET cases. Every attempt and stderr excerpt remains in coverage diagnostics. Balanced uses `-fa medium` with `fuzz-param-frequency=100`; deep uses `-fa high` with `fuzz-param-frequency=1000`. `-fm single` is retained so one parameter is mutated at a time and evidence remains attributable; it is not a low payload-count cap. SQLMap/Dalfox/other parameter scanners rank API/data-oriented contracts, meaningful identifier/query parameters, method and observed JSON/network evidence ahead of navigation-only parameters. After the scanner phases, both orchestrators perform a candidate-driven Chromium verification pass using the per-profile adaptive limits described above: 8/40/120 base candidates in `fast`/`balanced`/`deep`, expandable to 12/64/180 when the deterministic overflow conditions are met. The final action is restricted to the exact source parameter and is matched to the closest request context using the other query parameters, so two candidates on the same path/parameter but with different application context are verified separately. The source context is preserved through reconciliation and final finding deduplication, so a browser outcome cannot be reassigned to or merged with a different XSS context on the same route. The Browser server exports the parameters actually exercised so reconciliation remains deterministic even if nested diagnostics are lost in transport. Confirmed execution upgrades the source candidate and sets high verification confidence. An unexecuted browser reflection keeps the candidate's potential severity unchanged but limits confidence to medium; a successful exact-parameter bounded non-reproduction likewise preserves severity while setting confidence to low. Severity therefore expresses potential impact if the weakness is real, while confidence expresses how strongly the collected evidence supports its existence. For findings without a browser ceiling, the validated AI confidence becomes the final finding confidence. The subsequent AI analysis may enrich wording and reassess severity from impact evidence, but it cannot raise confidence above the deterministic browser ceiling (MEDIUM for reflection without execution, LOW for bounded non-reproduction). Static assets such as CSS, JavaScript, images and fonts are excluded as Browser-XSS targets. Deterministic skips an exact URL/method/parameter case already exercised successfully by its earlier browser/workflow phase; Agentic performs the same bounded verification before AI analysis.

Nikto is reported as `partial` when its process exits successfully but neither request metrics nor a structured report are sufficient to verify scan coverage. Parsed console findings are preserved, but unverified coverage is never presented as a complete successful scan.

Terminal logging keeps long request URLs compact: when an URL exceeds the configured display threshold, only the endpoint plus parameter/query metadata are printed (for example parameter count and query length). The complete unmodified URL remains stored in scanner results, JSON artifacts and reports. The threshold can be adjusted with `SECOPS_TERMINAL_URL_MAX`.

The generated report also contains an **Endpoint coverage matrix**. It is built from the final discovery state, deterministic selector decisions and the scanner executions, not from finding counts. Each row identifies the assessment profile, HTTP method, discovered endpoint/request context, discovery source, concrete security tools that actually ran against that endpoint, a textual coverage status, a structured reason code and the explanatory reason when no completed test exists. Status values are `Tested`, `Discovered only`, `Skipped`, `Execution error`, `HTTP 404` and `HTTP 410`; no icon or informal symbol is used. Common omission codes include `DEFERRED_LOW_PRIORITY`, `BUDGET_LIMIT`, `NO_COMPATIBLE_PARAMETERS`, `UNSUPPORTED_METHOD`, `STATE_CHANGE_BLOCKED`, `OUT_OF_SCOPE`, `DUPLICATE_ROUTE_VARIANT`, `HTTP_404` and `HTTP_410`; Agentic additionally uses `PLANNER_DEFERRED` when a deterministic request candidate remained unexecuted after tool-group planning. A page merely visited by the crawler is therefore not labelled `Tested`. The section begins with a numeric summary that reports discovered request contexts, reachable/in-scope contexts, contexts tested by at least one concrete security-tool execution, discovery-only contexts, intentional skips, execution errors, HTTP 404/410 responses and tested coverage percentage. Anonymous and authenticated profiles are summarized independently, with an overall row when both are present. In aggregate multi-entry reports each row also retains the source job/entry point, so identical URLs reached from different configured entry points remain attributable. The complete matrix and the machine-readable `endpoint_coverage_summary` are serialized in report JSON and in the review snapshot and are embedded in `Assessment_Results_Data_<ID>.json`.

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

`configs/tourist-dashboard.json` contains the eight supplied public Snap4City dashboard-view URLs as eight enabled HTTPS service jobs. The configuration is intentionally **anonymous-only**: the services do not define a `credential_ref`, so `assessmentRunner.py` does not request `TOURIST_DASHBOARD_USERNAME`, `TOURIST_DASHBOARD_PASSWORD` or a target cookie, and no Snap4City/Keycloak target login is attempted. `auth_only=false` and `allow_state_changes=false` remain explicit for all eight entry points.

The eight service jobs are retained because each supplied URL must be exercised even when the views are not mutually linked during discovery. They nevertheless represent one logical assessment target. The top-level reporting block therefore uses:

```json
"reporting": {
  "aggregate_report": true,
  "keep_job_reports": false
}
```

After all jobs finish, the runner merges scanner results, coverage and per-entry discovery context into one primary aggregate PDF/HTML/JSON/review snapshot. The individual per-entry artifacts are moved under `reports/supporting/<assessment-id>/` as technical evidence; they do not replace the single aggregate assessment report. Reporting aggregation does not merge execution budgets: each entry URL is still scanned as its own bounded job.

The recommended validation command is:

```powershell
python .\assessmentRunner.py --config .\configs\tourist-dashboard.json --orchestrator deterministic --mode balanced --dry-run --authorized
```
