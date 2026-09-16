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
   Playwright/Chromium and the selected AI backends. On Debian it also installs the native WeasyPrint host libraries
   `libpango-1.0-0`, `libpangoft2-1.0-0` and `libharfbuzz-subset0`, so PDF rendering does not fail only because the Python
   package is present while Pango/Harfbuzz are missing. With `--with-lab` it also prepares the local DVWA lab. At the end it
   prints ready-to-copy commands.

2. **Run the first baseline with Deterministic in `balanced` mode on DVWA.** The execution order is fixed, so this is the
   easiest run to inspect and reproduce. After the baseline works, use Agentic in `balanced` mode when you want adaptive
   action selection and AI evidence analysis.

3. **Choose how to describe the new target.**
   - Use `assessmentRunner.py --target <URL>` for a single starting URL when the run is anonymous or when you already have
     a valid cookie that can be passed with `--cookies`.
   - Use `assessmentRunner.py --config <FILE>` when you only have the target username/password and the session must be
     created through browser/OIDC login. Direct `--target` mode does not accept target username/password and does not run
     the provider-neutral `browser_oidc` login workflow.
   - Also use `--config` when the authorized scope contains several hosts, ports, base paths, identities or explicit entry
     URLs that must all be tested.

4. **Do not list every internal URL unless the scope requires specific entry URLs.** For a normal application, give the
   root URL or the relevant base path and let discovery expand the authorized surface. Exact same-origin URLs are always
   in scope; additional origins are followed when explicitly authorized and, when `authorization.allow_same_host_ports=true`, HTTP/HTTPS services on other ports of the same exact hostname are also admissible; when `authorization.discover_same_host_services=true`, discovery proactively probes the exact authorized host using runtime service databases plus a bounded generic TCP-space sweep and adds responsive web services as normal seeds. Discovery follows HTML links/forms, inline/external JavaScript literal navigation,
   rendered DOM navigation attributes, safe menu/dropdown expansion and dynamic `document`, `xhr` and `fetch` requests observed
   by Chromium. Values carried by routing parameters such as `redirect`, `linkUrl`, `page` or `resource` are preserved when they
   identify different internal modules and safe nested destinations are added back to the discovery queue. If several supplied URLs
   must each be guaranteed as starting points, declare them as separate services in the configuration. External validation/reference
   datasets are never runtime inputs to discovery, planning, target configuration or scanner selection; any comparison against them is a post-run evaluation step.

5. **Validate a new configuration before scanning it.**

   ```powershell
   python .\assessmentRunner.py --config .\configs\platform.example.json --orchestrator deterministic --mode balanced --dry-run --authorized
   ```

   `--dry-run` validates and expands the configuration without starting scanners. The example above adds `--authorized` only because `platform.example.json` deliberately ships with `authorization.confirmed=false`; before a real assessment, replace the placeholder authorization/reference and confirm the real scope instead of relying on the example override. Dry-run does not require the MCP/scanner runtime or a locally installed Agentic model, and it does not resolve reusable secrets; those checks are deferred to a real execution.

6. **Use `balanced` unless you need a different trade-off.** `fast` is intended for smoke tests and short diagnostics.
   `deep` increases discovery and scanner budgets, so use it after the target, authentication and scope have been checked.

7. **Watch the terminal during the assessment.** Deterministic reports the fixed pipeline stages. Agentic also reports
   planner rounds and selected actions. Execution status and coverage remain separate from security findings.

### Active scope and request-rate policy

Active testing is based on explicit HTTP authorization, not DNS-parent relationships or textual hostname prefixes. The primary target origin is always in scope and additional exact origins can be authorized with `authorization.allowed_origins` or repeated `--authorized-origin`. An origin is scheme + hostname + effective port, but a site-level authorization can deliberately cover additional HTTP/HTTPS services on the **same exact hostname**. `authorization.allow_same_host_ports=true` enables that exact-host multi-port scope; it never authorizes a sibling/prefix/suffix hostname. When `authorization.discover_same_host_services=true` is also set, discovery performs a bounded proactive service-discovery pass on that exact hostname. Candidate ports come first from standard runtime service databases (for example the local OS/Nmap service database when present). Any remaining profile budget is filled by a deterministic **stratified walk across the whole TCP range 1-65535** rather than by simply counting upward from port 1: each next probe bisects a still-uncovered interval, so low, middle and high port ranges are represented early. Candidate generation is application-agnostic and never consumes external validation/reference data. A port is promoted to the web surface only after an HTTP response is actually recognized; HTTPS classification uses a bounded TLS handshake and HTTP probe, while an open TCP port that is not confirmed as HTTP/HTTPS remains **web-unconfirmed inventory** and is not falsely labelled either non-web or web-tested. Responsive HTTP/HTTPS roots become priority discovery seeds and can reach ZAP/Nuclei/specialist selection. HTTP↔HTTPS changes are allowed only on the same exact authorized hostname under this site-level policy. Credential propagation is stricter than authorization: a raw Cookie header is never copied to another hostname and is only speculatively reused where normal cookie scheme/domain/path policy permits it and the session probe validates it. For an absolute URL with no written port, HTTP implies 80 and HTTPS implies 443. Legacy DNS-suffix scope widening remains rejected.

Concrete sibling examples with `allow_same_host_ports=true`:

| Discovered URL | Result | Reason |
| --- | --- | --- |
| `https://app.example.org:8443/app` | **Accepted** | Same exact authorized hostname; the site-level multi-port rule allows HTTP/HTTPS services on other ports. |
| `https://api.example.org/app` | **Accepted only if explicitly authorized** | It is a sibling hostname, so the multi-port flag alone does not authorize it. An exact `allowed_origins`/service entry does. |
| `https://api.example.org:8443/app` | **Accepted only if `api.example.org` is explicitly authorized first** | A sibling hostname is never inferred; once that exact hostname is authorized, its HTTP/HTTPS ports may be discovered under the same rule. |
| `http://app.example.org:8080/app` | **Accepted** | Scheme and port may differ because the site-level rule is tied to the same exact hostname and HTTP/HTTPS protocols. |
| `https://app.example.org.evil.test/app` | **Rejected** | This is a different hostname under `evil.test`, not part of `app.example.org`. |

Login and SSO endpoints are not excluded by name. `/login.php`, `/ssoLogin.php`, `/auth/...` or any other authentication route remains testable when it belongs to an authorized origin. During browser authentication the page may temporarily visit a different origin; that does not authorize scanners against the external identity-provider origin. Redirects followed by sensitive Python helper/probe requests are restricted to same-origin transitions. The same guard is used by session probes, runtime target preparation, logout verification and lightweight injection pre-verifiers, so helper traffic cannot widen scope merely because an endpoint returns an external `Location`. When a session probe is stopped by that guard, or exhausts the bounded same-origin redirect limit, authentication is reported as inconclusive rather than treating the remaining 3xx response as proof of an authenticated session. Traversal/LFI pre-verification uses the same redirect guard as the other request-level verifiers. External scanner wrappers also disable autonomous redirect following where the tool exposes such a control: Arjun, Nuclei, SQLMap and Commix are invoked with redirect following disabled/ignored, ZAP direct seeding does not follow redirects, its context regex is anchored to the exact scheme/host/effective-port origin, targeted active scans use in-scope-only mode, and ZAP itself is switched to Protected mode as a second barrier; Nikto is launched without its global follow-redirects option. This does **not** discard the normal application redirect destinations found by project-controlled discovery: HTTP/Chromium discovery follows bounded redirects while every destination remains inside the configured authorization policy. Same-origin hops are followed normally; an exact additional origin is followed when it was explicitly authorized before the run; and, when `allow_same_host_ports=true`, a different port is also allowed only for the same exact authorized hostname over HTTP/HTTPS. The final in-scope URL is recorded and fed back into broad/specialist selection. Nuclei therefore receives both the original in-scope target and the bounded discovered in-scope URL set; Nikto may start directly from the final URL reached by its own project-controlled same-origin baseline probe. The scanner process itself is still prevented from making an autonomous cross-origin hop. This is intentionally conservative: scanner-internal/template-specific behavior that *itself* requires following a redirect is not guaranteed to be reproduced by central discovery. Nuclei's documented `-fhr` means "follow redirects on the same host". That is not used as the authorization boundary because the flag description does not by itself guarantee the same rule as this project's allow-list: Nuclei documents protocol redirects separately, and its template variables distinguish `Host` from `Hostname` (where `Hostname` includes the port). The assessment therefore evaluates every redirect hop against the configured authorization policy (explicit origins plus the optional exact-host HTTP/HTTPS multi-port rule) instead of assuming that Nuclei's shorter "same host" wording is equivalent. The enlarged selector/discovery budgets remain bounded by profile; this residual redirect-dependent scanner behavior is reported/documented as a containment trade-off rather than claimed as zero coverage loss. FFUF is not launched with redirect-following enabled; the Dalfox wrapper does not enable its follow-redirects option. Discovery prints a single `[SCOPE]` notice when it observes out-of-scope URLs/origins, explicitly stating that they were not queued for active testing. Chromium separately reports ordinary external subresource traffic needed for rendering/authentication and the number of blocked top-level navigations toward unauthorized origins; those dependency requests are never converted into active scanner cases. The Browser XSS/workflow verifier applies the same top-level rule: third-party subresources required to render an authorized page may load, but a document/navigation redirect is followed only when its destination is admitted by the configured authorization policy (explicit origin, or another HTTP/HTTPS port of the same exact hostname when `allow_same_host_ports=true`); an unauthorized destination is aborted and recorded rather than followed as a new verification target. Service Workers are deliberately not disabled only to make this guard stricter: doing so can change PWA behavior and reduce verification coverage. The browser route guard therefore protects controllable top-level/document navigations, while external dependency traffic (including browser-managed behavior) remains observational traffic and is never promoted into an active scanner case.

Any external ground-truth or reference dataset used to evaluate discovery is kept **outside assessment runtime**. It is not injected into configuration, discovery, planning or scanner selection; post-run comparison may use it to measure what the platform discovered autonomously.

The unified MCP runtime is also version-bound at runtime: `secopsServer.py` exposes a source fingerprint frozen at process startup, and the orchestrator validates it before reusing an already-listening loopback endpoint. A stale SecOps server from another checkout/version, or an unrelated process on the configured port, is rejected with a clear preflight/runtime error instead of silently executing old wrappers. This check is transport-level and works on Linux, macOS and Windows without relying on platform-specific PID/port ownership APIs.

The containment layers are deliberately different by tool rather than blindly duplicated. The shared orchestrator gate decides which origins/request contracts are authorized before any specialist is called, including the optional same-host multi-port rule when enabled. Project discovery owns bounded authorized redirect resolution. Sensitive Python probes/custom checks use the shared same-origin redirect helper. Arjun/Nuclei/SQLMap/Commix disable autonomous redirect following, FFUF/Dalfox do not enable it, and Nikto omits global follow; they operate on URLs already admitted by discovery. `--disable-redirects` really does prevent Arjun itself from following **all** redirects, including internal ones. To preserve the ordinary GET case, the wrapper first resolves a short same-host redirect chain with auto-follow disabled, checking every hop and allowing a discovered alternate port only when the configured multi-port policy permits it. If a redirect points to a different hostname that is separately authorized, the wrapper deliberately does **not** carry the current raw cookie across that hop; central discovery handles that destination separately with the session applicable to that origin. Non-GET cases are not replayed merely to resolve redirects, avoiding duplicate stateful requests. A redirect generated only by one of Arjun's own parameter probes is still not followed inside Arjun, so this remains a documented containment-versus-coverage trade-off rather than a claim of perfectly equivalent redirect behavior. ZAP needs additional internal barriers because it maintains its own site tree/spider/active scanner: exact-origin context, in-scope-only active scans, Protected mode and no-follow direct seeding all enforce the *same* scope policy at different ZAP layers. These barriers do not lower the configured endpoint/request-contract/template selector budgets; they prevent a selected in-scope case from creating an unapproved destination at runtime.

`execution.request_rate` is the operator-facing traffic parameter. If it is omitted, the runner uses **10 requests/second**. Integer values from **1 through 50 requests/second** are accepted; a value above 50, below 1, non-numeric or non-finite is rejected and falls back to the default 10 rather than being silently clamped. The runner prints the effective policy in the console, and a fallback is also recorded in Results Data and in the report Run configuration. `SECOPS_MAX_REQUEST_RATE` is the normalized child-process environment value derived from this configuration; it is not the preferred user configuration surface. **The rate policy is per assessment process, not a VM-wide/global token bucket.** Inside one Deterministic or Agentic assessment, active specialist tool calls execute strictly one after another, so SQLMap, Nuclei, Dalfox, FFUF and the other specialist processes of that assessment do not overlap. If the operator intentionally starts two independent `assessmentRunner.py` processes, each process has its own pacer and its own `execution.request_rate`; their aggregate traffic can therefore be higher than either configured value. The project does not silently coordinate or divide the rate between unrelated assessment processes. When concurrent assessments are desired, the operator should lower the rate in each configuration according to the target/environment capacity. Individual tools can still have bounded internal concurrency (for example Nuclei runs with `-c 2`, `-bs 1`, `-pc 1` in all three profiles, while ZAP uses one active-scan thread per host), and browser subresources are not a packet-level global token bucket, so the configured number is a project traffic-control parameter rather than a mathematical guarantee for every TCP request. Nuclei, FFUF and Arjun receive explicit rate caps; SQLMap and Commix receive delays; ZAP is configured with bounded internal active-scan concurrency/delay; the built-in HTTP crawler and top-level Chromium navigations are paced as well. The Browser XSS/workflow verifier also receives the configured rate and paces document navigations (including same-origin redirect hops); Chromium-managed CSS/JS/image/XHR subresources are not represented as a packet-level token bucket. Changing the rate changes timing, not the endpoint/request-contract/template selection budgets and therefore does not reduce configured coverage.

8. **Read the final artifacts from `reports/`.** PDF and HTML are the human-readable reports. Their Discovery summary now also exposes the HTTP/Chromium base, adaptive overflow and maximum budgets, queued candidates, script usage, application-family breadth and aggregate runtime sibling-authentication outcomes for each profile. The report JSON contains the
   technical report data. `.review.json` is the redacted rerender snapshot. When `assessmentRunner.py` is used,
   `Assessment_Results_Data_<ID>.json` is the preferred redacted dataset for audit and later analysis. It embeds both per-tool coverage and the endpoint coverage matrix, together with scanner results, discovery and diagnostics. The runner prints
   the exact paths under `Assessment final artifacts`.

### Authentication: direct target or configuration?

This distinction is important:

- `--target` mode accepts `--cookies`. It can therefore run anonymously or reuse an authenticated session that already exists.
- `--target` mode has no target `--username` or `--password` option. It does not create an OIDC session from account credentials.
- If you only have the username/password of the assessed application, use a JSON configuration with a credential such as
  `kind: "browser_oidc"`. `assessmentRunner.py` performs the browser login and passes the resulting cookies to the existing orchestrators.
- When an OIDC credential has `optional: true`, missing credentials or a failed login fall back to the anonymous profile.
  `--auth-only` is different: it requires a valid authenticated session, so the job is blocked if login cannot provide one.
- Browser/OIDC authentication does not widen the attack scope. A login page or SSO wrapper on an already authorized origin remains a normal application surface and may be tested. If the browser temporarily crosses to a different origin to complete authentication, that external origin is used only for the browser login flow unless it is admitted by the configured authorization policy; the multi-port option applies only to the same exact hostname/scheme and never authorizes an external IdP hostname. A raw Cookie header is never copied to another hostname. When `authorization.allow_same_host_ports=true`, the same header is tried first on another discovered port of the exact same hostname and scheme because HTTP cookies are not port-scoped. The order is **existing cookie → validation/session probe → saved browser/OIDC state → original username/password if the login flow requests them**. A conclusively rejected speculative raw cookie is remembered per cookie+destination origin so later scanners do not keep retrying the same invalid session; a repaired browser/origin-specific session is used instead. No second child-console credential prompt is opened.

### What should I normally choose?

| Need | Recommended choice |
| --- | --- |
| First run / reproducible baseline | `assessmentRunner.py` or `orchestratorDeterministic.py`, `--mode balanced` |
| Single target, anonymous or cookie already available | `assessmentRunner.py --target <URL>` |
| Only target username/password available | `assessmentRunner.py --config <FILE>` with a supported login credential such as `browser_oidc` |
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
bypass this shared Python gate. The shared request-contract policy is enforced before broad ZAP/Nuclei replay and before
request-level specialist ranking/execution: read-only GET and POST query/search/API contracts remain eligible, while destructive
URLs, high-confidence mutating POST routes/actions, credential-changing forms and file uploads are withheld. Filtering before
specialist ranking also means a blocked mutating request cannot consume a bounded scanner slot that a later safe contract could use. Individual
wrappers retain their own additional safety limits, so the flag is an absolute project policy without reducing all POST
coverage to zero.

## Credential and token terminology (legend)

This document uses the word "token" for two unrelated access-credential concepts. Every later
mention of "token" in this file is tagged with one of the two markers below, so it is always clear
which access is meant:

- **(1) AI-token** — Snap4City access/refresh tokens that authenticate to the remote LLM API (the AI
  backend used by the Agentic planner). Managed by the Snap4City `TokenManager`, cached in
  `token_stored.json`, and completely unrelated to any assessed target. Token acquisition/refresh POSTs use bounded timeouts and do not automatically follow HTTP redirects, so provider credentials are not forwarded to an unexpected redirect destination.
- **(2) Target-token** — Target cookies, target JWTs and anti-CSRF tokens (for example `--cookies`,
  `--jwt-token`, or the `dashboard_session` login) belonging to the application being assessed. Never
  Snap4City credentials, never shared with the AI provider.

## How the core files work

### Initialization

- `initScript.py`: Installs/verifies dependencies, scanners, Docker images and Playwright. On Debian the host prerequisite set includes the native WeasyPrint runtime libraries `libpango-1.0-0`, `libpangoft2-1.0-0` and `libharfbuzz-subset0`; these reporting libraries are installed even when scanner installation is skipped. Chromium is a verified default dependency: unless `--skip-browser` is explicitly used, initialization installs the Playwright Chromium build (and Linux host dependencies) and fails if a headless launch cannot be completed. With `--with-lab` it sets up
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
  Service discovery is web-scope driven but can be proactive for a site-level exact-host authorization: `discover_same_host_services=true` probes the already-authorized hostname using standard runtime service databases plus a bounded stratified walk over the generic TCP space, promotes responsive HTTP/HTTPS roots into discovery, and records open non-web TCP ports as inventory only. `fast` samples 4,096 positions, `balanced` samples 32,768 positions spread over the full 1-65535 range, and `deep` can examine the complete TCP port space. The hostname is resolved once before the sweep and every real socket attempt is paced by the assessment request-rate policy. External validation/reference datasets are not runtime inputs.
- `assessmentRunner.py`: accepts either a platform JSON configuration or a direct `--target`/`--cookies` invocation, then delegates
  each HTTP/HTTPS job to the existing Deterministic or Agentic orchestrator. Direct mode consumes an already available cookie session;
  target username/password login is configuration-driven. Non-web protocols may be inventoried but are explicitly recorded as unsupported
  by the current web-assessment orchestrators rather than being silently treated as tested.
- `configs/dvwa.example.json`: non-secret placeholder that shows the exact DVWA configuration structure without containing a usable session.
- `configs/dvwa.generated.json`: generated by `initScript.py --with-lab` from the fresh DVWA session and immediately usable.
- `configs/platform.example.json`: generic multi-asset example. Each enabled HTTP/HTTPS service is an explicit target job and the example sets `allow_same_host_ports=true` to demonstrate site-level port authorization for already-authorized exact hostnames. Different hostnames are never inferred from DNS suffixes or discovered links. `browser_oidc` credentials can be attached to a service without making credentials or authorization synonymous. A secondary cookie identity and aggregate reporting are also illustrated.
### Who decides request priority

There is no separate ranking service and the AI does not assign request importance. Ranking is implemented in `orchestratorShared.py`. Discovery first builds normalized `request_cases` from HTTP crawl links/forms, JavaScript endpoint extraction and Playwright network observations. Python then applies compatibility/safety filters and computes a different score for each specialist. `_tool_case_priority()` handles SQLMap, Dalfox, Commix, Traversal and IDOR; `_browser_case_priority()`, `_workflow_case_priority()` and `_authorization_case_priority()` handle their dedicated classes; Arjun uses its own endpoint score. The generic `_risk_terms()` component gives small weights to security-relevant words in the path and parameter names, while each specialist adds much larger class-specific weights.

For example, SQLMap receives higher priority for SQL/data/search routes, SQL-relevant parameter names, POST/JSON contracts, live Playwright-observed requests and successful 2xx/3xx browser responses. Dalfox rewards XSS/search/comment/message inputs and live browser traffic; Commix rewards command/exec routes and `cmd`/`host`-like parameters; Traversal rewards file/download/template/path inputs; IDOR accepts read-only GET cases with mutable object-reference parameters (numeric, UUID, long hex or digit-bearing opaque identifiers) while excluding navigation/OIDC controls; Browser strongly rewards client-side source/sink evidence; Workflow prioritizes upload, authentication, CAPTCHA, CSRF/token and other stateful form shapes; Authorization prioritizes read-only identity/object/resource identifiers and privileged-resource routes. Incompatible methods, logout/destructive routes, static resources, oversized generated requests and observed 404/410 cases are rejected before specialist budget selection. When state changes are disabled, `DELETE`, `PUT` and `PATCH` contracts are treated as mutating by method and POST bodies are inspected recursively so destructive actions nested inside JSON cannot bypass the central gate.

Discovery breadth is adaptive before specialist selection. The HTTP crawler fills base/adaptive maxima of **120/220, 600/1100 and 1200/2200** useful pages in fast/balanced/deep. Chromium uses **72/200, 400/1200 and 800/2400** navigations, expands up to **16/64/112** safe menu/dropdown controls per rendered page across **3/6/9** rescanning passes, and successfully inspects up to **128/640/1200** JavaScript assets. Route-value retention is **8/20/32** variants per discovery shape. Queue ranking still deduplicates equivalent route shapes, penalizes static/vendor noise and gives underrepresented application families a generic breadth bonus; the larger budgets therefore go to distinct application surfaces rather than repeated values. When proactive same-host service discovery is enabled, every responsive HTTP/HTTPS service root on the exact authorized hostname becomes a high-priority seed before these budgets are spent. Confirmed 404/410 responses remain diagnostic and do not create specialist request contracts.

The resulting cases are sorted by score, then bounded by tool-specific route-shape deduplication so changing only an ordinary input value cannot occupy the whole budget. Discovery itself retains up to 6/12/16 value variants per route in fast/balanced/deep; expensive request-level specialist execution uses the narrower generic cap 2/4/6. Absolute HTTP(S) routing destinations retain their host/path semantics so distinct application destinations are not collapsed merely because the outer route is identical. SQLMap, Dalfox, Commix, IDOR, Browser, Workflow and Authorization use structural route identities based on origin/path/parameter names; Traversal alone preserves semantic routing/resource values because `redirect=file.php`, `page=module.php` or `template=...` can select a genuinely different server-side resource. Traversal execution additionally requires a parameter-level LFI/path signal: a file/path/routing parameter or an observed local-resource/traversal value. Generic `id`, role or sorting parameters no longer consume the LFI reserve merely because their route has a high generic risk score. Obvious static cache/version variants remain discovery evidence (JavaScript is still parsed for endpoint hints) but do not consume request-level injection budgets; Dalfox also excludes non-HTML CSS/font/image/media targets while keeping JavaScript with real functional parameters eligible. One-shot OAuth/OIDC protocol instances carrying transient values such as `state`, `nonce`, `code` or session identifiers are compacted so repeated values do not consume bounded budgets. Stable login/SSO routes on an authorized origin remain normal application surfaces and are not excluded merely because they implement authentication. The fixed specialist base is filled first. Only after that, `_select_with_adaptive_specialist_budget()` may admit high-value deferred cases whose score is at least 75% of the base cutoff and whose request contains evidence specific to that vulnerability class. SQLMap, Dalfox and Commix also receive a separate bounded **generic live-input breadth reserve** after class-specific ranking: a request can enter this reserve only when discovery has concrete live evidence (for example a successful browser response, POST/JSON contract or observed XHR/fetch) and it is not static, destructive, logout, oversized generated traffic or identity-protocol plumbing. This avoids treating an unfamiliar application parameter name as automatically untestable without spraying injection payloads over navigation-only controls. Deterministic consumes these ranked selections directly. Agentic receives the same deterministic candidate pool; every applicable broad and specialist capability gets a Python-selected base group, while the AI chooses which adaptive/overflow groups deserve additional depth. The model never changes individual-request scores, authorization, state-change policy or tool compatibility.

### Completion-driven attack coverage

There is deliberately **no configured coverage percentage** or external acceptance target in runtime configuration. Evaluation criteria are kept outside discovery and planning. Both orchestrators first run the broad scanners and the deeper vulnerability-class specialists. Only afterward they compute structural request contexts (`method + route/routing semantics + parameter names`) that already received completion evidence from a concrete test and run a final completion-driven **safe surface sweep** over still-untested reachable, non-destructive contexts. This prevents one POST body shape from suppressing a different POST body shape on the same URL while still collapsing harmless value-only duplicates. The sweep continues until the eligible queue is exhausted or the generic profile cap/deadline is reached; it does not stop because an arbitrary percentage was reached. Redirects are disabled inside this batch, normal scope/cookie/state-change rules are reused, and only requests that actually receive an HTTP response count as tested. Its foreign-Origin/CORS and response-classification probe improves active breadth but never substitutes for SQLMap, Dalfox, Commix, Traversal, ZAP, Nuclei, Authorization, Browser or Workflow.

The report therefore exposes **two coverage numbers**: (1) contexts tested by any active check, including the safe-surface sweep, and (2) **broad/specialist tested coverage**, which excludes contexts reached only by that final baseline. This makes it impossible to claim a high attack-coverage percentage merely by replaying many shallow requests.

### Profile breadth budgets

The profiles increase discovery breadth **and** deep scanner execution. All ceilings are generic and applied only after scope/safety filtering, application-family fairness and semantic/structural deduplication; none contains application names, target endpoint lists or externally supplied port data. `balanced` is now sized for a real large web application rather than a small top-N sample. ZAP/Nuclei work is batched inside one scanner process where possible, while request-level specialists remain sequential to preserve target safety and session integrity.

| Coverage bound | fast | balanced | deep |
| --- | ---: | ---: | ---: |
| HTTP crawler pages per profile (base / adaptive max) | 120 / 220 | 600 / 1100 | 1200 / 2200 |
| Chromium navigations per profile (base / adaptive max) | 72 / 200 | 400 / 1200 | 800 / 2400 |
| Safe menu controls per rendered page / DOM passes | 16 / 3 | 64 / 6 | 112 / 9 |
| JavaScript assets successfully inspected | 128 | 640 | 1200 |
| Discovery route-value variants per shape | 8 | 20 | 32 |
| Same-host TCP candidate cap when proactive discovery is enabled | 4096 | 32768 | 65535 |
| ZAP ranked/proxy-verified request contracts | 80 | 320 | 640 |
| ZAP native active request contexts | 32 | 96 | 192 |
| ZAP passive observations retained | 180 | 800 | 1400 |
| ZAP generic GET fallback pages | 1 | 2 | 3 |
| Nuclei focused/static targets | 128 | 1024 | 2048 |
| Nuclei DAST request contracts | 96 | 1200 | 3000 |
| Nuclei DAST batch size | 48 | 160 | 240 |
| SQLMap cases (base / adaptive / generic-live reserve) | 6 / +2 / +4 | 72 / +48 / +96 | 128 / +96 / +160 |
| Dalfox cases (base / adaptive / generic-live reserve) | 8 / +3 / +6 | 96 / +64 / +128 | 160 / +112 / +192 |
| Commix cases (base / adaptive / generic-live reserve) | 6 / +2 / +2 | 64 / +48 / +64 | 112 / +96 / +96 |
| Traversal base / adaptive; routing-resource reserve | 8 / +4; 32 | 96 / +64; 192 | 160 / +112; 320 |
| IDOR base / adaptive | 6 / +2 | 64 / +48 | 112 / +96 |
| Authorization base / adaptive | 10 / +4 | 128 / +72 | 192 / +128 |
| Browser verification base / adaptive | 10 / +4 | 128 / +72 | 192 / +128 |
| Workflow base / adaptive | 8 / +3 | 96 / +56 | 160 / +112 |
| Arjun endpoints base / adaptive | 12 / +4 | 96 / +64 | 160 / +112 |
| Interactsh OAST candidates | 2 | 6 | 10 |
| Final Chromium XSS base / adaptive max | 12 / 20 | 96 / 160 | 200 / 320 |
| Safe-surface sweep contexts per profile | 800 | 6000 | 15000 |
| ZAP primary tool deadline (s) | 120 | 2400 | 4800 |
| Nuclei primary tool deadline (s) | 240 | 3600 | 7200 |
| Agentic tool-group catalog shown to AI | 64 | 96 | 128 |
| Agentic tool-group budget per profile | 20 | 30 | 40 |
| Agentic breadth-review additions per sparse profile | +5 | +10 | +14 |
| Agentic concrete normal floor, TOTAL actions/round | 120 | 420 | 760 |
| Agentic ordinary R1 / R2 ceiling, TOTAL actions/round | 144 / 160 | 516 / 580 | 920 / 1016 |
| Agentic configured ordinary per-round maximum, TOTAL | 184 | 644 | 1144 |
| Agentic absolute hard cap, TOTAL actions/round | 184 | **800** | 1144 |

Concrete Agentic actions use **one shared round budget across all active profiles**, not one budget per profile. Tool-group planning remains per profile (20/30/40 groups), but the concrete executor distributes the shared cap fairly across profiles and then across capabilities; unused capacity from a small profile flows to the others. In `balanced`, 420 is the normal total floor, R1/R2 ordinary ceilings are 516/580 and the configured ordinary maximum is 644. When deterministic baseline work still requires more breadth, Python may raise the resolved base dynamically, but an independent final guard enforces an **absolute 800-action total hard cap for the whole round**, including anonymous and authenticated profiles together. For example, 1000+1000 eligible actions resolve at the cap to 400+400; 100+1000 can resolve to 100+700. With two rounds, the ordinary arithmetic ceilings remain 304/1096/1936 in fast/balanced/deep; the balanced emergency/dynamic absolute ceiling is 1600 across two rounds, never more than 800 in either round. These are ceilings, not quotas: only discovery-supported, in-scope, non-equivalent actions are executed. Broad/JWT and every applicable specialist base group are selected deterministically by Python so an AI plan cannot omit an entire SQLi/XSS/command-injection/traversal/authorization/browser/workflow class. AI reasoning is used mainly to choose adaptive/overflow capability groups and later-round follow-up depth from real scanner evidence.

Traversal keeps distinct routing/file values only when they plausibly select different local resources. The other specialists use structural route identities so harmless value-only variants do not multiply work. The generic live-input reserve applies only to SQLMap/Dalfox/Commix and is deliberately separate from adaptive high-value overflow: it broadens real attack execution on unfamiliar applications without replacing vulnerability-class prioritization. IDOR uses the same family-fair/route-shape strategy but can now mutate numeric, UUID, hexadecimal and digit-bearing opaque query references instead of silently requiring decimal integers. Wrapper timeout ceilings were audited against the profile table: Arjun, FFUF, Traversal and Nuclei no longer clip the larger balanced/deep timeout supplied by the orchestrator.

Nuclei and ZAP were widened because one bounded scanner process can cover far more distinct request contexts than launching hundreds of external specialist processes. Nuclei keeps its internal concurrency/rate controls and splits DAST into auditable batches of 48/160/240 request contracts in fast/balanced/deep under one shared action deadline; unused time flows to later batches, while an incomplete batch does not make its untouched inputs look tested. ZAP keeps a protected exact-origin context and one global deadline: 80/320/640 ranked contracts can receive proxy-assisted verification, while 32/96/192 structurally distinct contexts are reserved for the more expensive native active scanner. Native active scanning is enabled only when ZAP accepts both the single-thread-per-host setting and the delay derived from `execution.request_rate`; if either pacing control is unavailable, native active scanning is disabled fail-closed while the independently paced proxy-assisted verifier may continue, and the ZAP result is reported as partial. Native per-case time is allocated from the remaining deadline instead of as a percentage of the original timeout, so increasing the total timeout genuinely allows more cases to run rather than merely making every individual case slower. A ZAP case that merely starts but does not complete is recorded as incomplete, not `Tested`. The increased target/request-contract ceilings therefore improve breadth while the existing traffic and wall-clock controls remain the safety boundary. Nuclei selection and completion are likewise reported separately: a long DAST/focused input list is not automatically counted as fully tested when the Nuclei phase times out or returns partial. Exact request contexts enter the specialist-tested numerator only when the wrapper can identify their completed execution; selected-but-incomplete inputs remain visible as audit evidence.

### Discovery and scanner coverage

Discovery combines an HTTP crawler, HTML/form parsing, external and inline JavaScript navigation extraction, rendered-DOM inspection and a bounded Playwright/Chromium queue. Exact same-origin URLs are always eligible; other origins require explicit authorization, while `allow_same_host_ports=true` permits HTTP/HTTPS services on other ports of the same exact hostname. With proactive same-host service discovery enabled, the port candidate set is derived at runtime from standard service databases and then filled with a deterministic stratified walk across the full generic TCP range up to the active profile cap (4096/32768/65535); it does not simply scan the first N port numbers and no target-specific external port source is consulted. Responsive web roots are fed back as normal high-priority seeds. TLS (Transport Layer Security) is the cryptographic protocol used by HTTPS to encrypt the connection and authenticate the server certificate. For an authorized HTTPS root, the crawler first uses normal certificate validation; only a certificate/trust-chain validation failure triggers one retry of that same authorized URL with trust verification disabled. Protocol/cipher negotiation errors do not trigger this fallback, and the fallback is recorded as discovery diagnostics rather than treated as a TLS finding. The crawler uses 120/220, 600/1100 and 1200/2200 useful-page base/max budgets in fast/balanced/deep; Chromium uses 72/200, 400/1200 and 800/2400 navigations and JavaScript inspection uses 128/640/1200 useful assets. Per-origin caps, route-shape deduplication, application-family fairness and 404/410 filtering prevent one noisy module from consuming the increased capacity. Safe menu expansion uses 16/64/112 controls per page across 3/6/9 DOM passes. Volatile OAuth/OIDC plumbing remains evidence but is compacted so transient values do not saturate the queue. Deterministic discovery and just-in-time authenticated-session refresh keep Playwright Sync API work off the active asyncio loop. Scope diagnostics record blocked destinations rather than relabeling their in-scope source. Query strings found in HTML/JavaScript are also normalized defensively: if an unescaped ampersand inside a human-readable value would make `urllib.parse` invent a whitespace-padded pseudo-parameter (for example `pageTitle=A & B` becoming a parameter named ` B`), the original URL remains in evidence but that fragment is not promoted to a route-shape or scanner parameter. Legitimate structured names such as `columns[0][data]`, `no_columns[]`, dotted names and colon-separated names remain valid.

GET and POST are first-class request contracts. HTML forms, query strings, JavaScript `fetch`/XHR/axios hints and browser-observed requests preserve method, body, content type and nested JSON parameter paths. Discovery itself remains non-mutating: Chromium aborts non-GET/HEAD/OPTIONS navigation requests before transmission and destructive routes are blocked, but the observed POST body can still become a contract for later compatible scanners. When `allow_state_changes=false`, replay is filtered by contract rather than by method alone: read-only POST search/query/API requests remain eligible, while high-confidence mutating POST routes/actions, credential-changing forms and file uploads are withheld from ZAP/Nuclei DAST and from request-level specialist execution. The same validation is applied again in Agentic plan validation, Deterministic specialist scheduling and isolated `--only-tool` runs. A read-only GET such as a setup/security page is not excluded merely by its path name, and benign controls such as `action=view` or `reset=false` are not treated as mutations. Destructive words inside ordinary search/filter data do not by themselves block a request (`q=delete` remains testable): value-based blocking is limited to action/navigation selectors such as `action`, `operation`, `redirect`, `page`, `url` and equivalent routing keys, while mutating route/query-key prefixes remain blocked directly. An explicit false therefore remains binding without deleting useful GET/POST coverage from the assessment. Workflow authentication-throttling probes with deliberately invalid credentials are also suppressed when `allow_state_changes=false`, because repeated failed logins can update server-side lockout/rate counters; the form is still classified structurally. A generic `token` parameter alone is no longer sufficient to allocate a Workflow action slot. SQLMap keeps the original discovered request for attribution/session validation, seeds only selected blank parameters with a neutral value in the scanner copy, and skips its heavy REST engine when the bounded execution-time probe returns 404/410 without candidate evidence. Credential scope remains explicit: a raw primary Cookie header is never copied to a different hostname; when `allow_same_host_ports=true` it may be tried on another authorized port of the exact same hostname/scheme because HTTP cookies are not port-scoped, but the session probe must validate it. Browser storage-state cookies continue to follow their real host-only/Domain/Path/Secure rules. Authorized sibling origins or same-origin application paths receive authenticated coverage only when a cookie is actually applicable there or runtime OIDC/SSO establishes one; no-cookie work is never relabeled as authenticated.

IDOR-Forge is kept in its isolated upstream virtual environment. The initializer explicitly installs a Python-version-compatible `matplotlib` even when a particular upstream `requirements.txt` revision omits it, and its post-install preflight imports both `matplotlib` and `IDORChecker`. The runtime wrapper repeats only a bounded read-only preflight before a target request and then uses the time remaining on the same IDOR action deadline. It never runs `pip install` or mutates the upstream environment during an assessment: a stale/missing dependency fails fast with an actionable diagnostic and is repaired by rerunning `python initScript.py` without `--skip-scanners`.

Observed sibling origins are not merely inventoried, but broad coverage is profile-sensitive so `balanced` does not spend most of its runtime repeating expensive general scanners on every authorized host. A shared origin-ranking function scores each observed sibling from its strongest discovered application route plus bounded evidence for forms, request contracts, browser navigation/network traffic and parameterized interactions. Full no-cookie ZAP/Nuclei/Nikto sibling coverage uses an adaptive per-mode allocation: the top 6/32/64 origins form the base set in fast/balanced/deep, with overflow up to 12/64/128 only for additional origins scoring at least 75% of the base cutoff and carrying observed interactive application evidence (forms, request contracts, browser navigation/network traffic or equivalent ranked signals). Sibling broad runs also use reduced per-run timeout factors of 55%/75%/85% of the corresponding primary broad-scanner timeout, with a 45-second floor. If both anonymous and authenticated profiles are active, this no-cookie sibling broad sweep runs only once under anonymous; the authenticated profile does not repeat the identical cookie-less work. These caps affect only the broad ZAP/Nuclei/Nikto sweep: specialist request-case selectors still accept safe URLs admitted by the configured authorization policy from every observed sibling origin, so a high-value SQLMap, Dalfox, Traversal, IDOR, Authorization, Browser or Workflow candidate is not excluded merely because its origin fell outside the broad-sibling top set. Authentication/session probes are evaluated against the concrete request URL. Raw Cookie headers are never widened to a different hostname; with `allow_same_host_ports=true` they are tried on another authorized port of the same hostname/scheme, matching the fact that HTTP cookies are not port-scoped. The probe must still validate the session. If it fails, browser-derived Domain/Path/Secure/host-only state is tried next and the already-resolved username/password are used only if the login flow requests them; a newly validated origin-specific session then replaces the speculative raw-cookie reuse for subsequent scanners. The resulting contracts are shared by both orchestrators and drive ranking instead of inventing endpoints or parameters.

ZAP active mode is selected from the scan profile rather than from whether the current profile has a cookie: `fast` uses bounded targeted active scanning, `balanced` prioritized active scanning and `deep` the broader bounded mode; `diagnostic_only` remains passive. Scanner inventory is read through the Python API and retried through the raw ZAP JSON API; if metadata is unavailable, a curated set of known injection/path-traversal rule IDs is used as a compatibility fallback. Static assets are excluded from active-case selection. Parameterized request contracts remain the preferred insertion points. If semantic classification produces no compatible parameterized native plan, ZAP now performs a second bounded fallback on at most 1/2/3 safe GET application pages in fast/balanced/deep, with `recurse=False` and a small curated set of installed reflected-XSS, generic-SQLi, traversal and command-injection rules. This allows active coverage on a discovered sibling origin even when its current contracts have no query/body parameters, without turning the fallback into an unbounded recursive active spider. Distinct application endpoints are retained while equivalent request shapes are deduplicated. Planned, attempted, started and completed native cases are counted separately; ZAP reports complete active coverage only when all four counts agree with the planned case count. A planned case that cannot start, remains incomplete, or is not attempted therefore makes the bounded ZAP result partial. Rule IDs are enabled one by one and the wrapper records which IDs ZAP actually accepted. `partial/no_active_scan_rules_enabled` is therefore reserved for the case where neither a compatible parameterized plan nor a safe generic GET fallback with an installed curated rule can be constructed/enabled. Passive observations are retained up to 180/800/1400 in fast/balanced/deep so a saturated observation cap is not mistaken for a complete inventory; security findings are kept separately from that observation ceiling.

At Nuclei startup the wrapper revalidates the recorded official template directory against the local filesystem. If the runtime path is stale, it performs a read-only bounded rediscovery among configured/local standard template locations and uses an existing inventory without downloading or installing anything during the assessment. A missing official inventory no longer means that the whole Nuclei action does nothing: bundled SecOps direct-evidence templates still run when available and the result is marked `PARTIAL` with an explicit coverage gap for the missing official/DAST phases. If only the DAST subtree is missing, non-DAST direct and official phases still run. A hard failure is reserved for the case in which neither the official inventory nor the bundled direct templates are usable. Conversely, if the outer MCP watchdog finalizes a partial result before Nuclei returns its own metadata, the console now reports the template inventory as **unknown** rather than inventing `total=0`/`directory=not-resolved` values. This prevents a transport timeout from being misdiagnosed as an empty template installation.

The current Nuclei pipeline does not invoke `-as` automatic scan: its direct templates are project HTTP templates, official exposure/technology/vulnerability selections come from the official HTTP template tree, and DAST consumes discovered HTTP request contracts. Nuclei's `-pt` option is a **template protocol-type filter** (`http`, `headless`, `workflow`, `tcp`, `dns`, `ssl`, and others); `-pt http` would mean "run only templates whose protocol type is HTTP". It is not a network-scope or port-authorization control. The project therefore does not add a blanket `-pt http` to every phase: the phases that currently run already select HTTP template trees/contracts explicitly, while a blanket filter could later exclude an intentionally selected headless/workflow template. This avoids implicit TCP/DNS/SSL discovery without adding a redundant restriction.

Nuclei consumes discovered request contracts for bounded DAST checks in all three modes: the current ceilings are **96/1200/3000 request contracts** in fast/balanced/deep, while focused/static target ceilings are **128/1024/2048**; the initializer now requires a DAST-capable current Nuclei runtime (minimum v3.11.1), verifies the official `nuclei-templates/dast` subtree and performs a template-load DAST runtime check before assessments start. The DAST phase explicitly selects that directory. Request-shaped Proxify JSONL is attempted first; if the engine rejects it, the same GET/POST request contracts are serialized to the other officially supported Proxify YAML MultiDoc input mode; only if both request-shaped modes fail does the wrapper fall back to a plain URL list for compatible GET cases. Every attempt and stderr excerpt remains in coverage diagnostics. Fast uses `-fa low` with `fuzz-param-frequency=20`; balanced uses `-fa medium` with `fuzz-param-frequency=100`; deep uses `-fa high` with `fuzz-param-frequency=1000`. `-fm single` is retained so one parameter is mutated at a time and evidence remains attributable; it is not a low payload-count cap. SQLMap/Dalfox/other parameter scanners rank API/data-oriented contracts, meaningful identifier/query parameters, method and observed JSON/network evidence ahead of navigation-only parameters. After the scanner phases, both orchestrators perform a candidate-driven Chromium verification pass using the per-profile adaptive limits described above: 12/96/200 base candidates in `fast`/`balanced`/`deep`, expandable to 20/160/320 when the deterministic overflow conditions are met. The final action is restricted to the exact source parameter and is matched to the closest request context using the other query parameters, so two candidates on the same path/parameter but with different application context are verified separately. The source context is preserved through reconciliation and final finding deduplication, so a browser outcome cannot be reassigned to or merged with a different XSS context on the same route. The Browser server exports the parameters actually exercised so reconciliation remains deterministic even if nested diagnostics are lost in transport. Confirmed execution upgrades the source candidate and sets high verification confidence. An unexecuted browser reflection keeps the candidate's potential severity unchanged but limits confidence to medium; a successful exact-parameter bounded non-reproduction likewise preserves severity while setting confidence to low. Severity therefore expresses potential impact if the weakness is real, while confidence expresses how strongly the collected evidence supports its existence. For findings without a browser ceiling, the validated AI confidence becomes the final finding confidence. The subsequent AI analysis may enrich wording and reassess severity from impact evidence, but it cannot raise confidence above the deterministic browser ceiling (MEDIUM for reflection without execution, LOW for bounded non-reproduction). Static assets such as CSS, JavaScript, images and fonts are excluded as Browser-XSS targets. Deterministic skips an exact URL/method/parameter case already exercised successfully by its earlier browser/workflow phase; Agentic performs the same bounded verification before AI analysis.

Nikto is reported as `partial` when its process exits successfully but neither request/host-tested metrics nor a structured report are sufficient to verify scan coverage. A positive official `host(s) tested` summary is accepted as completion evidence even when that Nikto build omits the request counter or writes no useful CSV rows. Parsed console findings are preserved, but unverified coverage is never presented as a complete successful scan.

Terminal logging keeps long request URLs compact: when an URL exceeds the configured display threshold, only the endpoint plus parameter/query metadata are printed (for example parameter count and query length). The complete unmodified URL remains stored in scanner results, JSON artifacts and reports. The threshold can be adjusted with `SECOPS_TERMINAL_URL_MAX`.

Agentic report wording is provider-neutral: the cover still records the concrete provider/model used for the run, while the risk-methodology and executive-summary text refer to the configured AI provider/model rather than assuming Ollama.

The generated report also contains an **Endpoint coverage matrix**. It is built from the final discovery state, deterministic selector decisions and the scanner executions, not from finding counts. Each row identifies the assessment profile, HTTP method, discovered endpoint/request context, discovery source, concrete security tools that actually ran against that endpoint, a textual coverage status, a structured reason code and the explanatory reason when no completed test exists. Status values are `Tested`, `Discovered only`, `Skipped`, `Execution error`, `HTTP 404` and `HTTP 410`; no icon or informal symbol is used. Common omission codes include `DEFERRED_LOW_PRIORITY`, `BUDGET_LIMIT`, `NO_COMPATIBLE_PARAMETERS`, `UNSUPPORTED_METHOD`, `STATE_CHANGE_BLOCKED`, `OUT_OF_SCOPE`, `DUPLICATE_ROUTE_VARIANT`, `HTTP_404` and `HTTP_410`; Agentic additionally uses `PLANNER_DEFERRED` when a deterministic request candidate remained unexecuted after tool-group planning. A page merely visited by the crawler is therefore not labelled `Tested`. Broad-scanner evidence is attached to the exact URL when observable: Nuclei focused/DAST inputs and ZAP targeted active scans are labelled separately from request-level specialist executions, so broad coverage is not confused with a direct SQLMap/Dalfox/Commix/Traversal/Authorization-style validation. The section begins with a numeric summary that reports discovered request contexts, reachable/in-scope contexts, contexts tested by at least one concrete security-tool execution, discovery-only contexts, intentional skips, execution errors, HTTP 404/410 responses and tested coverage percentage. Anonymous and authenticated profiles are summarized independently, with an overall row when both are present. In aggregate multi-entry reports each row also retains the source job/entry point, so identical URLs reached from different configured entry points remain attributable. The complete matrix and the machine-readable `endpoint_coverage_summary` are serialized in report JSON and in the review snapshot and are embedded in `Assessment_Results_Data_<ID>.json`.

### Session-lifecycle logout verification

Logout handling is profile-aware and intentionally separate from generic fuzzing. Anonymous discovery does not spend scanner budget on logout/signout/logoff endpoints because there is no authenticated session to invalidate. Authenticated discovery may retain a logout request contract, including a POST form, but does not execute it during ordinary crawling or specialist scanning. After the remaining authenticated checks and final browser verification have completed, the session verifier executes one bounded logout flow and replays the pre-logout cookie against the protected session probe. If the old cookie still provides authenticated access, the result is a deterministically confirmed session-invalidation vulnerability (CWE-613); if the old cookie is rejected, logout invalidation is verified; if the response cannot be distinguished reliably, the check remains partial rather than creating a vulnerability. Login/SSO routing is the inverse: stable application login routes remain observable/testable in the anonymous profile but are not sent to SQLMap/Dalfox/Commix/Traversal from an already authenticated profile. Volatile OAuth/OIDC protocol and application callback instances are excluded from generic injection/traversal/workflow selection in both profiles while their stable login route remains usable for authentication.

## Requirements

- Python 3.12+
- Docker
- Ollama only for local `llama`/`qwen` Agentic models. `initScript.py --with-lab` provisions both by default;
  `--prepare-ai snap4city` does not provision or require Ollama because no local model is requested.
- The Snap4City AI model/provider requires network access plus `snap4city_model_credentials.json` or interactive model credentials. This file is unrelated to the account used to log in to the assessed dashboard. The provider is remote and is verified during initialization rather than downloaded. Token (1) endpoint calls use bounded HTTP timeouts; transport or JSON failures fall back through the normal cached-token/refresh/user-credential sequence (1) and cannot block indefinitely.
- Scanner command-line contracts are checked during initialization where the tool exposes stable help output. Arjun is pinned to `2.2.7`, its known upstream status-code issue is patched when necessary, and the runtime detects whether JSON output is exposed as `-o` or `-oJ` and whether rate limiting is `--rate-limit` or legacy `--ratelimit`. FFUF, Interactsh, Dalfox and native Nuclei also receive option-contract checks for the flags used by their wrappers. This turns a renamed/unsupported CLI option into an initialization error instead of discovering it after a long assessment has already reached the specialist stage. Nikto remains best-effort at help-contract time because distro launchers expose inconsistent help, while its runtime keeps the existing native/Docker fallback.

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

Before an assessment, the initializer keeps managed local repository copies of SQLMap and Commix under `~/.local/opt/` even when a same-named command already exists on `PATH`, because the wrappers require `sqlmapapi.py`/`commix.py` rather than merely a shell command. Nuclei preflight validates the complete set of CLI flags used by the wrapper (including DAST input/fuzzing/filter options) for both native and official-Docker execution. This turns version/CLI incompatibilities into setup-time errors instead of late scanner failures.

## Configuration-driven assessments

Validate a configuration without launching scanners:

```powershell
python .\assessmentRunner.py --config .\configs\dvwa.generated.json --orchestrator deterministic --mode balanced --dry-run
```

Configuration values for `orchestrator`, `mode` and `model` are normalized to lowercase during validation, so equivalent case variants cannot pass validation and then fail later at the orchestrator CLI. Validation also rejects non-boolean `enabled`, `auth_only`, `allow_state_changes` and `require_ai` values, invalid `max_rounds`, unresolved `credential_ref`/`secondary_credential_ref` names, and `auth_only=true` services without a primary credential. This keeps `--dry-run` consistent with the real execution path instead of accepting a plan that would fail only when secrets are resolved.

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
credentials are all you have, use a configuration with `kind: "browser_oidc"` or obtain an authorized cookie separately.
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

### Configuration-driven remote targets

For a remote authorized application, keep host resolution, credentials and target-specific service declarations in the assessment configuration or in the operator environment; do not encode them in crawler/planner code or generic documentation. A typical validation flow is:

```powershell
python .\assessmentRunner.py --config .\configs\<assessment>.json --orchestrator deterministic --mode balanced --dry-run --authorized
python .\assessmentRunner.py --config .\configs\<assessment>.json --orchestrator deterministic --mode balanced --authorized
python .\assessmentRunner.py --config .\configs\<assessment>.json --orchestrator agentic --model snap4city --max-rounds 2 --mode balanced --require-ai --authorized
```

A service without `credential_ref` is anonymous-only. When a service references an optional `browser_oidc` credential, the runner resolves the configured environment variables (or asks once in an interactive parent process), keeps those values in memory, performs the browser login and passes only the resulting scoped authentication state to child orchestrators. The generic fallback order is **applicable cookie -> session validation -> saved browser/OIDC state -> original username/password when the login flow requests them**. Raw cookies are never copied to another hostname. Multi-port authorization and authentication reuse remain separate decisions: `allow_same_host_ports=true` may authorize another HTTP/HTTPS service on the same exact hostname, but credentials are reused only when their cookie/storage policy applies and validation succeeds.

`discover_same_host_services=true` is valid only together with `allow_same_host_ports=true`. It proactively looks for HTTP/HTTPS services on that already-authorized exact hostname using runtime service information plus the bounded generic stratified TCP-space walk. This behavior does not authorize sibling hostnames and does not use target-specific reference data.

When several configured entry URLs normalize to the same logical service and safety/authentication policy, the runner may coalesce them into one job while preserving all supplied URLs as initial discovery entry points. Truly distinct origins/services remain distinct jobs.

### Oversized report transport
Report generation remains on the unified MCP Streamable HTTP endpoint. When the serialized report input exceeds the safe inline threshold, the orchestrator compresses it and sends bounded chunks through repeated MCP/HTTP tool calls; the report service reconstructs the payload in memory and renders it after completeness, size and SHA-256 integrity checks. Client chunk size and total chunk count are bounded consistently with the report server, and the inline threshold is never allowed to exceed the configured report payload ceiling. No local-file handoff is used for report input.

Reporting uses budgets that are separate from ordinary scanner execution. Chunk upload has its own bounded transfer budget and each chunk has an individual HTTP timeout; once all chunks are accepted, reconstruction and rendering use an adaptive report budget based on the uncompressed payload size. Defaults are 120 s per chunk, 900 s for the complete upload, 4200 s plus 60 s per MiB for reconstruction/rendering (capped at 7200 s), and 3600 s for the PDF renderer itself. These are ceilings, not expected durations. While the final MCP rendering call is running, the orchestrator emits periodic `[REPORT WAIT]` heartbeats and, when the locally-owned server log is available, includes its latest `[REPORT SERVER]` stage. Progress therefore remains visible during long PDF conversion instead of leaving an idle SSH terminal. The complete endpoint matrix remains in HTML/JSON/review data; only the print/PDF variant caps detailed endpoint rows at 260 by default (prioritizing execution errors and untested gaps) so thousands of repetitive matrix rows cannot dominate WeasyPrint rendering. If PDF rendering itself fails or reaches its renderer limit, the already-created JSON, HTML and review snapshot paths are returned instead of being discarded. Relevant overrides are `SECOPS_MCP_REPORT_CHUNK_TIMEOUT`, `SECOPS_MCP_REPORT_TRANSFER_TIMEOUT`, `SECOPS_MCP_REPORT_RENDER_TIMEOUT`, `SECOPS_MCP_REPORT_RENDER_SECONDS_PER_MIB`, `SECOPS_MCP_REPORT_RENDER_TIMEOUT_MAX` and `SECOPS_REPORT_PDF_TIMEOUT`.

Report recovery distinguishes a normal `SecOps_*_Assessment_*` artifact from the minimal `SecOps_*_Emergency_*` last-resort artifact. If the report service has already written any normal JSON/HTML/review/PDF artifact but the final MCP/HTTP response is interrupted or reaches its outer time budget, the orchestrator recovers those deterministic paths and does not create an Emergency duplicate. An Emergency report is written only when no normal artifact can be recovered. `assessmentRunner.py` independently applies the same preference when collecting files created during a job, so one job contributes one primary human-facing report: a normal Assessment report wins over an Emergency artifact, and the terminal labels a normal HTML used because the PDF is unavailable as `HTML report (PDF fallback)` while a genuine last-resort artifact is labeled `Emergency HTML report`. Each assessment now receives a collision-resistant identifier (microseconds, process id and random suffix), and each child job receives a unique report id through the runner. Artifact collection matches only that id/prefix instead of accepting every file modified during the job interval, so simultaneous assessment processes cannot overwrite or accidentally claim each other's reports. Results Data, report JSON/HTML/review snapshots and the final PDF publication use atomic replace semantics where applicable, so an interruption cannot normally leave a half-written persistent artifact in place of a previously complete one.
