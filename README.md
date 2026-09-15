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
   in scope; additional origins are followed when explicitly authorized and, when `authorization.allow_same_host_ports=true`, discovered URLs on other ports of the same exact hostname/scheme are also admitted without port enumeration. Discovery follows HTML links/forms, inline/external JavaScript literal navigation,
   rendered DOM navigation attributes, safe menu/dropdown expansion and dynamic `document`, `xhr` and `fetch` requests observed
   by Chromium. Values carried by routing parameters such as `redirect`, `linkUrl`, `page` or `resource` are preserved when they
   identify different internal modules and safe nested destinations are added back to the discovery queue. If several supplied URLs
   must each be guaranteed as starting points, declare them as separate services in the configuration. Benchmark/reference URL lists
   used to evaluate discovery are not injected into target configs or crawler code.

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

Active testing is based on explicit HTTP authorization, not DNS-parent relationships or textual hostname prefixes. The primary target origin is always in scope and additional exact origins can be authorized with `authorization.allowed_origins` or repeated `--authorized-origin`. An origin is scheme + hostname + effective port: `http://example.com` and `http://example.com:80` are equivalent, while `http://example.com:8080` is a different origin even though it can still belong to the same web site/server. For assessments where authorization is granted to the whole web host rather than one port, `authorization.allow_same_host_ports=true` enables **discovered multi-port scope**: an HTTP(S) URL on another port is accepted when its hostname is exactly the same as an already-authorized hostname and its scheme is unchanged. The field defaults to `false`. It does not enumerate or scan arbitrary ports; a different port enters the queue only after a link, redirect, browser request or other normal discovery evidence exposes an HTTP/HTTPS URL for it. A protocol change (HTTP↔HTTPS) or a different hostname still requires an explicit authorized origin/service. The dashboard-test, tourist-dashboard and platform example configs set this field to `true` because they model site-level authorization. For an absolute URL with no written port, HTTP implies 80 and HTTPS implies 443, so `https://www.snap4city.org/path` is equivalent to `https://www.snap4city.org:443/path`. `example.com.evil` is a completely different hostname (under `evil`), not another page, subdomain or port of `example.com`. For example, with `https://www.snap4city.org` authorized and `allow_same_host_ports=true`, a discovered `https://www.snap4city.org:8443/` is admissible; `https://processloader.snap4city.org:8443/` is not admitted merely because it is a sibling hostname. If `https://processloader.snap4city.org` is separately present in `allowed_origins`, however, the same flag can also admit a discovered `https://processloader.snap4city.org:8443/`. Legacy DNS-suffix scope widening is rejected.

Concrete sibling examples with `allow_same_host_ports=true`:

| Discovered URL | Result | Reason |
| --- | --- | --- |
| `https://www.snap4city.org:8443/app` | **Accepted** | Same exact hostname and scheme as the authorized `https://www.snap4city.org`; only the port changed. |
| `https://processloader.snap4city.org/app` | **Accepted only if explicitly authorized** | It is a sibling hostname, so the multi-port flag alone does not authorize it. An exact `allowed_origins`/service entry does. |
| `https://processloader.snap4city.org:8443/app` | **Accepted only if `processloader.snap4city.org` is explicitly authorized first** | Once that hostname is an authorized base, the flag may extend that hostname to a discovered port on the same scheme. |
| `https://iot-directory.snap4city.org/app` | **Rejected if not explicitly authorized** | Sharing the `snap4city.org` parent domain is not authorization. |
| `https://www.snap4city.org.evil.example/app` | **Rejected** | This is a different hostname under `evil.example`, not part of `www.snap4city.org`. |

Login and SSO endpoints are not excluded by name. `/login.php`, `/ssoLogin.php`, `/auth/...` or any other authentication route remains testable when it belongs to an authorized origin. During browser authentication the page may temporarily visit a different origin; that does not authorize scanners against the external identity-provider origin. Redirects followed by sensitive Python helper/probe requests are restricted to same-origin transitions. The same guard is used by session probes, runtime target preparation, logout verification and lightweight injection pre-verifiers, so helper traffic cannot widen scope merely because an endpoint returns an external `Location`. When a session probe is stopped by that guard, or exhausts the bounded same-origin redirect limit, authentication is reported as inconclusive rather than treating the remaining 3xx response as proof of an authenticated session. Traversal/LFI pre-verification uses the same redirect guard as the other request-level verifiers. External scanner wrappers also disable autonomous redirect following where the tool exposes such a control: Arjun, Nuclei, SQLMap and Commix are invoked with redirect following disabled/ignored, ZAP direct seeding does not follow redirects, its context regex is anchored to the exact scheme/host/effective-port origin, targeted active scans use in-scope-only mode, and ZAP itself is switched to Protected mode as a second barrier; Nikto is launched without its global follow-redirects option. This does **not** discard the normal application redirect destinations found by project-controlled discovery: HTTP/Chromium discovery follows bounded redirects while every destination remains inside the configured authorization policy. Same-origin hops are followed normally; an exact additional origin is followed when it was explicitly authorized before the run; and, when `allow_same_host_ports=true`, a different port is also allowed only for the same exact hostname and same scheme. The final in-scope URL is recorded and fed back into broad/specialist selection. Nuclei therefore receives both the original in-scope target and the bounded discovered in-scope URL set; Nikto may start directly from the final URL reached by its own project-controlled same-origin baseline probe. The scanner process itself is still prevented from making an autonomous cross-origin hop. This is intentionally conservative: scanner-internal/template-specific behavior that *itself* requires following a redirect is not guaranteed to be reproduced by central discovery. Nuclei's documented `-fhr` means "follow redirects on the same host". That is not used as the authorization boundary because the flag description does not by itself guarantee the same rule as this project's allow-list: Nuclei documents protocol redirects separately, and its template variables distinguish `Host` from `Hostname` (where `Hostname` includes the port). The assessment therefore evaluates every redirect hop against the configured authorization policy (explicit origins plus the optional same-host/same-scheme multi-port rule) instead of assuming that Nuclei's shorter "same host" wording is equivalent. The selector budgets are unchanged, but this residual redirect-dependent scanner behavior is reported/documented as a containment trade-off rather than claimed as zero coverage loss. FFUF is not launched with redirect-following enabled; the Dalfox wrapper does not enable its follow-redirects option. Discovery prints a single `[SCOPE]` notice when it observes out-of-scope URLs/origins, explicitly stating that they were not queued for active testing. Chromium separately reports ordinary external subresource traffic needed for rendering/authentication and the number of blocked top-level navigations toward unauthorized origins; those dependency requests are never converted into active scanner cases. The Browser XSS/workflow verifier applies the same top-level rule: third-party subresources required to render an authorized page may load, but a document/navigation redirect is followed only when its destination is admitted by the configured authorization policy (explicit origin, or same-host/same-scheme different port when `allow_same_host_ports=true`); an unauthorized destination is aborted and recorded rather than followed as a new verification target. Service Workers are deliberately not disabled only to make this guard stricter: doing so can change PWA behavior and reduce verification coverage. The browser route guard therefore protects controllable top-level/document navigations, while external dependency traffic (including browser-managed behavior) remains observational traffic and is never promoted into an active scanner case.

The coverage oracle used by the project (for example an external Excel list or docker-compose inventory) is **not** injected into discovery or configuration. It is used only after a run to compare what the platform discovered autonomously. This prevents benchmark leakage while making missed routes measurable.

The containment layers are deliberately different by tool rather than blindly duplicated. The shared orchestrator gate decides which origins/request contracts are authorized before any specialist is called, including the optional same-host multi-port rule when enabled. Project discovery owns bounded authorized redirect resolution. Sensitive Python probes/custom checks use the shared same-origin redirect helper. Arjun/Nuclei/SQLMap/Commix disable autonomous redirect following, FFUF/Dalfox do not enable it, and Nikto omits global follow; they operate on URLs already admitted by discovery. `--disable-redirects` really does prevent Arjun itself from following **all** redirects, including internal ones. To preserve the ordinary GET case, the wrapper first resolves a short same-host/same-scheme chain with auto-follow disabled, checking every hop and allowing a discovered alternate port only when the configured multi-port policy permits it. If a redirect points to a different hostname that is separately authorized, the wrapper deliberately does **not** carry the current raw cookie across that hop; central discovery handles that destination separately with the session applicable to that origin. Non-GET cases are not replayed merely to resolve redirects, avoiding duplicate stateful requests. A redirect generated only by one of Arjun's own parameter probes is still not followed inside Arjun, so this remains a documented containment-versus-coverage trade-off rather than a claim of perfectly equivalent redirect behavior. ZAP needs additional internal barriers because it maintains its own site tree/spider/active scanner: exact-origin context, in-scope-only active scans, Protected mode and no-follow direct seeding all enforce the *same* scope policy at different ZAP layers. These barriers do not lower the configured endpoint/request-contract/template selector budgets; they prevent a selected in-scope case from creating an unapproved destination at runtime.

`execution.request_rate` is the operator-facing traffic parameter. If it is omitted, the runner uses **10 requests/second**. Integer values from **1 through 50 requests/second** are accepted; a value above 50, below 1, non-numeric or non-finite is rejected and falls back to the default 10 rather than being silently clamped. The runner prints the effective policy in the console, and a fallback is also recorded in Results Data and in the report Run configuration. `SECOPS_MAX_REQUEST_RATE` is the normalized child-process environment value derived from this configuration; it is not the preferred user configuration surface. Deterministic and Agentic execute active specialist tool calls strictly one after another, so SQLMap, Nuclei, Dalfox, FFUF and the other specialist processes do not overlap globally. Individual tools can still have bounded internal concurrency (for example Nuclei runs with `-c 2`, `-bs 1`, `-pc 1` in all three profiles, while ZAP uses one active-scan thread per host), and browser subresources are not a packet-level global token bucket, so the configured number is a project traffic-control parameter rather than a mathematical guarantee for every TCP request. Nuclei, FFUF and Arjun receive explicit rate caps; SQLMap and Commix receive delays; ZAP is configured with bounded internal active-scan concurrency/delay; the built-in HTTP crawler and top-level Chromium navigations are paced as well. The Browser XSS/workflow verifier also receives the configured rate and paces document navigations (including same-origin redirect hops); Chromium-managed CSS/JS/image/XHR subresources are not represented as a packet-level token bucket. Changing the rate changes timing, not the endpoint/request-contract selection budgets.

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
  Service discovery is intentionally web-scope driven, not an implicit TCP port scan. A service published only on a different host/port is assessed when that service is explicitly authorized/configured or when an already authorized web surface exposes a URL that remains inside the configured scope. A Docker Compose inventory can therefore be used as external ground truth to identify missing service coverage, but its ports are never injected into a target configuration automatically.
- `assessmentRunner.py`: accepts either a platform JSON configuration or a direct `--target`/`--cookies` invocation, then delegates
  each HTTP/HTTPS job to the existing Deterministic or Agentic orchestrator. Direct mode consumes an already available cookie session;
  target username/password login is configuration-driven. Non-web protocols may be inventoried but are explicitly recorded as unsupported
  by the current web-assessment orchestrators rather than being silently treated as tested.
- `configs/dvwa.example.json`: non-secret placeholder that shows the exact DVWA configuration structure without containing a usable session.
- `configs/dvwa.generated.json`: generated by `initScript.py --with-lab` from the fresh DVWA session and immediately usable.
- `configs/dashboard-test.json`: definition for the authorized `192.168.1.81` / `dashboard-test` target. HTTP/80 with base path `/` is enabled while HTTPS/443 remains a separately configured disabled service until verified. `authorization.allow_same_host_ports=true` means an HTTP URL on another port of `dashboard-test` may enter scope only if normal discovery actually exposes it; this does not enumerate ports and does not authorize sibling hostnames. The config does not authorize the parent DNS domain and does not contain benchmark endpoint lists. Its `dashboard_session` uses the provider-neutral `browser_oidc` workflow; authentication may navigate through external identity infrastructure without authorizing the IdP for active testing.
- `configs/platform.example.json`: generic multi-asset example. Each enabled HTTP/HTTPS service is an explicit target job and the example sets `allow_same_host_ports=true` to demonstrate site-level port authorization for already-authorized exact hostnames. Different hostnames are never inferred from DNS suffixes or discovered links. `browser_oidc` credentials can be attached to a service without making credentials or authorization synonymous. A secondary cookie identity and aggregate reporting are also illustrated.
### Who decides request priority

There is no separate ranking service and the AI does not assign request importance. Ranking is implemented in `orchestratorShared.py`. Discovery first builds normalized `request_cases` from HTTP crawl links/forms, JavaScript endpoint extraction and Playwright network observations. Python then applies compatibility/safety filters and computes a different score for each specialist. `_tool_case_priority()` handles SQLMap, Dalfox, Commix, Traversal and IDOR; `_browser_case_priority()`, `_workflow_case_priority()` and `_authorization_case_priority()` handle their dedicated classes; Arjun uses its own endpoint score. The generic `_risk_terms()` component gives small weights to security-relevant words in the path and parameter names, while each specialist adds much larger class-specific weights.

For example, SQLMap receives higher priority for SQL/data/search routes, SQL-relevant parameter names, POST/JSON contracts, live Playwright-observed requests and successful 2xx/3xx browser responses. Dalfox rewards XSS/search/comment/message inputs and live browser traffic; Commix rewards command/exec routes and `cmd`/`host`-like parameters; Traversal rewards file/download/template/path inputs; IDOR accepts only GET cases with numeric object-reference parameters; Browser strongly rewards client-side source/sink evidence; Workflow prioritizes upload, authentication, CAPTCHA, CSRF/token and other stateful form shapes; Authorization prioritizes read-only identity/object/resource identifiers and privileged-resource routes. Incompatible methods, logout/destructive routes, static resources, oversized generated requests and observed 404/410 cases are rejected before specialist budget selection. When state changes are disabled, `DELETE`, `PUT` and `PATCH` contracts are treated as mutating by method and POST bodies are inspected recursively so destructive actions nested inside JSON cannot bypass the central gate.

Discovery breadth is also adaptive before specialist selection. The HTTP crawler fills a fixed base of 70/280/420 useful pages and may continue to 110/420/650 in fast/balanced/deep while the next queued URL remains at least 75% as valuable as the base cutoff. A separate request-attempt ceiling is 1.75x/2.0x/2.0x the adaptive page maximum, so dead links remain bounded without prematurely stopping a useful crawl when many 404/410 responses are present. Confirmed HTTP 404/410 URLs are retained as diagnostics but no longer create specialist request contracts. The queue adds a generic diversity bonus for underrepresented top-level application families (origin + first path segment), so a large portal section cannot monopolize the bounded crawl simply because it exposes more links. Chromium uses base/adaptive maxima of 36/90, 160/520 and 240/720 navigations in fast/balanced/deep and performs at most one bounded fallback navigation/DOM extraction retry for transient abort, timeout or destroyed-execution-context failures. JavaScript discovery uses a separate useful-asset and fetch-attempt budget (48/256/384 useful assets and factors 1.5x/1.75x/1.75x), so dead or unreachable scripts are diagnostic attempts rather than lost useful-analysis slots. Authenticated Chromium discovery imports the real saved browser storage state when available and writes back the refreshed state after navigation, preserving Domain/Path/Secure, host-only cookies and identity-provider/local-storage state instead of flattening everything to one origin-wide Cookie header.

The resulting cases are sorted by score, then bounded by tool-specific route-shape deduplication so changing only an ordinary input value cannot occupy the whole budget. Discovery itself retains up to 6/12/16 value variants per route in fast/balanced/deep; expensive request-level specialist execution uses the narrower generic cap 2/4/6. Absolute HTTP(S) routing destinations retain their host/path semantics so distinct application destinations are not collapsed merely because the outer route is identical. SQLMap, Dalfox, Commix, IDOR, Browser, Workflow and Authorization use structural route identities based on origin/path/parameter names; Traversal alone preserves semantic routing/resource values because `redirect=file.php`, `page=module.php` or `template=...` can select a genuinely different server-side resource. Traversal execution additionally requires a parameter-level LFI/path signal: a file/path/routing parameter or an observed local-resource/traversal value. Generic `id`, role or sorting parameters no longer consume the LFI reserve merely because their route has a high generic risk score. Obvious static cache/version variants remain discovery evidence (JavaScript is still parsed for endpoint hints) but do not consume request-level injection budgets; Dalfox also excludes non-HTML CSS/font/image/media targets while keeping JavaScript with real functional parameters eligible. One-shot OAuth/OIDC protocol instances carrying transient values such as `state`, `nonce`, `code` or session identifiers are compacted so repeated values do not consume bounded budgets. Stable login/SSO routes on an authorized origin remain normal application surfaces and are not excluded merely because they implement authentication. The fixed specialist base is filled first. Only after that, `_select_with_adaptive_specialist_budget()` may admit high-value deferred cases whose score is at least 75% of the base cutoff and whose request contains evidence specific to that vulnerability class. Deterministic consumes these ranked selections directly. Agentic uses exactly the same ranked concrete pool, groups it by `(profile, tool)`, and lets the model choose complementary tool groups; the model does not change individual-request scores or decide which SQLMap/IDOR/etc. URL ranks above another.

### Profile breadth budgets

The profiles increase both discovery breadth and scanner execution ceilings. Limits are deliberately applied after relevance ranking and route-shape deduplication, so a larger budget is spent preferentially on distinct API/form/request surfaces rather than repeated calendar pages, archives, static assets or equivalent query-value variants. ZAP and Nuclei limits are request-contract/target ceilings, not HTTP request counts. Specialist rows written as `base / adaptive max` use bounded adaptive overflow: `orchestratorShared.py` deterministically ranks the request contracts for the vulnerability class, fills the fixed base first, and can admit deferred cases only when the base is saturated, the deferred score is at least 75% of the base cutoff score and strong class-relevant evidence is present. For discretionary Agentic capability groups the model may choose among the eligible actions, but it cannot change the scores, threshold or scope; baseline broad/JWT groups are selected by Python. A second, independent Agentic execution budget prevents the union of many large specialist groups from turning one round into hundreds of sequential scanner invocations. The fixed per-profile base remains the normal capacity, but a small evidence-backed overflow is available already in round 1 and grows gradually in later rounds; ordinary lower-ranked actions never fill that overflow by themselves.

| Coverage bound | fast | balanced | deep |
| --- | ---: | ---: | ---: |
| HTTP crawler pages per profile (base / adaptive max) | 70 / 110 | 280 / 420 | 420 / 650 |
| HTTP request-attempt ceiling (x adaptive page max) | 1.75x | 2.0x | 2.0x |
| Chromium navigations per profile (base / adaptive max) | 36 / 90 | 160 / 520 | 240 / 720 |
| Safe menu/dropdown controls expanded per rendered page | 6 | 18 | 28 |
| JavaScript assets successfully inspected | 48 | 256 | 384 |
| JavaScript fetch-attempt ceiling (x useful-asset budget) | 1.5x | 1.75x | 1.75x |
| ZAP request contracts considered | 10 | 32 | 60 |
| ZAP passive observations retained | 60 | 220 | 450 |
| ZAP generic GET active-fallback pages | 1 | 2 | 3 |
| Nuclei focused/static targets | 20 | 96 | 160 |
| Nuclei DAST request contracts | 10 | 64 | 112 |
| SQLMap cases (base / adaptive max) | 3 / 4 | 24 / 40 | 36 / 60 |
| Dalfox cases (base / adaptive max) | 3 / 4 | 24 / 40 | 36 / 60 |
| Commix cases (base / adaptive max) | 3 / 4 | 18 / 30 | 24 / 40 |
| Traversal cases (base / adaptive max; routing/file reserve) | 3 / 4; 16 | 24 / 40; 64 | 36 / 60; 112 |
| Traversal routing/file coverage reserve | 16 | 64 | 112 |
| Browser cases (base / adaptive max) | 3 / 4 | 24 / 40 | 36 / 60 |
| Workflow cases (base / adaptive max) | 3 / 4 | 24 / 36 | 36 / 54 |
| IDOR cases (base / adaptive max) | 3 / 4 | 20 / 32 | 32 / 48 |
| Authorization cases (base / adaptive max) | 4 / 5 | 28 / 40 | 40 / 64 |
| Arjun endpoints (base / adaptive max) | 3 / 4 | 24 / 36 | 36 / 54 |
| Interactsh Agentic candidate actions per round/profile | 1 | 3 | 4 |
| Interactsh Deterministic OAST cases per profile | 1 | 2 | 3 |
| JWT tokens analyzed per profile | 16 | 64 | 192 |
| Final Chromium XSS candidates per profile (base / adaptive max) | 8 / 12 | 40 / 64 | 120 / 180 |
| Agentic tool-group catalog shown to AI | 32 | 40 | 48 |
| Agentic tool-group budget per profile | 12 | 16 | 18 |
| Agentic breadth-review additions per sparse profile | 3 | 6 | 8 |
| Agentic concrete actions per round/profile (base / R1 max / R2 max / R3+ ceiling) | 48 / 54 / 58 / 62 | 144 / 168 / 184 / 200 | 288 / 328 / 352 / 376 |
| Agentic planner-action ceiling per profile with `--max-rounds 2` (R1+R2) | 112 | 352 | 680 |
| Same ceiling with anonymous + authenticated both active | 224 | 704 | 1360 |

Traversal uses semantic route identities for routing/file parameters: two requests that share a path and parameter name but route to different internal resources remain distinct. The other request-oriented specialists deliberately use structural route identities, so value-only variants do not multiply SQLMap/Dalfox/Commix/Browser/Workflow work. Traversal additionally has a bounded routing/file reserve of 16/64/112 cases in fast/balanced/deep. Reserve cases stay high-priority inside the Traversal group, but Agentic expansion now admits only one action per selected capability on each round-robin pass; the reserve therefore cannot consume the profile budget before SQLMap, Dalfox, Browser or other selected capabilities receive their share. The reserve is generic, does not inject target-specific URLs and does not bypass scope or state-change safety checks. Absolute HTTP(S) callback values such as OAuth `redirect_uri=https://...` are not treated as local-file selectors.

For Agentic execution, the per-tool adaptive pools above are only candidate pools; they are not all executed in the same round. Python expands selected profile/tool groups with a capability-fair round-robin. The normal per-profile bases are 48/144/288 actions in fast/balanced/deep. Evidence-backed overflow is available from round 1 with caps +6/+24/+40, producing round-1 maxima 54/168/328. The cap then grows by +4/+16/+24 per additional round until the configured ceilings +14/+56/+88 are reached: round 2 maxima are 58/184/352 and round 3+ ceilings are 62/200/376. Overflow slots can contain only deterministic coverage-reserve or adaptive specialist cases already tagged by the class-specific ranking; prior findings or newly discovered Arjun parameters raise a tool to higher overflow priority in later rounds. Ordinary lower-ranked actions cannot fill overflow merely because capacity remains. Deferred actions are not discarded: later planner rounds expose the next ranked request contracts. The later-round planner is explicitly instructed not to select another specialist batch merely because lower-ranked contracts remain; previous results, newly exposed surface, unresolved high-confidence candidates or materially distinct request families should justify the extra work.
There is deliberately no second assessment-wide hard cap layered over these per-round limits: with `--max-rounds 2`, the gross planner ceilings are therefore 112/352/680 actions per profile (224/704/1360 if anonymous and authenticated both saturate every round). These are arithmetic ceilings rather than expected workloads, and they exclude the separate final Chromium XSS verification and authenticated logout checks. Keeping this explicit preserves the requested later-round growth; if real VM runs still spend excessive time after the first round, a separate cumulative cap can be introduced as an independent policy rather than silently weakening the per-round scheduler.

Deterministic deliberately has no planner-wide action cap: it executes each tool's own ranked bounded selection. If every per-tool adaptive ceiling, every authorized broad-sibling slot and the separate final Chromium stage were simultaneously saturated, the gross per-profile orchestrator-action ceilings would be 87/477/916 for an anonymous profile and 95/520/983 for an authenticated profile in fast/balanced/deep; the authenticated figure also includes up to three final logout checks. These are conservative ceilings, not expected workloads: unavailable classes, cross-profile no-cookie deduplication, missing siblings, adaptive evidence gates, early tool reallocation and fewer unresolved XSS candidates normally reduce them substantially. One orchestrator action is a scanner invocation/request contract, not one HTTP request; ZAP, Nuclei, SQLMap and Chromium may perform multiple bounded requests internally.

Broad scanner timeout ceilings are `zap` 120/600/1080s, `nuclei` 360/1200/1800s, `nikto` 60/180/300s and `ffuf` 50/120/210s in fast/balanced/deep. The MCP transport watchdog is derived from the selected scanner timeout plus connection/transport margin, so a DEEP scanner is not aborted by the generic MCP default while its own bounded budget is still valid. Main specialist ceilings are SQLMap 75/180/300s, Dalfox 45/120/210s, Commix 90/180/300s, Traversal 35/75/120s, Browser 45/120/210s and Workflow 40/105/180s. The individual wrappers accept at least the timeout assigned by these profiles (for example Workflow up to 240s, Authorization/Session up to 180s, Browser/FFUF up to 300s and Nuclei up to 2400s), so an inner wrapper cap cannot silently shorten a valid BALANCED/DEEP run. Agentic planner ceilings are 900/1800/3000s with context windows 6144/8192/12288 and output budgets 800/1300/1800 tokens. These are upper bounds; completed tools return immediately.
In balanced Nuclei runs the focused exposure/misconfiguration phase now receives an adaptive share of the existing Nuclei timeout based on the number of focused targets, up to 150 seconds, while preserving a DAST floor. This is budget redistribution, not a reduction in templates or endpoints: small target sets keep the previous short phase, while large sets are not forced to fail at the former fixed 55-second boundary.

JWT analysis is profile-local and bounded at 16/64/192 unique discovered tokens in fast/balanced/deep. The bound is intentionally high because the verifier only decodes and inspects token structure/claims locally and does not perform a network attack; different tokens can represent different issuers, audiences or roles. In Agentic, the JWT capability is baseline-selected whenever tokens exist, while raw token values remain local and are not exposed in the compact planner view.

Final Chromium XSS verification uses a separate adaptive stage shared by Deterministic and Agentic. It ranks only unresolved XSS candidates that have a compatible safe request contract, selects a per-profile base of 8/40/120 in fast/balanced/deep, and can extend to 12/64/180 when the base is saturated and deferred candidates remain at least 75% of the base cutoff score. Context match, an exact source parameter, client-side source/sink evidence, observed live browser traffic and existing scanner evidence raise this deterministic priority; the AI does not decide the overflow.

Before the base/adaptive cut is applied, request-oriented specialist selectors bound ordinary value-only variants to avoid saturation. The semantic fingerprint is intentionally Traversal-specific: values of routing parameters remain distinct only when they identify an internal resource that can plausibly participate in file/module selection. Thus `/user?id=1` and `/user?id=2` share an ordinary structural shape, SQLMap/Dalfox/Commix do not multiply work across harmless routing-value variants, while `ssoLogin.php?redirect=devices.php` and `ssoLogin.php?redirect=models.php` can remain two Traversal surfaces. Absolute web callbacks and pure OAuth/OIDC metadata do not enter the LFI reserve. Specialist ranking also performs a generic origin/application-family breadth pass before filling remaining slots by score, preventing one very large module from consuming every bounded specialist slot.

Adaptive specialist overflow is deliberately separate from timeout growth: it allows more distinct high-value request contracts to be tested without extending the time allowance of each individual run. Strong evidence requires at least one vulnerability-class-specific signal, such as a relevant parameter or route, numeric/object identifiers for IDOR, identity/privileged-resource signals for Authorization, browser source/sink evidence, or workflow-specific form/token/upload/authentication metadata; POST/JSON shape, observed XHR/fetch traffic, a live 2xx/3xx browser response and high-value application/API routing strengthen that decision but do not grant overflow by themselves. Selected overflow cases are tagged in the deterministic selection summaries and in the Agentic action catalog for auditability.

Nuclei accepts up to 20/96/160 focused targets and 10/64/112 DAST request contracts. Its wrapper keeps internal template concurrency at 2 (`-c 2`), bulk size at 1 and payload concurrency at 1; this is internal work inside one Nuclei process and applies identically whether that process was invoked by Deterministic or Agentic. Both focused-target and DAST selection preserve application-family breadth before filling residual slots by score. Focused-target selection first represents distinct application path families and then fills remaining slots by score; explicitly configured entry points, when present for a legitimate multi-entry target, remain first-priority seeds. Fast therefore keeps a small bounded DAST sample instead of disabling DAST entirely; balanced/deep retain larger bounded fuzz aggression and global time/concurrency/rate controls. GET and POST contracts are both eligible when compatible with the template/input mode. ZAP considers up to 10/32/60 ranked request contracts for targeted/prioritized/full active modes.

### Discovery and scanner coverage

Discovery combines an HTTP crawler, HTML/form parsing, external and inline JavaScript navigation extraction, rendered-DOM inspection and a bounded Playwright/Chromium queue. Browser rendering/authentication may load ordinary cross-origin dependencies needed by the page or traverse an external IdP, but those observations never become active scanner targets unless the destination satisfies the configured authorization policy. Exact same-origin URLs are always eligible; cross-origin URLs are admitted when they match an explicit authorized origin or, with `allow_same_host_ports=true`, when they differ only by port on the same exact hostname and scheme. DNS suffixes never authorize active testing. There is no domain-name or benchmark-URL special case in discovery. The crawler uses base/adaptive useful-page budgets of 70/110, 280/420 and 420/650 in fast/balanced/deep. Chromium uses adaptive per-profile navigation budgets of 36/90, 160/520 and 240/720 (base/max), while JavaScript inspection uses 48/256/384 successfully fetched assets. Script fetch attempts have a separate 1.5x/1.75x/1.75x ceiling, so 404/timeout assets do not consume the useful-script quota. Volatile OAuth/OIDC plumbing (`state`, `nonce`, `session_code`, `tab_id`, `execution`, challenge values) is still recorded as authentication evidence but is de-prioritized and keeps only one discovery value variant per route shape; normal application routes retain the 6/12/16 variant allowance. This prevents identity-provider churn from consuming page/navigation budgets without hiding real login forms or application SSO wrappers. On each rendered page Chromium can additionally expand up to 6/18/28 safe menu/dropdown/collapse controls; controls inside forms and controls with destructive/state-changing labels are not clicked, and the browser request guard continues to abort non-GET/HEAD/OPTIONS navigation. Discovery reads `href`, frame/form actions and common `data-*` navigation attributes before and after expansion, and recognizes literal `window.open`, `location.*` and URL/path assignments in HTML/JS. Routing parameters that contain internal paths/files are semantically fingerprinted and their safe nested destination is queued, so different discovered module selectors are not collapsed as mere value variants. Existing credential `login_path`/`validation_path` values can be passed by the runner as ordinary priority seeds under normal budgets; they are not reported as supplied entry points and no external benchmark list is injected into a target configuration. Queue ranking gives the exact primary target origin a small generic priority bonus, so explicitly authorized sibling origins remain discoverable/testable without displacing the main application's highest-value pages from bounded HTTP/Chromium coverage. HTTP 404 and 410 responses remain recorded as crawl diagnostics, but they do not consume the useful crawl-page quota and no longer create specialist request contracts, so dead links cannot displace valid pages from Chromium/ZAP seeding or consume specialist budgets. A separate HTTP request-attempt ceiling is 1.75x/2.0x/2.0x the adaptive useful-page maximum in fast/balanced/deep (with the same bounded per-origin principle), preventing broken-link-heavy applications from causing unbounded extra requests without prematurely stopping useful discovery. The console also reports when the useful HTTP-page budget or the HTTP-attempt budget is actually saturated while candidates remain queued, so a large target can be distinguished from a crawl that naturally exhausted its surface. If HTML pages are available but Chromium records zero successful navigations, the console emits an explicit browser warning and prioritizes Playwright/runtime/navigation errors ahead of ordinary 404/410 messages. Deterministic discovery invokes the synchronous Playwright crawler in a worker thread, so it never runs the Playwright Sync API inside LangGraph's active `asyncio` loop. Agentic normally reaches discovery from a synchronous graph invocation, but it uses the shared `discover_target_sync_safe()` guard as well: if that code is ever invoked while an asyncio loop is already active, discovery is moved to a worker thread before the Playwright Sync API is entered. When Chromium uses adaptive overflow, the console reports base, overflow and attempted/max counts; if the maximum is reached with queued candidates still present it reports the remaining queue explicitly. Discovered URLs are also sanitized before scope/ranking/request handling: stray literal or percent-encoded ASCII whitespace at the end of the authority is removed without changing path/query content, preventing malformed HTML links such as `https://host%20` from becoming wasted DNS requests. Literal HTML/JavaScript URL extraction also normalizes complete escaped HTTP(S) forms such as `https\://host/path` but rejects incomplete scheme fragments such as `http\:/`, so parser noise cannot be turned into synthetic relative routes such as `/ServiceMap/http\:/`. Scope diagnostics record the blocked redirect destination rather than the authorized source page; an in-scope page that redirects outward therefore cannot appear spuriously in the `[SCOPE]` list of external origins.

GET and POST are first-class request contracts. HTML forms, query strings, JavaScript `fetch`/XHR/axios hints and browser-observed requests preserve method, body, content type and nested JSON parameter paths. Discovery itself remains non-mutating: Chromium aborts non-GET/HEAD/OPTIONS navigation requests before transmission and destructive routes are blocked, but the observed POST body can still become a contract for later compatible scanners. When `allow_state_changes=false`, replay is filtered by contract rather than by method alone: read-only POST search/query/API requests remain eligible, while high-confidence mutating POST routes/actions, credential-changing forms and file uploads are withheld from ZAP/Nuclei DAST and from request-level specialist execution. The same validation is applied again in Agentic plan validation, Deterministic specialist scheduling and isolated `--only-tool` runs. A read-only GET such as a setup/security page is not excluded merely by its path name, and benign controls such as `action=view` or `reset=false` are not treated as mutations. An explicit false therefore remains binding without deleting useful POST coverage from the assessment. Credential scope remains explicit: a raw primary Cookie header is never copied to a different hostname; when `allow_same_host_ports=true` it may be tried on another authorized port of the exact same hostname/scheme because HTTP cookies are not port-scoped, but the session probe must validate it. Browser storage-state cookies continue to follow their real host-only/Domain/Path/Secure rules. Authorized sibling origins or same-origin application paths receive authenticated coverage only when a cookie is actually applicable there or runtime OIDC/SSO establishes one; no-cookie work is never relabeled as authenticated.

IDOR-Forge is kept in its isolated upstream virtual environment. The initializer explicitly installs a Python-version-compatible `matplotlib` even when a particular upstream `requirements.txt` revision omits it, and its post-install preflight imports both `matplotlib` and `IDORChecker`. The runtime wrapper repeats that check before a target request. If an otherwise valid stale IDOR-Forge venv is missing only `matplotlib`, the wrapper performs one bounded `pip` repair attempt (`SECOPS_IDOR_AUTO_REPAIR=0` disables it) and reruns the preflight; broader dependency failures still produce an actionable diagnostic and are repaired by rerunning `python initScript.py` without `--skip-scanners`.

Observed sibling origins are not merely inventoried, but broad coverage is profile-sensitive so `balanced` does not spend most of its runtime repeating expensive general scanners on every authorized host. A shared origin-ranking function scores each observed sibling from its strongest discovered application route plus bounded evidence for forms, request contracts, browser navigation/network traffic and parameterized interactions. Full no-cookie ZAP/Nuclei/Nikto sibling coverage uses an adaptive per-mode allocation: the top 2/5/10 origins form the base set in fast/balanced/deep, with overflow up to 3/8/16 only for additional origins scoring at least 75% of the base cutoff and carrying observed interactive application evidence (forms, request contracts, browser navigation/network traffic or equivalent ranked signals). Sibling broad runs also use reduced per-run timeout factors of 55%/75%/85% of the corresponding primary broad-scanner timeout, with a 45-second floor. If both anonymous and authenticated profiles are active, this no-cookie sibling broad sweep runs only once under anonymous; the authenticated profile does not repeat the identical cookie-less work. These caps affect only the broad ZAP/Nuclei/Nikto sweep: specialist request-case selectors still accept safe URLs admitted by the configured authorization policy from every observed sibling origin, so a high-value SQLMap, Dalfox, Traversal, IDOR, Authorization, Browser or Workflow candidate is not excluded merely because its origin fell outside the broad-sibling top set. Authentication/session probes are evaluated against the concrete request URL. Raw Cookie headers are never widened to a different hostname; with `allow_same_host_ports=true` they are tried on another authorized port of the same hostname/scheme, matching the fact that HTTP cookies are not port-scoped. The probe must still validate the session. If it fails, browser-derived Domain/Path/Secure/host-only state is tried next and the already-resolved username/password are used only if the login flow requests them; a newly validated origin-specific session then replaces the speculative raw-cookie reuse for subsequent scanners. The resulting contracts are shared by both orchestrators and drive ranking instead of inventing endpoints or parameters.

ZAP active mode is selected from the scan profile rather than from whether the current profile has a cookie: `fast` uses bounded targeted active scanning, `balanced` prioritized active scanning and `deep` the broader bounded mode; `diagnostic_only` remains passive. Scanner inventory is read through the Python API and retried through the raw ZAP JSON API; if metadata is unavailable, a curated set of known injection/path-traversal rule IDs is used as a compatibility fallback. Static assets are excluded from active-case selection. Parameterized request contracts remain the preferred insertion points. If semantic classification produces no compatible parameterized native plan, ZAP now performs a second bounded fallback on at most 1/2/3 safe GET application pages in fast/balanced/deep, with `recurse=False` and a small curated set of installed reflected-XSS, generic-SQLi, traversal and command-injection rules. This allows active coverage on a discovered sibling origin even when its current contracts have no query/body parameters, without turning the fallback into an unbounded recursive active spider. Distinct application endpoints are retained while equivalent request shapes are deduplicated. Planned, attempted, started and completed native cases are counted separately; ZAP reports complete active coverage only when all four counts agree with the planned case count. A planned case that cannot start, remains incomplete, or is not attempted therefore makes the bounded ZAP result partial. Rule IDs are enabled one by one and the wrapper records which IDs ZAP actually accepted. `partial/no_active_scan_rules_enabled` is therefore reserved for the case where neither a compatible parameterized plan nor a safe generic GET fallback with an installed curated rule can be constructed/enabled. Passive observations are retained up to 60/220/450 in fast/balanced/deep so a saturated observation cap is not mistaken for a complete inventory; security findings are kept separately from that observation ceiling.

The current Nuclei pipeline does not invoke `-as` automatic scan: its direct templates are project HTTP templates, official exposure/technology/vulnerability selections come from the official HTTP template tree, and DAST consumes discovered HTTP request contracts. Nuclei's `-pt` option is a **template protocol-type filter** (`http`, `headless`, `workflow`, `tcp`, `dns`, `ssl`, and others); `-pt http` would mean "run only templates whose protocol type is HTTP". It is not a network-scope or port-authorization control. The project therefore does not add a blanket `-pt http` to every phase: the phases that currently run already select HTTP template trees/contracts explicitly, while a blanket filter could later exclude an intentionally selected headless/workflow template. This avoids implicit TCP/DNS/SSL discovery without adding a redundant restriction.

Nuclei consumes discovered request contracts for bounded DAST checks in all three modes: `fast` keeps a small 10-contract sample, while `balanced`/`deep` use larger 64/112-contract ceilings; the initializer now requires a DAST-capable current Nuclei runtime (minimum v3.11.1), verifies the official `nuclei-templates/dast` subtree and performs a template-load DAST runtime check before assessments start. The DAST phase explicitly selects that directory. Request-shaped Proxify JSONL is attempted first; if the engine rejects it, the same GET/POST request contracts are serialized to the other officially supported Proxify YAML MultiDoc input mode; only if both request-shaped modes fail does the wrapper fall back to a plain URL list for compatible GET cases. Every attempt and stderr excerpt remains in coverage diagnostics. Fast uses `-fa low` with `fuzz-param-frequency=20`; balanced uses `-fa medium` with `fuzz-param-frequency=100`; deep uses `-fa high` with `fuzz-param-frequency=1000`. `-fm single` is retained so one parameter is mutated at a time and evidence remains attributable; it is not a low payload-count cap. SQLMap/Dalfox/other parameter scanners rank API/data-oriented contracts, meaningful identifier/query parameters, method and observed JSON/network evidence ahead of navigation-only parameters. After the scanner phases, both orchestrators perform a candidate-driven Chromium verification pass using the per-profile adaptive limits described above: 8/40/120 base candidates in `fast`/`balanced`/`deep`, expandable to 12/64/180 when the deterministic overflow conditions are met. The final action is restricted to the exact source parameter and is matched to the closest request context using the other query parameters, so two candidates on the same path/parameter but with different application context are verified separately. The source context is preserved through reconciliation and final finding deduplication, so a browser outcome cannot be reassigned to or merged with a different XSS context on the same route. The Browser server exports the parameters actually exercised so reconciliation remains deterministic even if nested diagnostics are lost in transport. Confirmed execution upgrades the source candidate and sets high verification confidence. An unexecuted browser reflection keeps the candidate's potential severity unchanged but limits confidence to medium; a successful exact-parameter bounded non-reproduction likewise preserves severity while setting confidence to low. Severity therefore expresses potential impact if the weakness is real, while confidence expresses how strongly the collected evidence supports its existence. For findings without a browser ceiling, the validated AI confidence becomes the final finding confidence. The subsequent AI analysis may enrich wording and reassess severity from impact evidence, but it cannot raise confidence above the deterministic browser ceiling (MEDIUM for reflection without execution, LOW for bounded non-reproduction). Static assets such as CSS, JavaScript, images and fonts are excluded as Browser-XSS targets. Deterministic skips an exact URL/method/parameter case already exercised successfully by its earlier browser/workflow phase; Agentic performs the same bounded verification before AI analysis.

Nikto is reported as `partial` when its process exits successfully but neither request/host-tested metrics nor a structured report are sufficient to verify scan coverage. A positive official `host(s) tested` summary is accepted as completion evidence even when that Nikto build omits the request counter or writes no useful CSV rows. Parsed console findings are preserved, but unverified coverage is never presented as a complete successful scan.

Terminal logging keeps long request URLs compact: when an URL exceeds the configured display threshold, only the endpoint plus parameter/query metadata are printed (for example parameter count and query length). The complete unmodified URL remains stored in scanner results, JSON artifacts and reports. The threshold can be adjusted with `SECOPS_TERMINAL_URL_MAX`.

The generated report also contains an **Endpoint coverage matrix**. It is built from the final discovery state, deterministic selector decisions and the scanner executions, not from finding counts. Each row identifies the assessment profile, HTTP method, discovered endpoint/request context, discovery source, concrete security tools that actually ran against that endpoint, a textual coverage status, a structured reason code and the explanatory reason when no completed test exists. Status values are `Tested`, `Discovered only`, `Skipped`, `Execution error`, `HTTP 404` and `HTTP 410`; no icon or informal symbol is used. Common omission codes include `DEFERRED_LOW_PRIORITY`, `BUDGET_LIMIT`, `NO_COMPATIBLE_PARAMETERS`, `UNSUPPORTED_METHOD`, `STATE_CHANGE_BLOCKED`, `OUT_OF_SCOPE`, `DUPLICATE_ROUTE_VARIANT`, `HTTP_404` and `HTTP_410`; Agentic additionally uses `PLANNER_DEFERRED` when a deterministic request candidate remained unexecuted after tool-group planning. A page merely visited by the crawler is therefore not labelled `Tested`. Broad-scanner evidence is attached to the exact URL when observable: Nuclei focused/DAST inputs and ZAP targeted active scans are labelled separately from request-level specialist executions, so broad coverage is not confused with a direct SQLMap/Dalfox/Commix/Traversal/Authorization-style validation. The section begins with a numeric summary that reports discovered request contexts, reachable/in-scope contexts, contexts tested by at least one concrete security-tool execution, discovery-only contexts, intentional skips, execution errors, HTTP 404/410 responses and tested coverage percentage. Anonymous and authenticated profiles are summarized independently, with an overall row when both are present. In aggregate multi-entry reports each row also retains the source job/entry point, so identical URLs reached from different configured entry points remain attributable. The complete matrix and the machine-readable `endpoint_coverage_summary` are serialized in report JSON and in the review snapshot and are embedded in `Assessment_Results_Data_<ID>.json`.

### Session-lifecycle logout verification

Logout handling is profile-aware and intentionally separate from generic fuzzing. Anonymous discovery does not spend scanner budget on logout/signout/logoff endpoints because there is no authenticated session to invalidate. Authenticated discovery may retain a logout request contract, including a POST form, but does not execute it during ordinary crawling or specialist scanning. After the remaining authenticated checks and final browser verification have completed, the session verifier executes one bounded logout flow and replays the pre-logout cookie against the protected session probe. If the old cookie still provides authenticated access, the result is a deterministically confirmed session-invalidation vulnerability (CWE-613); if the old cookie is rejected, logout invalidation is verified; if the response cannot be distinguished reliably, the check remains partial rather than creating a vulnerability. Login/SSO routing is the inverse: stable application login routes remain observable/testable in the anonymous profile but are not sent to SQLMap/Dalfox/Commix/Traversal from an already authenticated profile. Volatile OAuth/OIDC protocol and application callback instances are excluded from generic injection/traversal/workflow selection in both profiles while their stable login route remains usable for authentication.

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

If either variable is missing and the runner has an interactive terminal, it asks only for the missing value once and hides password input. The values resolved from environment variables or that initial prompt are retained in runner memory for the entire assessment; later sibling-origin authentication never asks for them again in the child/orchestrator console.
These two variables are credentials of the **assessed dashboard account** and are unrelated to `snap4city_model_credentials.json`, which authenticates the Snap4City AI provider used by the Agentic planner. The AI provider is separate from target authentication. `login_path` is an optional optimization, not a mandatory fact that must be known for every application. When it is configured, Chromium tries that application entry point with priority. When it is omitted on the initial target, the browser spends a small bounded fraction of the existing login timeout on generic same-origin pre-auth discovery: it follows only ordinary non-destructive GET navigation candidates, prioritizes generic login/auth/account/app signals, and stops when it observes a login form/control or an OIDC redirect. If that bounded pass finds nothing stronger, authentication falls back to the configured target/root as before. This pre-auth discovery never authorizes another origin and never submits application forms. It cannot guess a completely unlinked secret login route, so an explicit `login_path` remains useful when the login entry is not reachable from the configured target/root or from the few bounded same-origin links it exposes. The login flow itself may traverse a cross-origin identity-provider page, but scanners remain confined to destinations admitted by the configured authorization policy (explicit origins plus the optional same-host/same-scheme multi-port rule). Raw cookies are never copied cross-origin, and the anonymous profile never inherits browser/session state from the authenticated profile.
For `browser_oidc` credentials, `reuse_on_authorized_siblings: true` enables same-issuer/realm reauthentication only for destinations already admitted by the authorization policy; it never widens active scope. On an authorized same-host/same-scheme port, authentication follows a fixed fallback order: **existing raw cookie -> saved browser/OIDC storage state -> the original username/password**. The raw cookie may be tried across the port boundary because cookies are not port-scoped, but it is never copied to a different hostname and is never trusted merely because the host matches: the session probe must validate it. If it is rejected, the browser state is tried and credentials are reused only if the IdP/login flow actually requests them. A successfully repaired session becomes origin-specific and supersedes the failed raw-cookie attempt for subsequent scanners. The username/password, browser storage state and cookies are not written to the source configuration or Results Data. To hand the already-resolved authentication state from `assessmentRunner.py` to the child orchestrator, the runner creates a short-lived mode-0600 JSON file, exposes only its path through `SECOPS_RUNTIME_AUTH_STATE`, and deletes the file as soon as that job exits. `DASHBOARD_TEST_COOKIE='PHPSESSID=<SESSION>; ...'` remains a manual session override: it is never propagated to a different hostname. When `allow_same_host_ports=true`, it may be tried on another discovered/authorized port of the exact same hostname and scheme, but that use must pass the normal session validation; if it fails, saved browser/OIDC state and then the original username/password are used as fallbacks. If username/password are also available they can still be reused for sibling OIDC/SSO; if they are unavailable and the saved SSO state cannot authenticate a sibling, that sibling remains anonymous rather than triggering another console prompt. If no account/session is available, leaving the initial console values empty keeps the optional job anonymous; `--auth-only` instead blocks because an authenticated primary session is required. An authenticated profile is eligible for scanner planning only while discovery has not conclusively marked that session ineffective; an invalid supplied cookie therefore cannot be reported as authenticated coverage or suppress the corresponding anonymous coverage. After initialization, `dashboard-test.json` is included automatically in the generic per-config command list: it receives one Deterministic BALANCED command and one Agentic BALANCED command using `--max-rounds 2 --mode balanced --require-ai` and the effective Agentic model (Snap4City or the verified local fallback). The initializer no longer depends on a hardcoded dashboard-test command and no longer prints the isolated ZAP diagnostic command.


### Tourist dashboard configuration

`configs/tourist-dashboard.json` contains the eight supplied public Snap4City dashboard-view URLs as eight enabled HTTPS service jobs and sets `authorization.allow_same_host_ports=true`; another HTTPS port on `www.snap4city.org` is therefore eligible only if it is actually exposed by normal discovery, not through port enumeration. This configuration is intentionally **anonymous-only**: the eight services do not define `credential_ref` and the file has no target `credentials` block, so `assessmentRunner.py` never asks for `TOURIST_DASHBOARD_COOKIE`, `TOURIST_DASHBOARD_USERNAME` or `TOURIST_DASHBOARD_PASSWORD` and never starts a browser/OIDC login for this assessment. `auth_only=false` keeps the anonymous profile enabled and `allow_state_changes=false` remains explicit for all eight entry points.

The generic rule is the same for any configuration-driven service: **absence of `credential_ref` means no target authentication is attempted for that service**. To convert an authenticated/optional-auth service to anonymous-only, remove its `credential_ref` (or leave it empty); if no service uses that credential anymore, remove the unused entry from the top-level `credentials` object as well. `auth_only=false` alone is not an anonymous-only switch: when a valid `credential_ref` exists, the runner may execute both anonymous and authenticated coverage.

The JSON configuration remains eight services because those are the supplied authorized views. At runtime, before scanners start, the runner detects that the eight enabled services share the same asset, origin, path and safety policy. It coalesces them into one logical job and passes all eight full URLs as forced discovery entry points. Discovery, scanners, Agentic analysis and reporting therefore run once rather than eight times, while every configured dashboard view remains in the initial discovery set. No configuration rewrite is required and `--only <job-id>` still executes one exact service without coalescing for diagnostics. The existing reporting block remains valid:

```json
"reporting": {
  "aggregate_report": true,
  "keep_job_reports": false
}
```

Because the runtime plan now contains one logical job for these equivalent views, it produces one normal job report directly; aggregate reporting remains relevant only when multiple genuinely distinct jobs survive normalization.

The recommended validation command is:

```powershell
python .\assessmentRunner.py --config .\configs\tourist-dashboard.json --orchestrator deterministic --mode balanced --dry-run --authorized
```


### Oversized report transport
Report generation remains on the unified MCP Streamable HTTP endpoint. When the serialized report input exceeds the safe inline threshold, the orchestrator compresses it and sends bounded chunks through repeated MCP/HTTP tool calls; the report service reconstructs the payload in memory and renders it after completeness, size and SHA-256 integrity checks. Client chunk size and total chunk count are bounded consistently with the report server, and the inline threshold is never allowed to exceed the configured report payload ceiling. No local-file handoff is used for report input.

Reporting uses budgets that are separate from ordinary scanner execution. Chunk upload has its own bounded transfer budget and each chunk has an individual HTTP timeout; once all chunks are accepted, reconstruction and rendering use an adaptive report budget based on the uncompressed payload size. Defaults are 120 s per chunk, 900 s for the complete upload, 4200 s plus 60 s per MiB for reconstruction/rendering (capped at 7200 s), and 3600 s for the PDF renderer itself. These are ceilings, not expected durations. While the final MCP rendering call is running, the orchestrator emits periodic `[REPORT WAIT]` heartbeats and, when the locally-owned server log is available, includes its latest `[REPORT SERVER]` stage. Progress therefore remains visible during long PDF conversion instead of leaving an idle SSH terminal. The complete endpoint matrix remains in HTML/JSON/review data; only the print/PDF variant caps detailed endpoint rows at 260 by default (prioritizing execution errors and untested gaps) so thousands of repetitive matrix rows cannot dominate WeasyPrint rendering. If PDF rendering itself fails or reaches its renderer limit, the already-created JSON, HTML and review snapshot paths are returned instead of being discarded. Relevant overrides are `SECOPS_MCP_REPORT_CHUNK_TIMEOUT`, `SECOPS_MCP_REPORT_TRANSFER_TIMEOUT`, `SECOPS_MCP_REPORT_RENDER_TIMEOUT`, `SECOPS_MCP_REPORT_RENDER_SECONDS_PER_MIB`, `SECOPS_MCP_REPORT_RENDER_TIMEOUT_MAX` and `SECOPS_REPORT_PDF_TIMEOUT`.

Report recovery distinguishes a normal `SecOps_*_Assessment_*` artifact from the minimal `SecOps_*_Emergency_*` last-resort artifact. If the report service has already written any normal JSON/HTML/review/PDF artifact but the final MCP/HTTP response is interrupted or reaches its outer time budget, the orchestrator recovers those deterministic paths and does not create an Emergency duplicate. An Emergency report is written only when no normal artifact can be recovered. `assessmentRunner.py` independently applies the same preference when collecting files created during a job, so one job contributes one primary human-facing report: a normal Assessment report wins over an Emergency artifact, and the terminal labels a normal HTML used because the PDF is unavailable as `HTML report (PDF fallback)` while a genuine last-resort artifact is labeled `Emergency HTML report`.
