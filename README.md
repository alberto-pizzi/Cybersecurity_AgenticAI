# Agentic AI Pentesting & Reporting Automation System through MCP

Piattaforma per assessment web autorizzati con discovery condivisa, scanner MCP, autenticazione, orchestrazione Deterministic o Agentic e reporting JSON, HTML e PDF.

Questa guida è pensata anche per chi riceve il progetto senza conoscerne il codice. Il percorso consigliato è: inizializzare l'ambiente, copiare una configurazione di esempio, validarla con `--dry-run`, verificare l'autenticazione se presente e solo dopo avviare l'assessment.

Il progetto non usa benchmark esterni come input runtime. Endpoint, parametri, servizi e request contract devono essere scoperti dal target autorizzato.

## Manuale operativo: avvio rapido

### 1. Preparazione

```bash
cd ~/Cybersecurity_AgenticAI
python initScript.py
```

Questo comando installa o verifica dipendenze, scanner, Chromium e preflight senza avviare il laboratorio di training. Per avviare anche il laboratorio locale e preparare i backend AI usare:

```bash
python initScript.py --with-lab
```

Per stampare soltanto la guida dei comandi, senza installare o avviare componenti:

```bash
python initScript.py --commands-only
```

Requisiti operativi: Python 3.13 nella VM Debian, accesso alla rete del target autorizzato e spazio sufficiente per scanner e report. In una installazione normale non usare `--skip-scanners`.

Per preparare un solo backend AI insieme al laboratorio:

```bash
python initScript.py --with-lab --prepare-ai snap4city
# oppure: llama / qwen
```

Snap4City usa credenziali del provider separate dalle credenziali del target. Se serve specificare il file esplicitamente:

```bash
python initScript.py --with-lab --prepare-ai snap4city \
  --snap4city-credentials snap4city_model_credentials.json
```

### 2. Validazione della configurazione

```bash
python assessmentRunner.py \
  --config ~/Cybersecurity_AgenticAI/configs/dashboard-test.json \
  --orchestrator agentic \
  --mode balanced \
  --max-rounds 2 \
  --require-ai \
  --dry-run \
  --authorized
```

Il dry-run controlla configurazione, scope e job generati. Non avvia gli scanner.

### 3. Assessment Agentic

```bash
python ~/Cybersecurity_AgenticAI/assessmentRunner.py \
  --config ~/Cybersecurity_AgenticAI/configs/dashboard-test.json \
  --orchestrator agentic \
  --max-rounds 2 \
  --mode balanced \
  --require-ai \
  --authorized
```

### 4. Assessment Deterministic

```bash
python ~/Cybersecurity_AgenticAI/assessmentRunner.py \
  --config ~/Cybersecurity_AgenticAI/configs/dashboard-test.json \
  --orchestrator deterministic \
  --mode balanced \
  --authorized
```

## Architettura

I componenti principali sono:

| Componente | Funzione |
| --- | --- |
| `assessmentRunner.py` | Espande la configurazione, prepara i job e avvia l'orchestratore. |
| `orchestratorShared.py` | Discovery, scope, rate, request contract, sessioni e helper comuni. |
| `orchestratorDeterministic.py` | Pipeline fissa e riproducibile. |
| `orchestratorAgentic.py` / `orchestratorAgenticCore.py` | Planner AI, round, execution, verification e analisi finale. |
| `servers/` | Wrapper MCP e controlli sviluppati nel progetto. |
| `servers/reporting/` | Normalizzazione, coverage e rendering dei report. |
| `setupTools.py` | Preparazione e preflight dei tool. |
| `initScript.py` | Inizializzazione e guida operativa. |

Deterministic e Agentic condividono discovery, sessioni, scope, scanner e reporting. La differenza principale è la strategia con cui vengono scelte le azioni.

## Scope e autorizzazione

Lo scope predefinito è same-origin, quindi protocollo, hostname e porta.

`allow_same_host_ports=true` autorizza servizi HTTP o HTTPS su altre porte dello stesso hostname esatto.

`discover_same_host_services=true` abilita la ricerca proattiva di servizi web sullo stesso hostname. Richiede l'autorizzazione multi-porta.

Queste opzioni non autorizzano hostname sibling.

I redirect vengono seguiti solo quando la destinazione rimane autorizzata. Gli scanner che potrebbero seguire redirect autonomamente vengono configurati in modo restrittivo.

`allow_state_changes=false` blocca richieste distruttive o non necessarie. Login e SSO necessari alla sessione vengono gestiti separatamente dal traffico di attacco.

## Rate e parallelismo

Il rate operativo normale è 10 request start/s.

```json
{
  "execution": {
    "request_rate": 10
  }
}
```

Il parallelismo serve a sfruttare l'I/O senza aumentare il picco di richieste. Le richieste controllate dal progetto condividono un pacer. Gli scanner esterni mantengono anche i propri limiti.

Il pacer è condiviso anche tra processi avviati dallo stesso utente sulla VM, quindi due assessment non moltiplicano automaticamente il rate configurato. Evitare comunque run concorrenti sullo stesso target perché duplicano lavoro e possono contendere scanner stateful o risorse locali.

## Discovery

La discovery usa più sorgenti:

- crawler HTTP
- Chromium e Playwright
- link, form, iframe e redirect osservati
- risposte browser e traffico asincrono
- JavaScript e source map quando disponibili
- `robots.txt`, sitemap, OpenAPI, Swagger, manifest e service worker
- FFUF
- Arjun
- ZAP site tree
- service discovery same-host quando autorizzata

Ogni richiesta utile diventa un request contract con metodo, URL, parametri, body e content type.

### Fairness e anti-saturation

La superficie viene divisa in famiglie applicative derivate da origin, directory e struttura osservata. Le nuove famiglie ricevono una prima opportunità prima che una famiglia molto grande consumi tutta la coda.

Le route shape già molto rappresentate perdono priorità rispetto a nuove directory, nuovi endpoint e nuovi request contract.

Le pagine 404 e 410 vengono registrate ma non devono saturare il budget delle pagine utili.

### Browser lento

I profili normali usano timeout browser più ampi del profilo TEST. Una navigazione lenta può ricevere un solo retry entro il budget del profilo. Se Chromium fallisce, il ramo può ancora essere esplorato tramite HTTP quando esiste una risposta utile.

### FFUF, Arjun e ZAP come strumenti che ampliano la discovery

FFUF, Arjun e ZAP possono aggiungere nuova superficie al grafo delle richieste osservate.

FFUF verifica nuovi URL e avvia un recrawl limitato dal budget.

Arjun aggiunge parametri osservati ai request contract.

ZAP può reimportare URL in-scope dal site tree.

Nel percorso Agentic questi tool devono comunque essere selezionati dal modello. Python gestisce solo l’ordine tra gli strumenti che scoprono superficie e quelli che la testano.

## Service discovery same-host

Quando autorizzata, la service discovery cerca servizi HTTP e HTTPS su altre porte dello stesso hostname.

Una porta aperta non viene automaticamente considerata superficie web. Solo i servizi confermati come HTTP o HTTPS diventano origin da esplorare.

Il sweep completo viene memorizzato e non viene ripetuto nei round successivi. Il tempo successivo viene speso sul crawling dei servizi trovati.

Limiti principali di discovery:

| Profilo | HTTP base / max | Chromium base / max | Script | Candidate porte same-host |
| --- | ---: | ---: | ---: | ---: |
| TEST | 8 / 16 | 4 / 8 | 12 | 32 |
| FAST | 360 / 1200 | 220 / 700 | 640 | 8192 |
| BALANCED | 2500 / 8000 | 1500 / 5000 | 4000 | 65535 |
| DEEP | 6000 / 18000 | 3500 / 10000 | 8000 | 65535 |

I ceiling sono limiti massimi, non obiettivi obbligatori. Una discovery può terminare prima quando la coda non produce più nuova superficie.

## Autenticazione

Sono supportati profili anonymous e authenticated.

Le identità possono usare cookie già disponibili oppure workflow browser/OIDC. Le sessioni sono separate per identità e application root.

Prima di un'azione authenticated viene eseguito un precheck. Se la sessione è scaduta, il sistema può provare refresh, riuso dello storage o nuovo login in base alla configurazione.

Fallimenti tecnici ripetuti sullo stesso application scope entrano in cooldown. Un rifiuto conclusivo delle credenziali impedisce submit ripetuti della password.

Se una sessione viene recuperata, le azioni bloccate possono tornare eleggibili nei round successivi.

Per controllare solo l'autenticazione:

```bash
python assessmentRunner.py \
  --config <config.json> \
  --orchestrator agentic \
  --mode balanced \
  --auth-only \
  --authorized
```

## Deterministic

Deterministic usa una pipeline stabilita dal codice. Ranking e deduplica riducono i casi equivalenti. Gli strumenti che ampliano la discovery possono essere eseguiti prima degli specialisti.

Questa modalità è utile quando si vuole una baseline riproducibile.

## Agentic e LangGraph

Agentic costruisce azioni concrete derivate dalla discovery. Una azione identifica almeno tool, profilo, target e request context.

Il planner AI decide quali ID selezionare e in quale ordine. Python controlla scope, safety, compatibilità e risorse.

Il planner non deve perdere candidati per limiti di contesto. Il catalogo viene suddiviso in batch. Se un batch è troppo grande viene diviso. Se una singola azione è accompagnata da troppo contesto storico, vengono compattati solo i metadati consultivi.

Con `--require-ai`, una fase AI obbligatoria che non può essere completata viene segnalata come errore. Non viene sostituita silenziosamente da una scelta deterministica.

### Round e capacità

| Profilo | Round predefiniti | Reference actions / round | Planner max / round | Planner cumulativo |
| --- | ---: | ---: | ---: | ---: |
| TEST | 1 | 24 | 120 s | 120 s |
| FAST | 2 | 180 | 1800 s | 3600 s |
| BALANCED | 2 | 480 | 3600 s | 7200 s |
| DEEP | 3 | 720 | 5400 s | 16200 s |

Le reference actions non sono hard cap di coverage nei profili normali. L'ammissione può crescere quando il catalogo restante e i round disponibili lo richiedono.

Il secondo round riceve il delta della discovery e le famiglie ancora sottocoperte. Un'azione non eseguita nel primo round può rimanere eleggibile.

## Profili e budget

| Fase | TEST | FAST | BALANCED | DEEP |
| --- | ---: | ---: | ---: | ---: |
| Esecuzione operativa | 1,5 h | 16 h | 48 h | 96 h |
| Verifica protetta | 10 min | 60 min | 120 min | 240 min |
| Analisi AI protetta | 10 min | 120 min | 360 min | 720 min |
| Reporting protetto | 20 min | 60 min | 120 min | 240 min |
| Hard watchdog | 3 h | 24 h | 66 h | 128 h |

Il watchdog è una rete di sicurezza contro hang. Non è una durata prevista.

TEST è un profilo diagnostico. FAST, BALANCED e DEEP sono profili di copertura. BALANCED è il default consigliato.

## Tool disponibili

| Tool | Tipo | Origine e runtime | Integrazione del progetto |
| --- | --- | --- | --- |
| FFUF | Discovery | Open source, binario locale | `ffufServer.py` |
| Arjun | Discovery | Open source, Python locale | `arjunServer.py` |
| ZAP | Proxy, spider, DAST | Open source, daemon o Docker | `zapServer.py`, `zapVerification.py` |
| Nuclei | Template scanning e DAST | Open source, binario o Docker | `nucleiServer.py` |
| Nikto | Web server assessment | Open source, Perl o Docker | `niktoServer.py` |
| SQLMap | SQL injection | Open source, checkout GitHub | `sqlmapServer.py` |
| Dalfox | XSS | Open source, binario locale | `dalfoxServer.py` |
| Commix | Command injection | Open source, checkout GitHub | `commixServer.py` |
| Interactsh | OAST | Open source, client locale | `interactshServer.py` |
| IDOR Forge | IDOR e BOLA | Open source, checkout GitHub | `idorForgeServer.py` con fallback nativo |
| Traversal | Traversal e LFI | Codice del progetto | `traversalServer.py` |
| Authorization | Access control | Codice del progetto | `authorizationServer.py` |
| Browser | Verifica client-side | Codice del progetto con Playwright | `browserServer.py` |
| Workflow | Flussi multi-step | Codice del progetto | `workflowServer.py` |
| Session | Session security | Codice del progetto | `sessionServer.py` |
| JWT | Token analysis | Codice del progetto con PyJWT | `jwtServer.py` |

Docker modifica il runtime, non la provenienza del tool. I wrapper sono codice del progetto e non fork degli scanner.

## Reporting

Ogni assessment produce JSON, HTML e PDF quando il renderer è disponibile.

Il JSON contiene il dataset completo. L'HTML è pensato per la consultazione. Il PDF è una sintesi di consegna e può ridurre righe ripetitive quando la matrice è enorme.

Il report separa:

1. finding di sicurezza
2. stato dell'esecuzione dei tool
3. coverage della superficie

Un timeout non significa assenza di vulnerabilità. Nel report, `candidate` indica un problema ancora da verificare e `vulnerability` un finding confermato.

### Analisi AI finale

Nel percorso Agentic la fase finale può produrre descrizione, impatto e remediation per vulnerability e candidate.

I batch vengono controllati contro la finestra di contesto. Un batch troppo grande viene diviso. Un singolo finding enorme viene compattato solo nella copia inviata al modello. L'evidenza originale resta intatta.

### Origine dei testi nel report

In Deterministic, descrizione, impatto e soluzione derivano dallo scanner o dal wrapper. Il reporting può completare campi mancanti solo per vulnerability confermate usando regole conservative.

In Agentic, il nodo di analisi può produrre la narrativa finale per vulnerability e candidate. Il testo e l'evidenza originali rimangono disponibili. Observation e discovery non vengono convertite in vulnerability dall'AI.

Il renderer mostra i campi finali. Non decide autonomamente il contenuto tecnico.

### Report molto grandi

Il payload viene compresso e trasferito in chunk di dimensione limitata. Il fallback locale usa la stessa struttura materializzata del report normale. La crescita della coverage non deve eliminare righe dalla ricostruzione finale.

Se il PDF fallisce ma JSON e HTML sono validi, gli artefatti esistenti vengono conservati.

## Configurazione

Per una nuova applicazione conviene copiare `configs/platform.example.json` e rimuovere ciò che non serve:

```bash
cp configs/platform.example.json configs/mio-target.json
```

Il campo `authorization.confirmed` va impostato a `true` solo dopo aver verificato l'autorizzazione reale. Il parser richiede `schema_version`, `platform`, almeno un elemento in `assets`, almeno un servizio per asset e la sezione `execution`.

Esempio minimo valido:

```json
{
  "schema_version": 1,
  "platform": {"name": "example-target"},
  "authorization": {
    "confirmed": true,
    "reference": "riferimento autorizzazione",
    "allow_same_host_ports": false,
    "discover_same_host_services": false
  },
  "assets": [
    {
      "id": "webhost",
      "host": "target.example",
      "services": [
        {
          "id": "http-main",
          "url": "http://target.example/",
          "auth_only": false,
          "allow_state_changes": false
        }
      ]
    }
  ],
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

Un servizio può usare `url` oppure la combinazione `protocol`, `port` e `base_path`. `allow_same_host_ports` e `discover_same_host_services` appartengono a `authorization`, non al singolo servizio. La seconda opzione richiede la prima.

Per un target autenticato aggiungere una credenziale e collegarla al servizio. Le password non vanno scritte nel JSON. Si indicano i nomi delle variabili d'ambiente:

```json
"credentials": {
  "user": {
    "kind": "browser_oidc",
    "cookie_env": "SECOPS_TARGET_COOKIE",
    "username_env": "SECOPS_TARGET_USERNAME",
    "password_env": "SECOPS_TARGET_PASSWORD",
    "login_path": "/",
    "validation_path": "/",
    "optional": true
  }
}
```

Nel servizio usare `"credential_ref": "user"`. Per più identità usare `credential_refs`. Se le variabili non sono disponibili, i profili browser/OIDC non opzionali possono richiedere i dati in console.

Su Linux, per esempio:

```bash
export SECOPS_TARGET_USERNAME='utente'
export SECOPS_TARGET_PASSWORD='password'
```

Per aggiungere altre origin esatte già autorizzate usare `authorization.allowed_origins` oppure ripetere `--authorized-origin` da CLI. Non usare `allowed_host_suffixes` per l'active testing.

Non inserire nel config elenchi di endpoint presi da ground truth o benchmark. Le entry point devono essere reali punti iniziali autorizzati, non una lista usata per pilotare la discovery.

Prima del run eseguire sempre il dry-run. Per una configurazione con login è utile anche `--auth-only`. Il file `configs/platform.example.json` mostra la forma completa con più asset, più servizi e più identità.

## Opzioni principali di assessmentRunner

`--config FILE` usa una configurazione multi-asset.

`--target URL` esegue un target diretto. Con target diretto, `--cookies` passa la sessione primaria e `--secondary-cookies` aggiunge una seconda identità per confronti authorization/BOLA.

`--orchestrator agentic|deterministic` sceglie il percorso.

`--mode test|fast|balanced|deep` sceglie il profilo.

`--model snap4city|llama|qwen` seleziona il backend AI Agentic.

`--max-rounds 1|2|3` sovrascrive il numero di round Agentic.

`--auth-only` esegue soltanto i profili autenticati.

`--authorized` conferma l'autorizzazione per target non locali.

`--authorized-origin URL` aggiunge una origin esatta autorizzata.

`--allow-same-host-ports` e `--no-allow-same-host-ports` controllano lo scope multi-porta sullo stesso hostname.

`--discover-same-host-services` e `--no-discover-same-host-services` controllano la service discovery proattiva.

`--allow-state-changes` e `--no-allow-state-changes` controllano i probe che possono modificare stato, sempre entro limiti di tempo e quantità.

`--require-ai` rende obbligatori planning e final analysis AI. `--no-require-ai` consente il fallback previsto dal progetto.

`--dry-run` valida il piano senza avviare gli scanner.

`--only ID` limita l'esecuzione a uno specifico job di servizio.

`--stop-on-error` interrompe dopo il primo job bloccato. Un exit non-zero dell'orchestratore eseguibile è comunque fatale.

Per la lista sempre aggiornata usare `python assessmentRunner.py --help`. Per le opzioni di installazione e preflight usare `python initScript.py --help`.

## Monitoraggio

```bash
mkdir -p logs
LOG="logs/balanced_$(date +%Y%m%d_%H%M%S).log"
python assessmentRunner.py \
  --config configs/dashboard-test.json \
  --orchestrator agentic \
  --max-rounds 2 \
  --mode balanced \
  --require-ai \
  --authorized > "$LOG" 2>&1
```

```bash
tail -n 300 -F "$LOG"
```

Per sessioni SSH lunghe usare `tmux`.

## Dove sono i risultati

Gli artefatti sono salvati in `reports/`.

Per scaricare un file:

```bash
scp debian@<host>:/home/debian/Cybersecurity_AgenticAI/reports/<file> .
```

## Troubleshooting

| Problema | Controllo |
| --- | --- |
| Login fallito | Verificare credenziali, redirect OIDC e log auth. |
| Molti auth precheck falliti | Verificare la sessione sulla specifica radice applicativa. |
| Discovery con coda residua | Controllare limiti, pagine lente e se la coda di discovery sta ancora producendo nuovi endpoint. |
| Planner fallito | Controllare provider, budget e diagnostica dei batch. |
| Tool partial | Leggere il codice diagnostico e il timeout. |
| PDF mancante | Usare HTML e JSON e controllare la diagnostica del renderer. |
| Rate sotto 10 req/s | Il rate è un massimo. Pagine lente e tool seriali possono non saturarlo. |

## Sicurezza operativa

Usare soltanto target propri o esplicitamente autorizzati.

Il limite di traffico è coordinato cross-process. Evitare comunque assessment concorrenti sullo stesso target per non duplicare lavoro e stato degli scanner.

Non abilitare state-changing probe senza una necessità esplicita.

Non interpretare zero finding come prova di assenza di vulnerabilità senza controllare coverage e limitation.
