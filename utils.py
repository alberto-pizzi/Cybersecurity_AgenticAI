from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

import requests

ROOT_DIR = Path(__file__).resolve().parent
SERVERS_DIR = ROOT_DIR / "servers"
REPORTS_DIR = ROOT_DIR / "reports"
WORDLISTS_DIR = ROOT_DIR / "wordlists"
LOCAL_BIN = Path.home() / ".local" / "bin"

_SOURCE_FINGERPRINT_CACHE: str | None = None


def safe_int_value(value: Any, default: int = 0) -> int:
    """Return an integral finite metadata value or a safe default.

    This is intended for scanner/MCP/report metadata, not user-facing numeric parsing. Booleans are
    rejected explicitly because Python treats them as integers. Fractional/non-finite values are
    rejected rather than silently truncated.
    """
    if isinstance(value, bool):
        return int(default)
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return int(default)
    if not math.isfinite(number) or not number.is_integer():
        return int(default)
    try:
        return int(number)
    except (TypeError, ValueError, OverflowError):
        return int(default)


def safe_port_value(value: Any, default: int) -> int:
    """Return a valid TCP/UDP port or a validated default without raising."""
    fallback = safe_int_value(default, 80)
    if not 1 <= fallback <= 65535:
        fallback = 80
    port = safe_int_value(value, fallback)
    return port if 1 <= port <= 65535 else fallback


def safe_float_value(value: Any, default: float = 0.0) -> float:
    """Return finite floating metadata or a safe default without raising."""
    if isinstance(value, bool):
        return float(default)
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return float(default)
    return number if math.isfinite(number) else float(default)


def deadline_bounded_request_timeout(
    configured_timeout: Any, deadline: float, *, connect_ratio: float = 0.25, minimum_component: float = 0.01,
) -> tuple[float, float]:
    """Return Requests connect/read timeouts whose combined allowance fits the remaining deadline.

    Requests interprets a scalar or a ``(connect, read)`` tuple as independent socket phase
    timeouts, not as one wall-clock total.  When a scanner already owns a monotonic deadline,
    allowing each component to equal the whole remaining budget can approximately double the
    intended phase allowance on a slow connection.  This helper preserves configured component
    caps while splitting the currently remaining budget between connect and read.
    """
    left = float(deadline) - time.monotonic()
    if left <= 0:
        raise requests.Timeout("shared scanner deadline reached")

    floor = max(0.001, min(float(minimum_component), left / 2.0))
    if isinstance(configured_timeout, tuple) and len(configured_timeout) == 2:
        connect_cap = max(floor, safe_float_value(configured_timeout[0], left))
        read_cap = max(floor, safe_float_value(configured_timeout[1], left))
        total_cap = connect_cap + read_cap
        preferred_ratio = connect_cap / total_cap if total_cap > 0 else 0.25
    elif configured_timeout is None:
        connect_cap = read_cap = left
        preferred_ratio = max(0.05, min(float(connect_ratio), 0.95))
    else:
        cap = max(floor, safe_float_value(configured_timeout, left))
        connect_cap = read_cap = cap
        preferred_ratio = max(0.05, min(float(connect_ratio), 0.95))

    if connect_cap + read_cap <= left:
        return float(connect_cap), float(read_cap)

    connect_timeout = min(connect_cap, max(floor, left * preferred_ratio))
    read_timeout = min(read_cap, max(floor, left - connect_timeout))

    # Tiny floating-point/floor corrections must never inflate the pair beyond ``left``.
    if connect_timeout + read_timeout > left:
        read_timeout = max(0.001, left - connect_timeout)
    if connect_timeout + read_timeout > left:
        connect_timeout = max(0.001, left - read_timeout)
    return float(connect_timeout), float(read_timeout)


def safe_bool_value(value: Any, default: bool = False) -> bool:
    """Normalize bool-like scanner metadata without truthiness surprises."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = safe_float_value(value, float('nan'))
        if math.isfinite(number) and number in {0.0, 1.0}:
            return bool(int(number))
        return bool(default)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {'true', 'yes', 'on', '1'}:
            return True
        if normalized in {'false', 'no', 'off', '0', ''}:
            return False
    return bool(default)

# Fingerprint the active SecOps Python source tree so an orchestrator never silently reuses an
# MCP server that was started from stale code. The value is cached per process: the server keeps
# the fingerprint of the files it actually loaded at startup, while a newly started orchestrator
# computes the fingerprint of its own checkout. Identical source trees may live at different paths.
def secops_source_fingerprint() -> str:
    global _SOURCE_FINGERPRINT_CACHE
    if _SOURCE_FINGERPRINT_CACHE is not None:
        return _SOURCE_FINGERPRINT_CACHE
    digest = hashlib.sha256()
    candidates = [path for path in ROOT_DIR.glob("*.py") if path.is_file()]
    if SERVERS_DIR.is_dir():
        candidates.extend(path for path in SERVERS_DIR.rglob("*.py") if path.is_file() and "__pycache__" not in path.parts)
    for path in sorted(candidates, key=lambda item: item.relative_to(ROOT_DIR).as_posix().lower()):
        relative = path.relative_to(ROOT_DIR).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    _SOURCE_FINGERPRINT_CACHE = digest.hexdigest()
    return _SOURCE_FINGERPRINT_CACHE

# Central fail-closed request-state policy shared by orchestrators and direct MCP wrappers.
# GET/HEAD/OPTIONS remain eligible unless the route explicitly represents a mutation; PUT/PATCH/
# DELETE are always blocked when state changes are disabled. POST is accepted only with strong
# read-only evidence, so direct tool calls cannot bypass the orchestrator's safety gate.
def request_contract_state_change_reason(case: dict[str, Any]) -> str:
    if not isinstance(case, dict):
        return ""
    url = str(case.get("url") or "")
    method = str(case.get("method") or "GET").upper()
    try:
        parsed = urlparse(url)
    except ValueError:
        parsed = urlparse("")
    raw_path = str(parsed.path or "")
    path = raw_path.lower()

    # Method-override mechanisms can turn an apparently read-only outer request into PUT/PATCH/
    # DELETE on common frameworks. Treat both headers and conventional query/body fields as the
    # effective method for the state-change gate instead of trusting the transport verb alone.
    headers = case.get("headers")
    header_pairs: list[tuple[str, str]] = []
    if isinstance(headers, dict):
        header_pairs = [(str(name).lower(), str(value).strip().upper()) for name, value in headers.items()]
    elif isinstance(headers, (list, tuple)):
        for row in headers:
            if isinstance(row, (list, tuple)) and len(row) >= 2:
                header_pairs.append((str(row[0]).lower(), str(row[1]).strip().upper()))
    override_header_names = {"x-http-method-override", "x-http-method", "x-method-override", "x-original-method"}
    for name, value in header_pairs:
        if name in override_header_names and value and value not in {"GET", "HEAD", "OPTIONS"}:
            return f"state-changing HTTP method override: {value}"
    path_tokens = {token for token in re.split(r"[^a-z0-9]+", path) if token}
    mutating_tokens = {
        "delete", "remove", "destroy", "reset", "install", "reinstall", "uninstall", "setup",
        "upload", "register", "signup", "create", "update", "save", "modify", "change",
        "truncate", "purge", "wipe", "logout", "signout", "logoff", "commit", "approve",
        "reject", "enable", "disable", "activate", "deactivate", "publish", "unpublish",
    }
    destructive_get_tokens = {
        "delete", "remove", "destroy", "reinstall", "uninstall", "truncate", "purge",
        "wipe", "logout", "signout", "logoff",
    }
    # A mutating parent route can expose a read-only child endpoint (for example
    # /setup/status or /upload/validate). These tokens are also used to distinguish a descriptive
    # GET route such as /delete/preview from an imperative /delete/123 action.
    read_only_route_tokens = {
        "search", "query", "lookup", "find", "filter", "list", "read", "get", "fetch",
        "preview", "validate", "check", "status", "report", "export", "autocomplete",
        "suggest", "resolve", "inspect", "view", "select", "load", "retrieve", "describe",
        "count", "info", "details",
    }
    basename = raw_path.rstrip("/").rsplit("/", 1)[-1].rsplit(".", 1)[0]
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", basename)
    basename_tokens = [token.lower() for token in re.split(r"[^A-Za-z0-9]+", separated) if token]
    final_path_tokens = set(basename_tokens)
    read_only_post_route = bool(final_path_tokens & read_only_route_tokens)

    def route_segment_tokens(segment: str) -> set[str]:
        stem = str(segment or "").rsplit(".", 1)[0]
        split_camel = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", stem)
        return {token.lower() for token in re.split(r"[^A-Za-z0-9]+", split_camel) if token}

    route_segments = [segment for segment in raw_path.split("/") if segment]
    navigational_reset_suffixes = {"password", "form", "page", "view", "preview", "request", "token"}
    destructive_route = False
    for index, segment in enumerate(route_segments):
        tokens = route_segment_tokens(segment)
        hits = tokens & destructive_get_tokens
        if not hits:
            continue
        # /reset-password and delete-preview style resources describe a page/preview rather than an
        # action. A destructive parent followed by an explicit read-only child is treated likewise.
        if "reset" in hits and len(basename_tokens) > 1 and basename_tokens[0] == "reset" and basename_tokens[1] in navigational_reset_suffixes:
            continue
        if tokens & read_only_route_tokens:
            continue
        if index + 1 < len(route_segments):
            next_tokens = route_segment_tokens(route_segments[index + 1])
            if next_tokens & read_only_route_tokens:
                continue
        destructive_route = True
        break
    if destructive_route:
        return "destructive or state-changing route"
    if method in {"POST", "JSON", "XML"} and path_tokens & mutating_tokens and not read_only_post_route:
        return "state-changing POST route"

    query_pairs = [(str(name).lower(), str(value).lower()) for name, value in parse_qsl(parsed.query, keep_blank_values=True)]
    content_type = str(case.get("content_type") or case.get("enctype") or "").lower()

    def graphql_document_kind(value: str) -> str:
        """Classify top-level GraphQL operation definitions without mistaking fields/names for them."""
        text = str(value or "")
        n = len(text)
        i = 0
        operation_types: list[str] = []
        saw_fragment = False

        def skip_ignored(pos: int) -> int:
            while pos < n:
                if text[pos].isspace() or text[pos] == ",":
                    pos += 1
                    continue
                if text[pos] == "#":
                    newline = text.find("\n", pos + 1)
                    pos = n if newline < 0 else newline + 1
                    continue
                break
            return pos

        def read_name(pos: int) -> tuple[str, int]:
            if pos >= n or not (text[pos].isalpha() or text[pos] == "_"):
                return "", pos
            end = pos + 1
            while end < n and (text[end].isalnum() or text[end] == "_"):
                end += 1
            return text[pos:end], end

        def skip_string(pos: int) -> int:
            # GraphQL supports ordinary quoted strings and triple-quoted block strings. Braces and
            # operation keywords inside either form are data, not document structure.
            if text.startswith('"""', pos):
                end = text.find('"""', pos + 3)
                return n if end < 0 else end + 3
            pos += 1
            while pos < n:
                if text[pos] == "\\":
                    pos += 2
                    continue
                if text[pos] == '"':
                    return pos + 1
                pos += 1
            return n

        def skip_selection_set(pos: int) -> int:
            depth = 0
            while pos < n:
                ch = text[pos]
                if ch == '"':
                    pos = skip_string(pos)
                    continue
                if ch == "#":
                    pos = skip_ignored(pos)
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth <= 0:
                        return pos + 1
                pos += 1
            return n

        def find_selection_set(pos: int) -> int:
            paren = bracket = object_depth = 0
            while pos < n:
                ch = text[pos]
                if ch == '"':
                    pos = skip_string(pos)
                    continue
                if ch == "#":
                    pos = skip_ignored(pos)
                    continue
                if ch == "(":
                    paren += 1
                elif ch == ")" and paren:
                    paren -= 1
                elif ch == "[":
                    bracket += 1
                elif ch == "]" and bracket:
                    bracket -= 1
                elif ch == "{":
                    if paren or bracket or object_depth:
                        object_depth += 1
                    else:
                        return pos
                elif ch == "}" and object_depth:
                    object_depth -= 1
                pos += 1
            return -1

        while True:
            i = skip_ignored(i)
            if i >= n:
                break
            if text[i] == "{":
                operation_types.append("query")  # shorthand query operation
                i = skip_selection_set(i)
                continue
            word, after_word = read_name(i)
            if not word:
                break
            kind = word.lower()
            if kind not in {"query", "mutation", "subscription", "fragment"}:
                # A non-definition token at document level means this is not confidently parseable
                # as GraphQL; the caller will keep a GraphQL route/content-type fail-closed.
                break
            selection = find_selection_set(after_word)
            if selection < 0:
                # A bare word such as ordinary search text `query=mutation` is not a GraphQL
                # operation definition unless it actually owns a selection set.
                break
            if kind in {"query", "mutation", "subscription"}:
                operation_types.append(kind)
            else:
                saw_fragment = True
            i = skip_selection_set(selection)

        if any(kind == "mutation" for kind in operation_types):
            return "mutation"
        if any(kind == "subscription" for kind in operation_types):
            return "subscription"
        if operation_types and all(kind == "query" for kind in operation_types):
            return "query"
        if saw_fragment:
            return "fragment"
        return ""

    # GraphQL-over-HTTP normally rejects mutations sent with GET, but the central safety gate must
    # not rely on the target being standards-compliant. Detect an actual GraphQL document in the
    # URL before the generic GET early-return, while leaving ordinary ?query=search-text untouched.
    url_graphql_values = [
        value for name, value in query_pairs
        if name == "query" or re.split(r"[.\[]", name)[-1].rstrip("]") == "query"
    ]
    url_graphql = str(url_graphql_values[-1] if url_graphql_values else "").strip()
    url_graphql_kind = graphql_document_kind(url_graphql)
    if method in {"GET", "HEAD", "OPTIONS"} and url_graphql_kind in {"mutation", "subscription"}:
        return "state-changing GraphQL operation"

    # Only controller/action selectors make their *value* part of the current operation. Navigation
    # parameters (next/redirect/url/path/target/...) are deliberately not included: they do not by
    # themselves mutate the current request, and any resulting redirect is checked before following.
    action_names = {"action", "operation", "op", "task", "mode", "command", "do", "event",
                    "method", "_method", "http_method", "httpmethod"}
    benign_action_values = {"view", "show", "list", "read", "get", "search", "query", "find", "lookup", "status", "preview", "check", "validate", "report", "export", "count", "info", "details"}
    falsey_values = {"", "0", "false", "no", "off", "none", "null"}
    explicit_mutating_field_names = {
        "delete", "remove", "destroy", "reset", "upload", "register", "signup", "create",
        "update", "save", "modify", "change", "truncate", "purge", "wipe", "logout",
        "signout", "logoff", "commit", "approve", "reject", "enable", "disable", "activate",
        "deactivate", "publish", "unpublish",
    }
    for name, value in query_pairs:
        leaf_name = re.split(r"[.\[]", name)[-1].rstrip("]")
        # Match an explicit controller field, not a descriptive name such as last_update or
        # created_at. This keeps filters/metadata discoverable while still blocking delete=1 etc.
        if leaf_name in explicit_mutating_field_names and value not in falsey_values:
            return "state-changing URL parameter"
        if name in {"method", "_method", "http_method", "httpmethod"}:
            override = value.strip().upper()
            if override and override not in {"GET", "HEAD", "OPTIONS"}:
                return f"state-changing URL method override: {override}"
        if name in action_names:
            tokens = {token for token in re.split(r"[^a-z0-9]+", value) if token}
            if tokens & mutating_tokens and not tokens <= benign_action_values:
                return "state-changing URL action"

    if method in {"PUT", "PATCH", "DELETE"}:
        return f"state-changing {method} request method"
    if method in {"GET", "HEAD", "OPTIONS"}:
        # Bodies/files on normally read-only methods are non-standard and cannot be assumed harmless.
        # Ordinary discovery does not use them, so failing closed here removes an edge-case bypass
        # without reducing normal GET/HEAD/OPTIONS coverage.
        if str(case.get("data") or "").strip() or case.get("file_parameters"):
            return f"{method} request with body/files not proven read-only"
        return ""
    if method not in {"POST", "JSON", "XML"}:
        return f"HTTP method {method or 'UNKNOWN'} not proven read-only"

    file_parameters = {str(value).strip().lower() for value in case.get("file_parameters", []) if str(value).strip()}
    if file_parameters or "multipart/form-data" in content_type:
        return "file-upload POST contract"

    pairs = list(query_pairs)
    raw_data = str(case.get("data") or "")
    payload: Any = None
    if raw_data:
        if "json" in content_type or method == "JSON" or raw_data.lstrip().startswith(("{", "[")):
            try:
                payload = json.loads(raw_data)
            except Exception:
                payload = None
            def add_json(value: Any, prefix: str = "", depth: int = 0) -> None:
                if depth > 5:
                    return
                if isinstance(value, dict):
                    for name, nested in value.items():
                        key = f"{prefix}.{name}" if prefix else str(name)
                        if isinstance(nested, (dict, list)):
                            add_json(nested, key, depth + 1)
                        else:
                            pairs.append((key.lower(), str(nested or "").lower()))
                elif isinstance(value, list):
                    for index, nested in enumerate(value[:40]):
                        add_json(nested, f"{prefix}[{index}]" if prefix else f"[{index}]", depth + 1)
            if isinstance(payload, (dict, list)):
                add_json(payload)
        else:
            pairs.extend((str(name).lower(), str(value).lower()) for name, value in parse_qsl(raw_data, keep_blank_values=True))
    for field in case.get("fields", []) if isinstance(case.get("fields"), list) else []:
        if isinstance(field, dict) and field.get("name"):
            pairs.append((str(field.get("name")).lower(), str(field.get("value") or "").lower()))

    names = {name for name, _ in pairs}
    leaf_names = {re.split(r"[.\[]", name)[-1].rstrip("]") for name in names}

    # Method overrides are authoritative even on otherwise read-only endpoints or GraphQL queries.
    for name, value in pairs:
        leaf = re.split(r"[.\[]", name)[-1].rstrip("]")
        if name in {"method", "_method", "http_method", "httpmethod"} or leaf in {"method", "_method", "http_method", "httpmethod"}:
            override = value.strip().upper()
            if override and override not in {"GET", "HEAD", "OPTIONS"}:
                return f"state-changing POST method override: {override}"

    # GraphQL operation type is stronger evidence than variable names, but a generic form/API field
    # named ``query`` is extremely common and must not by itself reclassify an ordinary read-only
    # search endpoint as GraphQL. Treat the request as GraphQL only when the route/content type says
    # so, or when a JSON/form ``query`` value actually looks like a GraphQL document. This preserves
    # safe POST /search and POST /query coverage while still blocking mutation/subscription traffic.
    graphql_values = [value for name, value in pairs if name == "query" or re.split(r"[.\[]", name)[-1].rstrip("]") == "query"]
    if isinstance(payload, dict):
        graphql = str(payload.get("query") or "").strip()
    elif graphql_values:
        graphql = str(graphql_values[-1]).strip()
    elif raw_data and ("graphql" in path or "graphql" in content_type):
        # application/graphql (and some GraphQL endpoints without an explicit content type) carry
        # the GraphQL document directly in the POST body rather than in a form/JSON `query` field.
        graphql = raw_data.strip()
    else:
        graphql = ""
    graphql_kind = graphql_document_kind(graphql)
    graphql_request = bool("graphql" in path or "graphql" in content_type or graphql_kind)
    if graphql_request:
        if graphql_kind == "query":
            return ""
        if graphql_kind in {"mutation", "subscription"}:
            return "state-changing GraphQL operation"
        return "POST contract not proven read-only while state changes are disabled"

    mutating_names = {
        "password_new", "password_conf", "new_password", "confirm_password", "newpassword",
        "role_update", "permission_update",
    }
    if (names & mutating_names or leaf_names & mutating_names) and not read_only_post_route:
        return "state-changing POST field"
    if {"username", "password"} <= names or {"user", "password"} <= names:
        return "authentication POST contract"
    for name, value in pairs:
        leaf = re.split(r"[.\[]", name)[-1].rstrip("]")
        if leaf in explicit_mutating_field_names and value not in falsey_values and not read_only_post_route:
            return "state-changing POST field"
        if name in action_names or leaf in action_names:
            tokens = {token for token in re.split(r"[^a-z0-9]+", value) if token}
            if tokens & mutating_tokens:
                return "state-changing POST action"

    read_only_tokens = read_only_route_tokens | {"calculate", "compute"}
    if path_tokens & read_only_tokens:
        return ""
    for name, value in pairs:
        leaf = re.split(r"[.\[]", name)[-1].rstrip("]")
        if name in action_names or leaf in action_names:
            values = {token for token in re.split(r"[^a-z0-9]+", value) if token}
            if values & (read_only_tokens | benign_action_values):
                return ""
    return "POST contract not proven read-only while state changes are disabled"


def request_contract_allowed(case: dict[str, Any], allow_state_changes: bool) -> tuple[bool, str]:
    if allow_state_changes:
        return True, ""
    reason = request_contract_state_change_reason(case)
    return not bool(reason), reason


def request_invocation_state_change_reason(
    method: str, url: str, *, data: Any = None, json_body: Any = None, params: Any = None,
    files: Any = None, headers: Any = None,
) -> str:
    """Classify the concrete HTTP invocation before any network request is sent.

    This is defense-in-depth for shared HTTP helpers: wrappers should still reject unsafe contracts
    before constructing a scan, but a forgotten wrapper gate must not make the first request
    fail-open. Query params/body/file metadata are normalized to the same central policy shape.
    """
    effective_url = str(url or "")
    if params not in (None, "", {}, []):
        try:
            effective_url = str(requests.Request("GET", effective_url, params=params).prepare().url or effective_url)
        except Exception:
            # If parameters cannot be serialized, the concrete URL cannot be classified before
            # transmission. Fail closed for every method instead of treating an unrenderable GET as
            # implicitly safe.
            return "request parameters could not be normalized for state-change policy"
    content_type = ""
    if isinstance(headers, dict):
        content_type = next((str(value) for name, value in headers.items() if str(name).lower() == "content-type"), "")
    body = ""
    if json_body is not None:
        try:
            body = json.dumps(json_body, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            return "JSON request body could not be normalized for state-change policy"
        content_type = content_type or "application/json"
    elif data not in (None, ""):
        if isinstance(data, (dict, list, tuple)):
            try:
                prepared = requests.Request("POST", "http://secops.invalid/", data=data).prepare()
                raw_body = prepared.body
                body = raw_body.decode("utf-8", errors="replace") if isinstance(raw_body, bytes) else str(raw_body or "")
                content_type = content_type or str(prepared.headers.get("Content-Type") or "")
            except Exception:
                return "request body could not be normalized for state-change policy"
        else:
            body = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
    file_parameters: list[str] = []
    if files:
        if isinstance(files, dict):
            file_parameters = [str(name) for name in files]
        elif isinstance(files, (list, tuple)):
            for row in files:
                if isinstance(row, (list, tuple)) and row:
                    file_parameters.append(str(row[0]))
        if not file_parameters:
            file_parameters = ["file"]
    return request_contract_state_change_reason({
        "url": effective_url, "method": str(method or "GET").upper(), "data": body,
        "content_type": content_type, "file_parameters": file_parameters, "headers": headers or {},
    })

# Returns a non-reversible identifier for one HTTP request body contract. The report uses this
# only to keep distinct POST bodies separate without exposing submitted values or credentials.
def request_body_fingerprint(method: str, data: str = "", parameters: Iterable[str] | None = None) -> str:
    if str(method or "GET").upper() != "POST":
        return ""
    payload = str(data or "")
    names = sorted({str(value).strip().lower() for value in (parameters or []) if str(value).strip()})
    if not payload and not names:
        return ""
    digest = hashlib.sha256()
    digest.update(payload.encode("utf-8", errors="replace"))
    digest.update(b"\0")
    digest.update("\n".join(names).encode("utf-8", errors="replace"))
    return digest.hexdigest()[:16]

# Persist text artifacts atomically on Linux, macOS and Windows. A crash can therefore leave the
# previous complete file or the new complete file, rather than a half-written Results Data/report.
def atomic_write_text(path: str | Path, text: str, *, encoding: str = "utf-8") -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding=encoding, dir=str(destination.parent),
            prefix=f".{destination.name}.", suffix=".tmp", delete=False, newline="",
        ) as handle:
            temporary_name = handle.name
            handle.write(text)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        os.replace(temporary_name, destination)
        temporary_name = ""
        return destination
    finally:
        if temporary_name:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass

# Shared assessment traffic policy. The assessment configuration selects the effective
# per-active-scanner request rate. Ten requests/second is the project default. Integer values
# from 1 through 50 are accepted. Invalid, fractional, non-finite, non-positive or above-cap values fall back
# to the default instead of being silently clamped, so an accidental value cannot create a
# substantially different traffic profile than the operator intended.
DEFAULT_REQUEST_RATE = 10.0
REQUEST_RATE_HARD_CAP = 50.0
# Shared upper bound for authenticated identities attached to one service/direct target.
# This bounds profile multiplication and O(N^2) cross-account authorization comparisons.
MAX_AUTHENTICATED_IDENTITIES = 16
IDENTITY_LABEL_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

def valid_identity_label(value: str) -> bool:
    return bool(IDENTITY_LABEL_RE.fullmatch(str(value or "").strip()))
_REQUEST_RATE_UNSET = object()

def scanner_request_rate_policy(value: Any = _REQUEST_RATE_UNSET) -> dict[str, Any]:
    use_environment = value is _REQUEST_RATE_UNSET
    env_value = os.getenv("SECOPS_MAX_REQUEST_RATE") if use_environment else None
    raw = env_value if env_value not in (None, "") else (DEFAULT_REQUEST_RATE if use_environment else value)
    fallback_reason = ""
    try:
        if isinstance(raw, bool):
            raise ValueError("boolean request rate is not valid")
        rate = float(raw)
    except (TypeError, ValueError):
        rate = DEFAULT_REQUEST_RATE
        fallback_reason = "invalid request-rate value"
    if not math.isfinite(rate):
        rate = DEFAULT_REQUEST_RATE
        fallback_reason = "non-finite request-rate value"
    elif not rate.is_integer():
        rate = DEFAULT_REQUEST_RATE
        fallback_reason = "request rate must be an integer number of requests/second"
    elif rate < 1.0:
        rate = DEFAULT_REQUEST_RATE
        fallback_reason = "request rate must be at least 1 request/second"
    elif rate > REQUEST_RATE_HARD_CAP:
        rate = DEFAULT_REQUEST_RATE
        fallback_reason = f"request rate exceeds the maximum of {REQUEST_RATE_HARD_CAP:g} requests/second"
    return {
        "requested": raw,
        "effective": rate,
        "default": DEFAULT_REQUEST_RATE,
        "hard_cap": REQUEST_RATE_HARD_CAP,
        "fallback_applied": bool(fallback_reason),
        "fallback_reason": fallback_reason,
    }

def scanner_request_rate(value: Any = _REQUEST_RATE_UNSET) -> float:
    return float(scanner_request_rate_policy(value)["effective"])


class RequestRatePacer:
    """Per-tool-call HTTP pacer shared by project-controlled request helpers.

    The orchestrators execute specialist tools sequentially, but one custom checker can issue
    several requests of its own. Reusing one pacer for the whole checker keeps those requests
    under the configured assessment rate, including each redirect hop and retry.
    """

    def __init__(self, request_rate: Any = _REQUEST_RATE_UNSET) -> None:
        self.rate = scanner_request_rate(request_rate)
        self.interval_seconds = 1.0 / self.rate
        self._last_request_at = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = self.interval_seconds - (now - self._last_request_at)
            if delay > 0:
                time.sleep(delay)
            self._last_request_at = time.monotonic()


def runtime_request_rate_policy() -> dict[str, Any]:
    policy = scanner_request_rate_policy()
    requested = os.getenv("SECOPS_REQUEST_RATE_REQUESTED")
    if requested not in (None, ""):
        policy["requested"] = requested
    configured = os.getenv("SECOPS_REQUEST_RATE_CONFIGURED")
    if configured is not None:
        policy["configured"] = configured == "1"
        policy["source"] = "execution.request_rate" if policy["configured"] else "default"
    fallback = os.getenv("SECOPS_REQUEST_RATE_FALLBACK")
    if fallback is not None:
        policy["fallback_applied"] = fallback == "1"
    reason = os.getenv("SECOPS_REQUEST_RATE_FALLBACK_REASON")
    if reason is not None:
        policy["fallback_reason"] = reason
    return policy


MCP_HTTP_HOST = "127.0.0.1"
MCP_HTTP_PATH = "/mcp"
MCP_UNIFIED_SERVICE = "secops"
MCP_SERVER_PORTS: dict[str, int] = {MCP_UNIFIED_SERVICE: 8100}


# The complete security catalogue is exposed through one local MCP service.
def mcp_http_port(service_name: str = MCP_UNIFIED_SERVICE) -> int:
    name = str(service_name or MCP_UNIFIED_SERVICE).strip().lower()
    if name not in MCP_SERVER_PORTS:
        raise KeyError(f"Unknown MCP HTTP service: {service_name}")
    return int(MCP_SERVER_PORTS[name])


# Builds the local URL of the unified MCP security service.
def mcp_http_url(service_name: str = MCP_UNIFIED_SERVICE, host: str = MCP_HTTP_HOST) -> str:
    return f"http://{host}:{mcp_http_port(service_name)}{MCP_HTTP_PATH}"


# Only the unified interface is allowed to own an MCP HTTP listener.
def run_mcp_http(mcp: Any, service_name: str = MCP_UNIFIED_SERVICE) -> None:
    name = str(service_name or MCP_UNIFIED_SERVICE).strip().lower()
    if name != MCP_UNIFIED_SERVICE:
        raise RuntimeError(
            f"Standalone MCP service '{service_name}' is disabled; run servers/secopsServer.py instead."
        )
    host = os.getenv("SECOPS_MCP_HOST", MCP_HTTP_HOST).strip() or MCP_HTTP_HOST
    port = safe_int_value(os.getenv("SECOPS_MCP_PORT", str(mcp_http_port(MCP_UNIFIED_SERVICE))), mcp_http_port(MCP_UNIFIED_SERVICE))
    mcp.run(transport="http", host=host, port=port)

_FATAL_STARTUP_PATTERNS = (
    r"is not recognized as an internal or external command",
    r"non .? riconosciuto come comando interno o esterno",
    r"can't open perl script",
    r"cannot open perl script",
    r"modulenotfounderror",
    r"traceback \(most recent call last\)",
    r"createprocess error",
    r"/usr/bin/env:.*no such file",
)


_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


# Parses a Cookie header and rejects invalid or duplicate cookie names.
def parse_cookie_header(value: str) -> list[tuple[str, str]]:


    text = str(value or "").strip()
    if not text:
        return []
    if "\r" in text or "\n" in text:
        raise ValueError("Cookie header contains a prohibited control character.")

    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"Invalid cookie pair without '=': {part!r}")
        name, cookie_value = part.split("=", 1)
        name = name.strip()
        cookie_value = cookie_value.strip()
        if not name or not _COOKIE_NAME_RE.fullmatch(name):
            raise ValueError(f"Invalid cookie name: {name!r}")
        lowered = name.lower()
        if lowered in seen:
            raise ValueError(f"Duplicate cookie name: {name}")
        seen.add(lowered)
        pairs.append((name, cookie_value))
    return pairs


# Cookie normalization rebuilds the header in a single consistent format.
def canonical_cookie_header(value: str) -> str:
    return "; ".join(f"{name}={cookie_value}" for name, cookie_value in parse_cookie_header(value))


# Stable session identity is independent from pair ordering in a Cookie header. Duplicate cookie
# names are already rejected by parse_cookie_header(), so sorting cannot collapse two distinct
# same-name path cookies that the flattened project header format cannot represent in the first place.
def cookie_header_fingerprint(value: str) -> str:
    pairs = parse_cookie_header(value)
    if not pairs:
        return ""
    normalized = sorted(((name.casefold(), cookie_value) for name, cookie_value in pairs), key=lambda row: row[0])
    payload = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


# Cookie-name extraction exposes only the names present in the supplied header.
def cookie_names(value: str) -> list[str]:
    return [name for name, _ in parse_cookie_header(value)]


# Login-page detection uses the final URL and form content to recognize authentication screens.
def response_looks_like_login(response: Any) -> bool:

    try:
        final_url = str(response.url).lower()
        text = str(response.text)[:100_000].lower()
    except Exception:
        return False
    path = urlparse(final_url).path.rstrip("/")
    password_field = "type=\"password\"" in text or "type='password'" in text
    auth_words = any(term in text for term in ("login", "log in", "sign in", "signin", "authenticate"))
    return (
        path.endswith(("/login", "/login.php", "/signin", "/sign-in", "/auth"))
        or (password_field and auth_words)
    )


# Loads the local runtime file when it exists.
def load_runtime_config() -> dict[str, Any]:

    path = ROOT_DIR / ".secops_runtime.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


# Normalizes a DNS/IP hostname for exact-host policy comparisons. Unicode DNS labels are
# converted to their IDNA ASCII representation so a user-facing international hostname and its
# punycode form cannot create two different authorization/cookie-scope decisions. A terminal DNS
# dot is ignored because it denotes the same absolute hostname.
def normalized_hostname(value: str) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        # Keep malformed/non-DNS literals stable rather than inventing a different hostname;
        # URL validation/scope checks remain fail-closed at their normal boundary.
        return host


# Parses an HTTP/HTTPS origin without allowing malformed authority/port text to escape as an exception.
def _url_origin_parts(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlparse(str(url or "").strip())
        scheme = str(parsed.scheme or "").lower()
        # A terminal DNS dot denotes the same absolute hostname (example.com. == example.com).
        # Normalize it centrally so exact-origin and same-host-port decisions do not disagree with
        # browser/DNS semantics merely because one discovered URL used the absolute form.
        host = normalized_hostname(parsed.hostname or "")
        if scheme not in {"http", "https"} or not host:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
    except (TypeError, ValueError):
        return None
    return scheme, host, int(port)


# Converts a URL into the scheme, host, and port key used by runtime profiles.
def origin_key(url: str) -> str:
    parts = _url_origin_parts(url)
    if parts is None:
        return ""
    scheme, host, port = parts
    return f"{scheme}://{host}:{port}"


# Runtime profile lookup only accepts settings bound to the exact target origin and path.
def target_runtime_profile(target: str) -> dict[str, Any]:

    profiles = load_runtime_config().get("target_profiles", {})
    if not isinstance(profiles, dict):
        return {}
    value = profiles.get(origin_key(target), {})
    if not isinstance(value, dict):
        return {}
    configured_target = str(value.get("target_url") or "").strip()
    if configured_target:
        configured = urlparse(configured_target)
        requested = urlparse(str(target or ""))
        configured_path = (configured.path or "/").rstrip("/") or "/"
        requested_path = (requested.path or "/").rstrip("/") or "/"
        if origin_key(configured_target) != origin_key(target) or configured_path != requested_path:
            return {}
    return value


# Docker routing resolves the optional internal route configured for the current target.
def runtime_container_route(target: str, scanner_container: str = "") -> dict[str, Any]:

    profile = target_runtime_profile(target)
    route = profile.get("container_route", {})
    if not isinstance(route, dict):
        return {}
    allowed = str(route.get("scanner_container") or "")
    if allowed and scanner_container and allowed != scanner_container:
        return {}
    return route


# Applies target-specific preparation requests before a scanner starts.
def apply_runtime_target_preparation(target: str, cookies: str, *, allow_state_changes: bool = False, deadline: float | None = None) -> dict[str, Any]:


    profile = target_runtime_profile(target)
    requests_spec = profile.get("pre_scan_requests", [])
    if not cookies or not isinstance(requests_spec, list) or not requests_spec:
        return {"performed": False, "configured": bool(requests_spec), "usable": True}
    session = requests.Session()
    session.headers.update({
        "Cookie": cookies,
        "Cache-Control": "no-cache",
        "User-Agent": "SecOps-Target-Preparation/1.0",
    })
    outcomes: list[dict[str, Any]] = []
    usable = True
    conclusive = True
    transient_errors: list[str] = []
    for item in requests_spec[:8]:
        if deadline is not None and time.monotonic() >= float(deadline):
            conclusive = False
            transient_errors.append("Timeout: shared preparation deadline reached")
            outcomes.append({"skipped": True, "diagnosis": "assessment_time_budget_exhausted", "reason": "shared preparation deadline reached"})
            break
        if not isinstance(item, dict):
            continue
        method = str(item.get("method") or "GET").upper()
        path = str(item.get("path") or "").strip()
        if method not in {"GET", "POST"} or not path:
            continue
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        if origin_key(url) != origin_key(target):
            usable = False
            outcomes.append({"url": url, "error": "cross-origin preparation request rejected"})
            continue
        request_data = str(item.get("data") or "") if method == "POST" else ""
        declared_state_change = safe_bool_value(item.get("state_changing"), False)
        state_reason = request_contract_state_change_reason({
            "url": url, "method": method, "data": request_data,
            "parameters": list(item.get("parameters") or []),
            "content_type": str(item.get("content_type") or ""),
        })
        if not allow_state_changes and (declared_state_change or state_reason):
            required = safe_bool_value(item.get("required"), False)
            usable = usable and (not required)
            outcomes.append({
                "method": method, "url": url, "skipped": True,
                "diagnosis": "state_change_policy_blocked",
                "reason": ("declared state-changing preparation" if declared_state_change else state_reason),
                "required": required,
            })
            continue
        try:
            response = request_same_origin_redirects(
                method, url, session=session, data=request_data if method == "POST" else None,
                timeout=(4, 15), deadline=deadline, allow_state_changes=bool(allow_state_changes),
            )
            accepted = item.get("accepted_statuses", [200, 204, 302])
            accepted_set = {int(value) for value in accepted if str(value).isdigit()}
            redirect_guard = str(response.headers.get("X-SecOps-Redirect-Guard") or "")
            ok = (not redirect_guard) and (response.status_code in accepted_set if accepted_set else response.status_code < 400)
            usable = usable and ok
            outcomes.append({
                "method": method, "url": url, "status": response.status_code,
                "final_url": str(response.url), "accepted": ok,
                "redirect_guard": redirect_guard,
            })
        except requests.RequestException as exc:


            conclusive = False
            error = f"{type(exc).__name__}: {exc}"
            transient_errors.append(error)
            outcomes.append({"method": method, "url": url, "error": error, "transient": True})
    return {
        "performed": bool(outcomes), "configured": True, "usable": usable,
        "conclusive": conclusive, "transient_error": bool(transient_errors),
        "transient_errors": transient_errors[-5:], "requests": outcomes,
    }


# Sends an HTTP request again after short temporary failures.
def request_with_retries(
    method: str,
    url: str,
    *,
    attempts: int = 3,
    backoff_seconds: float = 0.65,
    pacer: RequestRatePacer | None = None,
    request_rate: Any = _REQUEST_RATE_UNSET,
    deadline: float | None = None,
    allow_state_changes: bool = False,
    **kwargs: Any,
) -> tuple[requests.Response | None, list[str]]:


    errors: list[str] = []
    active_pacer = pacer or RequestRatePacer(request_rate)
    for attempt in range(max(1, int(attempts))):
        try:
            if deadline is not None:
                left = float(deadline) - time.monotonic()
                if left <= 0:
                    errors.append("Timeout: shared scanner deadline reached")
                    break
                kwargs["timeout"] = deadline_bounded_request_timeout(kwargs.get("timeout"), float(deadline))
            if kwargs.get("allow_redirects"):
                return request_same_origin_redirects(method, url, pacer=active_pacer, deadline=deadline, allow_state_changes=allow_state_changes, **kwargs), errors
            # Scanner helpers never inherit Requests' method-dependent redirect defaults. A caller
            # must opt in explicitly; opt-in follow is always routed through the same-origin guard.
            kwargs["allow_redirects"] = False
            if not allow_state_changes:
                state_reason = request_invocation_state_change_reason(
                    method, url, data=kwargs.get("data"), json_body=kwargs.get("json"),
                    params=kwargs.get("params"), files=kwargs.get("files"), headers=kwargs.get("headers"),
                )
                if state_reason:
                    raise requests.RequestException(f"state-change policy blocked request before send: {state_reason}")
            active_pacer.wait()
            return requests.request(method=method, url=url, **kwargs), errors
        except (requests.Timeout, requests.ConnectionError) as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            if attempt + 1 < attempts:
                delay = backoff_seconds * (attempt + 1)
                if deadline is not None:
                    delay = min(delay, max(0.0, float(deadline) - time.monotonic()))
                if delay > 0:
                    time.sleep(delay)
        except requests.RequestException as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            break
    return None, errors


# Session probing confirms that a scanner still reaches the target as the authenticated user.
def scanner_session_probe(
    url: str,
    cookies: str,
    method: str = "GET",
    data: str = "",
    timeout: int = 12,
    attempts: int = 3,
    *,
    pacer: RequestRatePacer | None = None,
    request_rate: Any = _REQUEST_RATE_UNSET,
    deadline: float | None = None,
    allow_tls_trust_retry: bool = False,
) -> dict[str, Any]:


    if not cookies:
        return {"performed": False, "authenticated": None, "conclusive": True}
    method_upper = str(method or "GET").upper()
    state_reason = request_contract_state_change_reason({"url": str(url or ""), "method": method_upper, "data": str(data or "")})
    if state_reason:
        return {
            "performed": False, "authenticated": None, "conclusive": False,
            "state_change_blocked": True, "diagnosis": "state_change_policy_blocked", "reason": state_reason,
        }
    response, errors = request_with_retries(
        str(method or "GET").upper(),
        url,
        attempts=attempts,
        data=data if str(method).upper() != "GET" else None,
        headers={"Cookie": cookies, "Cache-Control": "no-cache"},
        timeout=(4, max(6, int(timeout))),
        allow_redirects=True,
        pacer=pacer,
        request_rate=request_rate,
        deadline=deadline,
        allow_state_changes=False,
        allow_tls_trust_retry=bool(allow_tls_trust_retry),
    )
    if response is None:
        return {
            "performed": True,
            "authenticated": None,
            "conclusive": False,
            "transient_error": True,
            "errors": errors,
            "error": errors[-1] if errors else "request failed",
        }
    redirect_guard = str(response.headers.get("X-SecOps-Redirect-Guard") or "")
    login = response_looks_like_login(response)
    if redirect_guard:
        diagnosis = "cross_origin_redirect_blocked" if redirect_guard == "cross-origin-blocked" else "redirect_limit_reached"
        return {
            "performed": True,
            "authenticated": None,
            "conclusive": False,
            "transient_error": False,
            "diagnosis": diagnosis,
            "status": int(response.status_code),
            "final_url": str(response.url),
            "login_detected": login,
            "redirect_guard": redirect_guard,
            "location": str(response.headers.get("Location") or ""),
            "bytes": len(response.content),
            "attempt_errors": errors,
        }
    authenticated = response.status_code < 400 and not login
    return {
        "performed": True,
        "authenticated": authenticated,
        "conclusive": True,
        "transient_error": False,
        "status": int(response.status_code),
        "final_url": str(response.url),
        "login_detected": login,
        "bytes": len(response.content),
        "attempt_errors": errors,
    }

# Adds the project tool folders to PATH for the current process.
def setup_path() -> None:

    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    parts = [item for item in os.environ.get("PATH", "").split(os.pathsep) if item]
    if str(LOCAL_BIN) not in parts:
        os.environ["PATH"] = str(LOCAL_BIN) + os.pathsep + os.environ.get("PATH", "")


# Finds an executable by checking the project tool folder and system PATH.
def find_executable(name: str) -> str | None:
    setup_path()
    return shutil.which(name) or shutil.which(f"{name}.bat") or shutil.which(f"{name}.exe")


# URL normalization removes fragments and trailing path separators without altering query values.
def normalize_url(url: str) -> str:
    try:
        parsed = urlparse(sanitize_discovered_url(url))
    except ValueError as exc:
        raise ValueError("The target must be a valid absolute HTTP/HTTPS URL.") from exc
    if _url_origin_parts(url) is None:
        raise ValueError("The target must be a valid absolute HTTP/HTTPS URL with a valid port.")
    path = parsed.path
    if len(path) > 1:
        path = path.rstrip("/")
    elif path == "/" and not parsed.query:
        path = ""
    return urlunparse(parsed._replace(path=path, fragment=""))


# Origin comparison requires the same scheme, host, and effective port; malformed discovered URLs are out of scope.
def same_origin(left: str, right: str) -> bool:
    a = _url_origin_parts(left)
    b = _url_origin_parts(right)
    return a is not None and b is not None and a == b


# Converts an absolute HTTP/HTTPS URL into a stable origin string.
def normalized_origin(url: str) -> str:
    parts = _url_origin_parts(url)
    if parts is None:
        return ""
    scheme, host, port = parts
    default_port = 80 if scheme == "http" else 443
    port_fragment = "" if port == default_port else f":{port}"
    host_fragment = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{host_fragment}{port_fragment}"


# Builds an anchored regular expression for exactly one HTTP origin. Default ports are
# accepted in both implicit and explicit form because they represent the same effective origin.
def exact_origin_authority_regex(url: str) -> str:
    parts = _url_origin_parts(url)
    if parts is None:
        return r"(?!)"
    scheme, host, port = parts
    host_fragment = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 80 if scheme == "http" else 443
    port_fragment = rf"(?::{port})?" if port == default_port else re.escape(f":{port}")
    return rf"(?i:{re.escape(scheme)}://{re.escape(host_fragment)}{port_fragment})"


# Matches only URLs on the exact scheme/host/effective-port origin, never hostname prefixes.
def exact_origin_url_regex(url: str) -> str:
    return rf"^{exact_origin_authority_regex(url)}(?:[/?#].*)?$"


# Follows redirect chains only while every hop remains on the starting origin.
def request_same_origin_redirects(
    method: str, url: str, *, max_redirects: int = 5, session: requests.Session | None = None,
    pacer: RequestRatePacer | None = None, request_rate: Any = _REQUEST_RATE_UNSET,
    deadline: float | None = None, allow_state_changes: bool = False,
    allow_tls_trust_retry: bool = False, **kwargs: Any,
) -> requests.Response:
    """Send one HTTP request and follow redirects only while they remain on the starting origin.

    A redirect to another origin is returned as the final response and is never requested. This keeps
    normal application redirects working without allowing a scanner helper to escape the authorized
    target merely because the server emitted a Location header.
    """
    start = str(url or '')
    current = start
    kwargs = dict(kwargs)
    kwargs.pop('allow_redirects', None)
    configured_timeout = kwargs.get('timeout')
    response: requests.Response | None = None
    active_pacer = pacer or RequestRatePacer(request_rate)
    tls_trust_override = False

    def _certificate_trust_error(exc: BaseException) -> bool:
        message = str(exc or '').lower()
        return any(token in message for token in (
            'certificate verify failed', 'self signed certificate', 'self-signed certificate',
            'unable to get local issuer certificate', 'unable to verify the first certificate',
            'hostname mismatch', 'certificate has expired', 'certificate is not yet valid',
        ))

    for _ in range(max(0, int(max_redirects)) + 1):
        requester = session.request if session is not None else requests.request
        if deadline is not None and float(deadline) - time.monotonic() <= 0:
            raise requests.Timeout("shared scanner deadline reached")
        if not allow_state_changes:
            state_reason = request_invocation_state_change_reason(
                method, current, data=kwargs.get("data"), json_body=kwargs.get("json"),
                params=kwargs.get("params"), files=kwargs.get("files"), headers=kwargs.get("headers"),
            )
            if state_reason:
                raise requests.RequestException(f"state-change policy blocked request before send: {state_reason}")
        active_pacer.wait()
        if deadline is not None:
            left = float(deadline) - time.monotonic()
            if left <= 0:
                raise requests.Timeout("shared scanner deadline reached")
            kwargs['timeout'] = deadline_bounded_request_timeout(configured_timeout, float(deadline))
        request_kwargs = dict(kwargs)
        if tls_trust_override:
            request_kwargs['verify'] = False
        try:
            response = requester(method, current, allow_redirects=False, **request_kwargs)
        except requests.exceptions.SSLError as exc:
            # When an explicitly authorized caller opts in, retry the exact same origin after a
            # certificate trust failure. Protocol/cipher/handshake errors are never bypassed.
            if (
                not allow_tls_trust_retry
                or tls_trust_override
                or request_kwargs.get('verify') is False
                or not _certificate_trust_error(exc)
            ):
                raise
            active_pacer.wait()
            if deadline is not None:
                left = float(deadline) - time.monotonic()
                if left <= 0:
                    raise requests.Timeout("shared scanner deadline reached") from exc
                request_kwargs['timeout'] = deadline_bounded_request_timeout(configured_timeout, float(deadline))
            request_kwargs['verify'] = False
            response = requester(method, current, allow_redirects=False, **request_kwargs)
            tls_trust_override = True
        if tls_trust_override:
            response.headers['X-SecOps-TLS-Trust-Retry'] = 'authorized-origin-certificate-trust-only'
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = str(response.headers.get('Location') or '').strip()
        if not location:
            return response
        candidate = urljoin(current, location)
        if not same_origin(start, candidate):
            response.headers['X-SecOps-Redirect-Guard'] = 'cross-origin-blocked'
            return response
        method_upper = str(method).upper()
        # Match Requests/browser redirect method rebuilding: 303 and 302 become GET for every
        # non-HEAD method; historical 301 changes POST to GET; 307/308 preserve method/body.
        switch_to_get = (
            (response.status_code == 303 and method_upper != 'HEAD')
            or (response.status_code == 302 and method_upper != 'HEAD')
            or (response.status_code == 301 and method_upper == 'POST')
        )
        if switch_to_get:
            method = 'GET'
            kwargs.pop('data', None)
            kwargs.pop('json', None)
            headers = kwargs.get('headers')
            if isinstance(headers, dict):
                # A redirected GET must not inherit entity headers from the original request.
                headers = dict(headers)
                for header_name in list(headers):
                    if str(header_name).lower() in {'content-length', 'content-type', 'transfer-encoding'}:
                        headers.pop(header_name, None)
                kwargs['headers'] = headers
        if not allow_state_changes:
            candidate_method = str(method).upper()
            candidate_data = str(kwargs.get('data') or '') if candidate_method != 'GET' else ''
            state_reason = request_contract_state_change_reason({
                'url': candidate, 'method': candidate_method, 'data': candidate_data,
            })
            if state_reason:
                response.headers['X-SecOps-State-Change-Guard'] = 'state-change-blocked'
                response.headers['X-SecOps-State-Change-Reason'] = state_reason[:240]
                return response
        current = candidate
    assert response is not None
    response.headers['X-SecOps-Redirect-Guard'] = 'redirect-limit-reached'
    return response


# Explicit assessment scope may extend beyond one origin without implicitly trusting unrelated external hosts.
def url_in_authorized_scope(
    target: str,
    candidate: str,
    authorized_origins: list[str] | tuple[str, ...] | set[str] | None = None,
    allow_same_host_ports: bool = False,
) -> bool:
    if same_origin(target, candidate):
        return True
    candidate_parts = _url_origin_parts(candidate)
    if candidate_parts is None:
        return False
    candidate_origin = normalized_origin(candidate)
    exact_origins = {normalized_origin(value) for value in (authorized_origins or []) if normalized_origin(value)}
    if candidate_origin in exact_origins:
        return True
    if allow_same_host_ports:
        candidate_scheme, candidate_host, _ = candidate_parts
        bases = [target, *(authorized_origins or [])]
        for value in bases:
            parts = _url_origin_parts(str(value or ''))
            if parts is None:
                continue
            scheme, host, _ = parts
            # Site-level same-host authorization can cover HTTP/HTTPS services exposed on
            # other ports of the exact already-authorized hostname. This is intentionally
            # broader than cookie propagation: credentials are still evaluated separately
            # against normal scheme/domain/path rules and runtime validation.
            if scheme in {'http', 'https'} and candidate_scheme in {'http', 'https'} and host == candidate_host:
                return True
    # DNS suffixes are intentionally not an active-attack authorization mechanism.
    # A discovered sibling host must be listed as an exact authorized origin before it can be tested.
    return False


# Response previews keep a short printable body excerpt for diagnostics.
def response_excerpt(text: str, marker: str = "", limit: int = 900) -> str:
    value = str(text or "")
    index = value.find(marker) if marker else -1
    if index < 0:
        return value[:limit]
    start = max(0, index - limit // 3)
    return value[start:start + limit]


# Keeps the useful end of long process output for diagnostics.
def trim_process_output(result: dict[str, Any], limit: int) -> dict[str, Any]:
    for key in ("stdout", "stderr"):
        value = str(result.get(key, ""))
        if len(value) > limit:
            result[key] = value[-limit:]
            result[f"{key}_truncated"] = True
    return result


# Removes stray whitespace from discovered URL authorities without touching path/query data.
def sanitize_discovered_url(url: str) -> str:
    raw = str(url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    basename = str(parsed.path or '').rstrip('/').rsplit('/', 1)[-1]
    if re.fullmatch(r'\.(?:php|phtml|jsp|jspx|asp|aspx|html?|cgi|pl|py|rb)', basename, re.I):
        # Dynamic source extraction can occasionally concatenate an empty route stem with a file
        # extension (for example '/.php'). Such a path is a synthetic artefact, not a meaningful
        # endpoint. Reject only the extension-only basename; legitimate dotfiles remain untouched.
        return ""
    netloc = str(parsed.netloc or "").strip()
    if netloc:
        userinfo = ""
        hostport = netloc
        if "@" in hostport:
            userinfo, hostport = hostport.rsplit("@", 1)
        host = hostport
        port_fragment = ""
        if hostport.startswith("["):
            closing = hostport.find("]")
            if closing >= 0:
                host = hostport[: closing + 1]
                port_fragment = hostport[closing + 1 :]
        elif ":" in hostport:
            maybe_host, maybe_port = hostport.rsplit(":", 1)
            if maybe_port.isdigit():
                host, port_fragment = maybe_host, ":" + maybe_port
        host = re.sub(r"(?i)(?:%20|%09|%0a|%0d)+$", "", host.strip())
        hostport = host + port_fragment
        netloc = (userinfo + "@" if userinfo else "") + hostport
    return urlunparse(parsed._replace(netloc=netloc, fragment=""))


# Resolves a discovered link against its base URL and sanitizes stray authority whitespace.
def absolute_url(base: str, candidate: str) -> str:
    return sanitize_discovered_url(urljoin(str(base or "").strip(), str(candidate or "").strip()))


# Server tools share one result structure for status, findings, output, and diagnostics.
def make_result(
    tool: str,
    status: str,
    target: str = "",
    output: str = "",
    vulnerabilities: list[dict[str, Any]] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "tool": tool,
        "status": status,
        "target": target,
        "output": output,
        "vulnerabilities": vulnerabilities or [],
    }
    result.update(extra)
    return result


# Successful runs are wrapped in the common server result format.
def success(tool: str, target: str = "", output: str = "", **extra: Any) -> dict[str, Any]:
    return make_result(tool, "success", target, output, **extra)


# Partial runs preserve useful findings while using the common server result format.
def partial(tool: str, target: str, output: str, **extra: Any) -> dict[str, Any]:
    return make_result(tool, "partial", target, output, **extra)


# Skipped runs keep a clear reason in the common server result format.
def skipped(tool: str, target: str, reason: str, **extra: Any) -> dict[str, Any]:
    return make_result(tool, "skipped", target, reason, **extra)


# Failed runs include process details that help explain why the tool did not complete.
def failure(
    tool: str,
    target: str,
    message: str,
    *,
    return_code: int | None = None,
    stdout: str = "",
    stderr: str = "",
    diagnosis: str = "scanner_error",
    **extra: Any,
) -> dict[str, Any]:
    return make_result(
        tool,
        "error",
        target,
        message,
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        diagnosis=diagnosis,
        **extra,
    )


# Converts timeout output into normal text for diagnostics.
def _decode_timeout_output(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


# Startup diagnosis scans process output for errors that show the scanner never launched correctly.
def _fatal_startup_error(text: str) -> str:
    lowered = text.lower()
    return next((pattern for pattern in _FATAL_STARTUP_PATTERNS if re.search(pattern, lowered, re.I)), "")


# While external scanners run, the process wrapper enforces time limits and preserves useful partial output.
def run_process(
    tool: str,
    command: list[str],
    *,
    target: str,
    timeout: int = 180,
    accepted_codes: Iterable[int] = (0,),
    cwd: Path | None = None,
    progress_callback: Callable[[], None] | None = None,
    progress_interval: float = 5.0,
) -> dict[str, Any]:

    executable = find_executable(command[0])
    if not executable:
        return failure(tool, target, f"Executable not found: {command[0]}", diagnosis="missing_executable")

    resolved_command = [executable, *command[1:]]
    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    started = time.monotonic()
    try:
        if progress_callback is None:
            completed = subprocess.run(
                resolved_command,
                cwd=str(cwd) if cwd else None,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(1, int(timeout)),
                shell=False,
            )
        else:
            # A progress callback is used by scanners such as Nuclei that write structured
            # findings incrementally to disk. Polling communicate() lets the wrapper snapshot
            # those artifacts while the child is still running without introducing scanner
            # concurrency or changing its stdout/stderr contract.
            process = subprocess.Popen(
                resolved_command,
                cwd=str(cwd) if cwd else None,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
            stdout = stderr = ""
            timeout_seconds = max(1.0, float(timeout))
            interval = max(0.5, min(float(progress_interval), timeout_seconds))
            while True:
                remaining = timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    process.kill()
                    stdout, stderr = process.communicate()
                    raise subprocess.TimeoutExpired(resolved_command, timeout_seconds, output=stdout, stderr=stderr)
                try:
                    stdout, stderr = process.communicate(timeout=min(interval, remaining))
                    break
                except subprocess.TimeoutExpired:
                    try:
                        progress_callback()
                    except Exception:
                        # Checkpointing/telemetry must never abort the scanner itself.
                        pass
            completed = subprocess.CompletedProcess(resolved_command, process.returncode, stdout or "", stderr or "")
    # A timeout keeps any useful output instead of hiding work the scanner already completed.
    except subprocess.TimeoutExpired as exc:
        stdout = _decode_timeout_output(exc.stdout)
        stderr = _decode_timeout_output(exc.stderr)
        if progress_callback is not None:
            try:
                progress_callback()
            except Exception:
                pass
        return failure(
            tool,
            target,
            f"Timeout after {timeout} seconds",
            stdout=stdout,
            stderr=stderr,
            diagnosis="timeout",
            timed_out=True,
            duration_seconds=round(time.monotonic() - started, 3),
            command=resolved_command,
        )
    except OSError as exc:
        return failure(
            tool,
            target,
            f"Cannot start process: {exc}",
            diagnosis="process_start_failed",
            duration_seconds=round(time.monotonic() - started, 3),
            command=resolved_command,
        )

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    combined = "\n".join(value.strip() for value in (stdout, stderr) if value.strip()).strip()
    fatal_pattern = _fatal_startup_error(combined)
    if fatal_pattern:
        return failure(
            tool,
            target,
            "The scanner launcher failed before the scan started.",
            return_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            diagnosis="scanner_runtime_dependency_missing",
            duration_seconds=round(time.monotonic() - started, 3),
            command=resolved_command,
            matched_startup_error=fatal_pattern,
        )

    if completed.returncode not in set(accepted_codes):
        return failure(
            tool,
            target,
            f"Process exited with code {completed.returncode}",
            return_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            diagnosis="unexpected_exit_code",
            duration_seconds=round(time.monotonic() - started, 3),
            command=resolved_command,
        )

    return success(
        tool,
        target,
        combined or "Command completed without textual output.",
        return_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        command=resolved_command,
        duration_seconds=round(time.monotonic() - started, 3),
    )


# Reads JSONL output and ignores lines that are not valid JSON.
def read_json_lines(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        try:
            value = json.loads(raw_line.strip())
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows