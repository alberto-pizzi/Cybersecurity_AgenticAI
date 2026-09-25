from __future__ import annotations

import errno
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
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, unquote, urljoin, urlparse, urlunparse

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
    # Tool/MCP function signatures use ``None`` as their natural optional default. Treating that
    # as an explicit invalid value used to fall back to 10 req/s instead of inheriting the
    # assessment's SECOPS_MAX_REQUEST_RATE. That could exceed a configured low rate whenever a
    # caller omitted the explicit request_rate argument. Both omitted and None now inherit the
    # assessment environment; an actually supplied non-None value is still validated normally.
    use_environment = value is _REQUEST_RATE_UNSET or value is None
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


def available_cpu_count() -> int:
    """Return the CPU count this process can actually use inside a VM/container/cpuset.

    Python 3.13 exposes ``os.process_cpu_count()`` which honors process CPU availability. Older
    runtimes fall back to sched_getaffinity/os.cpu_count. The result is always at least one.
    """
    candidates: list[int] = []
    process_cpu_count = getattr(os, "process_cpu_count", None)
    if callable(process_cpu_count):
        try:
            value = process_cpu_count()
            if value:
                candidates.append(int(value))
        except (OSError, TypeError, ValueError):
            pass
    if hasattr(os, "sched_getaffinity"):
        try:
            candidates.append(len(os.sched_getaffinity(0)))
        except (OSError, TypeError):
            pass
    try:
        value = os.cpu_count()
        if value:
            candidates.append(int(value))
    except (OSError, TypeError, ValueError):
        pass
    return max(1, min(value for value in candidates if value > 0) if candidates else 1)


def secops_parallelism_policy(value: Any = _REQUEST_RATE_UNSET) -> dict[str, Any]:
    """Derive bounded CPU/network concurrency from the configured target request rate.

    Network workers are intentionally allowed to outnumber CPUs because they spend most of their
    lifetime waiting for sockets/TLS/server responses. CPU-heavy child processes use a much tighter
    budget. None of these worker counts changes the authoritative request-start ceiling: project
    HTTP helpers still pass through ``RequestRatePacer`` and external scanners still receive their
    native aggregate rate/delay setting.
    """
    rate = max(1.0, scanner_request_rate(value))
    detected_cpus = available_cpu_count()

    raw_cpu_budget = os.getenv("SECOPS_CPU_BUDGET", "").strip()
    if raw_cpu_budget:
        requested_cpu_budget = safe_int_value(raw_cpu_budget, detected_cpus)
        cpu_budget = max(1, min(detected_cpus, requested_cpu_budget))
        cpu_budget_source = "SECOPS_CPU_BUDGET"
    else:
        reserve_default = 1 if detected_cpus >= 4 else 0
        reserve = max(0, min(detected_cpus - 1, safe_int_value(os.getenv("SECOPS_CPU_RESERVE", reserve_default), reserve_default)))
        cpu_budget = max(1, detected_cpus - reserve)
        cpu_budget_source = "auto"

    network_hard_cap = max(1, min(64, safe_int_value(os.getenv("SECOPS_NETWORK_MAX_INFLIGHT", "32"), 32)))
    browser_hard_cap = max(1, min(32, safe_int_value(os.getenv("SECOPS_BROWSER_MAX_INFLIGHT", "16"), 16)))
    scanner_hard_cap = max(1, min(32, safe_int_value(os.getenv("SECOPS_SCANNER_MAX_WORKERS", "8"), 8)))
    profile_hard_cap = max(1, min(4, safe_int_value(os.getenv("SECOPS_PROFILE_DISCOVERY_WORKERS", "4"), 4)))
    heavy_local_hard_cap = max(1, min(8, safe_int_value(os.getenv("SECOPS_HEAVY_LOCAL_WORKERS", "4"), 4)))

    # Roughly 1.5 seconds of target latency can be hidden at the configured request rate without
    # creating unbounded thread pools. The CPU multiplier is deliberately high only for I/O waits.
    network_rate_need = max(1, int(math.ceil(rate * 1.5)))
    network_cpu_cap = max(1, cpu_budget * 8)
    network_workers = max(1, min(network_hard_cap, network_rate_need, network_cpu_cap))

    # Browser route callbacks do more Python/DOM work than plain HTTP fetches, so keep a tighter
    # in-flight bound while still allowing enough outstanding requests to hide normal latency.
    browser_rate_need = max(1, int(math.ceil(rate)))
    browser_cpu_cap = max(1, cpu_budget * 4)
    browser_workers = max(1, min(browser_hard_cap, browser_rate_need, browser_cpu_cap))

    # Native scanners may create CPU work per response/template. Their concurrency therefore stays
    # close to the usable CPU budget; their native rate flag/delay remains the traffic authority.
    scanner_workers = max(1, min(scanner_hard_cap, int(math.ceil(rate)), cpu_budget * 2))

    # Discovery profile coordinators are allowed to overlap up to the usable CPU budget. Their
    # HTTP/JS work shares one process-wide network pool, so increasing profile coordinators no
    # longer multiplies discovery worker threads. Chromium itself is heavier: a separate browser
    # profile-slot budget keeps only about one browser workload per two usable CPUs active at once.
    profile_workers = max(1, min(profile_hard_cap, cpu_budget))

    # Chromium, local LLM inference/model loading and PDF rendering can each consume a sizeable
    # fraction of the VM CPU/RAM even when their child thread pools are individually clamped.
    # Give all such workloads one shared VM-wide slot family. On small VMs this intentionally
    # serializes heavy local work; larger VMs gain one slot per roughly two usable CPUs.
    heavy_local_workers = max(1, min(heavy_local_hard_cap, max(1, cpu_budget // 2)))
    browser_profile_workers = max(1, min(profile_workers, heavy_local_workers))

    return {
        "request_rate": rate,
        "detected_cpus": detected_cpus,
        "cpu_budget": cpu_budget,
        "cpu_budget_source": cpu_budget_source,
        "network_workers": network_workers,
        "browser_workers": browser_workers,
        "scanner_workers": scanner_workers,
        "profile_workers": profile_workers,
        "browser_profile_workers": browser_profile_workers,
        "heavy_local_workers": heavy_local_workers,
        "network_hard_cap": network_hard_cap,
        "browser_hard_cap": browser_hard_cap,
        "scanner_hard_cap": scanner_hard_cap,
        "profile_hard_cap": profile_hard_cap,
        "heavy_local_hard_cap": heavy_local_hard_cap,
    }


def subprocess_parallelism_environment(base_env: dict[str, str] | None = None, value: Any = _REQUEST_RATE_UNSET) -> dict[str, str]:
    """Return a child-process environment that prevents nested CPU-pool oversubscription.

    Scanner children must not inherit a workstation/VM shell setting that exceeds the SecOps CPU
    budget. ``SECOPS_CPU_BUDGET``/``SECOPS_CPU_RESERVE`` are the operator-facing controls; inherited
    Go/OpenMP/BLAS thread counts are normalized here so nested libraries cannot multiply worker
    counts behind an already-concurrent scanner process.
    """
    env = dict(base_env or os.environ)
    policy = secops_parallelism_policy(value)
    cpu_budget = max(1, int(policy["cpu_budget"]))
    # Go scanners may otherwise use every visible CPU even when SecOps intentionally reserved one.
    # Set the project budget explicitly rather than setdefault(): a larger inherited GOMAXPROCS
    # would bypass the anti-oversubscription policy. Operators wanting a smaller budget should use
    # SECOPS_CPU_BUDGET, which feeds the same central policy.
    env["GOMAXPROCS"] = str(cpu_budget)
    # External scanner processes may import NumPy/matplotlib or native libraries. Their own SecOps
    # worker count already provides concurrency, so nested math-library pools stay single-threaded.
    for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
        env[name] = "1"
    env.setdefault("MPLBACKEND", "Agg")
    return env


def request_rate_budget_scale(value: Any = _REQUEST_RATE_UNSET, *, reference_rate: float = DEFAULT_REQUEST_RATE) -> float:
    """Return the conservative wall-clock expansion required by a lower configured request rate.

    Network-bound work configured for the project default of 10 req/s must not be truncated merely
    because an operator intentionally selected 1/2/3 req/s. Faster-than-default rates do not shrink
    budgets automatically: local CPU, server latency and scanner startup costs do not scale inversely
    with the configured request rate.
    """
    rate = max(1.0, scanner_request_rate(value))
    reference = max(1.0, float(reference_rate or DEFAULT_REQUEST_RATE))
    return max(1.0, reference / rate)


def rate_aware_network_budget(base_seconds: Any, value: Any = _REQUEST_RATE_UNSET, *,
                              network_fraction: float = 1.0, safety_multiplier: float = 1.0,
                              minimum_seconds: float = 0.0) -> float:
    """Scale only the network-bound share of a timeout, never below its rate-10 baseline.

    ``network_fraction=1`` is appropriate for request-count dominated scanners/discovery. Browser
    workflows can use a smaller fraction because rendering/JavaScript time is mostly local.
    """
    base = max(0.0, safe_float_value(base_seconds, 0.0))
    fraction = min(1.0, max(0.0, safe_float_value(network_fraction, 1.0)))
    scale = request_rate_budget_scale(value)
    adjusted = base * ((1.0 - fraction) + fraction * scale) * max(1.0, safe_float_value(safety_multiplier, 1.0))
    return max(float(minimum_seconds or 0.0), adjusted)


_GLOBAL_RATE_CLIENT_TTL_SECONDS = max(5.0, min(120.0, safe_float_value(os.getenv("SECOPS_RATE_CLIENT_TTL_SECONDS", "15"), 15.0)))
_GLOBAL_RATE_LOCAL_FALLBACK_LOCK = threading.Lock()
_GLOBAL_TRAFFIC_LOCAL_FALLBACK_LOCK = threading.Lock()
_RESOURCE_SLOT_FALLBACK_GUARD = threading.Lock()
_RESOURCE_SLOT_FALLBACK_LOCKS: dict[str, threading.Lock] = {}

def _global_request_rate_state_path() -> Path:
    configured = str(os.getenv("SECOPS_GLOBAL_RATE_STATE") or "").strip()
    if configured:
        return Path(configured).expanduser()
    try:
        owner = str(os.getuid())
    except (AttributeError, OSError):
        owner = str(os.getenv("USERNAME") or os.getenv("USER") or "default")
    safe_owner = re.sub(r"[^A-Za-z0-9_.-]+", "_", owner) or "default"
    return Path(tempfile.gettempdir()) / f"secops-global-request-rate-{safe_owner}.json"


def _global_target_traffic_lock_path() -> Path:
    state_path = _global_request_rate_state_path()
    return state_path.with_suffix(state_path.suffix + ".traffic.lock")


def _assessment_rate_contract_state_path() -> Path:
    configured = str(os.getenv("SECOPS_ASSESSMENT_RATE_CONTRACT_STATE") or "").strip()
    if configured:
        return Path(configured).expanduser()
    state_path = _global_request_rate_state_path()
    return state_path.with_suffix(state_path.suffix + ".assessment-contract.json")


def _assessment_rate_contract_lock_path() -> Path:
    state_path = _assessment_rate_contract_state_path()
    return state_path.with_suffix(state_path.suffix + ".lock")


class AssessmentRateContractError(RuntimeError):
    """Raised when concurrent target-execution windows disagree on request rate."""


def _rate_client_process_alive(client_key: str) -> bool:
    """Best-effort liveness check for a pacer client key.

    Old state files previously retained exited assessment PIDs for the full TTL, which could keep a
    later run artificially throttled below its configured rate. Unknown/legacy keys fail open to
    TTL handling; explicit dead PIDs are removed immediately.
    """
    raw = str(client_key or "")
    pid_text = raw.split(":", 1)[0]
    try:
        pid = int(pid_text)
    except (TypeError, ValueError):
        return True
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        return exc.errno != errno.ESRCH


@contextmanager
def _cross_process_file_lock(
    path: Path, *, exclusive: bool, deadline: float | None, fallback_lock: threading.Lock,
):
    """Acquire a deadline-aware cross-process file lock.

    Debian/Linux uses shared locks for project-controlled request starts and an exclusive lock for
    unmanaged/native scanners. Windows development falls back to an exclusive one-byte lock because
    msvcrt has no shared-lock equivalent. Returning ``False`` lets callers honor their wall-clock
    deadline instead of blocking indefinitely behind another assessment process.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+b")
    locked = False
    local_locked = False
    use_local_fallback = False
    try:
        while not locked and not local_locked:
            if deadline is not None and time.monotonic() >= float(deadline):
                yield False
                return
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0, os.SEEK_END)
                    if handle.tell() == 0:
                        handle.write(b"0")
                        handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    flag = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                    fcntl.flock(handle.fileno(), flag | fcntl.LOCK_NB)
                locked = True
                break
            except ImportError:
                use_local_fallback = True
                break
            except (BlockingIOError, OSError):
                remaining = None if deadline is None else max(0.0, float(deadline) - time.monotonic())
                if remaining is not None and remaining <= 0.0:
                    yield False
                    return
                time.sleep(min(0.05, remaining) if remaining is not None else 0.05)
        if use_local_fallback:
            if deadline is None:
                fallback_lock.acquire()
                local_locked = True
            else:
                local_locked = fallback_lock.acquire(timeout=max(0.0, float(deadline) - time.monotonic()))
                if not local_locked:
                    yield False
                    return
        yield True
    finally:
        try:
            if locked:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            if local_locked:
                fallback_lock.release()
        finally:
            handle.close()


@contextmanager
def _cross_process_rate_lock(path: Path, deadline: float | None = None):
    with _cross_process_file_lock(
        path, exclusive=True, deadline=deadline, fallback_lock=_GLOBAL_RATE_LOCAL_FALLBACK_LOCK,
    ) as acquired:
        yield acquired


def _load_assessment_rate_contract_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "clients": {}}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AssessmentRateContractError(
            f"cannot safely read assessment-rate contract state {path}: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("clients", {}), dict):
        raise AssessmentRateContractError(
            f"assessment-rate contract state {path} is malformed; refusing target execution"
        )
    return raw


def _live_assessment_rate_clients(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    live: dict[str, dict[str, Any]] = {}
    for key, metadata in dict(state.get("clients") or {}).items():
        client_key = str(key or "")
        if not _rate_client_process_alive(client_key):
            continue
        if not isinstance(metadata, dict):
            raise AssessmentRateContractError(
                f"live assessment-rate client {client_key!r} has malformed metadata"
            )
        raw_rate = metadata.get("rate")
        try:
            rate = float(raw_rate)
        except (TypeError, ValueError, OverflowError) as exc:
            raise AssessmentRateContractError(
                f"live assessment-rate client {client_key!r} has invalid rate {raw_rate!r}"
            ) from exc
        if (
            not math.isfinite(rate) or not rate.is_integer()
            or rate < 1.0 or rate > REQUEST_RATE_HARD_CAP
        ):
            raise AssessmentRateContractError(
                f"live assessment-rate client {client_key!r} has unsafe rate {raw_rate!r}"
            )
        item = dict(metadata)
        item["rate"] = float(rate)
        live[client_key] = item
    return live


@contextmanager
def assessment_rate_contract(request_rate: Any = _REQUEST_RATE_UNSET, *, deadline: float | None = None):
    """Require one configured target rate across concurrent SecOps execution windows.

    Python-controlled requests can dynamically share the minimum active pacer rate, but a native
    scanner receives its aggregate rate when the command is built and cannot be retuned while it
    owns the exclusive target-traffic lease.  Therefore two independently launched assessments
    using different configured rates must never have overlapping target-execution windows.

    Same-rate windows are allowed concurrently.  State and lock failures are fail-closed: refusing
    to begin target execution is safer than allowing a native scanner to exceed another active
    assessment's configured contract. Dead process entries are pruned on every acquire/release.
    """
    rate = scanner_request_rate(request_rate)
    state_path = _assessment_rate_contract_state_path()
    lock_path = _assessment_rate_contract_lock_path()
    client_key = f"{os.getpid()}:{threading.get_ident()}:{time.monotonic_ns()}"
    acquired_contract = False

    lock_deadline = deadline if deadline is not None else time.monotonic() + 10.0
    try:
        with _cross_process_rate_lock(lock_path, deadline=lock_deadline) as locked:
            if not locked:
                raise AssessmentRateContractError(
                    "timed out acquiring the cross-process assessment-rate contract lock"
                )
            state = _load_assessment_rate_contract_state(state_path)
            clients = _live_assessment_rate_clients(state)
            conflicting = {
                key: float(meta["rate"])
                for key, meta in clients.items()
                if abs(float(meta["rate"]) - rate) > 1e-9
            }
            if conflicting:
                active_rates = sorted({value for value in conflicting.values()})
                formatted = ", ".join(f"{value:g}" for value in active_rates)
                raise AssessmentRateContractError(
                    f"configured request rate {rate:g} req/s conflicts with active SecOps "
                    f"target-execution rate(s) {formatted} req/s; use the same execution.request_rate "
                    "for concurrent assessments or run them sequentially"
                )
            now = time.time()
            clients[client_key] = {
                "pid": os.getpid(),
                "rate": float(rate),
                "started": now,
                "seen": now,
            }
            payload = {
                "version": 1,
                "configured_rate": float(rate),
                "clients": clients,
                "updated": now,
            }
            try:
                atomic_write_text(state_path, json.dumps(payload, sort_keys=True, separators=(",", ":")))
            except Exception as exc:
                raise AssessmentRateContractError(
                    f"cannot safely persist assessment-rate contract state {state_path}: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            acquired_contract = True
        yield {
            "acquired": True,
            "request_rate": float(rate),
            "client_key": client_key,
            "state_path": str(state_path),
        }
    finally:
        if acquired_contract:
            cleanup_deadline = time.monotonic() + 10.0
            try:
                with _cross_process_rate_lock(lock_path, deadline=cleanup_deadline) as locked:
                    if locked:
                        state = _load_assessment_rate_contract_state(state_path)
                        clients = _live_assessment_rate_clients(state)
                        clients.pop(client_key, None)
                        now = time.time()
                        payload = {
                            "version": 1,
                            "configured_rate": (
                                float(next(iter(clients.values()))["rate"]) if clients else None
                            ),
                            "clients": clients,
                            "updated": now,
                        }
                        atomic_write_text(
                            state_path, json.dumps(payload, sort_keys=True, separators=(",", ":"))
                        )
            except Exception:
                # Cleanup failure can only leave a conservative stale lease. The next process prunes
                # it after this PID exits; never turn cleanup into a second exception over the scan.
                pass


def _resource_slot_lock(resource: str, slot: int) -> tuple[Path, threading.Lock]:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(resource or "resource")).strip("._") or "resource"
    path = _global_request_rate_state_path().with_suffix(
        _global_request_rate_state_path().suffix + f".{safe}.slot{int(slot)}.lock"
    )
    key = str(path)
    with _RESOURCE_SLOT_FALLBACK_GUARD:
        fallback = _RESOURCE_SLOT_FALLBACK_LOCKS.get(key)
        if fallback is None:
            fallback = threading.Lock()
            _RESOURCE_SLOT_FALLBACK_LOCKS[key] = fallback
    return path, fallback


@contextmanager
def cross_process_resource_slot(resource: str, slots: int, *, deadline: float | None = None):
    """Acquire one bounded cross-process slot for a heavyweight local resource.

    Unlike target traffic pacing, this lease controls local CPU/RAM-heavy work such as Chromium.
    Multiple assessment processes therefore share the same VM-level slot budget instead of each
    independently launching up to its own local concurrency cap.  Slot acquisition never consumes a
    target request token and is deadline-aware.
    """
    slot_count = max(1, min(32, int(slots or 1)))
    held = None
    held_slot: int | None = None
    try:
        while held is None:
            now = time.monotonic()
            if deadline is not None and now >= float(deadline):
                yield None
                return
            for slot in range(slot_count):
                now = time.monotonic()
                if deadline is not None and now >= float(deadline):
                    yield None
                    return
                # Probe each slot briefly rather than blocking on slot 0 while another slot is free.
                probe_deadline = now + 0.01
                if deadline is not None:
                    probe_deadline = min(probe_deadline, float(deadline))
                path, fallback = _resource_slot_lock(resource, slot)
                candidate = _cross_process_file_lock(
                    path, exclusive=True, deadline=probe_deadline, fallback_lock=fallback,
                )
                acquired = candidate.__enter__()
                if acquired:
                    held = candidate
                    held_slot = slot
                    break
                candidate.__exit__(None, None, None)
            if held is None:
                remaining = None if deadline is None else max(0.0, float(deadline) - time.monotonic())
                if remaining is not None and remaining <= 0.0:
                    yield None
                    return
                time.sleep(min(0.05, remaining) if remaining is not None else 0.05)
        yield held_slot
    finally:
        if held is not None:
            held.__exit__(None, None, None)


@contextmanager
def heavy_compute_workload_lease(request_rate: Any = _REQUEST_RATE_UNSET, *, deadline: float | None = None):
    """Share the VM budget used by CPU/RAM-heavy local SecOps workloads.

    Chromium, local Ollama inference/model preparation and report rendering all compete for the
    same physical VM resources.  A common cross-process slot family prevents independently started
    assessments from multiplying those heavyweight workloads while leaving I/O-bound request
    concurrency free to hide network latency.
    """
    policy = secops_parallelism_policy(request_rate)
    slots = max(1, int(policy.get("heavy_local_workers") or 1))
    with cross_process_resource_slot("heavy-local", slots, deadline=deadline) as slot:
        yield slot


@contextmanager
def browser_workload_lease(request_rate: Any = _REQUEST_RATE_UNSET, *, deadline: float | None = None):
    """Share the common VM heavyweight-work budget for Chromium workloads."""
    with heavy_compute_workload_lease(request_rate, deadline=deadline) as slot:
        yield slot


@contextmanager
def target_traffic_lease(*, exclusive: bool, deadline: float | None = None):
    """Coordinate native scanners with project-controlled requests across assessment processes.

    Project-controlled HTTP/TCP starts take a shared lease briefly while the global rate token is
    assigned. A native scanner, whose internal requests cannot consume Python tokens one by one,
    takes the exclusive lease for its bounded execution window and receives its own aggregate native
    rate/delay option. This prevents native scanners and Python helpers (or two native scanners) from
    multiplying the target traffic ceiling on the same VM user account.
    """
    with _cross_process_file_lock(
        _global_target_traffic_lock_path(), exclusive=bool(exclusive), deadline=deadline,
        fallback_lock=_GLOBAL_TRAFFIC_LOCAL_FALLBACK_LOCK,
    ) as acquired:
        yield acquired



@contextmanager
def native_target_workload_lease(request_rate: Any = _REQUEST_RATE_UNSET, *, deadline: float | None = None):
    """Acquire VM-heavy capacity before exclusive unmanaged/native target traffic.

    Lock ordering is deliberate: heavy-local first, target-traffic second. A Chromium workload can
    therefore finish the project-controlled requests it already owns before a native scanner takes
    the exclusive traffic lease; reversing the order could deadlock a small VM when only one heavy
    slot exists. The returned diagnostics separate resource wait from target-traffic wait.
    """
    heavy_started = time.monotonic()
    with heavy_compute_workload_lease(request_rate, deadline=deadline) as heavy_slot:
        heavy_wait = time.monotonic() - heavy_started
        if heavy_slot is None:
            yield {
                "acquired": False, "heavy_slot": None,
                "heavy_wait_seconds": heavy_wait, "target_wait_seconds": 0.0,
                "diagnosis": "heavy_resource_lease_timeout",
            }
            return
        traffic_started = time.monotonic()
        with target_traffic_lease(exclusive=True, deadline=deadline) as traffic_acquired:
            target_wait = time.monotonic() - traffic_started
            yield {
                "acquired": bool(traffic_acquired), "heavy_slot": heavy_slot,
                "heavy_wait_seconds": heavy_wait, "target_wait_seconds": target_wait,
                "diagnosis": "" if traffic_acquired else "target_traffic_lease_timeout",
            }

class RequestRatePacer:
    """Assessment-host request-start pacer for project-controlled network helpers.

    All SecOps Python processes owned by the same OS user coordinate through a tiny locked state
    file. Multiple workers may therefore keep requests in flight to hide response latency, while
    request *starts* remain globally spaced by the configured rate. Active lower-rate clients are
    retained briefly, so concurrent project-controlled assessments fail conservatively toward the
    lowest recently active configured rate rather than summing independent per-process pacers.

    External scanners still receive their own native rate/delay flag and are executed sequentially
    by the orchestrator; this shared pacer governs every project-controlled HTTP/TCP helper.
    """

    def __init__(self, request_rate: Any = _REQUEST_RATE_UNSET) -> None:
        self.rate = scanner_request_rate(request_rate)
        self.interval_seconds = 1.0 / self.rate
        self._last_request_at = 0.0
        self._lock = threading.Lock()
        self._state_path = _global_request_rate_state_path()
        self._lock_path = self._state_path.with_suffix(self._state_path.suffix + ".lock")
        self._client_key = f"{os.getpid()}:{self.rate:g}"
        self._wait_count = 0
        self._throttle_seconds = 0.0
        self._last_effective_rate = self.rate

    def _wait_shared(self, deadline: float | None = None) -> bool:
        with target_traffic_lease(exclusive=False, deadline=deadline) as traffic_acquired:
            if not traffic_acquired:
                return False
            with _cross_process_rate_lock(self._lock_path, deadline=deadline) as rate_acquired:
                if not rate_acquired:
                    return False
                now = time.time()
                state: dict[str, Any] = {}
                state_corrupt = False
                try:
                    if self._state_path.is_file():
                        loaded = json.loads(self._state_path.read_text(encoding="utf-8"))
                        if isinstance(loaded, dict):
                            state = loaded
                        else:
                            state_corrupt = True
                except OSError:
                    # If the shared state cannot be read, fail closed. Starting a target request
                    # without knowing the last cross-process start could violate the configured
                    # maximum rate. Callers treat False as a bounded timeout/defer condition.
                    return False
                except (ValueError, TypeError, json.JSONDecodeError):
                    # A malformed state file may have been left by an interrupted/legacy process.
                    # Recover conservatively by forcing one full configured interval before the
                    # next token rather than resetting the history and allowing an immediate burst.
                    state_corrupt = True
                    state = {}
                clients = state.get("clients") if isinstance(state.get("clients"), dict) else {}
                fresh_clients: dict[str, dict[str, float]] = {}
                current_pid_prefix = f"{os.getpid()}:"
                for key, row in clients.items():
                    if not isinstance(row, dict):
                        continue
                    key_text = str(key)
                    # A current-PID entry with a different configured rate belongs to an older
                    # pacer instance (or a reused PID after restart); do not let it self-throttle
                    # the current process until TTL expiry.
                    if key_text.startswith(current_pid_prefix) and key_text != self._client_key:
                        continue
                    seen = safe_float_value(row.get("seen"), 0.0)
                    rate = safe_float_value(row.get("rate"), 0.0)
                    if (
                        rate >= 1.0 and seen > 0.0
                        and now - seen <= _GLOBAL_RATE_CLIENT_TTL_SECONDS
                        and _rate_client_process_alive(key_text)
                    ):
                        fresh_clients[key_text] = {"rate": rate, "seen": seen}
                fresh_clients[self._client_key] = {"rate": self.rate, "seen": now}
                effective_rate = min(row["rate"] for row in fresh_clients.values()) if fresh_clients else self.rate
                interval = 1.0 / max(1.0, effective_rate)
                last_start = safe_float_value(state.get("last_start"), 0.0)
                # Wall-clock jumps or stale files must not create an unbounded sleep after reboot/NTP.
                if last_start <= 0.0 or last_start > now + 5.0 or now - last_start > 3600.0:
                    last_start = 0.0
                if state_corrupt:
                    # Unknown previous state => assume a request could have started just now.
                    last_start = now
                delay = max(0.0, interval - (now - last_start))
                if deadline is not None:
                    remaining = float(deadline) - time.monotonic()
                    if remaining <= delay:
                        return False
                self._last_effective_rate = effective_rate
                self._throttle_seconds += delay
                if delay > 0.0:
                    time.sleep(delay)
                if deadline is not None and time.monotonic() >= float(deadline):
                    return False
                started = time.time()
                payload = {
                    "last_start": started,
                    "effective_rate": effective_rate,
                    "clients": fresh_clients,
                    "updated": started,
                }
                try:
                    atomic_write_text(self._state_path, json.dumps(payload, sort_keys=True))
                except OSError:
                    # Never grant a target request when the cross-process timestamp cannot be
                    # persisted: another process could otherwise acquire the lock immediately and
                    # start a second request without observing this token. Fail closed instead.
                    return False
                self._wait_count += 1
                return True

    def wait(self, deadline: float | None = None) -> bool:
        with self._lock:
            # The shared file pacer is authoritative. The local timestamp is retained for telemetry
            # and for environments where persistence becomes temporarily unavailable.
            ok = self._wait_shared(deadline)
            if ok:
                self._last_request_at = time.monotonic()
            return ok

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                'configured_rate': self.rate,
                'last_effective_shared_rate': self._last_effective_rate,
                'request_starts': self._wait_count,
                'throttle_sleep_seconds': round(self._throttle_seconds, 3),
            }


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
            if not active_pacer.wait(deadline):
                raise requests.Timeout("shared scanner deadline reached while waiting for request-rate slot")
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
        if not active_pacer.wait(deadline):
            raise requests.Timeout("shared scanner deadline reached while waiting for request-rate slot")
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
            if not active_pacer.wait(deadline):
                raise requests.Timeout("shared scanner deadline reached while waiting for TLS-retry request-rate slot")
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


_UNRESOLVED_ROUTE_TEMPLATE_SEGMENT = re.compile(
    r'^(?::[A-Za-z_][A-Za-z0-9_-]*\??|\{[A-Za-z_][A-Za-z0-9_.-]*\}|<[A-Za-z_][A-Za-z0-9_.:-]*>|\[[A-Za-z_][A-Za-z0-9_.-]*\]|\$\{[A-Za-z_][A-Za-z0-9_.-]*\})$'
)


def unresolved_route_template_url(url: str) -> bool:
    """Return True for client/framework route templates that are not concrete network targets.

    Only whole path segments with explicit placeholder syntax are rejected. Colons/brackets inside
    ordinary concrete path text and all query values remain untouched.
    """
    try:
        path = unquote(str(urlparse(str(url or '')).path or ''))
    except Exception:
        return False
    return any(
        bool(_UNRESOLVED_ROUTE_TEMPLATE_SEGMENT.fullmatch(segment))
        for segment in path.split('/') if segment
    )


# Removes stray whitespace from discovered URL authorities without touching path/query data.
def sanitize_discovered_url(url: str) -> str:
    raw = str(url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if unresolved_route_template_url(raw):
        # Client-side routers and source maps commonly expose patterns such as /:realm or /{id}.
        # They are useful static evidence but are not concrete URLs and must never become active
        # scanner targets.
        return ""
    if "\\" in raw:
        # Raw backslashes are not a stable HTTP URL representation and in discovery data almost
        # always come from JavaScript/regex/source-map text (for example ``\x3c`` or ``[^\/]``).
        # Real network URLs use percent encoding instead, so retain the source evidence elsewhere
        # but do not promote this fragment to an active target.
        return ""
    if re.search(r';[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$]*\?\(', raw) and '==' in str(parsed.query or ''):
        # Source extraction can splice minified JavaScript expressions into a URL-looking token,
        # e.g. ``vendor/;e.action?(t=e.action==``. Require both code-shaped path and comparison
        # syntax so ordinary semicolon/matrix parameters are not rejected.
        return ""
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
    target_traffic: bool = True,
) -> dict[str, Any]:

    executable = find_executable(command[0])
    if not executable:
        return failure(tool, target, f"Executable not found: {command[0]}", diagnosis="missing_executable")

    resolved_command = [executable, *command[1:]]
    env = subprocess_parallelism_environment(os.environ.copy())
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    started = time.monotonic()
    process_deadline = started + max(1.0, float(timeout))
    external_lease_wait_seconds = 0.0
    external_resource_wait_seconds = 0.0
    try:
        # Native target scanners cannot consume Python rate tokens request-by-request, so they hold
        # the exclusive target-traffic lease and enforce the configured aggregate rate internally.
        # Purely local capability/help subprocesses explicitly opt out and must not idle target I/O
        # from another assessment while they inspect a binary on the VM.
        lease_context = (
            native_target_workload_lease(deadline=process_deadline)
            if target_traffic else nullcontext({
                "acquired": True, "heavy_slot": -1, "heavy_wait_seconds": 0.0,
                "target_wait_seconds": 0.0, "diagnosis": "",
            })
        )
        with lease_context as lease_state:
            external_lease_wait_seconds = float(lease_state.get("target_wait_seconds", 0.0)) if target_traffic else 0.0
            external_resource_wait_seconds = float(lease_state.get("heavy_wait_seconds", 0.0)) if target_traffic else 0.0
            if not lease_state.get("acquired"):
                return failure(
                    tool, target,
                    "Native scanner could not acquire the bounded VM/target execution lease before its deadline.",
                    diagnosis=str(lease_state.get("diagnosis") or "native_workload_lease_timeout"),
                    timed_out=True, duration_seconds=round(time.monotonic() - started, 3),
                    command=resolved_command,
                    external_rate_lease_wait_seconds=round(external_lease_wait_seconds, 3),
                    external_resource_lease_wait_seconds=round(external_resource_wait_seconds, 3),
                )
            remaining_timeout = max(0.001, process_deadline - time.monotonic())
            if progress_callback is None:
                completed = subprocess.run(
                    resolved_command,
                    cwd=str(cwd) if cwd else None,
                    env=env,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=remaining_timeout,
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
                interval = max(0.5, min(float(progress_interval), remaining_timeout))
                while True:
                    remaining = process_deadline - time.monotonic()
                    if remaining <= 0:
                        process.kill()
                        stdout, stderr = process.communicate()
                        raise subprocess.TimeoutExpired(resolved_command, max(1.0, float(timeout)), output=stdout, stderr=stderr)
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
            external_rate_lease_wait_seconds=round(external_lease_wait_seconds, 3),
            external_resource_lease_wait_seconds=round(external_resource_wait_seconds, 3),
        )
    except OSError as exc:
        return failure(
            tool,
            target,
            f"Cannot start process: {exc}",
            diagnosis="process_start_failed",
            duration_seconds=round(time.monotonic() - started, 3),
            command=resolved_command,
            external_rate_lease_wait_seconds=round(external_lease_wait_seconds, 3),
            external_resource_lease_wait_seconds=round(external_resource_wait_seconds, 3),
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
            external_rate_lease_wait_seconds=round(external_lease_wait_seconds, 3),
            external_resource_lease_wait_seconds=round(external_resource_wait_seconds, 3),
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
            external_rate_lease_wait_seconds=round(external_lease_wait_seconds, 3),
            external_resource_lease_wait_seconds=round(external_resource_wait_seconds, 3),
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
        external_rate_lease_wait_seconds=round(external_lease_wait_seconds, 3),
        external_resource_lease_wait_seconds=round(external_resource_wait_seconds, 3),
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