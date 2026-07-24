from __future__ import annotations

import hashlib
import re
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
from fastmcp import FastMCP

from utils import failure, skipped, success

mcp = FastMCP("IDOR Differential Checker")


def mutate_first_numeric_parameter(url: str) -> tuple[str, str] | None:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for index, (name, value) in enumerate(pairs):
        if re.fullmatch(r"\d+", value):
            changed = pairs.copy()
            changed[index] = (name, str(int(value) + 1))
            return name, urlunparse(parsed._replace(query=urlencode(changed)))
    return None


def _looks_like_login(response: requests.Response) -> bool:
    text = response.text[:8000].lower()
    return "login.php" in response.url.lower() or ("type=\"password\"" in text and "login" in text)


@mcp.tool()
def run_idor_check(target_url: str, cookies: str = "", timeout: int = 20) -> dict:
    """Perform a cautious differential check; identical generic responses are not flagged."""
    mutation = mutate_first_numeric_parameter(target_url)
    if not mutation:
        return skipped("IDOR Differential Checker", target_url, "No numeric query parameter was available for a differential check.")
    parameter, mutated_url = mutation
    session = requests.Session()
    if cookies:
        session.headers["Cookie"] = cookies
    try:
        original = session.get(target_url, timeout=timeout, allow_redirects=True)
        mutated = session.get(mutated_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return failure("IDOR Differential Checker", target_url, str(exc), diagnosis="request_failed")

    original_hash = hashlib.sha256(original.content).hexdigest()
    mutated_hash = hashlib.sha256(mutated.content).hexdigest()
    similarity = SequenceMatcher(None, original.text[:100_000], mutated.text[:100_000]).ratio()
    same_status = original.status_code == mutated.status_code == 200
    changed_content = original_hash != mutated_hash
    candidate = same_status and changed_content and 0.55 <= similarity < 0.995 and not _looks_like_login(original) and not _looks_like_login(mutated)

    findings = []
    if candidate:
        findings.append({
            "alert": "Potential IDOR candidate",
            "risk": "medium",
            "category": "candidate",
            "description": f"Changing numeric parameter '{parameter}' returned a different but structurally similar successful response.",
            "impact": "If the changed object belongs to another user and no authorization check is enforced, unauthorized data access or modification may be possible.",
            "solution": "Enforce object-level authorization on every request and manually verify with two accounts that have different permissions.",
            "url": mutated_url,
            "parameter": parameter,
            "confidence": "low",
            "evidence": (
                f"original_status={original.status_code}; mutated_status={mutated.status_code}; "
                f"original_bytes={len(original.content)}; mutated_bytes={len(mutated.content)}; similarity={similarity:.3f}"
            ),
        })

    return success(
        "IDOR Differential Checker", target_url,
        f"Differential request completed. Candidate: {candidate}.",
        vulnerabilities=findings, mutated_url=mutated_url, candidate=candidate,
        similarity=round(similarity, 4), content_changed=changed_content,
        authenticated=bool(cookies),
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")