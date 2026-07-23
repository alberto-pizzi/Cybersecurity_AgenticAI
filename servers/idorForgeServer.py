from __future__ import annotations

import re
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
            mutated = urlunparse(parsed._replace(query=urlencode(changed)))
            return name, mutated
    return None


@mcp.tool()
def run_idor_check(target_url: str, cookies: str = "", timeout: int = 20) -> dict:
    """
    Performs a small differential check on the first numeric query parameter.

    This is a heuristic, not a proof: a reported candidate must be manually verified
    with two accounts that have different permissions.
    """
    mutation = mutate_first_numeric_parameter(target_url)
    if not mutation:
        return skipped(
            "IDOR Differential Checker",
            target_url,
            "No numeric query parameter was available for a differential check.",
        )

    parameter, mutated_url = mutation
    session = requests.Session()
    if cookies:
        session.headers["Cookie"] = cookies

    try:
        original = session.get(target_url, timeout=timeout, allow_redirects=True)
        mutated = session.get(mutated_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return failure("IDOR Differential Checker", target_url, str(exc))

    similar_size = abs(len(original.content) - len(mutated.content)) <= max(
        100, int(len(original.content) * 0.10)
    )
    candidate = (
        original.status_code == mutated.status_code == 200
        and similar_size
        and original.url != mutated.url
    )

    findings = []
    if candidate:
        findings.append({
            "alert": "Potential IDOR candidate",
            "risk": "medium",
            "description": (
                f"Changing parameter '{parameter}' produced another successful, "
                "similarly sized response. Manual multi-user authorization testing is required."
            ),
            "solution": "Enforce object-level authorization on every server-side access.",
            "url": mutated_url,
            "parameter": parameter,
            "evidence": f"Original bytes={len(original.content)}, changed bytes={len(mutated.content)}",
        })

    return success(
        "IDOR Differential Checker",
        target_url,
        f"Differential request completed. Candidate: {candidate}",
        vulnerabilities=findings,
        mutated_url=mutated_url,
        candidate=candidate,
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")