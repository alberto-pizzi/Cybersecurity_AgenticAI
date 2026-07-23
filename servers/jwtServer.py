from __future__ import annotations

from fastmcp import FastMCP
import jwt

from utils import failure, skipped, success

mcp = FastMCP("JWT Analyzer")


@mcp.tool()
def run_jwt_scan(jwt_token: str = "", target_url: str = "") -> dict:
    """
    Analyses a JWT supplied by the user or discovered by the orchestrator.

    It never invents a sample token. No token means the tool is explicitly skipped.
    """
    if not jwt_token:
        return skipped("JWT Analyzer", target_url, "No JWT was supplied or discovered.")

    try:
        header = jwt.get_unverified_header(jwt_token)
        payload = jwt.decode(jwt_token, options={"verify_signature": False})
    except Exception as exc:
        return failure("JWT Analyzer", target_url, f"Invalid JWT: {exc}")

    findings = []
    algorithm = str(header.get("alg", "")).lower()
    if algorithm == "none":
        findings.append({
            "alert": "JWT accepts no-signature algorithm",
            "risk": "critical",
            "description": "The token declares alg=none.",
            "solution": "Reject unsigned tokens and enforce an explicit algorithm allow-list.",
            "url": target_url,
        })
    if "exp" not in payload:
        findings.append({
            "alert": "JWT without expiration",
            "risk": "medium",
            "description": "The token has no exp claim.",
            "solution": "Issue short-lived tokens with expiration and rotation.",
            "url": target_url,
        })

    return success(
        "JWT Analyzer",
        target_url,
        f"JWT decoded without signature verification. Findings: {len(findings)}",
        vulnerabilities=findings,
        header=header,
        payload=payload,
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")