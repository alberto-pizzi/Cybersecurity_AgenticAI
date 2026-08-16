from __future__ import annotations

from datetime import datetime, timezone

import jwt

from utils import failure, skipped, success

from scannerCommon import service

mcp, _serve = service("JWT Analyzer", "jwt")

@mcp.tool()
def run_jwt_scan(jwt_token: str = "", target_url: str = "") -> dict:
    if not jwt_token:
        return skipped("JWT Analyzer", target_url, "No JWT was supplied or discovered.")
    try:
        header = jwt.get_unverified_header(jwt_token)
        payload = jwt.decode(jwt_token, options={"verify_signature": False})
    except Exception as exc:
        return failure("JWT Analyzer", target_url, f"Invalid JWT: {exc}", diagnosis="invalid_jwt")

    findings = []
    algorithm = str(header.get("alg", "")).lower()
    if algorithm == "none":
        findings.append({
            "alert": "Unsigned JWT algorithm", "risk": "critical",
            "category": "candidate", "verification_status": "token-structure-only",
            "description": "The observed token declares alg=none. This is unsafe only if the target accepts unsigned tokens; this analyzer did not submit a modified token to the server.",
            "impact": "A verifier that accepts this token may allow attackers to forge arbitrary identities and claims.",
            "solution": "Reject unsigned tokens and enforce an explicit server-side algorithm allow-list.",
            "url": target_url, "confidence": "medium", "evidence": "JWT header alg=none",
        })
    if "exp" not in payload:
        findings.append({
            "alert": "JWT without expiration", "risk": "medium",
            "category": "candidate", "verification_status": "token-structure-only",
            "description": "The observed token does not contain an exp claim. This establishes token structure, not the server-side lifetime or revocation policy.",
            "impact": "A stolen token may remain reusable indefinitely unless it is revoked through another mechanism.",
            "solution": "Issue short-lived tokens with exp, rotate signing keys, and support revocation where required.",
            "url": target_url, "confidence": "high", "evidence": "JWT payload has no exp claim",
        })
    elif isinstance(payload.get("exp"), (int, float)) and payload["exp"] < datetime.now(timezone.utc).timestamp():
        findings.append({
            "alert": "Expired JWT observed", "risk": "info",
            "category": "observation", "verification_status": "token-structure-only",
            "description": "The observed JWT contains an expiration timestamp that is earlier than the assessment time. The analyzer did not test whether the server rejects it.",
            "impact": "The token should not authorize requests; acceptance would indicate a validation flaw.",
            "solution": "Ensure expiration is always verified by the server.",
            "url": target_url, "confidence": "high", "evidence": f"exp={payload['exp']}",
        })

    return success(
        "JWT Analyzer", target_url, f"JWT decoded without signature verification. Findings: {len(findings)}.",
        vulnerabilities=findings, header=header, payload=payload,
        analysis_note="Decoding alone does not prove that the target accepts a modified token.",
    )

if __name__ == "__main__":
    _serve()
