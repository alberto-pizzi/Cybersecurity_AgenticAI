from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from servers.niktoServer import (
    NIKTO_DOCKER_IMAGE,
    _docker_command_available,
    _docker_target,
    _find_perl,
    _perl_connectivity_probe,
    _python_connectivity_probe,
)
from utils import normalize_url


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Python, Strawberry Perl and Docker Nikto connectivity."
    )
    parser.add_argument("--target", default="http://127.0.0.1")
    args = parser.parse_args()
    target = normalize_url(args.target)

    result = {
        "target": target,
        "python": _python_connectivity_probe(target),
        "perl": {},
        "docker": {
            "available": _docker_command_available(),
            "image": NIKTO_DOCKER_IMAGE,
        },
    }

    perl = _find_perl()
    if perl is not None:
        result["perl"] = {
            "executable": str(perl),
            **_perl_connectivity_probe(perl, target),
        }
    else:
        result["perl"] = {
            "connected": False,
            "error": "Perl executable not found.",
        }

    if result["docker"]["available"]:
        docker_target, arguments, mode = _docker_target(target)
        result["docker"].update({
            "translated_target": docker_target,
            "mapping_mode": mode,
            "network_arguments": arguments,
        })
        inspect = subprocess.run(
            ["docker", "image", "inspect", NIKTO_DOCKER_IMAGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        result["docker"]["image_present"] = inspect.returncode == 0

    result["root_cause"] = (
        "Strawberry Perl socket layer cannot reach the target while Python can; use the Docker fallback."
        if result["python"].get("tcp_connected") and not result["perl"].get("connected")
        else "No Python-versus-Perl socket mismatch detected."
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["python"].get("tcp_connected") else 2


if __name__ == "__main__":
    raise SystemExit(main())
