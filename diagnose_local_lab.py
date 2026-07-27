from __future__ import annotations

import json
import initScript


def main() -> int:
    try:
        cookie = initScript.create_local_lab_session()
    except Exception as exc:
        print(json.dumps({
            "status": "error",
            "type": type(exc).__name__,
            "message": str(exc),
        }, indent=2, ensure_ascii=False))
        return 2

    print(json.dumps({
        "status": "success",
        "target": initScript.TARGET,
        "profile": "bundled-local-training-lab",
        "cookie_names": initScript.cookie_names(cookie),
        "cookie_header": cookie,
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
