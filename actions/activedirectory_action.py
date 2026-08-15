#!/usr/bin/env python3
"""Shared stdin/JSON entry point for curated Active Directory actions."""

from __future__ import annotations

import json
import os
import sys

_PACK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACK_ROOT not in sys.path:
    sys.path.insert(0, _PACK_ROOT)

from lib.activedirectory_client import MAX_INPUT_BYTES, ActiveDirectoryPackError, execute_action


def main() -> int:
    try:
        raw = sys.stdin.read(MAX_INPUT_BYTES + 1)
        if len(raw.encode("utf-8")) > MAX_INPUT_BYTES:
            raise ActiveDirectoryPackError("action parameters exceed the 64 KiB limit")
        params = json.loads(raw) if raw.strip() else {}
        if not isinstance(params, dict):
            raise ActiveDirectoryPackError("action parameters must be a JSON object")
        operation = os.environ.get("ATTUNE_ACTION", "").rsplit(".", 1)[-1]
        json.dump(execute_action(operation, params), sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except json.JSONDecodeError:
        print("activedirectory action failed: invalid JSON action parameters", file=sys.stderr)
    except ActiveDirectoryPackError as exc:
        print(f"activedirectory action failed: {exc}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 - redact unknown exception messages
        print(f"activedirectory action failed: {type(exc).__name__}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
