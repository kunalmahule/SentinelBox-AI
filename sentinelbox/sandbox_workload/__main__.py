"""Fixed entry point of the sandbox image: ``python -m sentinelbox.sandbox_workload``.

It takes no arguments. It reads one request from stdin (bounded), runs the approved synthetic job it describes and
writes one JSON object to stdout. Diagnostics go to stderr and are short. The request is data: it is never evaluated,
never used as a command, a path or a module name.
"""

from __future__ import annotations

import json
import sys

from . import protocol

EXIT_OK = 0
EXIT_BAD_REQUEST = 64
EXIT_INTERNAL = 70


def main(stdin=None, stdout=None, stderr=None) -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    if len(sys.argv) > 1 and stdin is sys.stdin.buffer:
        print("sentinelbox-sandbox-workload takes no arguments", file=stderr)
        return EXIT_BAD_REQUEST
    raw = stdin.read(protocol.MAX_REQUEST_BYTES + 1)
    try:
        request = protocol.parse_request(raw)
    except protocol.ProtocolError as exc:
        print(f"rejected request: {str(exc)[:1500]}", file=stderr)
        return EXIT_BAD_REQUEST
    try:
        if request.kind == "self_check":
            from . import selfcheck

            now = selfcheck.observe()
            response = protocol.build_response(request, status="complete", stop_reason=None, started_at=now["observed_at"],
                                               finished_at=now["observed_at"], planned=0, results=[], observations=now)
        else:
            from . import harness

            response = harness.run_job(request)
    except Exception as exc:  # noqa: BLE001 - report a short, non-sensitive message and fail
        print(f"workload failed: {type(exc).__name__}", file=stderr)
        return EXIT_INTERNAL
    stdout.write(json.dumps(response, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    stdout.write("\n")
    stdout.flush()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
