"""Code that runs INSIDE the sandbox container (Stage 5).

Trust boundary: everything in this package is untrusted from the host's point of view. The host sends a request on
stdin, reads one JSON object from stdout and validates it strictly with :mod:`.protocol`. This package never decides
a security verdict, never touches a database, never reads credentials and uses only the standard library plus the
Stage 1 mock engine and the Stage 2 runner (reused unchanged, through an in-process transport so no network is needed).
"""
