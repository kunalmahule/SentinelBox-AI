"""Stage 5: secure Docker sandbox for the synthetic adversarial workload.

Trust boundaries (the container is an *execution boundary, not an authority*):

* The HOST validates input, authorises the workload, enforces the policy, derives every verdict with the Stage 3
  rule engine and writes every audit record through the Stage 4 storage layer.
* The CONTAINER only executes the fixed workload (``sentinelbox.sandbox_workload``) on data sent over stdin and returns
  data over stdout. Its output, exit code and self-reported observations are validated, never trusted.

This is a hardening layer for running synthetic test workloads, not a proof of isolation: see the README threat model.
"""

POLICY_VERSION = "sandbox-policy-1"
