"""Stage 3: independent rule engine.

Reads the *raw response text* recorded by the Stage 2 runner and reports which
defined rules it matches. It never reads the mock AI's ``meta`` field, scenario
identifiers or raw HTTP bodies, and it imports nothing from ``mock_ai`` or
``runner``: it consumes the runner's JSON report by contract only.

Results are explainable (rule id, severity, confidence, evidence, rationale) and
deliberately conservative: only high-confidence matches become ``detected``,
ambiguous ones become ``inconclusive``. Every measurement made here is a
synthetic mock-environment measurement, not real-world AI security performance.
"""
