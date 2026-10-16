"""Stage 2: adversarial test runner.

Loads a prompt library, sends each case to a target's ``POST /chat`` endpoint and
records what came back. It makes **no safety judgement**: outcomes describe
whether a test executed, not whether the target's answer was safe. That is the
job of the Stage 3 rule engine, which must work from the raw responses.

This package deliberately does not import ``sentinelbox.mock_ai``.
"""
