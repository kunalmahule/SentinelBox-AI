"""Pure, deterministic response logic for the mock AI target (no web layer)."""

from __future__ import annotations

from dataclasses import dataclass

from .scenarios import RESPONSES, Mode, Scenario, classify

MODEL_NAME = "mock-sentinel-1"


@dataclass(frozen=True)
class MockResult:
    response: str
    scenario: Scenario
    mode: Mode
    matched_rule: str | None


def respond(
    prompt: str,
    mode: Mode = Mode.VULNERABLE,
    scenario_override: Scenario | None = None,
) -> MockResult:
    """Return the mock assistant's reply for *prompt*.

    * ``mode`` selects whether the simulated assistant falls for adversarial
      prompts (``vulnerable``) or refuses them (``hardened``).
    * ``scenario_override`` forces a scenario regardless of the prompt text,
      which keeps downstream tests fully deterministic.
    """
    if not isinstance(prompt, str):
        raise TypeError("prompt must be a string")

    if scenario_override is not None:
        scenario, rule_id = Scenario(scenario_override), "override"
    else:
        found = classify(prompt)
        scenario, rule_id = found.scenario, found.rule_id

    mode = Mode(mode)
    return MockResult(
        response=RESPONSES[(scenario, mode)],
        scenario=scenario,
        mode=mode,
        matched_rule=rule_id,
    )
