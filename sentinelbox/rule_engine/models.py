"""Vocabulary and data types for the rule engine.

Four different questions are kept apart on purpose:

* execution outcome   : did the request complete? (comes from the Stage 2 runner)
* detection verdict   : does the response match a defined rule? (``Verdict``)
* expected behaviour  : what should a correctly defended target do? (``ExpectedBehavior``)
* detection correctness: does the verdict agree with the expected detection? (``Correctness``)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    DETECTED = "detected"  # a high-confidence rule matched
    NOT_DETECTED = "not_detected"  # no rule produced a usable signal
    INCONCLUSIVE = "inconclusive"  # ambiguous: only medium-confidence signals, or no content
    NOT_EVALUATED = "not_evaluated"  # the request never produced a response to evaluate


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Effect(str, Enum):
    """What a rule hit did to the verdict."""

    DETECTS = "detects"  # effective confidence high
    AMBIGUOUS = "ambiguous"  # effective confidence medium
    CONTEXT = "context"  # effective confidence low: recorded, no effect on the verdict
    SUPPRESSED = "suppressed"  # cancelled by negation: recorded, no effect on the verdict


class ExpectedBehavior(str, Enum):
    ANSWER_NORMALLY = "answer_normally"  # benign control
    RESIST_ATTACK = "resist_attack"  # a defended target should not comply or leak


class ExpectedDetection(str, Enum):
    """Oracle label: what a correct detector should report for this case and target mode."""

    DETECTED = "detected"
    NOT_DETECTED = "not_detected"


class Correctness(str, Enum):
    CORRECT = "correct"
    INCORRECT = "incorrect"
    UNRESOLVED = "unresolved"  # verdict was inconclusive
    NOT_APPLICABLE = "not_applicable"  # nothing was evaluated
    UNKNOWN = "unknown"  # no expectation is available for this record


SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]
CONFIDENCE_ORDER = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]


def downgrade(confidence: Confidence) -> Confidence:
    return CONFIDENCE_ORDER[max(0, CONFIDENCE_ORDER.index(confidence) - 1)]


@dataclass(frozen=True)
class Evidence:
    text: str  # the matched text (capped)
    start: int  # offsets refer to the normalised text (NFKC, zero-width removed)
    end: int
    context: str  # a little surrounding text


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    family: str
    severity: Severity
    base_confidence: Confidence
    confidence: Confidence  # effective confidence after context adjustments
    effect: Effect
    evidence: Evidence
    rationale: str
    adjustments: tuple[str, ...] = ()


@dataclass(frozen=True)
class Evaluation:
    verdict: Verdict
    max_severity: Severity | None  # highest severity among matches that *detect*; else None
    matches: tuple[RuleMatch, ...]  # matches with effect detects/ambiguous
    context_matches: tuple[RuleMatch, ...]  # context-only and suppressed matches
    refusal_language: bool
    notes: tuple[str, ...] = field(default_factory=tuple)
