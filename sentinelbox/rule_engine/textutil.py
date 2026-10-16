"""Text normalisation and context checks shared by the rules."""

from __future__ import annotations

import re
import unicodedata

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
_QUOTES = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"'})

# Sentence break: . ! ? followed by whitespace/end (but not inside e.g. / i.e.), or a newline.
_BREAK = re.compile(r"(?<!e\.g)(?<!i\.e)[.!?](?=\s|$)|\n")

_NEGATION = re.compile(
    r"\b(?:not|never|no longer|cannot|unable|refus\w*|declin\w*|without|"
    r"won't|can't|don't|doesn't|didn't|isn't|aren't|wasn't|wouldn't|shouldn't|couldn't)\b",
    re.IGNORECASE,
)

_EXAMPLE_CUE = re.compile(
    r"(?:\bsuch as\b|\bfor example\b|\bfor instance\b|\be\.g\.|\bi\.e\.|\ban example\b|\bexamples? (?:include|are|is)\b|"
    r"\btypical (?:phrases?|prompts?|attacks?|payloads?)\b|"
    r"\battackers? (?:may|might|can|could|often|typically|will) (?:say|write|type|use|send|try)\b|"
    r"\b(?:someone|a user|the user|they|users|attackers?) (?:may |might |could |can |often )?(?:says?|said|writes?|wrote|types?|typed)\b|"
    r"\b(?:phrases?|messages?|prompts?|inputs?|instructions?|text|words?) (?:like|such as|that say|saying|reading)\b)",
    re.IGNORECASE,
)

MAX_EVIDENCE_CHARS = 160
CONTEXT_CHARS = 30


def normalize(text: str) -> str:
    """NFKC, drop zero-width characters, straighten curly quotes. Case is preserved."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    return text.translate(_QUOTES)


def sentence_start(text: str, pos: int) -> int:
    low = max(0, pos - 400)
    last = None
    for last in _BREAK.finditer(text, low, pos):
        pass
    return last.end() if last is not None else low


def negation_before(text: str, start: int) -> str | None:
    """Return the negation cue found earlier in the same sentence, if any."""
    segment = text[sentence_start(text, start):start]
    found = _NEGATION.search(segment)
    return found.group(0) if found else None


def quotation_context(text: str, start: int, end: int) -> str | None:
    """Return a description if the span looks quoted or introduced as an example."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    before = text[line_start:start]
    if before.count('"') % 2 == 1:
        return "inside double quotes"
    if text.count("`", 0, start) % 2 == 1:
        return "inside a code span or block"
    if re.search(r"(?<![A-Za-z0-9])'[^'\n]*$", before) and "'" in text[end:line_end]:
        return "inside single quotes"
    segment = text[max(sentence_start(text, start), start - 200):start]
    if _EXAMPLE_CUE.search(segment):
        return "introduced as an example or quoted phrase"
    return None


def snippet(text: str, start: int, end: int) -> tuple[str, str]:
    matched = text[start:end]
    if len(matched) > MAX_EVIDENCE_CHARS:
        matched = matched[:MAX_EVIDENCE_CHARS] + "..."
    context = text[max(0, start - CONTEXT_CHARS):min(len(text), end + CONTEXT_CHARS)]
    if len(context) > MAX_EVIDENCE_CHARS + 2 * CONTEXT_CHARS:
        context = context[: MAX_EVIDENCE_CHARS + 2 * CONTEXT_CHARS] + "..."
    return matched, context
