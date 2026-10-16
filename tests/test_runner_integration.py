"""End-to-end: the real runner against the real Stage 1 app, in-process (no sockets).

The Stage 1 marker constants are imported here, in the *tests*, only to confirm that the
prompt library still exercises the mock. The runner itself never looks at them.
"""

import json
from collections import defaultdict

import pytest
from runner_fakes import BASE_URL, MockAppTransport

from sentinelbox.mock_ai.scenarios import BYPASS_MARKER, CANARY_TOKEN, FAKE_API_KEY, INJECTION_MARKER
from sentinelbox.runner.cli import EXIT_OK, main
from sentinelbox.runner.library import load_library
from sentinelbox.runner.models import TargetMode
from sentinelbox.runner.report import build_report, validate_report, write_report
from sentinelbox.runner.runner import run_suite

LIBRARY = load_library()
BOTH = [TargetMode.VULNERABLE, TargetMode.HARDENED]


@pytest.fixture
def transport(client):
    return MockAppTransport(client)


@pytest.fixture
def full_run(transport):
    return run_suite(LIBRARY.cases, BOTH, BASE_URL, transport)


def by_category_and_mode(run):
    grouped = defaultdict(list)
    for r in run.results:
        grouped[(r.category, r.target_mode)].append(r)
    return grouped


def test_full_library_completes_in_both_modes(full_run):
    assert full_run.planned == 48 and len(full_run.results) == 48
    assert {r.outcome for r in full_run.results} == {"completed"}
    assert {r.http_status for r in full_run.results} == {200}


def test_only_prompt_and_mode_are_ever_sent(transport):
    run_suite(LIBRARY.cases, BOTH, BASE_URL, transport)
    assert len(transport.payloads) == 48
    assert {frozenset(p) for p in transport.payloads} == {frozenset({"prompt", "mode"})}


def test_vulnerable_target_replies_differ_by_category_as_the_library_intends(full_run):
    groups = by_category_and_mode(full_run)
    texts = lambda category: [r.response_text for r in groups[(category, "vulnerable")]]  # noqa: E731
    assert all(INJECTION_MARKER in t for t in texts("prompt_injection"))
    assert all(BYPASS_MARKER in t for t in texts("safety_bypass"))
    assert all(CANARY_TOKEN in t and FAKE_API_KEY in t for t in texts("canary_disclosure"))
    assert not any(m in t for t in texts("normal") for m in (INJECTION_MARKER, BYPASS_MARKER, CANARY_TOKEN, FAKE_API_KEY))


def test_hardened_target_never_leaks_markers_or_canaries(full_run):
    for r in full_run.results:
        if r.target_mode == "hardened":
            assert not any(m in r.response_text for m in (INJECTION_MARKER, BYPASS_MARKER, CANARY_TOKEN, FAKE_API_KEY))


def test_normal_prompts_get_the_same_reply_in_both_modes(full_run):
    groups = by_category_and_mode(full_run)
    assert {r.response_text for r in groups[("normal", "vulnerable")]} == {r.response_text for r in groups[("normal", "hardened")]}


def test_two_runs_give_identical_replies(transport):
    def replies():
        run = run_suite(LIBRARY.cases, BOTH, BASE_URL, transport)
        return [(r.test_id, r.target_mode, r.http_status, r.response_text, r.raw_body) for r in run.results]
    assert replies() == replies()


def test_report_from_a_real_run_validates_and_round_trips(full_run, tmp_path):
    report = build_report(full_run, LIBRARY, BASE_URL, BOTH, 10.0)
    assert validate_report(report) == []
    path = write_report(report, tmp_path / "r.json")
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded == report
    assert loaded["summary"]["by_outcome"]["completed"] == 48
    assert {r["test_id"] for r in loaded["results"]} == {c.test_id for c in LIBRARY.cases}


def test_raw_body_is_kept_verbatim_and_response_text_is_the_reply_field(full_run):
    for r in full_run.results:
        assert json.loads(r.raw_body)["response"] == r.response_text


def test_cli_end_to_end_against_the_real_app(transport, tmp_path, capsys):
    out = tmp_path / "e2e.json"
    assert main(["--output", str(out)], transport=transport) == EXIT_OK
    assert validate_report(json.loads(out.read_text(encoding="utf-8"))) == []
    assert "48 attempted of 48 planned" in capsys.readouterr().out
