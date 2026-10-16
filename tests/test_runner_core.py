"""Runner behaviour using a scripted fake transport (no sockets)."""

from datetime import datetime

import pytest
from runner_fakes import BASE_URL, FakeTransport, fake_clock, fake_timer, ok, raw

from sentinelbox.runner.library import load_library
from sentinelbox.runner.models import Category, Outcome, RunStatus, TargetMode, TestCase
from sentinelbox.runner.runner import execute_case, run_suite
from sentinelbox.runner.transport import (
    TargetUrlError,
    TransportConnectionError,
    TransportError,
    TransportTimeout,
)

V, H = TargetMode.VULNERABLE, TargetMode.HARDENED


def make_cases(n=4):
    cats = list(Category)
    return [TestCase(f"T-{i}", cats[i % 4], f"case {i}", f"prompt {i}") for i in range(n)]


def run(transport, cases=None, modes=(V,), **kwargs):
    return run_suite(make_cases() if cases is None else cases, list(modes), BASE_URL, transport,
                     clock=fake_clock(), timer=fake_timer(), **kwargs)


# --- successful runs ----------------------------------------------------------
def test_successful_run_records_every_required_field():
    transport = FakeTransport([ok("reply one")])
    result = run(transport, make_cases(1)).results[0]
    assert result.test_id == "T-0"
    assert result.category == "normal"
    assert result.target_mode == "vulnerable"
    assert result.timestamp == "2026-01-02T03:04:06.000+00:00"  # clock call #2 (call #1 is run start)
    assert result.duration_ms == 125.0
    assert result.http_status == 200
    assert result.outcome == "completed"
    assert result.response_text == "reply one"
    assert result.raw_body == '{"model": "fake-1", "response": "reply one"}'
    assert result.raw_body_truncated is False
    assert result.error is None


def test_requests_contain_only_prompt_and_mode_and_use_the_chat_url():
    transport = FakeTransport()
    run(transport, make_cases(2), modes=(V, H), timeout=3.5)
    assert [c["payload"] for c in transport.calls] == [
        {"prompt": "prompt 0", "mode": "vulnerable"}, {"prompt": "prompt 1", "mode": "vulnerable"},
        {"prompt": "prompt 0", "mode": "hardened"}, {"prompt": "prompt 1", "mode": "hardened"},
    ]
    assert {c["url"] for c in transport.calls} == {f"{BASE_URL}/chat"}
    assert {c["timeout"] for c in transport.calls} == {3.5}


def test_both_modes_run_mode_major_and_duplicates_are_ignored():
    run_result = run(FakeTransport(), make_cases(2), modes=(V, H, V))
    assert [(r.target_mode, r.test_id) for r in run_result.results] == [
        ("vulnerable", "T-0"), ("vulnerable", "T-1"), ("hardened", "T-0"), ("hardened", "T-1"),
    ]
    assert run_result.planned == 4
    assert run_result.status is RunStatus.COMPLETE
    assert run_result.stop_reason is None


def test_run_timestamps_are_utc_iso8601_and_increase():
    results = run(FakeTransport()).results
    stamps = [datetime.fromisoformat(r.timestamp) for r in results]
    assert all(s.utcoffset().total_seconds() == 0 for s in stamps)
    assert stamps == sorted(stamps) and len(set(stamps)) == len(stamps)


def test_default_clock_gives_timezone_aware_timestamps():
    result = run_suite(make_cases(1), [V], BASE_URL, FakeTransport())
    assert datetime.fromisoformat(result.results[0].timestamp).tzinfo is not None
    assert datetime.fromisoformat(result.started_at).tzinfo is not None


def test_empty_case_list_is_a_complete_empty_run():
    result = run(FakeTransport(), cases=[], modes=(V,))
    assert result.status is RunStatus.COMPLETE
    assert result.results == () and result.planned == 0


def test_on_result_is_called_once_per_attempted_case():
    seen = []
    run(FakeTransport(), make_cases(3), on_result=seen.append)
    assert [r.test_id for r in seen] == ["T-0", "T-1", "T-2"]


# --- HTTP errors ----------------------------------------------------------------
@pytest.mark.parametrize("status", [201, 204, 301, 302, 400, 404, 405, 422, 429, 500, 503])
def test_non_200_status_is_an_http_error_and_keeps_the_body(status):
    result = run(FakeTransport([raw(status, '{"detail": "nope"}')]), make_cases(1)).results[0]
    assert result.outcome == Outcome.HTTP_ERROR.value
    assert result.http_status == status
    assert result.raw_body == '{"detail": "nope"}'
    assert result.response_text is None
    assert result.error == f"HTTP {status}"


def test_a_422_reply_with_a_valid_looking_response_field_is_still_an_error():
    result = run(FakeTransport([raw(422, '{"response": "looks fine"}')]), make_cases(1)).results[0]
    assert result.outcome == "http_error" and result.response_text is None


# --- transport failures ---------------------------------------------------------
def test_timeout_is_recorded_without_status_or_body():
    result = run(FakeTransport([TransportTimeout("Timed out after 1s")]), make_cases(1)).results[0]
    assert (result.outcome, result.http_status, result.raw_body) == ("timeout", None, None)
    assert "Timed out" in result.error
    assert result.timestamp is not None and result.duration_ms is not None


def test_connection_error_is_recorded():
    result = run(FakeTransport([TransportConnectionError("Connection refused")]), make_cases(1)).results[0]
    assert (result.outcome, result.http_status) == ("connection_error", None)
    assert "refused" in result.error


def test_generic_transport_error_counts_as_connection_error():
    result = run(FakeTransport([TransportError("odd")]), make_cases(1)).results[0]
    assert result.outcome == "connection_error" and "odd" in result.error


def test_unexpected_exception_becomes_runner_error_and_the_run_continues():
    transport = FakeTransport([ValueError("boom"), ok("fine")])
    results = run(transport, make_cases(2)).results
    assert [r.outcome for r in results] == ["runner_error", "completed"]
    assert "ValueError: boom" in results[0].error


def test_mixed_outcomes_are_each_recorded_in_order():
    transport = FakeTransport([ok(), raw(500, "x"), TransportTimeout("t"), raw(200, "not json")])
    outcomes = [r.outcome for r in run(transport, make_cases(4)).results]
    assert outcomes == ["completed", "http_error", "timeout", "invalid_response"]


# --- malformed 200 responses ---------------------------------------------------
MALFORMED = [
    (b"", "not valid JSON"),
    (b"not json at all", "not valid JSON"),
    (b"<html>502 Bad Gateway</html>", "not valid JSON"),
    (b'{"response": "cut off', "not valid JSON"),
    (b'["a", "list"]', "not an object"),
    (b'"just a string"', "not an object"),
    (b"null", "not an object"),
    (b"42", "not an object"),
    (b"{}", "no string 'response'"),
    (b'{"model": "m"}', "no string 'response'"),
    (b'{"response": 5}', "no string 'response'"),
    (b'{"response": null}', "no string 'response'"),
    (b'{"response": ["x"]}', "no string 'response'"),
    (b'{"response": {"text": "x"}}', "no string 'response'"),
    (b'{"Response": "wrong case"}', "no string 'response'"),
    (b"\xff\xfe\x00bad", "not valid UTF-8"),
    (b"[" * 200_000, "not valid JSON"),  # nesting deep enough to raise RecursionError
]


@pytest.mark.parametrize("body, problem", MALFORMED, ids=[f"m{i}" for i in range(len(MALFORMED))])
def test_malformed_200_reply_is_an_invalid_response(body, problem):
    result = run(FakeTransport([raw(200, body)]), make_cases(1)).results[0]
    assert result.outcome == Outcome.INVALID_RESPONSE.value
    assert result.http_status == 200
    assert result.response_text is None
    assert problem in result.error
    assert result.raw_body == body.decode("utf-8", errors="replace")


def test_truncated_body_is_an_invalid_response_even_if_the_prefix_parses():
    result = run(FakeTransport([raw(200, b'{"response": "ok"}', truncated=True)]), make_cases(1)).results[0]
    assert result.outcome == "invalid_response"
    assert result.raw_body_truncated is True
    assert "size limit" in result.error


def test_one_malformed_reply_does_not_stop_later_cases():
    results = run(FakeTransport([raw(200, "garbage"), ok("good")]), make_cases(2)).results
    assert [r.outcome for r in results] == ["invalid_response", "completed"]


# --- no dependence on scenario metadata -------------------------------------------
@pytest.mark.parametrize(
    "extra",
    [{}, {"meta": {"scenario": "canary_disclosure", "matched_rule": "x"}}, {"meta": "garbage"}, {"meta": None},
     {"meta": {"scenario": "normal"}, "unrelated": [1, 2]}],
    ids=["no-meta", "claims-canary", "garbage-meta", "null-meta", "extra-fields"],
)
def test_outcome_and_response_text_do_not_depend_on_meta(extra):
    result = run(FakeTransport([ok("identical text", **extra)]), make_cases(1)).results[0]
    assert (result.outcome, result.response_text) == ("completed", "identical text")


def test_result_fields_never_include_scenario_information():
    fields = set(run(FakeTransport()).results[0].__dict__)
    assert fields == {"test_id", "category", "target_mode", "timestamp", "duration_ms", "http_status", "outcome",
                      "response_text", "raw_body", "raw_body_truncated", "error"}


def test_unicode_responses_are_preserved():
    result = run(FakeTransport([ok("你好 \U0001F680 café")]), make_cases(1)).results[0]
    assert result.response_text == "你好 \U0001F680 café"


# --- stopping early ----------------------------------------------------------------
def test_three_consecutive_connection_failures_abort_and_mark_the_rest_not_run():
    transport = FakeTransport([ok(), TransportConnectionError("refused")])  # last item repeats
    run_result = run(transport, make_cases(8))
    outcomes = [r.outcome for r in run_result.results]
    assert outcomes == ["completed"] + ["connection_error"] * 3 + ["not_run"] * 4
    assert run_result.status is RunStatus.ABORTED
    assert "3 consecutive" in run_result.stop_reason
    assert len(transport.calls) == 4  # no requests after the abort
    not_run = run_result.results[-1]
    assert (not_run.timestamp, not_run.duration_ms, not_run.http_status, not_run.raw_body) == (None, None, None, None)
    assert run_result.stop_reason in not_run.error
    assert run_result.planned == 8


def test_timeouts_also_count_towards_the_abort_threshold():
    transport = FakeTransport([TransportTimeout("t")])
    run_result = run(transport, make_cases(6), max_consecutive_failures=2)
    assert [r.outcome for r in run_result.results] == ["timeout", "timeout"] + ["not_run"] * 4
    assert run_result.status is RunStatus.ABORTED


def test_any_http_response_resets_the_consecutive_failure_count():
    script = [TransportTimeout("t"), TransportTimeout("t"), raw(500, "x"), TransportTimeout("t"), TransportTimeout("t"), ok()]
    run_result = run(FakeTransport(script), make_cases(6))
    assert run_result.status is RunStatus.COMPLETE
    assert "not_run" not in [r.outcome for r in run_result.results]


def test_threshold_of_one_stops_on_the_first_failure():
    run_result = run(FakeTransport([TransportConnectionError("x")]), make_cases(3), max_consecutive_failures=1)
    assert [r.outcome for r in run_result.results] == ["connection_error", "not_run", "not_run"]


def test_failures_on_the_final_case_do_not_mark_the_run_aborted():
    transport = FakeTransport([ok(), ok(), TransportConnectionError("x")])
    run_result = run(transport, make_cases(3), max_consecutive_failures=1)
    assert run_result.status is RunStatus.COMPLETE and run_result.stop_reason is None


def test_abort_in_the_first_mode_also_skips_the_second_mode():
    run_result = run(FakeTransport([TransportConnectionError("x")]), make_cases(2), modes=(V, H), max_consecutive_failures=2)
    assert [(r.target_mode, r.outcome) for r in run_result.results] == [
        ("vulnerable", "connection_error"), ("vulnerable", "connection_error"),
        ("hardened", "not_run"), ("hardened", "not_run"),
    ]


def test_keyboard_interrupt_returns_a_partial_run():
    transport = FakeTransport([ok(), ok(), KeyboardInterrupt()])
    run_result = run(transport, make_cases(5))
    assert run_result.status is RunStatus.INTERRUPTED
    assert "Ctrl+C" in run_result.stop_reason
    assert [r.outcome for r in run_result.results] == ["completed", "completed"] + ["not_run"] * 3
    assert run_result.results[2].test_id == "T-2"  # the in-flight case is reported as not run


# --- argument checking ---------------------------------------------------------------
@pytest.mark.parametrize("kwargs", [{"timeout": 0}, {"timeout": -1}, {"max_consecutive_failures": 0}])
def test_invalid_numeric_arguments_raise(kwargs):
    with pytest.raises(ValueError):
        run(FakeTransport(), **kwargs)


def test_non_loopback_target_is_refused_before_any_request():
    transport = FakeTransport()
    with pytest.raises(TargetUrlError):
        run_suite(make_cases(1), [V], "http://example.com", transport)
    assert transport.calls == []


def test_execute_case_works_on_its_own():
    case = TestCase("X-1", Category.SAFETY_BYPASS, "t", "p")
    result = execute_case(case, H, f"{BASE_URL}/chat", FakeTransport([ok("hi")]), 5.0)
    assert (result.test_id, result.category, result.target_mode, result.outcome) == ("X-1", "safety_bypass", "hardened", "completed")


def test_bundled_library_runs_against_a_fake_transport():
    cases = load_library().cases
    run_result = run(FakeTransport(), cases=cases, modes=(V, H))
    assert run_result.planned == 48 and all(r.outcome == "completed" for r in run_result.results)
