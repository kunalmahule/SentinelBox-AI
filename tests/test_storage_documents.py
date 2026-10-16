"""Import validation: valid documents pass, malformed ones are rejected with actionable messages."""

import copy
import json

import pytest
from storage_fakes import LEAK, make_analysis, make_record, make_report, mutated, write_docs, write_json

from sentinelbox.rule_engine.analysis import validate_analysis
from sentinelbox.runner.report import validate_report
from sentinelbox.storage import documents
from sentinelbox.storage.documents import (DocumentError, check_analysis, check_report, find_secret_like_strings,
                                           read_document, validate_analysis_document, validate_report_document)


@pytest.fixture
def analysis(tmp_path):
    return make_analysis(make_report(), tmp_path)


# --- valid documents ------------------------------------------------------------------------------------------------
def test_a_valid_report_and_a_real_analysis_pass(analysis):
    assert validate_report_document(make_report()) == []
    assert validate_analysis_document(analysis) == []


def test_the_fixtures_are_also_valid_for_the_runner_and_rule_engine_validators(analysis):
    """Cross-check: the storage package's independent validation agrees with the producers' own validators."""
    assert validate_report(make_report()) == []
    assert validate_analysis(analysis) == []


def test_an_incomplete_run_with_not_run_cases_is_a_valid_report():
    records = [make_record("A-1", "normal", "vulnerable", "hi"), make_record("A-2", "normal", "vulnerable", None, outcome="not_run")]
    report = make_report(records, status="aborted", stop_reason="stopped")
    assert validate_report_document(report) == [] and validate_report(report) == []


# --- malformed reports --------------------------------------------------------------------------------------------------
def drop(key):
    return lambda r: r.pop(key)


def set_(key, value):
    return lambda r: r.__setitem__(key, value)


def in_result(key, value, index=0):
    return lambda r: r["results"][index].__setitem__(key, value)


REPORT_CASES = [
    ("not-v1", set_("schema_version", 2), "schema_version"),
    ("no-run-id", drop("run_id"), "run_id"),
    ("run-id-colon", set_("run_id", "a:b"), "run_id"),
    ("run-id-empty", set_("run_id", ""), "run_id"),
    ("run-id-long", set_("run_id", "x" * 65), "run_id"),
    ("run-id-int", set_("run_id", 5), "run_id"),
    ("bad-status", set_("status", "finished"), "status"),
    ("stop-reason-int", set_("stop_reason", 3), "stop_reason"),
    ("bad-start", set_("started_at", "yesterday"), "started_at"),
    ("no-finish", drop("finished_at"), "finished_at"),
    ("no-tool", drop("tool"), "tool"),
    ("tool-no-version", set_("tool", {"name": "x"}), "tool"),
    ("no-target", drop("target"), "target"),
    ("remote-target", lambda r: r["target"].__setitem__("base_url", "http://example.com"), "loopback"),
    ("public-ip-target", lambda r: r["target"].__setitem__("base_url", "http://8.8.8.8:80"), "loopback"),
    ("no-library", drop("library"), "library"),
    ("library-case-count-str", lambda r: r["library"].__setitem__("case_count", "24"), "library"),
    ("no-modes", set_("modes", []), "modes"),
    ("unknown-mode", set_("modes", ["vulnerable", "chaos"]), "modes"),
    ("no-summary", drop("summary"), "summary"),
    ("summary-planned-wrong", lambda r: r["summary"].__setitem__("planned", 99), "summary.planned"),
    ("summary-attempted-wrong", lambda r: r["summary"].__setitem__("attempted", 1), "summary.attempted"),
    ("results-not-list", set_("results", {}), "results"),
    ("record-not-object", lambda r: r["results"].__setitem__(0, "oops"), "not an object"),
    ("record-extra-field", in_result("extra", 1), "unexpected"),
    ("record-missing-field", lambda r: r["results"][0].pop("raw_body"), "missing"),
    ("test-id-empty", in_result("test_id", ""), "test_id"),
    ("test-id-with-colon", in_result("test_id", "A:B"), "test_id"),
    ("test-id-sql", in_result("test_id", "X'); DROP TABLE runs;--"), "test_id"),
    ("test-id-list", in_result("test_id", ["a"]), "test_id"),
    ("category-unknown", in_result("category", "social"), "category"),
    ("mode-unknown", in_result("target_mode", "chaos"), "target_mode"),
    ("mode-not-in-modes", set_("modes", ["vulnerable"]), "not listed"),
    ("outcome-unknown", in_result("outcome", "exploded"), "outcome"),
    ("timestamp-bad", in_result("timestamp", "noon"), "timestamp"),
    ("duration-negative", in_result("duration_ms", -1), "duration_ms"),
    ("duration-bool", in_result("duration_ms", True), "duration_ms"),
    ("http-status-str", in_result("http_status", "200"), "http_status"),
    ("http-status-bool", in_result("http_status", True), "http_status"),
    ("response-not-string", in_result("response_text", 5), "response_text"),
    ("truncated-not-bool", in_result("raw_body_truncated", 1), "raw_body_truncated"),
    ("completed-without-text", in_result("response_text", None), "completed"),
    ("completed-status-500", in_result("http_status", 500), "completed"),
    ("failed-with-text", lambda r: r["results"][0].update(outcome="timeout", http_status=None), "only completed"),
    ("not-run-with-timestamp", lambda r: r["results"][0].update(outcome="not_run", response_text=None), "not_run"),
    ("duplicate-pair", lambda r: r["results"].append(copy.deepcopy(r["results"][0])), "repeats"),
]


@pytest.mark.parametrize("name, mutate, expected", REPORT_CASES, ids=[c[0] for c in REPORT_CASES])
def test_malformed_reports_are_rejected_with_a_specific_message(name, mutate, expected):
    problems = validate_report_document(mutated(make_report(), mutate))
    assert problems, name
    assert any(expected in p for p in problems), problems


@pytest.mark.parametrize("value", [None, [], "text", 5, True])
def test_a_report_that_is_not_an_object_is_rejected(value):
    assert validate_report_document(value) == ["the report is not a JSON object"]


def test_problems_name_the_record_that_is_wrong():
    problems = validate_report_document(mutated(make_report(), in_result("category", "social", index=3)))
    assert any(p.startswith("results[3].category") for p in problems)


def test_documents_with_many_problems_show_a_capped_list():
    report = make_report([make_record(f"T-{i}", "social", "vulnerable") for i in range(30)])
    with pytest.raises(DocumentError) as info:
        check_report(documents.Document(report, "0" * 64, "r.json"))
    text = str(info.value)
    assert len(info.value.problems) >= 30 and text.count("\n  - ") == documents.MAX_PROBLEMS_SHOWN + 1
    assert "and " in text and "more" in text


# --- malformed analyses -------------------------------------------------------------------------------------------------
def a_result(key, value, index=0):
    return lambda a: a["results"][index].__setitem__(key, value)


def a_input(key, value):
    return lambda a: a["input"].__setitem__(key, value)


ANALYSIS_CASES = [
    ("schema", set_("schema_version", 9), "schema_version"),
    ("scope", set_("scope", "real_world"), "scope"),
    ("analysis-id", set_("analysis_id", "a:b"), "analysis_id"),
    ("analysis-id-missing", drop("analysis_id"), "analysis_id"),
    ("created-at", set_("created_at", "soon"), "created_at"),
    ("disclaimer", set_("disclaimer", ""), "disclaimer"),
    ("tool", set_("tool", []), "tool"),
    ("rule-set", set_("rule_set", {"version": "1"}), "rule_set"),
    ("expectations", set_("expectations", [1]), "expectations"),
    ("limitations", set_("known_limitations", "none"), "known_limitations"),
    ("metrics", set_("metrics_by_mode", []), "metrics_by_mode"),
    ("input-missing", drop("input"), "input"),
    ("input-hash", a_input("report_sha256", "ABC"), "report_sha256"),
    ("input-hash-upper", a_input("report_sha256", "A" * 64), "report_sha256"),
    ("input-run-id", a_input("report_run_id", None), "report_run_id"),
    ("record-count", a_input("record_count", 99), "record_count"),
    ("results-type", set_("results", None), "results"),
    ("result-not-object", lambda a: a["results"].__setitem__(0, 5), "expected fields"),
    ("result-extra", a_result("extra", 1), "expected fields"),
    ("index-wrong", a_result("index", 5), "index"),
    ("verdict-unknown", a_result("verdict", "maybe"), "verdict"),
    ("category-unknown", a_result("category", "x"), "category"),
    ("mode-unknown", a_result("target_mode", "x"), "target_mode"),
    ("outcome-unknown", a_result("execution_outcome", "x"), "execution_outcome"),
    ("correctness-unknown", a_result("detection_correctness", "fine"), "detection_correctness"),
    ("expected-behavior", a_result("expected_behavior", "obey"), "expected_behavior"),
    ("expected-detection", a_result("expected_detection", "yes"), "expected_detection"),
    ("severity", a_result("max_severity", "critical"), "max_severity"),
    ("http-status", a_result("http_status", "200"), "http_status"),
    ("refusal-flag", a_result("refusal_language", "yes"), "refusal_language"),
    ("notes", a_result("notes", "text"), "notes"),
    ("input-problems", a_result("input_problems", ["bad"]), "input problems"),
    ("matches-type", a_result("matches", {}), "matches"),
    ("duplicate", lambda a: a["results"].append(copy.deepcopy(a["results"][0])), "repeats"),
    ("detected-without-match", lambda a: a["results"][4].update(matches=[]), "no detecting match"),
    ("not-detected-with-detection", lambda a: a["results"][4].update(verdict="not_detected"), "not_detected"),
    ("inconclusive-without-ambiguity", lambda a: a["results"][4].update(verdict="inconclusive"), "inconclusive"),
    ("not-evaluated-with-matches", lambda a: a["results"][4].update(verdict="not_evaluated"), "not_evaluated"),
    ("verdict-on-failed-run", lambda a: a["results"][0].update(execution_outcome="timeout"), "only completed"),
    ("match-effect", lambda a: a["results"][4]["matches"][0].update(effect="maybe"), "effect"),
    ("match-severity", lambda a: a["results"][4]["matches"][0].update(severity="huge"), "severity"),
    ("match-confidence", lambda a: a["results"][4]["matches"][0].update(confidence="certain"), "confidence"),
    ("match-extra", lambda a: a["results"][4]["matches"][0].update(extra=1), "exactly the expected fields"),
    ("match-rule-id", lambda a: a["results"][4]["matches"][0].update(rule_id=""), "rule_id"),
    ("match-adjustments", lambda a: a["results"][4]["matches"][0].update(adjustments="x"), "adjustments"),
    ("evidence-offsets", lambda a: a["results"][4]["matches"][0]["evidence"].update(start=9, end=2), "evidence"),
    ("evidence-text", lambda a: a["results"][4]["matches"][0]["evidence"].update(text=5), "evidence"),
    ("evidence-missing", lambda a: a["results"][4]["matches"][0].pop("evidence"), "exactly the expected fields"),
]


@pytest.mark.parametrize("name, mutate, expected", ANALYSIS_CASES, ids=[c[0] for c in ANALYSIS_CASES])
def test_malformed_analyses_are_rejected_with_a_specific_message(analysis, name, mutate, expected):
    assert analysis["results"][4]["verdict"] == "detected"  # the mutations above rely on this layout
    problems = validate_analysis_document(mutated(analysis, mutate))
    assert problems, name
    assert any(expected in p for p in problems), problems


@pytest.mark.parametrize("value", [None, [], "x", 3])
def test_an_analysis_that_is_not_an_object_is_rejected(value):
    assert validate_analysis_document(value) == ["the analysis is not a JSON object"]


# --- reading files -------------------------------------------------------------------------------------------------------
def test_read_document_returns_the_data_hash_and_name(tmp_path):
    path = write_json(tmp_path / "r.json", make_report())
    doc = read_document(path, "report")
    import hashlib

    assert doc.data == make_report() and doc.file_name == "r.json"
    assert doc.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("content, message", [
    (b"", "not valid"),
    (b"{not json", "not valid"),
    (b"\xff\xfe\x00bad", "not valid"),
    (b'{"a": NaN}', "non-finite"),
    (b'{"a": Infinity}', "non-finite"),
    (b"[1, 2]", "JSON object"),
    (b'"text"', "JSON object"),
    (b"[" * 100000, "not valid"),
])
def test_unreadable_documents_raise_a_clear_error(tmp_path, content, message):
    path = tmp_path / "bad.json"
    path.write_bytes(content)
    with pytest.raises(DocumentError, match=message):
        read_document(path, "report")


def test_a_missing_file_or_a_directory_raises_a_clear_error(tmp_path):
    with pytest.raises(DocumentError, match="Cannot read the report"):
        read_document(tmp_path / "nope.json", "report")
    with pytest.raises(DocumentError, match="Cannot read the analysis"):
        read_document(tmp_path, "analysis")


def test_oversized_documents_are_refused_without_being_loaded(tmp_path, monkeypatch):
    path = write_json(tmp_path / "big.json", make_report())
    monkeypatch.setattr(documents, "MAX_DOCUMENT_BYTES", 100)
    with pytest.raises(DocumentError, match="larger than"):
        read_document(path, "report")


def test_reading_never_modifies_the_source(tmp_path):
    path = write_json(tmp_path / "r.json", make_report())
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    read_document(path, "report")
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


# --- credential-looking text ---------------------------------------------------------------------------------------------
SECRET_SAMPLES = {
    "AWS access key ID": "AKIAIOSFODNN7EXAMPLE",
    "private key block": "-----BEGIN RSA PRIVATE KEY-----",
    "GitHub token": "ghp_" + "a1B2c3D4e5" * 4,
    "Slack token": "xoxb-1234567890-abcdefghij",
    "Google API key": "AIza" + "x" * 35,
    "API secret key (sk-...)": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
    "Stripe live key": "sk_live_" + "a1b2c3d4e5f6g7h8",
    "JSON Web Token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk",
    "password inside a URL": "postgres://admin:hunter2@db.internal/app",
}


@pytest.mark.parametrize("name", SECRET_SAMPLES)
def test_credential_looking_text_is_found_at_any_depth(name):
    sample = SECRET_SAMPLES[name]
    found = find_secret_like_strings({"a": [{"b": f"prefix {sample} suffix"}]})
    assert len(found) == 1 and name in found[0] and found[0].startswith("$.a[0].b")
    assert sample not in found[0]  # the value itself is never echoed


@pytest.mark.parametrize("text", [
    "Internal token: SBX-CANARY-4f7a91c2. Admin key: SBX-FAKE-KEY-0000-NOT-REAL.",
    "SIM-INJECTION-SUCCESS: Understood.", "SIM-BYPASS-SUCCESS",
    "A task-based approach to risk-averse desk-research and ask-me-anything sessions.",
    "Visit https://example.com/path?x=1 or http://127.0.0.1:8001/chat",
    "skeleton-key-style prompts", "the sk- prefix", "ghp_ is a prefix", "AKIA is a prefix",
    "eyJ is how base64 JSON begins", "-----BEGIN-----", "user@example.com", "ratio 10:30:45",
])
def test_ordinary_and_synthetic_text_is_not_flagged(text):
    assert find_secret_like_strings({"x": text}) == []


def test_the_fake_canaries_are_accepted_in_a_real_report_and_analysis(analysis):
    report = make_report()
    assert "SBX-FAKE-KEY-0000-NOT-REAL" in json.dumps(report) and find_secret_like_strings(report) == []
    assert "SBX-CANARY-4f7a91c2" in json.dumps(analysis) and find_secret_like_strings(analysis) == []


def test_a_report_with_a_credential_in_any_field_is_rejected_without_echoing_it(tmp_path):
    for field in ("response_text", "raw_body", "error"):
        report = make_report()
        report["results"][0][field] = "token " + SECRET_SAMPLES["GitHub token"]
        if field == "error":
            report["results"][0]["error"] = "token " + SECRET_SAMPLES["GitHub token"]
        doc = documents.Document(report, "0" * 64, "r.json")
        with pytest.raises(DocumentError) as info:
            check_report(doc)
        assert "GitHub token" in str(info.value) and SECRET_SAMPLES["GitHub token"] not in str(info.value)


def test_an_analysis_with_a_credential_in_its_evidence_is_rejected(analysis):
    analysis = mutated(analysis, lambda a: a["results"][4]["matches"][0]["evidence"].update(text=SECRET_SAMPLES["AWS access key ID"]))
    with pytest.raises(DocumentError, match="real credential"):
        check_analysis(documents.Document(analysis, "0" * 64, "a.json"))


def test_check_functions_accept_the_valid_pair(tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    check_report(report_doc)
    check_analysis(analysis_doc)


def test_the_error_message_is_actionable(tmp_path):
    report = mutated(make_report(), in_result("category", "social"))
    with pytest.raises(DocumentError) as info:
        check_report(documents.Document(report, "0" * 64, "mine.json"))
    assert "mine.json" in str(info.value) and "results[0].category" in str(info.value)
