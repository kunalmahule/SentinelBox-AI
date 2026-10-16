"""Querying runs and findings."""

import contextlib
import json

import pytest
from storage_fakes import make_analysis, make_record, make_report, write_docs

from sentinelbox.storage import importer, queries
from sentinelbox.storage.database import init_database, open_database
from sentinelbox.storage.queries import QueryError


@pytest.fixture
def stored(tmp_path):
    """Two runs, one analysed (rich rule hits), one stored without analysis."""
    path = init_database(tmp_path / "audit.db")
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    report_a, analysis_a = write_docs(tmp_path / "one", analysis_id="analysis-one")
    later = make_report(run_id="run0002efgh", started_at="2026-02-02T03:04:05.000+00:00",
                        records=[make_record("NORM-001", "normal", "vulnerable", "hi")])
    report_b, _ = write_docs(tmp_path / "two", report=later)
    with contextlib.closing(open_database(path)) as conn:
        importer.import_report_and_analysis(conn, report_a, analysis_a)
        importer.import_report(conn, report_b)
    with contextlib.closing(open_database(path, readonly=True)) as conn:
        yield conn, analysis_a.data


# --- runs --------------------------------------------------------------------------------------------------------------------------
def test_runs_are_listed_newest_first_with_counts(stored):
    conn, _ = stored
    runs = queries.list_runs(conn)
    assert [r["run_id"] for r in runs] == ["run0002efgh", "run0001abcd"]
    assert [(r["executions"], r["analyses"]) for r in runs] == [(1, 0), (6, 1)]
    assert all(r["data_classification"] == "synthetic_test_data" for r in runs)


def test_run_listing_filters_by_status_and_respects_the_limit(stored):
    conn, _ = stored
    assert queries.list_runs(conn, status="aborted") == []
    assert len(queries.list_runs(conn, status="complete")) == 2
    assert [r["run_id"] for r in queries.list_runs(conn, limit=1)] == ["run0002efgh"]


@pytest.mark.parametrize("limit", [0, -1, 1001, "5", None, True, 2.5])
def test_invalid_limits_are_rejected(stored, limit):
    conn, _ = stored
    with pytest.raises(QueryError, match="limit"):
        queries.list_runs(conn, limit=limit)
    with pytest.raises(QueryError, match="limit"):
        queries.list_findings(conn, limit=limit)


def test_unknown_status_is_rejected_with_the_allowed_values(stored):
    conn, _ = stored
    with pytest.raises(QueryError, match="complete, aborted, interrupted"):
        queries.list_runs(conn, status="finished")


def test_get_run_reports_outcomes_per_mode_and_its_analyses(stored):
    conn, _ = stored
    run = queries.get_run(conn, "run0001abcd")
    assert run["outcomes_by_mode"] == {"hardened": {"completed": 3}, "vulnerable": {"completed": 3}}
    assert run["modes"] == ["vulnerable", "hardened"] and "modes_json" not in run
    assert [a["analysis_id"] for a in run["analyses"]] == ["analysis-one"]
    with pytest.raises(QueryError, match="no stored run"):
        queries.get_run(conn, "missing")


def test_run_ids_resolve_by_unique_prefix(stored):
    conn, _ = stored
    assert queries.resolve_run_id(conn, "run0001abcd") == "run0001abcd"
    assert queries.resolve_run_id(conn, "run0001") == "run0001abcd"
    with pytest.raises(QueryError, match="several runs"):
        queries.resolve_run_id(conn, "run0")
    with pytest.raises(QueryError, match="no stored run matches"):
        queries.resolve_run_id(conn, "zzzz")
    for bad in ("ru", "", None, 5):
        with pytest.raises(QueryError, match="at least the first 4"):
            queries.resolve_run_id(conn, bad)


def test_prefix_resolution_treats_wildcards_literally(stored):
    conn, _ = stored
    for text in ("run%", "run_", "%%%%", "run0001%"):
        with pytest.raises(QueryError, match="no stored run matches"):
            queries.resolve_run_id(conn, text)


def test_analysis_ids_resolve_like_run_ids(stored):
    conn, _ = stored
    assert queries.resolve_analysis_id(conn, "analysis-one") == "analysis-one"
    assert queries.resolve_analysis_id(conn, "analysis") == "analysis-one"
    with pytest.raises(QueryError):
        queries.resolve_analysis_id(conn, "nothing")
    assert queries.latest_analysis_id(conn, "run0001abcd") == "analysis-one"
    assert queries.latest_analysis_id(conn, "run0002efgh") is None


# --- findings -------------------------------------------------------------------------------------------------------------------------
def test_all_findings_are_listed_in_analysis_order_with_their_rules(stored):
    conn, analysis = stored
    findings = queries.list_findings(conn)
    assert [f["ordinal"] for f in findings] == list(range(6))
    for finding, source in zip(findings, analysis["results"]):
        assert (finding["test_id"], finding["target_mode"], finding["verdict"]) == (source["test_id"], source["target_mode"], source["verdict"])
        assert [m["rule_id"] for m in finding["rules"] if not m["is_context"]] == [m["rule_id"] for m in source["matches"]]
        assert isinstance(finding["refusal_language"], bool) and finding["data_classification"] == "synthetic_test_data"


@pytest.mark.parametrize("kwargs, expected", [
    ({"verdicts": ("detected",)}, {("CAN-001", "vulnerable"), ("INJ-001", "vulnerable")}),
    ({"verdicts": ("not_detected",)}, {("NORM-001", "vulnerable"), ("NORM-001", "hardened"), ("CAN-001", "hardened"), ("INJ-001", "hardened")}),
    ({"verdicts": ("detected", "inconclusive")}, {("CAN-001", "vulnerable"), ("INJ-001", "vulnerable")}),
    ({"verdicts": ("inconclusive",)}, set()),
    ({"target_mode": "hardened"}, {("NORM-001", "hardened"), ("CAN-001", "hardened"), ("INJ-001", "hardened")}),
    ({"category": "canary_disclosure"}, {("CAN-001", "vulnerable"), ("CAN-001", "hardened")}),
    ({"test_id": "INJ-001", "target_mode": "vulnerable"}, {("INJ-001", "vulnerable")}),
    ({"rule_id": "R-CANARY-001"}, {("CAN-001", "vulnerable")}),
    ({"rule_id": "R-REF-001"}, {("CAN-001", "hardened"), ("INJ-001", "hardened")}),
    ({"rule_id": "R-NOPE-999"}, set()),
    ({"min_severity": "high"}, {("CAN-001", "vulnerable"), ("INJ-001", "vulnerable")}),
    ({"correctness": "correct"}, {("NORM-001", "vulnerable"), ("NORM-001", "hardened"), ("CAN-001", "vulnerable"),
                                  ("CAN-001", "hardened"), ("INJ-001", "vulnerable"), ("INJ-001", "hardened")}),
    ({"correctness": "incorrect"}, set()),
    ({"run_id": "run0001abcd", "analysis_id": "analysis-one", "verdicts": ("detected",), "target_mode": "vulnerable"},
     {("CAN-001", "vulnerable"), ("INJ-001", "vulnerable")}),
    ({"run_id": "run0002efgh"}, set()),
])
def test_finding_filters(stored, kwargs, expected):
    conn, _ = stored
    assert {(f["test_id"], f["target_mode"]) for f in queries.list_findings(conn, **kwargs)} == expected


def test_a_finding_filter_that_matches_nothing_returns_an_empty_list(stored):
    conn, _ = stored
    assert queries.list_findings(conn, test_id="NOPE") == []


@pytest.mark.parametrize("kwargs", [{"target_mode": "chaos"}, {"category": "social"}, {"verdicts": ("maybe",)},
                                    {"correctness": "fine"}, {"min_severity": "critical"}])
def test_invalid_filter_values_are_rejected_not_ignored(stored, kwargs):
    conn, _ = stored
    with pytest.raises(QueryError, match="unknown|choose one of"):
        queries.list_findings(conn, **kwargs)


@pytest.mark.parametrize("payload", ["' OR '1'='1", "x'; DROP TABLE findings; --", "%", "R-CANARY-001' --"])
def test_filter_values_are_bound_parameters_never_sql(stored, payload):
    conn, _ = stored
    assert queries.list_findings(conn, rule_id=payload) == []
    assert queries.list_findings(conn, test_id=payload) == []
    assert queries.list_findings(conn, run_id=payload) == []
    assert len(queries.list_findings(conn)) == 6  # the table is intact and still fully queryable


def test_severity_threshold_orders_info_low_medium_high(stored):
    conn, _ = stored
    every = {f["max_severity"] for f in queries.list_findings(conn)}
    assert queries.list_findings(conn, min_severity="info") and every >= {"high", None} - {None}
    assert queries.list_findings(conn, min_severity="high") == [f for f in queries.list_findings(conn) if f["max_severity"] == "high"]


def test_the_limit_caps_the_number_of_findings(stored):
    conn, _ = stored
    assert len(queries.list_findings(conn, limit=2)) == 2


def test_get_finding_returns_response_evidence_and_rationale(stored):
    conn, _ = stored
    finding = queries.get_finding(conn, "analysis-one:2")
    assert finding["test_id"] == "CAN-001" and finding["target_mode"] == "vulnerable" and finding["verdict"] == "detected"
    assert "SBX-CANARY-4f7a91c2" in finding["response_text"] and finding["data_classification"] == "synthetic_test_data"
    rules = {m["rule_id"]: m for m in finding["matches"]}
    assert rules["R-CANARY-001"]["evidence_text"] == "SBX-CANARY-4f7a91c2" and rules["R-CANARY-001"]["rationale"]
    assert isinstance(finding["notes"], list) and isinstance(rules["R-CANARY-001"]["adjustments"], list)
    with pytest.raises(QueryError, match="no stored finding"):
        queries.get_finding(conn, "analysis-one:99")


# --- summaries ---------------------------------------------------------------------------------------------------------------------------
def test_verdict_summary_agrees_with_the_rule_engine_metrics(stored):
    conn, analysis = stored
    summary = queries.verdict_summary(conn, "analysis-one")
    for mode, metrics in analysis["metrics_by_mode"].items():
        for verdict, expected in metrics["verdict_counts"].items():
            stored_count = sum(r["n"] for r in summary if r["target_mode"] == mode and r["verdict"] == verdict)
            assert stored_count == expected, (mode, verdict)
    tp = sum(r["n"] for r in summary if r["target_mode"] == "vulnerable" and r["verdict"] == "detected" and r["detection_correctness"] == "correct")
    assert tp == analysis["metrics_by_mode"]["vulnerable"]["confusion"]["tp"] == 2


def test_rule_summary_counts_hits_per_rule(stored):
    conn, analysis = stored
    summary = queries.rule_summary(conn, "analysis-one")
    expected = {}
    for r in analysis["results"]:
        for m in r["matches"] + r["context_matches"]:
            key = (m["rule_id"], m["effect"])
            expected[key] = expected.get(key, 0) + 1
    assert {(r["rule_id"], r["effect"]): r["hits"] for r in summary} == expected


def test_database_info_reports_version_counts_and_policy(stored):
    conn, _ = stored
    info = queries.database_info(conn)
    assert info["schema_version"] == 2 and info["counts"]["runs"] == 2 and info["counts"]["executions"] == 7
    assert info["counts"]["audit_events"] == 4 and "synthetic" in info["data_policy"]
    assert info["last_event"]["seq"] == 4 and json.dumps(info)
