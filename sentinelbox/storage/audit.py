"""Hash-chained audit event log.

Each event's hash covers its own fields and the previous event's hash, so editing, removing or reordering
an event breaks every later hash. This is tamper-*evidence*: someone with write access to the file can
rebuild the whole chain, so it must not be described as tamper-proof.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from .schema import EVENT_TYPES, GENESIS_HASH


def utc_timestamp(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="seconds")


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def compute_event_hash(seq: int, occurred_at: str, event_type: str, run_id: str | None, analysis_id: str | None,
                       detail_json: str, prev_hash: str) -> str:
    payload = canonical_json([seq, occurred_at, event_type, run_id, analysis_id, detail_json, prev_hash])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_event(conn: sqlite3.Connection, event_type: str, *, run_id: str | None = None,
                 analysis_id: str | None = None, detail: dict | None = None, now: datetime | None = None) -> int:
    """Append one event. Must be called inside the caller's write transaction. Returns its sequence number."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown audit event type {event_type!r}")
    last = conn.execute("SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
    seq = 1 if last is None else last["seq"] + 1
    prev_hash = GENESIS_HASH if last is None else last["event_hash"]
    occurred_at = utc_timestamp(now)
    detail_json = canonical_json(detail or {})
    event_hash = compute_event_hash(seq, occurred_at, event_type, run_id, analysis_id, detail_json, prev_hash)
    conn.execute(
        "INSERT INTO audit_events (seq, occurred_at, event_type, run_id, analysis_id, detail_json, prev_hash, event_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (seq, occurred_at, event_type, run_id, analysis_id, detail_json, prev_hash, event_hash),
    )
    return seq


def verify_chain(conn: sqlite3.Connection) -> list[str]:
    """Recompute the whole chain. Returns problems; an empty list means the chain is intact."""
    problems: list[str] = []
    expected_prev = GENESIS_HASH
    expected_seq = 1
    for row in conn.execute("SELECT * FROM audit_events ORDER BY seq"):
        if row["seq"] != expected_seq:
            problems.append(f"event sequence jumps from {expected_seq - 1} to {row['seq']} (an event is missing)")
            expected_seq = row["seq"]
        if row["prev_hash"] != expected_prev:
            problems.append(f"event {row['seq']}: prev_hash does not match the previous event")
        recomputed = compute_event_hash(row["seq"], row["occurred_at"], row["event_type"], row["run_id"],
                                        row["analysis_id"], row["detail_json"], row["prev_hash"])
        if recomputed != row["event_hash"]:
            problems.append(f"event {row['seq']}: contents do not match their hash (edited)")
        expected_prev = row["event_hash"]
        expected_seq += 1
    return problems
