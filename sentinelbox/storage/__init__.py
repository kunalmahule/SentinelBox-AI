"""Stage 4: SQLite-backed audit storage.

Stores imported runner reports (Stage 2) and rule-engine analyses (Stage 3) in a single SQLite
file, so runs and findings can be queried and their history cannot be edited quietly.

This package is deliberately separate from the runner and the rule engine: it imports nothing from
``mock_ai``, ``runner`` or ``rule_engine``. It consumes their JSON documents (the explicit interface)
and validates them with its own strict checks. The original JSON files are never modified.

Everything stored is synthetic mock-environment test data. The database is append-only through this
tool (triggers block UPDATE and DELETE) and keeps a hash-chained event log. That makes edits
*detectable*, not impossible: anyone who can write the file can still rewrite it.
"""
