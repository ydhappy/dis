from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 4

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    target_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    md5 TEXT NOT NULL,
    sha1 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    architecture TEXT NOT NULL,
    machine TEXT NOT NULL,
    subsystem TEXT NOT NULL,
    image_base TEXT NOT NULL,
    entry_point TEXT NOT NULL,
    compile_timestamp TEXT NOT NULL,
    section_count INTEGER NOT NULL,
    import_count INTEGER NOT NULL,
    export_count INTEGER NOT NULL,
    overlay_size INTEGER NOT NULL,
    suspicious_api_count INTEGER NOT NULL,
    protector_finding_count INTEGER NOT NULL,
    yara_match_count INTEGER NOT NULL DEFAULT 0,
    vmprotect_classification TEXT NOT NULL DEFAULT 'unknown',
    vmprotect_confidence INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_severity TEXT NOT NULL DEFAULT 'low',
    json_report_path TEXT NOT NULL,
    html_report_path TEXT NOT NULL,
    full_result_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analyses_sha256 ON analyses(sha256);
CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at);
CREATE INDEX IF NOT EXISTS idx_analyses_target_path ON analyses(target_path);
CREATE INDEX IF NOT EXISTS idx_analyses_risk_score ON analyses(risk_score);
CREATE INDEX IF NOT EXISTS idx_analyses_vmprotect_confidence ON analyses(vmprotect_confidence);
"""


class AnalysisDatabase:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(SCHEMA_SQL)
            self._migrate(connection)
            connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )
            connection.commit()

    def insert_analysis(self, result, report_paths: dict[str, Path]) -> int:
        self.initialize()
        result_dict: dict[str, Any] = result.to_dict()
        risk_score = int(result.risk.get("score", 0))
        risk_severity = str(result.risk.get("severity", "low"))
        vmprotect_classification = str(result.vmprotect_profile.get("classification", "unknown"))
        vmprotect_confidence = int(result.vmprotect_profile.get("confidence_score", 0) or 0)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO analyses (
                    created_at,
                    target_path,
                    file_size,
                    md5,
                    sha1,
                    sha256,
                    architecture,
                    machine,
                    subsystem,
                    image_base,
                    entry_point,
                    compile_timestamp,
                    section_count,
                    import_count,
                    export_count,
                    overlay_size,
                    suspicious_api_count,
                    protector_finding_count,
                    yara_match_count,
                    vmprotect_classification,
                    vmprotect_confidence,
                    risk_score,
                    risk_severity,
                    json_report_path,
                    html_report_path,
                    full_result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    result.path,
                    result.size,
                    result.hashes.md5,
                    result.hashes.sha1,
                    result.hashes.sha256,
                    result.architecture,
                    result.machine,
                    result.subsystem,
                    result.image_base,
                    result.entry_point,
                    result.compile_timestamp,
                    result.section_count,
                    result.import_count,
                    result.export_count,
                    result.overlay_size,
                    len(result.suspicious_apis),
                    len(result.protector_findings),
                    len(result.yara_matches),
                    vmprotect_classification,
                    vmprotect_confidence,
                    risk_score,
                    risk_severity,
                    str(report_paths["json"]),
                    str(report_paths["html"]),
                    json.dumps(result_dict, ensure_ascii=False),
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def list_recent(self, limit: int = 20) -> list[dict[str, Any]]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    created_at,
                    target_path,
                    sha256,
                    architecture,
                    section_count,
                    import_count,
                    suspicious_api_count,
                    protector_finding_count,
                    yara_match_count,
                    vmprotect_classification,
                    vmprotect_confidence,
                    risk_score,
                    risk_severity,
                    json_report_path,
                    html_report_path
                FROM analyses
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def _migrate(self, connection: sqlite3.Connection) -> None:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(analyses)").fetchall()}
        if "yara_match_count" not in columns:
            connection.execute("ALTER TABLE analyses ADD COLUMN yara_match_count INTEGER NOT NULL DEFAULT 0")
        if "vmprotect_classification" not in columns:
            connection.execute(
                "ALTER TABLE analyses ADD COLUMN vmprotect_classification TEXT NOT NULL DEFAULT 'unknown'"
            )
        if "vmprotect_confidence" not in columns:
            connection.execute(
                "ALTER TABLE analyses ADD COLUMN vmprotect_confidence INTEGER NOT NULL DEFAULT 0"
            )
        if "risk_score" not in columns:
            connection.execute("ALTER TABLE analyses ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0")
        if "risk_severity" not in columns:
            connection.execute("ALTER TABLE analyses ADD COLUMN risk_severity TEXT NOT NULL DEFAULT 'low'")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection
