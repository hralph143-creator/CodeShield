from __future__ import annotations

import json
import logging
import re
import shutil
import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from codeshield.models import (
    Finding,
    ManagedRule,
    RiskFactor,
    Rule,
    ScanHistoryRecord,
    ScanResult,
    ScanStats,
    WhitelistEntry,
)
from codeshield.rules import load_rules
from codeshield.rules import validate_rule_pattern


SCAN_STATUSES = {"completed", "cancelled", "failed"}
FINDING_STATUSES = {"unresolved", "confirmed", "false_positive", "ignored", "fixed"}
WHITELIST_TYPES = {"fingerprint", "file", "directory", "rule"}
CURRENT_SCHEMA_VERSION = 4
MAX_DATABASE_BACKUPS = 5
logger = logging.getLogger(__name__)


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY,
    project_name TEXT NOT NULL,
    project_path TEXT NOT NULL,
    project_root TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds REAL NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    candidate_files INTEGER NOT NULL DEFAULT 0,
    scanned_files INTEGER NOT NULL DEFAULT 0,
    skipped_files INTEGER NOT NULL DEFAULT 0,
    read_errors INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'completed',
    error_message TEXT NOT NULL DEFAULT '',
    suppressed_findings INTEGER NOT NULL DEFAULT 0,
    language_files_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL DEFAULT '',
    risk_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    file_path TEXT NOT NULL DEFAULT '',
    relative_path TEXT NOT NULL DEFAULT '',
    line_number INTEGER NOT NULL,
    column_number INTEGER NOT NULL DEFAULT 1,
    language TEXT NOT NULL,
    masked_value TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unresolved',
    reason TEXT NOT NULL,
    risk_factors_json TEXT NOT NULL DEFAULT '[]',
    entropy REAL NOT NULL DEFAULT 0,
    context TEXT NOT NULL DEFAULT '',
    suggestion TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_results_scan_id ON scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_results_fingerprint ON scan_results(fingerprint);

CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY,
    rule_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    risk_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    score INTEGER NOT NULL DEFAULT 40,
    base_score INTEGER NOT NULL DEFAULT 40,
    languages_json TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    suggestion TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rule_overrides (
    rule_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL DEFAULT 'fingerprint',
    value TEXT NOT NULL DEFAULT '',
    value_hash TEXT,
    path_pattern TEXT,
    rule_id TEXT,
    description TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    CHECK (value <> '' OR value_hash IS NOT NULL OR path_pattern IS NOT NULL OR rule_id IS NOT NULL)
);
"""


# 早期版本缺失的列用增量 ALTER 补齐，避免为历史用户重建整库或丢失已保存记录。
MIGRATION_COLUMNS = {
    "scan_history": {
        "project_root": "TEXT NOT NULL DEFAULT ''",
        "duration_ms": "INTEGER NOT NULL DEFAULT 0",
        "candidate_files": "INTEGER NOT NULL DEFAULT 0",
        "skipped_files": "INTEGER NOT NULL DEFAULT 0",
        "read_errors": "INTEGER NOT NULL DEFAULT 0",
        "error_message": "TEXT NOT NULL DEFAULT ''",
        "suppressed_findings": "INTEGER NOT NULL DEFAULT 0",
        "language_files_json": "TEXT NOT NULL DEFAULT '{}'",
    },
    "scan_results": {
        "rule_name": "TEXT NOT NULL DEFAULT ''",
        "relative_path": "TEXT NOT NULL DEFAULT ''",
        "column_number": "INTEGER NOT NULL DEFAULT 1",
        "risk_factors_json": "TEXT NOT NULL DEFAULT '[]'",
        "created_at": "TEXT NOT NULL DEFAULT ''",
    },
    "custom_rules": {
        "rule_id": "TEXT NOT NULL DEFAULT ''",
        "severity": "TEXT NOT NULL DEFAULT 'medium'",
        "score": "INTEGER NOT NULL DEFAULT 40",
        "languages_json": "TEXT NOT NULL DEFAULT '[]'",
        "description": "TEXT NOT NULL DEFAULT ''",
        "suggestion": "TEXT NOT NULL DEFAULT ''",
        "updated_at": "TEXT NOT NULL DEFAULT ''",
    },
    "whitelist": {
        "type": "TEXT NOT NULL DEFAULT 'fingerprint'",
        "value": "TEXT NOT NULL DEFAULT ''",
        "description": "TEXT NOT NULL DEFAULT ''",
        "enabled": "INTEGER NOT NULL DEFAULT 1",
    },
}


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists() and self.path.stat().st_size > 0
        if existed:
            with closing(self.connect()) as connection:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version < CURRENT_SCHEMA_VERSION:
                self._backup_before_migration()
        with closing(self.connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                for statement in (part.strip() for part in SCHEMA.split(";")):
                    if statement:
                        connection.execute(statement)
                for table, columns in MIGRATION_COLUMNS.items():
                    existing = {
                        row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
                    }
                    for name, declaration in columns.items():
                        if name not in existing:
                            connection.execute(
                                f"ALTER TABLE {table} ADD COLUMN {name} {declaration}"
                            )
                connection.execute(
                    "UPDATE scan_history SET project_root = project_path WHERE project_root = ''"
                )
                connection.execute(
                    "UPDATE scan_history SET duration_ms = CAST(duration_seconds * 1000 AS INTEGER) "
                    "WHERE duration_ms = 0"
                )
                connection.execute(
                    "UPDATE scan_results SET relative_path = file_path WHERE relative_path = ''"
                )
                connection.execute(
                    "UPDATE scan_results SET status = 'unresolved' WHERE status = 'unhandled'"
                )
                connection.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
                connection.commit()
            except Exception:
                connection.rollback()
                logger.exception("DB-001 SQLite迁移失败 path=%s", self.path)
                raise

    def _backup_before_migration(self) -> Path:
        backup_dir = self.path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        target = backup_dir / f"{self.path.stem}_{stamp}{self.path.suffix or '.db'}"
        sequence = 1
        while target.exists():
            target = backup_dir / f"{self.path.stem}_{stamp}_{sequence}{self.path.suffix or '.db'}"
            sequence += 1
        shutil.copy2(self.path, target)
        backups = sorted(
            backup_dir.glob(f"{self.path.stem}_*{self.path.suffix or '.db'}"),
            key=lambda item: item.name,
            reverse=True,
        )
        for old in backups[MAX_DATABASE_BACKUPS:]:
            old.unlink()
        logger.info("SQLite迁移前备份已创建 file=%s", target.name)
        return target

    def dashboard_counts(self) -> dict[str, int]:
        with closing(self.connect()) as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS scans,
                       COALESCE(SUM(scanned_files), 0) AS files,
                       COALESCE(SUM(finding_count), 0) AS findings,
                       COALESCE(SUM(critical_count), 0) AS critical
                FROM scan_history WHERE status = 'completed'
                """
            ).fetchone()
        return dict(row)

    def save_scan_result(self, result: ScanResult) -> int:
        if result.stats.status not in SCAN_STATUSES:
            raise ValueError("扫描状态不能持久化")
        counts = {level: 0 for level in ("critical", "high", "medium", "low")}
        for finding in result.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        now = datetime.now().isoformat(timespec="seconds")
        root = str(result.root)
        stats = result.stats

        with closing(self.connect()) as connection:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT INTO scan_history (
                        project_name, project_path, project_root, started_at, finished_at,
                        duration_seconds, duration_ms, candidate_files, scanned_files,
                        skipped_files, read_errors, finding_count, critical_count,
                        high_count, medium_count, low_count, status, suppressed_findings,
                        language_files_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.root.name or root,
                        root,
                        root,
                        stats.started_at.isoformat(timespec="milliseconds"),
                        stats.finished_at.isoformat(timespec="milliseconds") if stats.finished_at else None,
                        stats.duration_seconds,
                        round(stats.duration_seconds * 1000),
                        stats.candidate_files,
                        stats.scanned_files,
                        stats.skipped_files,
                        stats.read_errors,
                        len(result.findings),
                        counts["critical"],
                        counts["high"],
                        counts["medium"],
                        counts["low"],
                        stats.status,
                        stats.suppressed_findings,
                        json.dumps(stats.language_files, ensure_ascii=False, separators=(",", ":")),
                    ),
                )
                scan_id = int(cursor.lastrowid)
                rows = [self._finding_row(scan_id, finding, now) for finding in result.findings]
                if rows:
                    connection.executemany(
                        """
                        INSERT INTO scan_results (
                            scan_id, fingerprint, rule_id, rule_name, risk_type, severity,
                            score, file_path, relative_path, line_number, column_number,
                            language, masked_value, status, reason, risk_factors_json,
                            entropy, context, suggestion, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        rows,
                    )
                ids = [
                    int(row["id"])
                    for row in connection.execute(
                        "SELECT id FROM scan_results WHERE scan_id = ? ORDER BY id", (scan_id,)
                    )
                ]

        result.scan_id = scan_id
        result.findings[:] = [
            replace(finding, database_id=result_id, scan_id=scan_id)
            for finding, result_id in zip(result.findings, ids)
        ]
        return scan_id

    @staticmethod
    def _finding_row(scan_id: int, finding: Finding, created_at: str) -> tuple[object, ...]:
        factors = [
            {"key": factor.key, "points": factor.points, "detail": factor.detail}
            for factor in finding.risk_factors
        ]
        return (
            scan_id,
            finding.fingerprint,
            finding.rule_id,
            finding.rule_name,
            finding.risk_type,
            finding.severity,
            finding.score,
            finding.relative_path,
            finding.relative_path,
            finding.line_number,
            finding.column,
            finding.language,
            finding.masked_value,
            "unresolved" if finding.status == "unhandled" else finding.status,
            finding.reason,
            json.dumps(factors, ensure_ascii=False, separators=(",", ":")),
            finding.entropy,
            finding.context,
            finding.suggestion,
            created_at,
        )

    def list_scan_history(
        self, keyword: str = "", status: str = "", limit: int = 500
    ) -> list[ScanHistoryRecord]:
        clauses: list[str] = []
        values: list[object] = []
        if keyword.strip():
            clauses.append("(project_name LIKE ? OR project_root LIKE ?)")
            term = f"%{keyword.strip()}%"
            values.extend((term, term))
        if status:
            clauses.append("status = ?")
            values.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)
        with closing(self.connect()) as connection:
            rows = connection.execute(
                f"SELECT * FROM scan_history {where} "
                "ORDER BY COALESCE(finished_at, started_at) DESC, id DESC LIMIT ?",
                values,
            ).fetchall()
        return [self._history_record(row) for row in rows]

    def latest_scan(self) -> ScanHistoryRecord | None:
        records = self.list_scan_history(limit=1)
        return records[0] if records else None

    @staticmethod
    def _history_record(row: sqlite3.Row) -> ScanHistoryRecord:
        return ScanHistoryRecord(
            scan_id=int(row["id"]),
            project_name=row["project_name"],
            project_root=row["project_root"] or row["project_path"],
            started_at=datetime.fromisoformat(row["started_at"]),
            finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
            duration_ms=int(row["duration_ms"]),
            candidate_files=int(row["candidate_files"]),
            scanned_files=int(row["scanned_files"]),
            skipped_files=int(row["skipped_files"]),
            read_errors=int(row["read_errors"]),
            finding_count=int(row["finding_count"]),
            critical_count=int(row["critical_count"]),
            high_count=int(row["high_count"]),
            medium_count=int(row["medium_count"]),
            low_count=int(row["low_count"]),
            status=row["status"],
            suppressed_findings=int(row["suppressed_findings"]),
        )

    def load_scan_result(self, scan_id: int) -> ScanResult:
        with closing(self.connect()) as connection:
            history = connection.execute(
                "SELECT * FROM scan_history WHERE id = ?", (scan_id,)
            ).fetchone()
            if history is None:
                raise KeyError(scan_id)
            rows = connection.execute(
                "SELECT * FROM scan_results WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
        root = Path(history["project_root"] or history["project_path"])
        try:
            language_payload = json.loads(history["language_files_json"] or "{}")
            language_files = {
                str(language): int(count)
                for language, count in language_payload.items()
                if int(count) >= 0
            }
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
            language_files = {}
        stats = ScanStats(
            scan_root=str(root),
            started_at=datetime.fromisoformat(history["started_at"]),
            finished_at=datetime.fromisoformat(history["finished_at"]) if history["finished_at"] else None,
            duration_seconds=float(history["duration_seconds"]),
            candidate_files=int(history["candidate_files"]),
            scanned_files=int(history["scanned_files"]),
            skipped_files=int(history["skipped_files"]),
            read_errors=int(history["read_errors"]),
            status=history["status"],
            suppressed_findings=int(history["suppressed_findings"]),
            language_files=language_files,
        )
        findings = [self._restore_finding(root, row) for row in rows]
        return ScanResult(root=root, findings=findings, stats=stats, scan_id=scan_id)

    def previous_completed_scan(self, scan_id: int) -> ScanHistoryRecord | None:
        records = self.list_scan_history(status="completed")
        current_index = next((index for index, item in enumerate(records) if item.scan_id == scan_id), None)
        if current_index is None:
            return None
        current_root = self._normalized_root(records[current_index].project_root)
        for record in records[current_index + 1:]:
            if self._normalized_root(record.project_root) == current_root:
                return record
        return None

    def recent_completed_scans(self, limit: int = 5) -> list[ScanHistoryRecord]:
        return self.list_scan_history(status="completed", limit=limit)

    def dashboard_severity_counts(self) -> dict[str, int]:
        with closing(self.connect()) as connection:
            row = connection.execute(
                """
                SELECT COALESCE(SUM(critical_count), 0) AS critical,
                       COALESCE(SUM(high_count), 0) AS high,
                       COALESCE(SUM(medium_count), 0) AS medium,
                       COALESCE(SUM(low_count), 0) AS low
                FROM scan_history WHERE status = 'completed'
                """
            ).fetchone()
        return dict(row)

    @staticmethod
    def _normalized_root(value: str) -> str:
        return str(Path(value).resolve()).replace("\\", "/").casefold().rstrip("/")

    @staticmethod
    def _restore_finding(root: Path, row: sqlite3.Row) -> Finding:
        try:
            payload = json.loads(row["risk_factors_json"] or "[]")
            factors = tuple(
                RiskFactor(str(item["key"]), int(item["points"]), str(item["detail"]))
                for item in payload
            )
        except (TypeError, ValueError, KeyError, json.JSONDecodeError):
            factors = ()
        relative = row["relative_path"] or row["file_path"]
        return Finding(
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            risk_type=row["risk_type"],
            severity=row["severity"],
            score=int(row["score"]),
            file_path=str(root / relative),
            relative_path=relative,
            line_number=int(row["line_number"]),
            column=int(row["column_number"]),
            language=row["language"],
            masked_value=row["masked_value"],
            status="unresolved" if row["status"] == "unhandled" else row["status"],
            reason=row["reason"],
            risk_factors=factors,
            entropy=float(row["entropy"] or 0),
            context=row["context"],
            suggestion=row["suggestion"],
            fingerprint=row["fingerprint"],
            database_id=int(row["id"]),
            scan_id=int(row["scan_id"]),
        )

    def delete_scan(self, scan_id: int) -> None:
        with closing(self.connect()) as connection:
            with connection:
                connection.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))

    def update_finding_status(self, result_id: int, status: str) -> None:
        if status not in FINDING_STATUSES:
            raise ValueError("未知风险状态")
        with closing(self.connect()) as connection:
            with connection:
                cursor = connection.execute(
                    "UPDATE scan_results SET status = ? WHERE id = ?", (status, result_id)
                )
                if cursor.rowcount != 1:
                    raise KeyError(result_id)

    def add_whitelist(self, entry_type: str, value: str, description: str = "") -> int:
        if entry_type not in WHITELIST_TYPES or not value.strip():
            raise ValueError("白名单类型或目标无效")
        clean = value.strip().replace("\\", "/") if entry_type in {"file", "directory"} else value.strip()
        legacy = {
            "value_hash": clean if entry_type == "fingerprint" else None,
            "path_pattern": clean if entry_type in {"file", "directory"} else None,
            "rule_id": clean if entry_type == "rule" else None,
        }
        with closing(self.connect()) as connection:
            with connection:
                existing = connection.execute(
                    "SELECT id FROM whitelist WHERE type = ? AND value = ?",
                    (entry_type, clean),
                ).fetchone()
                if existing is not None:
                    connection.execute(
                        "UPDATE whitelist SET enabled = 1, description = ?, note = ? WHERE id = ?",
                        (description.strip(), description.strip(), int(existing["id"])),
                    )
                    return int(existing["id"])
                cursor = connection.execute(
                    """
                    INSERT INTO whitelist (
                        type, value, value_hash, path_pattern, rule_id,
                        description, note, created_at, enabled
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        entry_type,
                        clean,
                        legacy["value_hash"],
                        legacy["path_pattern"],
                        legacy["rule_id"],
                        description.strip(),
                        description.strip(),
                        datetime.now().isoformat(timespec="seconds"),
                    ),
                )
        return int(cursor.lastrowid)

    def list_whitelist(self) -> list[WhitelistEntry]:
        with closing(self.connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM whitelist ORDER BY created_at DESC, id DESC"
            ).fetchall()
        entries = []
        for row in rows:
            value = row["value"] or row["value_hash"] or row["path_pattern"] or row["rule_id"] or ""
            entries.append(
                WhitelistEntry(
                    int(row["id"]),
                    row["type"],
                    value,
                    row["description"] or row["note"],
                    datetime.fromisoformat(row["created_at"]),
                    bool(row["enabled"]),
                )
            )
        return entries

    def set_whitelist_enabled(self, entry_id: int, enabled: bool) -> None:
        with closing(self.connect()) as connection:
            with connection:
                connection.execute(
                    "UPDATE whitelist SET enabled = ? WHERE id = ?", (int(enabled), entry_id)
                )

    def delete_whitelist(self, entry_id: int) -> None:
        with closing(self.connect()) as connection:
            with connection:
                connection.execute("DELETE FROM whitelist WHERE id = ?", (entry_id,))

    def is_whitelisted(self, finding: Finding) -> bool:
        relative = finding.relative_path.replace("\\", "/")
        for entry in self.list_whitelist():
            if not entry.enabled:
                continue
            if entry.entry_type == "fingerprint" and entry.value == finding.fingerprint:
                return True
            if entry.entry_type == "rule" and entry.value == finding.rule_id:
                return True
            target = entry.value.rstrip("/")
            if entry.entry_type == "file" and relative == target:
                return True
            if entry.entry_type == "directory" and (relative == target or relative.startswith(target + "/")):
                return True
        return False

    def builtin_rule_overrides(self) -> dict[str, bool]:
        with closing(self.connect()) as connection:
            rows = connection.execute("SELECT rule_id, enabled FROM rule_overrides").fetchall()
        return {row["rule_id"]: bool(row["enabled"]) for row in rows}

    def set_builtin_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        with closing(self.connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO rule_overrides (rule_id, enabled, updated_at) VALUES (?, ?, ?)
                    ON CONFLICT(rule_id) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at
                    """,
                    (rule_id, int(enabled), datetime.now().isoformat(timespec="seconds")),
                )

    def list_managed_rules(self) -> list[ManagedRule]:
        overrides = self.builtin_rule_overrides()
        builtins = [
            ManagedRule(
                rule.id,
                rule.name,
                rule.risk_type,
                rule.pattern.pattern,
                rule.severity,
                rule.score,
                tuple(sorted(rule.languages)),
                rule.description,
                rule.suggestion,
                overrides.get(rule.id, True),
                True,
            )
            for rule in load_rules().rules
        ]
        with closing(self.connect()) as connection:
            rows = connection.execute("SELECT * FROM custom_rules ORDER BY id").fetchall()
        custom = [self._managed_custom(row) for row in rows]
        return builtins + custom

    @staticmethod
    def _managed_custom(row: sqlite3.Row) -> ManagedRule:
        languages = tuple(json.loads(row["languages_json"] or "[]"))
        rule_id = row["rule_id"] or f"custom_{row['id']}"
        return ManagedRule(
            rule_id,
            row["name"],
            row["risk_type"],
            row["pattern"],
            row["severity"],
            int(row["score"] or row["base_score"]),
            languages,
            row["description"],
            row["suggestion"],
            bool(row["enabled"]),
            False,
        )

    def save_custom_rule(
        self,
        name: str,
        risk_type: str,
        pattern: str,
        severity: str,
        score: int,
        languages: list[str],
        description: str,
        suggestion: str,
        enabled: bool = True,
        rule_id: str | None = None,
    ) -> str:
        self._validate_custom_rule(pattern, severity, score, languages)
        now = datetime.now().isoformat(timespec="seconds")
        with closing(self.connect()) as connection:
            with connection:
                if rule_id:
                    cursor = connection.execute(
                        """
                        UPDATE custom_rules SET name=?, risk_type=?, pattern=?, severity=?, score=?,
                            base_score=?, languages_json=?, description=?, suggestion=?, enabled=?, updated_at=?
                        WHERE rule_id=?
                        """,
                        (
                            name.strip(), risk_type.strip(), pattern, severity, score, score,
                            json.dumps(languages), description.strip(), suggestion.strip(),
                            int(enabled), now, rule_id,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise KeyError(rule_id)
                    return rule_id
                cursor = connection.execute(
                    """
                    INSERT INTO custom_rules (
                        rule_id, name, pattern, risk_type, severity, score, base_score,
                        languages_json, description, suggestion, enabled, created_at, updated_at
                    ) VALUES ('', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        name.strip(), pattern, risk_type.strip(), severity, score, score,
                        json.dumps(languages), description.strip(), suggestion.strip(), int(enabled), now, now,
                    ),
                )
                new_id = f"custom_{int(cursor.lastrowid)}"
                connection.execute(
                    "UPDATE custom_rules SET rule_id = ? WHERE id = ?", (new_id, cursor.lastrowid)
                )
        return new_id

    @staticmethod
    def _validate_custom_rule(pattern: str, severity: str, score: int, languages: list[str]) -> None:
        validate_rule_pattern(pattern)
        if severity not in {"critical", "high", "medium", "low"} or not 0 <= score <= 100:
            raise ValueError("等级或分数无效")
        if not languages:
            raise ValueError("至少选择一种语言")

    def delete_custom_rule(self, rule_id: str) -> None:
        if not rule_id.startswith("custom_"):
            raise ValueError("内置规则不能删除")
        with closing(self.connect()) as connection:
            with connection:
                connection.execute("DELETE FROM custom_rules WHERE rule_id = ?", (rule_id,))

    def set_custom_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        with closing(self.connect()) as connection:
            with connection:
                connection.execute(
                    "UPDATE custom_rules SET enabled = ?, updated_at = ? WHERE rule_id = ?",
                    (int(enabled), datetime.now().isoformat(timespec="seconds"), rule_id),
                )

    def active_custom_rules(self) -> list[Rule]:
        rules = []
        for managed in self.list_managed_rules():
            if managed.builtin or not managed.enabled:
                continue
            rules.append(
                Rule(
                    managed.rule_id,
                    managed.name,
                    managed.risk_type,
                    re.compile(managed.pattern),
                    managed.severity,
                    managed.score,
                    frozenset(managed.languages),
                    managed.description,
                    managed.suggestion,
                )
            )
        return rules

    def disabled_builtin_rule_ids(self) -> set[str]:
        return {rule_id for rule_id, enabled in self.builtin_rule_overrides().items() if not enabled}
