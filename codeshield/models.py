from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    name: str
    risk_type: str
    pattern: re.Pattern[str]
    severity: str
    score: int
    languages: frozenset[str]
    description: str
    suggestion: str


@dataclass(frozen=True, slots=True)
class RiskFactor:
    key: str
    points: int
    detail: str


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    risk_type: str
    severity: str
    score: int
    file_path: str
    relative_path: str
    line_number: int
    column: int
    language: str
    masked_value: str
    reason: str
    suggestion: str
    rule_name: str = ""
    entropy: float = 0.0
    risk_factors: tuple[RiskFactor, ...] = ()
    is_placeholder: bool = False
    is_comment: bool = False
    is_hardcoded: bool = False
    context: str = ""
    status: str = "unresolved"
    fingerprint: str = ""
    database_id: int | None = None
    scan_id: int | None = None


@dataclass(frozen=True, slots=True)
class ScanError:
    relative_path: str
    error_type: str
    message: str


@dataclass(slots=True)
class ScanStats:
    scan_root: str
    started_at: datetime
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    candidate_files: int = 0
    scanned_files: int = 0
    skipped_files: int = 0
    read_errors: int = 0
    language_files: dict[str, int] = field(default_factory=dict)
    risk_types: dict[str, int] = field(default_factory=dict)
    status: str = "scanning"
    suppressed_findings: int = 0


@dataclass(frozen=True, slots=True)
class ScanProgress:
    phase: str
    current_file: str
    processed_files: int
    candidate_files: int
    finding_count: int
    read_errors: int


@dataclass(slots=True)
class ScanResult:
    root: Path
    findings: list[Finding]
    stats: ScanStats
    errors: list[ScanError] = field(default_factory=list)
    scan_id: int | None = None


@dataclass(frozen=True, slots=True)
class ScanHistoryRecord:
    scan_id: int
    project_name: str
    project_root: str
    started_at: datetime
    finished_at: datetime | None
    duration_ms: int
    candidate_files: int
    scanned_files: int
    skipped_files: int
    read_errors: int
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    status: str
    suppressed_findings: int = 0


@dataclass(frozen=True, slots=True)
class WhitelistEntry:
    entry_id: int
    entry_type: str
    value: str
    description: str
    created_at: datetime
    enabled: bool


@dataclass(frozen=True, slots=True)
class ManagedRule:
    rule_id: str
    name: str
    risk_type: str
    pattern: str
    severity: str
    score: int
    languages: tuple[str, ...]
    description: str
    suggestion: str
    enabled: bool
    builtin: bool


@dataclass(frozen=True, slots=True)
class ComparisonItem:
    change: str
    finding: Finding


@dataclass(frozen=True, slots=True)
class ScanComparison:
    current_scan_id: int
    previous_scan_id: int
    new_findings: tuple[Finding, ...]
    persistent_findings: tuple[Finding, ...]
    resolved_findings: tuple[Finding, ...]

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def persistent_count(self) -> int:
        return len(self.persistent_findings)

    @property
    def resolved_count(self) -> int:
        return len(self.resolved_findings)
