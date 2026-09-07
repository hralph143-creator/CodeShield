from __future__ import annotations

import os
import logging
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from codeshield.config import AppConfig, FULL_IGNORED_DIRS, STANDARD_IGNORED_DIRS
from codeshield.language import detect_language, file_extension
from codeshield.models import Finding, Rule, ScanError, ScanProgress, ScanResult, ScanStats
from codeshield.rules import RuleDetector, finding_sort_key, load_rules


BINARY_SAMPLE_SIZE = 8192
logger = logging.getLogger(__name__)


def is_probably_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True

    # 源码里少量制表、换行属于正常情况；其余控制字节过多通常意味着二进制内容。
    control_bytes = sum(byte < 32 and byte not in (9, 10, 13) for byte in sample)
    return control_bytes / len(sample) > 0.10


def read_source_file(path: Path) -> tuple[str | None, str | None]:
    try:
        with path.open("rb") as stream:
            sample = stream.read(BINARY_SAMPLE_SIZE)
            if is_probably_binary(sample):
                return None, "binary"
            remainder = stream.read()
    except OSError:
        return None, "read_error"

    content = sample + remainder
    # utf-8-sig 同时兼容普通 UTF-8，并会移除 BOM；GBK 只作为 Windows 工程的有限回退。
    for encoding in ("utf-8-sig", "gbk"):
        try:
            return content.decode(encoding), None
        except UnicodeDecodeError:
            continue
    return None, "decode_error"


class ProjectScanner:
    def __init__(
        self,
        config: AppConfig,
        rule_path: Path | None = None,
        additional_rules: list[Rule] | None = None,
        disabled_rule_ids: set[str] | None = None,
        whitelist_matcher: Callable[[Finding], bool] | None = None,
    ) -> None:
        loaded = load_rules(rule_path)
        disabled = disabled_rule_ids or set()
        rules = [rule for rule in loaded.rules if rule.id not in disabled]
        rules.extend(additional_rules or [])
        if not rules:
            details = "; ".join(loaded.errors) or "没有可用规则"
            raise ValueError(f"规则加载失败：{details}")
        self.rule_errors = loaded.errors
        self.detector = RuleDetector(rules, config)
        self.whitelist_matcher = whitelist_matcher
        self.config = config
        self.supported_extensions = {value.lower() for value in config.included_extensions}
        if config.scan_mode == "full":
            ignored_dirs = FULL_IGNORED_DIRS
        elif config.scan_mode == "custom":
            ignored_dirs = config.ignored_dirs
        else:
            ignored_dirs = STANDARD_IGNORED_DIRS
        self.ignored_dirs = {value.casefold() for value in ignored_dirs}
        self.max_file_size = config.max_file_size_mb * 1024 * 1024

    def scan(
        self,
        root: Path | str,
        on_progress: Callable[[ScanProgress], None] | None = None,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> ScanResult:
        requested_root = Path(root).expanduser()
        if requested_root.is_symlink():
            raise ValueError(f"扫描目录不能是符号链接：{requested_root}")
        scan_root = requested_root.resolve()
        if not scan_root.exists() or not scan_root.is_dir():
            raise ValueError(f"扫描目录不存在或不是目录：{scan_root}")

        started = datetime.now()
        logger.info("扫描开始 mode=%s root=%s", self.config.scan_mode, scan_root)
        stats = ScanStats(scan_root=str(scan_root), started_at=started)
        findings = []
        errors: list[ScanError] = []
        cancel_requested = is_cancelled or (lambda: False)

        self._report(on_progress, "preparing", "", 0, stats, len(findings))
        candidates, enumeration_cancelled = self._candidate_files(
            scan_root,
            errors,
            cancel_requested,
        )
        stats.candidate_files = len(candidates)
        if enumeration_cancelled:
            logger.info("扫描取消 phase=enumeration root=%s", scan_root)
            return self._finish(scan_root, findings, stats, errors, "cancelled")

        self._report(on_progress, "scanning", "", 0, stats, len(findings))
        processed_files = 0
        for path in candidates:
            if cancel_requested():
                logger.info("扫描取消 phase=scanning root=%s", scan_root)
                return self._finish(scan_root, findings, stats, errors, "cancelled")

            relative = path.relative_to(scan_root)
            skip_reason = self._check_file(path)
            if skip_reason:
                stats.skipped_files += 1
                errors.append(ScanError(str(relative), skip_reason, skip_reason))
            else:
                text, read_error = read_source_file(path)
                if read_error:
                    stats.skipped_files += 1
                    if read_error in {"read_error", "decode_error"}:
                        stats.read_errors += 1
                    errors.append(ScanError(str(relative), read_error, read_error))
                else:
                    language = detect_language(path)
                    if language is None:
                        stats.skipped_files += 1
                        errors.append(ScanError(str(relative), "unknown_language", "unknown_language"))
                    else:
                        stats.scanned_files += 1
                        stats.language_files[language] = stats.language_files.get(language, 0) + 1
                        detected = self.detector.detect(text or "", path, relative, language)
                        if self.whitelist_matcher:
                            file_findings = []
                            for finding in detected:
                                if self.whitelist_matcher(finding):
                                    stats.suppressed_findings += 1
                                else:
                                    file_findings.append(finding)
                        else:
                            file_findings = detected
                        findings.extend(file_findings)
                        for finding in file_findings:
                            stats.risk_types[finding.risk_type] = stats.risk_types.get(finding.risk_type, 0) + 1

            processed_files += 1
            self._report(
                on_progress,
                "scanning",
                str(relative),
                processed_files,
                stats,
                len(findings),
            )

        result = self._finish(scan_root, findings, stats, errors, "completed")
        logger.info(
            "扫描完成 mode=%s files=%d findings=%d read_errors=%d duration=%.3fs",
            self.config.scan_mode,
            stats.scanned_files,
            len(findings),
            stats.read_errors,
            stats.duration_seconds,
        )
        return result

    def _candidate_files(
        self,
        scan_root: Path,
        errors: list[ScanError],
        is_cancelled: Callable[[], bool],
    ) -> tuple[list[Path], bool]:
        candidates: list[Path] = []

        def handle_walk_error(error: OSError) -> None:
            relative = self._relative(Path(error.filename), scan_root) if error.filename else Path(".")
            errors.append(ScanError(str(relative), "directory_error", type(error).__name__))

        for directory, dir_names, file_names in os.walk(
            scan_root,
            topdown=True,
            onerror=handle_walk_error,
            followlinks=False,
        ):
            if is_cancelled():
                return candidates, True
            current = Path(directory)
            dir_names[:] = sorted(
                name
                for name in dir_names
                if name.casefold() not in self.ignored_dirs and not (current / name).is_symlink()
            )
            for name in sorted(file_names, key=str.casefold):
                path = current / name
                if file_extension(path) not in self.supported_extensions:
                    continue
                candidates.append(path)
        return candidates, False

    @staticmethod
    def _finish(
        scan_root: Path,
        findings: list[Finding],
        stats: ScanStats,
        errors: list[ScanError],
        status: str,
    ) -> ScanResult:
        findings.sort(key=finding_sort_key)
        stats.finished_at = datetime.now()
        stats.duration_seconds = (stats.finished_at - stats.started_at).total_seconds()
        stats.status = status
        return ScanResult(scan_root, findings, stats, errors)

    @staticmethod
    def _report(
        callback: Callable[[ScanProgress], None] | None,
        phase: str,
        current_file: str,
        processed_files: int,
        stats: ScanStats,
        finding_count: int,
    ) -> None:
        if callback:
            callback(
                ScanProgress(
                    phase=phase,
                    current_file=current_file,
                    processed_files=processed_files,
                    candidate_files=stats.candidate_files,
                    finding_count=finding_count,
                    read_errors=stats.read_errors,
                )
            )

    def _check_file(self, path: Path) -> str | None:
        try:
            if path.is_symlink():
                return "symlink"
            if not path.exists() or not path.is_file():
                return "not_regular_file"
            if path.stat().st_size > self.max_file_size:
                # 大文件限制在打开前执行，避免无意中把构建产物读入内存。
                return "too_large"
        except OSError:
            return "metadata_error"
        return None

    @staticmethod
    def _relative(path: Path, root: Path) -> Path:
        try:
            return path.resolve().relative_to(root)
        except (OSError, ValueError):
            return Path(path.name)
