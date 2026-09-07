from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from codeshield.comparison import compare_scans
from codeshield.config import AppConfig, ConfigStore
from codeshield.database import Database
from codeshield.logging_setup import configure_logging
from codeshield.reporting import export_report
from codeshield.scanner import ProjectScanner


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify release persistence and reports")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--demo", type=Path, default=ROOT / "demo_project")
    args = parser.parse_args()

    data_dir = args.data_dir.resolve()
    report_dir = args.report_dir.resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    store = ConfigStore(data_dir)
    database = Database(data_dir / "codeshield.db")
    database.initialize()

    store.save(AppConfig(scan_mode="full"))
    database.add_whitelist("file", "python_demo.py", "发布验收白名单")
    database.set_builtin_rule_enabled("email_address", False)
    existing = next(
        (rule for rule in database.list_managed_rules() if not rule.builtin and rule.name == "发布验收规则"),
        None,
    )
    database.save_custom_rule(
        "发布验收规则",
        "Secret",
        r"release_marker\s*=\s*['\"](?P<value>[^'\"]+)['\"]",
        "medium",
        45,
        ["python"],
        "发布验收用自定义规则",
        "移到环境变量",
        rule_id=existing.rule_id if existing else None,
    )

    previous_record = database.latest_scan()
    previous_result = database.load_scan_result(previous_record.scan_id) if previous_record else None
    config = store.load()
    current_result = ProjectScanner(
        config,
        additional_rules=database.active_custom_rules(),
        disabled_rule_ids=database.disabled_builtin_rule_ids(),
        whitelist_matcher=database.is_whitelisted,
    ).scan(args.demo.resolve())
    current_id = database.save_scan_result(current_result)
    current_record = database.latest_scan()
    if current_result.findings:
        database.update_finding_status(current_result.findings[0].database_id, "confirmed")
        current_result = database.load_scan_result(current_id)

    comparison = None
    if previous_record and previous_result:
        comparison = compare_scans(
            previous_record.scan_id,
            previous_result.findings,
            current_id,
            current_result.findings,
        )
    html_path = export_report(report_dir, "html", current_record, current_result, comparison)
    json_path = export_report(report_dir, "json", current_record, current_result, comparison)

    log_path = configure_logging(data_dir)
    raw_secret = "ReleaseAcceptanceToken-DoNotPersist-9x8y7z"
    logging.getLogger("codeshield.release").error("token=%s", raw_secret)
    for handler in logging.getLogger().handlers:
        handler.flush()
    if raw_secret in log_path.read_text(encoding="utf-8"):
        raise RuntimeError("raw secret leaked into log")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if payload["tool"]["version"] != "1.0.0" or raw_secret in json_path.read_text(encoding="utf-8"):
        raise RuntimeError("release report validation failed")

    result = {
        "history": len(database.list_scan_history()),
        "findings_latest": len(current_result.findings),
        "whitelist": len(database.list_whitelist()),
        "custom_rules": sum(not rule.builtin for rule in database.list_managed_rules()),
        "builtin_email_enabled": database.builtin_rule_overrides().get("email_address", True),
        "setting_scan_mode": store.load().scan_mode,
        "html": str(html_path),
        "json": str(json_path),
        "log": str(log_path),
        "comparison": {
            "new": comparison.new_count,
            "persistent": comparison.persistent_count,
            "resolved": comparison.resolved_count,
        }
        if comparison
        else None,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
