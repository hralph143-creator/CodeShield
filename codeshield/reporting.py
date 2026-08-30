from __future__ import annotations

import html
import json
import re
from pathlib import Path

from codeshield import __version__
from codeshield.models import Finding, ScanComparison, ScanHistoryRecord, ScanResult


REPORT_VERSION = 1
INVALID_FILENAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
STATUS_LABELS = {
    "unresolved": "未处理",
    "confirmed": "已确认",
    "false_positive": "误报",
    "ignored": "已忽略",
    "fixed": "已修复",
}
SCAN_STATUS_LABELS = {"completed": "已完成", "cancelled": "已取消", "failed": "失败"}
SEVERITY_LABELS = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}


def safe_filename(value: str) -> str:
    cleaned = INVALID_FILENAME.sub("_", value).strip(" .") or "CodeShield_Report"
    if cleaned.upper() in RESERVED_NAMES:
        cleaned = f"_{cleaned}"
    return cleaned[:120].rstrip(" .")


def default_report_name(record: ScanHistoryRecord, extension: str) -> str:
    moment = record.finished_at or record.started_at
    base = safe_filename(f"CodeShield_{record.project_name}_{moment:%Y%m%d_%H%M%S}")
    return f"{base}.{extension.lstrip('.').lower()}"


def available_output_path(directory: Path, filename: str) -> Path:
    target = directory / filename
    if not target.exists():
        return target
    for index in range(1, 10_000):
        candidate = target.with_name(f"{target.stem} ({index}){target.suffix}")
        if not candidate.exists():
            return candidate
    raise OSError("无法生成可用的报告文件名")


def build_report_payload(
    record: ScanHistoryRecord,
    result: ScanResult,
    comparison: ScanComparison | None = None,
) -> dict[str, object]:
    summary = {
        "total": len(result.findings),
        "critical": sum(item.severity == "critical" for item in result.findings),
        "high": sum(item.severity == "high" for item in result.findings),
        "medium": sum(item.severity == "medium" for item in result.findings),
        "low": sum(item.severity == "low" for item in result.findings),
        "comparison": _comparison_payload(comparison),
    }
    return {
        "tool": {"name": "CodeShield", "version": __version__, "report_version": REPORT_VERSION},
        "scan": {
            "scan_id": record.scan_id,
            "project_name": record.project_name,
            "project_root": record.project_root,
            "started_at": record.started_at.isoformat(timespec="milliseconds"),
            "finished_at": record.finished_at.isoformat(timespec="milliseconds") if record.finished_at else None,
            "duration_ms": record.duration_ms,
            "status": record.status,
            "candidate_files": record.candidate_files,
            "scanned_files": record.scanned_files,
            "skipped_files": record.skipped_files,
            "read_errors": record.read_errors,
            "suppressed_findings": record.suppressed_findings,
        },
        "summary": summary,
        "findings": [_finding_payload(item) for item in result.findings],
    }


def build_json_report(
    record: ScanHistoryRecord,
    result: ScanResult,
    comparison: ScanComparison | None = None,
) -> str:
    return json.dumps(build_report_payload(record, result, comparison), ensure_ascii=False, indent=2)


def build_html_report(
    record: ScanHistoryRecord,
    result: ScanResult,
    comparison: ScanComparison | None = None,
) -> str:
    counts = {level: sum(item.severity == level for item in result.findings) for level in SEVERITY_LABELS}
    maximum = max(counts.values(), default=0) or 1
    bars = "".join(
        f'<div class="bar-row"><span>{_e(label)}</span><div class="track"><i class="{level}" '
        f'style="width:{counts[level] / maximum * 100:.1f}%"></i></div><b>{counts[level]}</b></div>'
        for level, label in SEVERITY_LABELS.items()
    )
    comparison_block = ""
    if comparison:
        comparison_block = f"""
        <section><h2>与上次扫描对比</h2><div class="compare">
          <div><b>{comparison.new_count}</b><span>新增风险</span></div>
          <div><b>{comparison.persistent_count}</b><span>持续风险</span></div>
          <div><b>{comparison.resolved_count}</b><span>已消除风险</span></div>
        </div><p class="note">白名单会影响最终结果差异，已消除不等同于已完成修复。</p></section>"""
    finding_rows = "".join(_finding_html(item) for item in result.findings)
    if not finding_rows:
        finding_rows = '<div class="empty">本次扫描没有风险项。</div>'
    finished = record.finished_at or record.started_at
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CodeShield 代码安全扫描报告</title><style>
:root{{--blue:#175cd3;--ink:#182230;--muted:#667085;--line:#e4e7ec;--bg:#f4f6f8}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.6 "Microsoft YaHei",Arial,sans-serif}}
main{{max-width:1120px;margin:32px auto;padding:0 22px}}header,section{{background:#fff;border:1px solid var(--line);border-radius:8px;padding:24px;margin-bottom:16px}}
h1{{font-size:28px;margin:0 0 4px}}h2{{font-size:18px;margin:0 0 16px}}.brand{{color:var(--blue);font-weight:700}}.muted,.note{{color:var(--muted)}}
.meta,.summary,.compare{{display:grid;gap:12px}}.meta{{grid-template-columns:repeat(3,1fr);margin-top:20px}}.meta div,.summary div,.compare div{{padding:12px;background:#f8fafc;border:1px solid #eaecf0;border-radius:6px}}
.meta span,.summary span,.compare span{{display:block;color:var(--muted);font-size:12px}}.summary{{grid-template-columns:repeat(5,1fr)}}.summary b,.compare b{{font-size:24px}}.compare{{grid-template-columns:repeat(3,1fr)}}
.bar-row{{display:grid;grid-template-columns:48px 1fr 38px;gap:12px;align-items:center;margin:10px 0}}.track{{height:10px;background:#eaecf0;border-radius:5px;overflow:hidden}}.track i{{display:block;height:100%;background:#84adff}}.track .critical{{background:#E5484D}}.track .high{{background:#F59E0B}}.track .medium{{background:#EAB308}}.track .low{{background:#3B82F6}}
.finding{{border-top:1px solid var(--line);padding:20px 0}}.finding:first-child{{border-top:0;padding-top:0}}.finding-head{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}.badge{{padding:2px 8px;border-radius:4px;background:#eef4ff;color:#175cd3;font-weight:600}}.score{{font-weight:700}}
.path{{overflow-wrap:anywhere;color:#475467}}code,pre{{font-family:Consolas,monospace}}code{{background:#f2f4f7;padding:3px 6px;border-radius:4px;overflow-wrap:anywhere}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#182230;color:#f2f4f7;padding:12px;border-radius:6px}}
.factors{{width:100%;border-collapse:collapse;margin:10px 0}}.factors td{{padding:6px 8px;border-bottom:1px solid #eaecf0}}.factors td:last-child{{width:70px;text-align:right;font-weight:600}}.empty{{color:var(--muted);padding:28px;text-align:center}}
@media(max-width:760px){{.meta,.summary{{grid-template-columns:1fr 1fr}}.compare{{grid-template-columns:1fr}}}}@media print{{body{{background:#fff}}main{{margin:0;max-width:none}}header,section{{break-inside:avoid;border-color:#bbb}}}}
</style></head><body><main>
<header><div class="brand">CodeShield</div><h1>代码安全扫描报告</h1><div class="muted">本报告由本地静态分析生成，敏感内容已脱敏。</div>
<div class="meta"><div><span>项目名称</span>{_e(record.project_name)}</div><div><span>扫描时间</span>{_e(finished.strftime('%Y-%m-%d %H:%M:%S'))}</div><div><span>扫描状态</span>{_e(SCAN_STATUS_LABELS.get(record.status, record.status))}</div><div><span>扫描文件</span>{record.scanned_files} / 候选 {record.candidate_files}</div><div><span>读取失败</span>{record.read_errors}</div><div><span>扫描耗时</span>{record.duration_ms / 1000:.2f} 秒</div></div>
<p class="path"><span class="muted">本地项目路径：</span>{_e(record.project_root)}</p></header>
<section><h2>风险摘要</h2><div class="summary"><div><b>{len(result.findings)}</b><span>风险总数</span></div>{''.join(f'<div><b>{counts[k]}</b><span>{v}</span></div>' for k,v in SEVERITY_LABELS.items())}</div><p class="note">白名单抑制 {record.suppressed_findings} 项</p>{bars}</section>
{comparison_block}<section><h2>风险详情</h2>{finding_rows}</section>
<footer class="muted">CodeShield · 报告格式版本 {REPORT_VERSION}</footer></main></body></html>"""


def export_report(
    directory: Path,
    report_type: str,
    record: ScanHistoryRecord,
    result: ScanResult,
    comparison: ScanComparison | None = None,
) -> Path:
    if not directory.exists() or not directory.is_dir():
        raise OSError("输出目录不存在")
    kind = report_type.lower()
    if kind not in {"html", "json"}:
        raise ValueError("不支持的报告类型")
    target = available_output_path(directory, default_report_name(record, kind))
    content = build_html_report(record, result, comparison) if kind == "html" else build_json_report(record, result, comparison)
    target.write_text(content, encoding="utf-8")
    return target


def _finding_payload(finding: Finding) -> dict[str, object]:
    return {
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "risk_type": finding.risk_type,
        "severity": finding.severity,
        "score": finding.score,
        "relative_path": finding.relative_path,
        "line_number": finding.line_number,
        "column": finding.column,
        "language": finding.language,
        "masked_value": finding.masked_value,
        "risk_factors": [{"key": item.key, "points": item.points, "detail": item.detail} for item in finding.risk_factors],
        "entropy": finding.entropy,
        "context": finding.context,
        "suggestion": finding.suggestion,
        "status": finding.status,
    }


def _comparison_payload(comparison: ScanComparison | None) -> dict[str, int] | None:
    if comparison is None:
        return None
    return {
        "previous_scan_id": comparison.previous_scan_id,
        "new": comparison.new_count,
        "persistent": comparison.persistent_count,
        "resolved": comparison.resolved_count,
    }


def _finding_html(finding: Finding) -> str:
    factors = "".join(f"<tr><td>{_e(item.detail)}</td><td>{item.points:+d}</td></tr>" for item in finding.risk_factors)
    return f"""<article class="finding"><div class="finding-head"><span class="badge">{_e(SEVERITY_LABELS.get(finding.severity, finding.severity))}</span><strong>{_e(finding.risk_type)}</strong><span class="score">{finding.score} / 100</span></div>
<p class="path">{_e(finding.rule_name or finding.rule_id)} · {_e(finding.relative_path)}:{finding.line_number}:{finding.column}</p><p>脱敏内容：<code>{_e(finding.masked_value)}</code></p>
<h3>检测依据</h3><table class="factors">{factors}</table><h3>脱敏上下文</h3><pre>{_e(finding.context)}</pre><p><strong>修复建议：</strong>{_e(finding.suggestion)}</p><p class="muted">状态：{_e(STATUS_LABELS.get(finding.status, finding.status))}</p></article>"""


def _e(value: object) -> str:
    # 所有动态文本在拼入 HTML 前统一转义，避免源码内容破坏页面结构或注入脚本。
    return html.escape(str(value), quote=True)
