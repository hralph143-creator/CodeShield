from __future__ import annotations

from codeshield.models import Finding, ScanComparison


def compare_scans(
    previous_scan_id: int,
    previous_findings: list[Finding],
    current_scan_id: int,
    current_findings: list[Finding],
) -> ScanComparison:
    previous = _by_fingerprint(previous_findings)
    current = _by_fingerprint(current_findings)
    shared = previous.keys() & current.keys()
    new_keys = current.keys() - previous.keys()
    resolved_keys = previous.keys() - current.keys()
    return ScanComparison(
        current_scan_id=current_scan_id,
        previous_scan_id=previous_scan_id,
        new_findings=tuple(current[key] for key in sorted(new_keys)),
        persistent_findings=tuple(current[key] for key in sorted(shared)),
        resolved_findings=tuple(previous[key] for key in sorted(resolved_keys)),
    )


def _by_fingerprint(findings: list[Finding]) -> dict[str, Finding]:
    indexed: dict[str, Finding] = {}
    for finding in findings:
        if finding.fingerprint and finding.fingerprint not in indexed:
            indexed[finding.fingerprint] = finding
    return indexed
