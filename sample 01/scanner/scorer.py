"""Scoring and security posture grading module."""
from __future__ import annotations


def score(checks: list[dict]) -> dict:
    """Calculate weighted posture summary score and category breakdown."""
    applicable = [c for c in checks if c.get("status") in {"present", "not_present"}]
    total = sum(c.get("weight", 1) for c in applicable)
    earned = sum(c.get("weight", 1) for c in applicable if c.get("status") == "present")
    percent = round(100 * earned / total) if total else None

    # Categorized breakdown for modern dashboard
    categories: dict[str, dict] = {}
    for c in checks:
        cat = c.get("category", "General")
        if cat not in categories:
            categories[cat] = {"total": 0, "passed": 0, "failed": 0, "other": 0}
        categories[cat]["total"] += 1
        st = c.get("status")
        if st == "present":
            categories[cat]["passed"] += 1
        elif st == "not_present":
            categories[cat]["failed"] += 1
        else:
            categories[cat]["other"] += 1

    if percent is None:
        label = "Insufficient observations"
        status_tier = "unknown"
        badge = "Indeterminate"
    elif percent >= 80:
        label = "Observed controls present"
        status_tier = "safe"
        badge = "Good Posture"
    elif percent >= 50:
        label = "Some controls need review"
        status_tier = "warning"
        badge = "Needs Attention"
    else:
        label = "Several controls need review"
        status_tier = "danger"
        badge = "High Risk"

    return {
        "score": percent,
        "completed": len(applicable),
        "total": len(checks),
        "applicable_weight": total,
        "label": label,
        "badge": badge,
        "status_tier": status_tier,
        "categories": categories,
    }
