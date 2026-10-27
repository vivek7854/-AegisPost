"""AI Security Advisor package providing remediation advice and interactive code snippets."""
from ai.advisor import (
    generate_advice,
    generate_fix_snippet,
    explain_security_concept,
    sanitize_report_for_ai,
)

__all__ = [
    "generate_advice",
    "generate_fix_snippet",
    "explain_security_concept",
    "sanitize_report_for_ai",
]
