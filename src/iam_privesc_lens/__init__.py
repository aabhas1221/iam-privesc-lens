"""iam-privesc-lens: offline AWS IAM privilege-escalation analysis."""

from .analyzer import Analyzer, EscalationPath, Finding, Report, analyze
from .model import Account, Principal, load_data, load_file
from .policy import Decision, PolicySet, parse_policy_document
from .techniques import TECHNIQUES, Severity, Technique

__version__ = "0.1.0"

__all__ = [
    "Account",
    "Analyzer",
    "Decision",
    "EscalationPath",
    "Finding",
    "PolicySet",
    "Principal",
    "Report",
    "Severity",
    "TECHNIQUES",
    "Technique",
    "__version__",
    "analyze",
    "load_data",
    "load_file",
    "parse_policy_document",
]
