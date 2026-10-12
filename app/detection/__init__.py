"""Deterministic authentication detection rules."""

from .rules import (
    RuleMatch,
    evaluate_feature_batch,
    evaluate_r001,
    evaluate_r002,
    evaluate_rules,
)

__all__ = [
    "RuleMatch",
    "evaluate_r001",
    "evaluate_r002",
    "evaluate_rules",
    "evaluate_feature_batch",
]
