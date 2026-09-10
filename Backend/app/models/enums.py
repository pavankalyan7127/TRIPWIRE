"""Tripwire enums matching the contract specification."""

from enum import Enum


class Decision(str, Enum):
    """Security decision for an action proposal.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §8
    """
    ALLOW = "ALLOW"
    CONFIRM = "CONFIRM"
    HARD_CONFIRM = "HARD_CONFIRM"
    BLOCK = "BLOCK"


class RiskBand(str, Enum):
    """Trajectory risk band classification.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §8

    LOW: trajectory_score < 0.35
    MEDIUM: 0.35 <= trajectory_score <= 0.65
    HIGH: trajectory_score > 0.65
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ActionClass(str, Enum):
    """Action reversibility classification.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §8
    Also known as Reversibility in some contract sections.

    Operational levels for trajectory calculations (per authorization):
    READ = 0.0
    WRITE = 0.5
    DESTRUCTIVE = 1.0
    """
    READ = "READ"
    WRITE = "WRITE"
    DESTRUCTIVE = "DESTRUCTIVE"
