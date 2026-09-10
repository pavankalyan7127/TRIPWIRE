"""Unit tests for Tripwire domain enums."""

import pytest

from app.models.enums import ActionClass, Decision, RiskBand


class TestDecisionEnum:
    """Tests for the Decision enum."""

    def test_all_valid_decision_values(self):
        """All four contract decisions must be defined."""
        assert Decision.ALLOW == "ALLOW"
        assert Decision.CONFIRM == "CONFIRM"
        assert Decision.HARD_CONFIRM == "HARD_CONFIRM"
        assert Decision.BLOCK == "BLOCK"
        assert len(Decision) == 4

    def test_decision_string_serialization(self):
        """Decision enum members must serialize to exact contract strings."""
        assert str(Decision.ALLOW) == "Decision.ALLOW"
        assert Decision.ALLOW.value == "ALLOW"
        assert Decision.CONFIRM.value == "CONFIRM"
        assert Decision.HARD_CONFIRM.value == "HARD_CONFIRM"
        assert Decision.BLOCK.value == "BLOCK"

    def test_decision_instantiation_from_valid_string(self):
        """Decision can be created from valid contract strings."""
        assert Decision("ALLOW") is Decision.ALLOW
        assert Decision("CONFIRM") is Decision.CONFIRM
        assert Decision("HARD_CONFIRM") is Decision.HARD_CONFIRM
        assert Decision("BLOCK") is Decision.BLOCK

    def test_invalid_decision_values_rejected(self):
        """Non-contract decision strings must raise ValueError."""
        invalid_values = [
            "APPROVE",
            "DENY",
            "REJECT",
            "REQUIRE_CONFIRMATION",
            "allow",
            "block",
            "PENDING",
            "",
            "1",
        ]
        for invalid in invalid_values:
            with pytest.raises(ValueError):
                Decision(invalid)


class TestRiskBandEnum:
    """Tests for the RiskBand enum."""

    def test_all_valid_risk_band_values(self):
        """All three contract risk bands must be defined."""
        assert RiskBand.LOW == "LOW"
        assert RiskBand.MEDIUM == "MEDIUM"
        assert RiskBand.HIGH == "HIGH"
        assert len(RiskBand) == 3

    def test_risk_band_string_serialization(self):
        """RiskBand enum members must serialize to exact contract strings."""
        assert RiskBand.LOW.value == "LOW"
        assert RiskBand.MEDIUM.value == "MEDIUM"
        assert RiskBand.HIGH.value == "HIGH"

    def test_risk_band_instantiation_from_valid_string(self):
        """RiskBand can be created from valid contract strings."""
        assert RiskBand("LOW") is RiskBand.LOW
        assert RiskBand("MEDIUM") is RiskBand.MEDIUM
        assert RiskBand("HIGH") is RiskBand.HIGH

    def test_invalid_risk_band_values_rejected(self):
        """Non-contract risk band strings must raise ValueError."""
        invalid_values = [
            "CRITICAL",
            "VERY_HIGH",
            "NONE",
            "low",
            "medium",
            "high",
            "SAFE",
            "",
            "0",
        ]
        for invalid in invalid_values:
            with pytest.raises(ValueError):
                RiskBand(invalid)


class TestActionClassEnum:
    """Tests for the ActionClass enum."""

    def test_all_valid_action_class_values(self):
        """All three contract action classes must be defined."""
        assert ActionClass.READ == "READ"
        assert ActionClass.WRITE == "WRITE"
        assert ActionClass.DESTRUCTIVE == "DESTRUCTIVE"
        assert len(ActionClass) == 3

    def test_action_class_string_serialization(self):
        """ActionClass enum members must serialize to exact contract strings."""
        assert ActionClass.READ.value == "READ"
        assert ActionClass.WRITE.value == "WRITE"
        assert ActionClass.DESTRUCTIVE.value == "DESTRUCTIVE"

    def test_action_class_instantiation_from_valid_string(self):
        """ActionClass can be created from valid contract strings."""
        assert ActionClass("READ") is ActionClass.READ
        assert ActionClass("WRITE") is ActionClass.WRITE
        assert ActionClass("DESTRUCTIVE") is ActionClass.DESTRUCTIVE

    def test_invalid_action_class_values_rejected(self):
        """Non-contract action class strings must raise ValueError."""
        invalid_values = [
            "EXECUTE",
            "ADMIN",
            "DELETE",
            "read",
            "write",
            "destructive",
            "MUTATING",
            "",
        ]
        for invalid in invalid_values:
            with pytest.raises(ValueError):
                ActionClass(invalid)
