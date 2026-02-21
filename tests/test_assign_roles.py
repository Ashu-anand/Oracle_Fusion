"""Tests for assign_roles.py"""

import json
from unittest.mock import MagicMock, mock_open, patch

import pytest
import yaml

from assign_roles import Config, OracleFusionAccessManager


# ---- Fixtures (reusable test data) ----

@pytest.fixture
def sample_config():
    """Fake Oracle Fusion config data."""
    return {
        "oracle_fusion": {
            "instance_code": "ecxh",
            "instance_name": "test",
            "username": "testuser",
            "password": "testpass",
        }
    }


@pytest.fixture
def manager(sample_config):
    """Create OracleFusionAccessManager with mocked config file."""
    config_yaml = yaml.dump(sample_config)
    with patch("builtins.open", mock_open(read_data=config_yaml)):
        return OracleFusionAccessManager(
            config_path="fake/config.yaml",
            file_name="fake/data.csv",
            allow_interactive=False,
        )


# ---- Config Loading Tests ----

class TestLoadConfig:
    """Tests for configuration loading."""

    def test_loads_config_from_yaml(self, manager):
        assert manager.username == "testuser"
        assert manager.password == "testpass"
        assert manager.instance_code == "ecxh"
        assert manager.instance_name == "test"

    def test_raises_error_when_config_missing(self):
        with pytest.raises(FileNotFoundError):
            OracleFusionAccessManager(
                config_path="nonexistent/config.yaml",
                file_name="fake.csv",
                allow_interactive=False,
            )

    def test_builds_correct_base_url(self, manager):
        assert manager.base_url == "https://ecxh-test-saasfaprod1.fa.ocs.oraclecloud.com"


# ---- user_has_access Tests ----

class TestUserHasAccess:
    """Tests for user_has_access method."""

    def test_returns_true_when_access_exists(self, manager):
        data = {
            "user1": {
                "Manager Role": {
                    "Business Unit": ["USA"]
                }
            }
        }
        assert manager.user_has_access(data, "user1", "Manager Role", "Business Unit", "USA") is True

    def test_returns_false_when_user_missing(self, manager):
        data = {}
        assert manager.user_has_access(data, "user1", "Manager Role", "Business Unit", "USA") is False

    def test_returns_false_when_role_missing(self, manager):
        data = {"user1": {}}
        assert manager.user_has_access(data, "user1", "Manager Role", "Business Unit", "USA") is False

    def test_returns_false_when_context_missing(self, manager):
        data = {"user1": {"Manager Role": {}}}
        assert manager.user_has_access(data, "user1", "Manager Role", "Business Unit", "USA") is False

    def test_returns_false_when_value_missing(self, manager):
        data = {"user1": {"Manager Role": {"Business Unit": ["Canada"]}}}
        assert manager.user_has_access(data, "user1", "Manager Role", "Business Unit", "USA") is False


# ---- API Payload Tests ----

class TestCreateApiPayload:
    """Tests for create_api_payload method."""

    def test_creates_correct_payload_structure(self, manager):
        reader = [("user1", "Business Unit", "Manager", "USA")]
        payload = manager.create_api_payload(reader)

        assert "parts" in payload
        assert len(payload["parts"]) == 1
        assert payload["parts"][0]["operation"] == "create"
        assert payload["parts"][0]["path"] == "/dataSecurities"

    def test_payload_contains_correct_user_data(self, manager):
        reader = [("user1", "Business Unit", "Manager", "USA")]
        payload = manager.create_api_payload(reader)
        part = payload["parts"][0]["payload"]

        assert part["UserName"] == "user1"
        assert part["SecurityContext"] == "Business Unit"
        assert part["RoleNameCr"] == "Manager"
        assert part["SecurityContextValue"] == "USA"

    def test_handles_multiple_records(self, manager):
        reader = [
            ("user1", "Business Unit", "Manager", "USA"),
            ("user2", "Ledger", "Accountant", "US Ledger"),
        ]
        payload = manager.create_api_payload(reader)
        assert len(payload["parts"]) == 2
        assert payload["parts"][0]["id"] == "part1"
        assert payload["parts"][1]["id"] == "part2"