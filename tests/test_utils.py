"""Tests for common/utils.py"""

import base64
from collections import defaultdict

from common.utils import convert_dict, generate_basic_auth_token


class TestGenerateBasicAuthToken:
    """Tests for generate_basic_auth_token function."""

    def test_returns_valid_basic_auth_format(self):
        token = generate_basic_auth_token("admin", "secret123")
        assert token.startswith("Basic ")

    def test_token_decodes_to_correct_credentials(self):
        token = generate_basic_auth_token("admin", "secret123")
        encoded_part = token.replace("Basic ", "")
        decoded = base64.b64decode(encoded_part).decode()
        assert decoded == "admin:secret123"

    def test_handles_special_characters_in_password(self):
        token = generate_basic_auth_token("user", "p@ss!word#123")
        encoded_part = token.replace("Basic ", "")
        decoded = base64.b64decode(encoded_part).decode()
        assert decoded == "user:p@ss!word#123"

    def test_handles_empty_credentials(self):
        token = generate_basic_auth_token("", "")
        encoded_part = token.replace("Basic ", "")
        decoded = base64.b64decode(encoded_part).decode()
        assert decoded == ":"


class TestConvertDict:
    """Tests for convert_dict function."""

    def test_converts_simple_defaultdict(self):
        dd = defaultdict(list)
        dd["key"] = ["value1", "value2"]
        result = convert_dict(dd)
        assert isinstance(result, dict)
        assert not isinstance(result, defaultdict)
        assert result == {"key": ["value1", "value2"]}

    def test_converts_nested_defaultdict(self):
        dd = defaultdict(lambda: defaultdict(list))
        dd["user1"]["role1"] = ["value1"]
        result = convert_dict(dd)
        assert isinstance(result, dict)
        assert isinstance(result["user1"], dict)
        assert not isinstance(result["user1"], defaultdict)

    def test_returns_regular_dict_unchanged(self):
        regular = {"key": "value"}
        result = convert_dict(regular)
        assert result == {"key": "value"}

    def test_handles_empty_defaultdict(self):
        dd = defaultdict(list)
        result = convert_dict(dd)
        assert result == {}

    def test_preserves_deeply_nested_values(self):
        dd = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        dd["user"]["role"]["context"].append("USA")
        result = convert_dict(dd)
        assert result["user"]["role"]["context"] == ["USA"]