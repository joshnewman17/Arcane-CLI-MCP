import pytest

from arcane_mcp.config import ConfigError, load_settings


def test_defaults():
    s = load_settings({"ARCANE_URL": "https://arcane.lan", "ARCANE_API_KEY": "k" * 10})
    assert (s.default_env, s.host, s.port, s.readonly) == ("0", "0.0.0.0", 8080, False)
    assert (s.max_output_chars, s.default_timeout_s, s.long_timeout_s) == (40000, 120, 1800)
    assert s.auth_token is None


@pytest.mark.parametrize(
    "env,msg",
    [
        ({}, "ARCANE_URL"),
        ({"ARCANE_URL": "arcane.lan", "ARCANE_API_KEY": "k"}, "http"),
        ({"ARCANE_URL": "http://a"}, "ARCANE_API_KEY"),
        ({"ARCANE_URL": "http://a", "ARCANE_API_KEY": "k", "MCP_PORT": "abc"}, "integer"),
        ({"ARCANE_URL": "http://a", "ARCANE_API_KEY": "k", "LONG_TIMEOUT_S": "0"}, "positive"),
    ],
)
def test_invalid(env, msg):
    with pytest.raises(ConfigError, match=msg):
        load_settings(env)


@pytest.mark.parametrize("value,expected", [("true", True), ("1", True), ("TRUE", True), ("false", False), ("", False)])
def test_readonly_parsing(value, expected):
    s = load_settings({"ARCANE_URL": "http://a", "ARCANE_API_KEY": "k", "ARCANE_MCP_READONLY": value})
    assert s.readonly is expected


def test_api_key_file(tmp_path):
    f = tmp_path / "key"
    f.write_text("arc_from_file\n")
    s = load_settings({"ARCANE_URL": "http://a", "ARCANE_API_KEY_FILE": str(f)})
    assert s.arcane_api_key == "arc_from_file"
