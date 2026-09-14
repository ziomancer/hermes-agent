"""Regression for required private-boundary policy and staged registration.

Real temporary plugin modules go through the actual loader. No private account,
provider, gateway home or source-text assertion participates in these tests.
"""

import json
import sys

import pytest

from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from hermes_cli.private_boundary import (
    BoundaryRegistration,
    PrivateBoundaryError,
    PrivateToolRegistration,
    load_boundary_policy,
    resolve_boundary_registration,
)
from hermes_constants import reset_hermes_home_override, set_hermes_home_override
from tools.registry import registry


def policy(home, content):
    home.mkdir(exist_ok=True)
    (home / "config.yaml").write_text(content)
    return load_boundary_policy(home)


def load_plugin(manager, home, name, source):
    directory = home / "plugins" / name
    directory.mkdir(parents=True)
    (directory / "__init__.py").write_text(source)
    manifest = PluginManifest(name=name, key=name, source="user", path=str(directory))
    token = set_hermes_home_override(home)
    try:
        manager._load_plugin(manifest)
    finally:
        reset_hermes_home_override(token)
    return manager._plugins[name]


def test_absent_policy_is_optional_without_factory_call(tmp_path):
    called = []
    p = load_boundary_policy(tmp_path)
    r = BoundaryRegistration.create(
        home=tmp_path, name="synthetic", api_version=1, plugin="fixture",
        factory=lambda context: called.append(context),
    )
    assert resolve_boundary_registration(p, (r,)) is None
    assert called == []


@pytest.mark.parametrize("content", [
    "privacy_boundary: null",
    "privacy_boundary: []",
    "privacy_boundary: {required: 'true', adapter: synthetic}",
    "privacy_boundary: {required: 1, adapter: synthetic}",
    "privacy_boundary: {required: true}",
    "privacy_boundary: {adapter: synthetic}",
    "privacy_boundary: {required: true, adapter: synthetic, api_version: true}",
    "privacy_boundary: {required: true, adapter: synthetic, typo: false}",
    "privacy_boundary: {required: true, required: false, adapter: synthetic}",
    "privacy_boundary: {required: true, adapter: synthetic}\nprivacy_boundary: {required: false}",
    "base: &base {privacy_boundary: {required: true, adapter: synthetic}}\n<<: *base",
    "privacy_boundary: {required: true, adapter: [synthetic]}",
    "[not, a, config]",
    "privacy_boundary: [",
])
def test_malformed_policy_never_becomes_optional(tmp_path, content):
    with pytest.raises(PrivateBoundaryError, match="^PRIVATE_BOUNDARY_POLICY_INVALID$"):
        policy(tmp_path, content)


def test_policy_digest_is_semantic_and_captured_home_is_immutable(tmp_path, monkeypatch):
    first = tmp_path / "first"
    p = policy(first, "privacy_boundary: {required: true, adapter: synthetic}")
    q = policy(first, "privacy_boundary: {api_version: 1, adapter: synthetic, required: true}")
    assert p == q
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "different"))
    assert p.home == first.resolve()
    with pytest.raises(PrivateBoundaryError, match="UNAVAILABLE"):
        resolve_boundary_registration(p, ())


def test_config_io_failure_is_fixed_error(tmp_path):
    (tmp_path / "config.yaml").mkdir()
    with pytest.raises(PrivateBoundaryError, match="^PRIVATE_BOUNDARY_POLICY_INVALID$"):
        load_boundary_policy(tmp_path)


def test_failed_real_registration_does_not_commit_factory(tmp_path):
    manager = PluginManager()
    loaded = load_plugin(manager, tmp_path, "private_failure_fixture", '''
def register(ctx):
    ctx.register_private_boundary("synthetic", 1, lambda context: None)
    raise RuntimeError("synthetic registration failure")
''')
    assert loaded.error is not None
    assert manager.get_private_boundary_registrations(tmp_path) == ()


@pytest.mark.parametrize("failure", ["import", "register", "commit", "missing", "interrupt"])
def test_failed_private_load_discards_relative_modules(tmp_path, monkeypatch, failure):
    # Regression for N2O-10: failed executable registration must not survive a retry.
    directory = tmp_path / "plugins" / "synthetic"
    directory.mkdir(parents=True)
    (directory / "helpers.py").write_text("MARKER = 'failed'\n")
    prefix = "from .helpers import MARKER\n"
    registration = "    ctx.register_private_boundary('synthetic', 1, lambda context: MARKER)\n"
    source = prefix + "def register(ctx):\n" + registration
    if failure == "import":
        source = prefix + "raise RuntimeError('synthetic import failure')\n"
    elif failure == "register":
        source += "    raise RuntimeError('synthetic registration failure')\n"
    elif failure == "missing":
        source = prefix
    elif failure == "interrupt":
        source += "    raise KeyboardInterrupt()\n"
    (directory / "__init__.py").write_text(source)
    manifest = PluginManifest(name="synthetic", key="synthetic", source="user",
                              kind="private-boundary", path=str(directory))
    before = {name for name in sys.modules if name.startswith("hermes_private_plugins.")}
    token = set_hermes_home_override(tmp_path)
    try:
        manager = PluginManager(private_boundary_only=True)
        if failure == "interrupt":
            with pytest.raises(KeyboardInterrupt):
                manager._load_plugin(manifest)
        else:
            with monkeypatch.context() as patch:
                if failure == "commit":
                    def fail_commit(context):
                        raise RuntimeError("synthetic commit failure")
                    patch.setattr(PluginContext, "_commit_private_boundaries", fail_commit)
                manager._load_plugin(manifest)
            assert not manager._plugins["synthetic"].enabled
        assert {name for name in sys.modules if name.startswith("hermes_private_plugins.")} == before
        # A different size avoids Python's timestamp/size bytecode-cache ambiguity.
        (directory / "helpers.py").write_text("MARKER = 'repaired helper'\n")
        (directory / "__init__.py").write_text(prefix + "def register(ctx):\n" + registration)
        repaired = PluginManager(private_boundary_only=True)
        repaired._load_plugin(manifest)
        assert repaired.get_private_boundary_registrations(tmp_path)[0].factory(None) == "repaired helper"
    finally:
        reset_hermes_home_override(token)


def test_private_force_reload_keeps_prior_relative_helpers(tmp_path):
    # Regression for N2O-10: rediscovery cannot hot-edit a captured factory's imports.
    directory = tmp_path / "plugins" / "synthetic"
    directory.mkdir(parents=True)
    (tmp_path / "config.yaml").write_text("plugins: {enabled: [synthetic]}\n")
    (directory / "plugin.yaml").write_text("name: synthetic\nkind: private-boundary\n")
    (directory / "helpers.py").write_text("MARKER = 'original'\n")
    (directory / "__init__.py").write_text(
        "from . import helpers\n"
        "def factory(context):\n    from .helpers import MARKER\n    return MARKER\n"
        "def register(ctx):\n    ctx.register_private_boundary('synthetic', 1, factory)\n"
    )
    token = set_hermes_home_override(tmp_path)
    try:
        manager = PluginManager(private_boundary_only=True)
        manager.discover_and_load()
        original = manager.get_private_boundary_registrations(tmp_path)[0]
        (directory / "helpers.py").write_text("MARKER = 'replacement helper'\n")
        manager.discover_and_load(force=True)
        replacement = manager.get_private_boundary_registrations(tmp_path)[0]
        assert replacement.factory(None) == "replacement helper"
        assert original.factory(None) == "original"
    finally:
        reset_hermes_home_override(token)


def test_duplicate_factory_poisoning_cannot_select_first_registration(tmp_path):
    manager = PluginManager()
    source = '''
def register(ctx):
    ctx.register_private_boundary("synthetic", 1, lambda context: None)
'''
    assert load_plugin(manager, tmp_path, "private_first_fixture", source).enabled
    assert load_plugin(manager, tmp_path, "private_second_fixture", source).error
    with pytest.raises(PrivateBoundaryError, match="^PRIVATE_BOUNDARY_DUPLICATE$"):
        manager.get_private_boundary_registrations(tmp_path)


def test_real_loader_keeps_two_profile_catalogs_out_of_global_registry(tmp_path):
    manager = PluginManager()
    original = set(registry.get_all_tool_names())
    for label in ("alpha", "beta"):
        home = tmp_path / label
        source = f'''
from hermes_cli.private_boundary import PrivateToolRegistration
def forbidden_discovery_call(*args):
    raise AssertionError("factory/check must not run during discovery")
def register(ctx):
    tool = PrivateToolRegistration.create(
        name="private_fixture_{label}", toolset="fixture_private",
        schema={{"name":"private_fixture_{label}","description":"Synthetic fixture",
                "parameters":{{"type":"object","properties":{{}},"additionalProperties":False}}}},
        handler=lambda args: '{{"status":"ok"}}', check_fn=forbidden_discovery_call)
    ctx.register_private_boundary("synthetic", 1, forbidden_discovery_call, tools=(tool,))
'''
        assert load_plugin(manager, home, "private_" + label + "_fixture", source).enabled
    for label in ("alpha", "beta"):
        home = tmp_path / label
        regs = manager.get_private_boundary_registrations(home)
        assert len(regs) == 1
        assert [tool.name for tool in regs[0].tools] == ["private_fixture_" + label]
        p = policy(home, "privacy_boundary: {required: true, adapter: synthetic}")
        assert resolve_boundary_registration(p, regs) is regs[0]
        other = manager.get_private_boundary_registrations(tmp_path / ("beta" if label == "alpha" else "alpha"))
        with pytest.raises(PrivateBoundaryError, match="UNAVAILABLE"):
            resolve_boundary_registration(p, other)
    assert manager.get_private_boundary_registrations(tmp_path / "optional") == ()
    assert manager._plugin_tool_names == set()
    assert set(registry.get_all_tool_names()) == original


def test_private_schema_has_no_shared_mutable_dictionary():
    schema = {"name": "private_schema_fixture", "description": "Synthetic",
              "parameters": {"type": "object", "properties": {"token": {"type": "string"}}}}
    tool = PrivateToolRegistration.create(
        name=schema["name"], toolset="fixture_private", schema=schema,
        handler=lambda args: json.dumps(args), check_fn=lambda runtime: True,
    )
    before = tool.schema_json
    schema["parameters"]["properties"]["token"]["type"] = "integer"
    tool.definition()["function"]["description"] = "changed"
    assert tool.schema_json == before
    assert tool.definition()["function"]["parameters"]["properties"]["token"]["type"] == "string"


@pytest.mark.parametrize("parameters", [
    {"type": "object", "required": 123},
    {"type": "object", "properties": []},
    {"type": "object", "properties": {"token": {"type": "not-a-type"}}},
])
def test_malformed_private_schema_refuses(parameters):
    with pytest.raises(PrivateBoundaryError, match="^PRIVATE_BOUNDARY_REGISTRATION_INVALID$"):
        PrivateToolRegistration.create(
            name="private_invalid_fixture", toolset="fixture_private",
            schema={"name": "private_invalid_fixture", "description": "Synthetic", "parameters": parameters},
            handler=lambda args: "{}", check_fn=lambda runtime: True,
        )
