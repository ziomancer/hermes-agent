"""C1: required homes cannot send through the legacy WhatsApp bridge."""

import asyncio
import json
import logging
import os
import subprocess
import sys
import threading
import time
import types
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.request import Request, urlopen

import pytest

from gateway.config import Platform, PlatformConfig
from hermes_cli import send_cmd
from hermes_cli.private_boundary import (
    LEGACY_WHATSAPP_SEND_REFUSAL, PrivateBoundaryError, load_boundary_policy,
)
from plugins.platforms.whatsapp.adapter import _standalone_send
from tools import send_message_tool as send_module


@contextmanager
def listening_bridge():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append((self.path, json.loads(body)))
            reply = b'{"success":true,"messageId":"synthetic-1"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], requests
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def policy_home(home, mode):
    if mode == "true":
        (home / "config.yaml").write_text("privacy_boundary: {required: true, adapter: synthetic}\n")
    elif mode == "false":
        (home / "config.yaml").write_text("privacy_boundary: {required: false}\n")
    elif mode == "malformed":
        (home / "config.yaml").write_text(
            "privacy_boundary: {required: true, required: false, adapter: synthetic}\n"
        )


def mkfifo_or_skip(path):
    maker = getattr(os, "mkfifo", None)
    if maker is None:
        pytest.skip("os.mkfifo is unavailable")
    try:
        maker(path)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"os.mkfifo is unavailable: {type(exc).__name__}")


def symlink_or_skip(path, target):
    try:
        path.symlink_to(target)
    except (AttributeError, OSError, NotImplementedError) as exc:
        pytest.skip(f"Path.symlink_to is unavailable: {type(exc).__name__}")


def fifo_case_runs_in_child(request, tmp_path):
    """Bound a FIFO regression with a process that can be killed on any OS."""
    probe = tmp_path / "fifo-capability-probe"
    mkfifo_or_skip(probe)
    probe.unlink()
    if os.environ.get("HERMES_FIFO_TEST_CHILD") == "1":
        return True

    project_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["HERMES_FIFO_TEST_CHILD"] = "1"
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", request.node.nodeid],
        cwd=project_root, env=env, capture_output=True, text=True, timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "1 passed" in completed.stdout, completed.stdout + completed.stderr
    return False


@pytest.mark.parametrize("mode", ["absent", "false", "true", "symlink", "fifo", "oversize"])
def test_policy_without_optional_open_flags_keeps_gateway_and_refusal_contract(
    tmp_path, monkeypatch, request, mode,
):
    """The Windows flag shape still loads ordinary homes and refuses unsafe ones."""
    if mode == "fifo" and not fifo_case_runs_in_child(request, tmp_path):
        return
    home = tmp_path / "home"
    home.mkdir()
    config = home / "config.yaml"
    if mode == "symlink":
        target = tmp_path / "synthetic-config.yaml"
        target.write_text("privacy_boundary: {required: false}\n")
        symlink_or_skip(config, target)
    elif mode == "fifo":
        mkfifo_or_skip(config)
    elif mode == "oversize":
        config.write_bytes(b"privacy_boundary: {required: false}\n#" + b"x" * (1024 * 1024))
    else:
        policy_home(home, mode)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(os, "O_NONBLOCK", raising=False)

    if mode in {"absent", "false"}:
        assert load_boundary_policy(home).required is False
        from gateway.run import GatewayRunner
        from gateway.config import GatewayConfig

        runner = GatewayRunner(config=GatewayConfig())
        assert runner._private_boundary_home == home
    elif mode == "true":
        assert load_boundary_policy(home).required is True
    else:
        with pytest.raises(PrivateBoundaryError, match="POLICY_INVALID"):
            load_boundary_policy(home)
    if mode not in {"absent", "false"}:
        from hermes_cli.private_boundary import legacy_whatsapp_send_refused

        assert legacy_whatsapp_send_refused()


@pytest.mark.parametrize("mode", ["fifo", "symlink", "true", "absent"])
def test_real_cli_send_refuses_unsafe_and_required_before_bootstrap_reads(tmp_path, request, mode):
    """Launch the installed interpreter through the real CLI import and dispatcher."""
    if mode == "fifo" and not fifo_case_runs_in_child(request, tmp_path):
        return
    home = tmp_path / "home"
    home.mkdir()
    config = home / "config.yaml"
    with listening_bridge() as (port, requests):
        yaml_text = (
            "platforms:\n  whatsapp:\n    enabled: true\n"
            f"    extra:\n      bridge_port: {port}\n"
        )
        if mode == "fifo":
            mkfifo_or_skip(config)
        elif mode == "symlink":
            target = tmp_path / "synthetic-config.yaml"
            target.write_text("privacy_boundary: {required: false}\n" + yaml_text)
            symlink_or_skip(config, target)
        elif mode == "true":
            config.write_text("privacy_boundary: {required: true, adapter: synthetic}\n" + yaml_text)
        else:
            config.write_text(yaml_text)

        env = os.environ.copy()
        env["HERMES_HOME"] = str(home)
        env["HOME"] = str(tmp_path)
        project_root = Path(__file__).resolve().parents[2]
        env["PYTHONPATH"] = os.pathsep.join(
            part for part in (str(project_root), env.get("PYTHONPATH")) if part
        )
        started = time.monotonic()
        completed = subprocess.run(
            [sys.executable, "-m", "hermes_cli.main", "send", "--to",
             "whatsapp:12345@g.us", "synthetic text", "--json"],
            cwd=project_root, env=env, capture_output=True, text=True, timeout=12,
        )
        assert time.monotonic() - started < 12
        payload = json.loads(completed.stdout)
        if mode == "absent":
            assert completed.returncode == 0, completed.stderr
            assert payload["success"] is True
            assert len(requests) == 1
        else:
            assert completed.returncode == 1, completed.stderr
            assert payload == {"error": LEGACY_WHATSAPP_SEND_REFUSAL}
            assert requests == []


def test_early_interface_config_reader_keeps_regular_config(tmp_path, monkeypatch):
    regular_home = tmp_path / "regular"
    regular_home.mkdir()
    (regular_home / "config.yaml").write_text("display: {interface: tui}\n")
    monkeypatch.setenv("HERMES_HOME", str(regular_home))
    from hermes_cli import main

    main._EARLY_INTERFACE_CACHE = None
    assert main._config_default_interface_early() == "tui"


def test_early_interface_config_reader_skips_fifo(tmp_path, monkeypatch, request):
    if not fifo_case_runs_in_child(request, tmp_path):
        return
    fifo_home = tmp_path / "fifo"
    fifo_home.mkdir()
    mkfifo_or_skip(fifo_home / "config.yaml")
    monkeypatch.setenv("HERMES_HOME", str(fifo_home))
    from hermes_cli import main

    main._EARLY_INTERFACE_CACHE = None
    assert main._config_default_interface_early() == "cli"


def test_missing_fifo_and_alarm_apis_skip_fifo_cases_but_run_portable_cases():
    project_root = Path(__file__).resolve().parents[2]
    test_file = Path(__file__).relative_to(project_root)
    fifo_nodes = [
        "test_policy_without_optional_open_flags_keeps_gateway_and_refusal_contract[fifo]",
        "test_real_cli_send_refuses_unsafe_and_required_before_bootstrap_reads[fifo]",
        "test_early_interface_config_reader_skips_fifo",
        *(f"test_unsafe_policy_refuses_at_each_send_entry[fifo-{entry}]"
          for entry in ("cli", "tool", "dispatch", "standalone")),
    ]
    portable_node = "test_unsafe_policy_refuses_at_each_send_entry[nested-cli]"
    script = (
        "import os, signal, sys, pytest\n"
        "with pytest.MonkeyPatch.context() as patch:\n"
        "    patch.delattr(os, 'mkfifo', raising=False)\n"
        "    patch.delattr(signal, 'SIGALRM', raising=False)\n"
        "    patch.delattr(signal, 'setitimer', raising=False)\n"
        "    raise SystemExit(pytest.main(['-q', '-rs', *sys.argv[1:]]))\n"
    )
    nodes = [f"{test_file}::{name}" for name in (*fifo_nodes, portable_node)]
    completed = subprocess.run(
        [sys.executable, "-c", script, *nodes], cwd=project_root,
        capture_output=True, text=True, timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "7 skipped" in completed.stdout
    assert "1 passed" in completed.stdout
    assert "os.mkfifo is unavailable" in completed.stdout


@pytest.mark.parametrize("entry", ["cli", "tool", "dispatch", "standalone"])
@pytest.mark.parametrize("unsafe", [
    "symlink", "dangling", "fifo", "oversize", "unreadable", "nested", "nested_required",
])
def test_unsafe_policy_refuses_at_each_send_entry(
    tmp_path, monkeypatch, capsys, request, entry, unsafe,
):
    if unsafe == "fifo" and not fifo_case_runs_in_child(request, tmp_path):
        return
    home = tmp_path / "home"
    home.mkdir()
    config = home / "config.yaml"
    if unsafe in {"symlink", "dangling"}:
        outside = tmp_path / "synthetic-outside.yaml"
        if unsafe == "symlink":
            outside.write_text("privacy_boundary: {required: false}\n")
        symlink_or_skip(config, outside)
    elif unsafe == "fifo":
        mkfifo_or_skip(config)
    elif unsafe == "oversize":
        config.write_bytes(b"privacy_boundary: {required: false}\n#" + b"x" * (1024 * 1024))
    elif unsafe == "unreadable":
        config.write_text("privacy_boundary: {required: false}\n")
        config.chmod(0)
        request.addfinalizer(lambda: config.chmod(0o600))
        if config.lstat().st_mode & 0o444:
            original_lstat = Path.lstat

            def unreadable_lstat(path, *args, **kwargs):
                entry = original_lstat(path, *args, **kwargs)
                if path == config:
                    return SimpleNamespace(
                        st_mode=entry.st_mode & ~0o444, st_size=entry.st_size,
                        st_dev=entry.st_dev, st_ino=entry.st_ino,
                    )
                return entry

            monkeypatch.setattr(Path, "lstat", unreadable_lstat)
        # Model a privileged process, where a plain read_text() would still
        # consume a mode-000 file. The safe reader must reject its mode first.
        original_read_text = type(config).read_text

        def privileged_read_text(path, *args, **kwargs):
            if path != config:
                return original_read_text(path, *args, **kwargs)
            config.chmod(0o400)
            try:
                return original_read_text(path, *args, **kwargs)
            finally:
                config.chmod(0)

        monkeypatch.setattr(type(config), "read_text", privileged_read_text)
    else:
        prefix = "privacy_boundary: {required: true, adapter: synthetic}\n" if unsafe == "nested_required" else ""
        config.write_text(prefix + "extra:\n" + "".join("  " * depth + "-\n" for depth in range(600)))
    monkeypatch.setenv("HERMES_HOME", str(home))

    # Symlink targets must never be opened. For the other cases, no downstream
    # body, config bridge, or transport may execute before the fixed refusal.
    actual_open = os.open
    opens = []

    def tracked_open(path, *args, **kwargs):
        opens.append(os.fspath(path))
        return actual_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(send_cmd, "_load_hermes_env", lambda: pytest.fail("config bridge ran"))
    monkeypatch.setattr(send_cmd, "_read_message_body", lambda *_: pytest.fail("body read"))
    monkeypatch.setattr("aiohttp.ClientSession", lambda *_a, **_k: pytest.fail("transport opened"))

    if entry == "cli":
        import argparse

        parser = argparse.ArgumentParser()
        send_cmd.register_send_subparser(parser.add_subparsers(dest="command"))
        args = parser.parse_args(["send", "--to", "whatsapp:synthetic", "synthetic"])
        with pytest.raises(SystemExit) as exited:
            send_cmd.cmd_send(args)
        assert exited.value.code == 1
        assert LEGACY_WHATSAPP_SEND_REFUSAL in capsys.readouterr().err
    elif entry == "tool":
        result = json.loads(send_module.send_message_tool({
            "action": "send", "target": "whatsapp:synthetic", "message": "synthetic",
        }))
        assert result == {"error": LEGACY_WHATSAPP_SEND_REFUSAL}
    elif entry == "dispatch":
        result = asyncio.run(send_module._send_to_platform(
            Platform.WHATSAPP, PlatformConfig(enabled=True), "synthetic", "synthetic",
        ))
        assert result == {"error": LEGACY_WHATSAPP_SEND_REFUSAL}
    else:
        result = asyncio.run(_standalone_send(
            PlatformConfig(enabled=True), "synthetic", "synthetic",
        ))
        assert result == {"error": LEGACY_WHATSAPP_SEND_REFUSAL}

    if unsafe in {"symlink", "dangling"}:
        assert os.fspath(config) not in opens
        assert os.fspath(outside) not in opens


@pytest.mark.parametrize("target", [None, False])
def test_missing_target_keeps_base_validation(tmp_path, monkeypatch, target):
    policy_home(tmp_path, "true")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    assert json.loads(send_module.send_message_tool({
        "action": "send", "target": target, "message": "synthetic",
    })) == {"error": "Both 'target' and 'message' are required when action='send'"}


def post_to_bridge(port, path="/send"):
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=b'{"message":"synthetic"}',
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=2) as response:
        assert response.status == 200


@pytest.mark.parametrize("mode", ["absent", "false", "true", "malformed"])
@pytest.mark.parametrize("kind", ["text", "media"])
def test_each_guard_refuses_alone(tmp_path, monkeypatch, capsys, caplog, mode, kind):
    policy_home(tmp_path, mode)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    blocked = mode in {"true", "malformed"}
    caplog.set_level(logging.WARNING)
    media = tmp_path / "synthetic.png"
    media.write_bytes(b"synthetic")

    with listening_bridge() as (port, requests):
        # cmd_send: a permissive replacement for the entire downstream tool
        # makes a reverted CLI guard observable even while other guards exist.
        downstream_calls = []
        fake_module = types.ModuleType("tools.send_message_tool")

        def permissive_tool(_args):
            downstream_calls.append(1)
            post_to_bridge(port)
            return json.dumps({"success": True})

        fake_module.send_message_tool = permissive_tool
        monkeypatch.setitem(sys.modules, "tools.send_message_tool", fake_module)
        body = tmp_path / "body.txt"
        body.write_text(f"caption MEDIA:{media}" if kind == "media" else "synthetic text")
        read_calls = []
        original_read = send_cmd._read_message_body

        def read_body(*args):
            read_calls.append(1)
            return original_read(*args)

        monkeypatch.setattr(send_cmd, "_read_message_body", read_body)
        parser_args = send_cmd.register_send_subparser
        import argparse

        parser = argparse.ArgumentParser()
        parser_args(parser.add_subparsers(dest="command"))
        args = parser.parse_args(["send", "--to", "whatsapp:12345@g.us", "--file", str(body)])
        with pytest.raises(SystemExit) as exit_result:
            send_cmd.cmd_send(args)
        assert exit_result.value.code == (1 if blocked else 0)
        assert len(read_calls) == (0 if blocked else 1)
        assert len(downstream_calls) == (0 if blocked else 1)
        assert len(requests) == (0 if blocked else 1)
        if blocked:
            assert LEGACY_WHATSAPP_SEND_REFUSAL in capsys.readouterr().err
            assert "synthetic.png" not in caplog.text

        # _handle_send: target resolution and media parsing are permissive
        # counting doubles, so its own early guard is the only protection.
        requests.clear()
        entry_counts = {name: 0 for name in ("parse", "resolve", "extract", "filter")}

        def parse(*_args):
            entry_counts["parse"] += 1
            return "12345@g.us", None, False

        def resolve(*_args):
            entry_counts["resolve"] += 1
            return "12345@g.us"

        def extract(_message):
            entry_counts["extract"] += 1
            return [], "synthetic"

        def filter_paths(paths):
            entry_counts["filter"] += 1
            return paths

        config = SimpleNamespace(
            platforms={Platform.WHATSAPP: PlatformConfig(enabled=True)},
            get_home_channel=lambda _platform: None,
        )
        monkeypatch.setattr(send_module, "_parse_target_ref", parse)
        monkeypatch.setattr("gateway.channel_directory.resolve_channel_name", resolve)
        monkeypatch.setattr("gateway.config.load_gateway_config", lambda: config)
        monkeypatch.setattr("gateway.platforms.base.BasePlatformAdapter.extract_media", extract)
        monkeypatch.setattr("gateway.platforms.base.BasePlatformAdapter.filter_media_delivery_paths", filter_paths)
        monkeypatch.setattr("model_tools._run_async", lambda coro: asyncio.run(coro))

        async def permissive_dispatch(*_args, **_kwargs):
            post_to_bridge(port)
            return {"success": True}

        monkeypatch.setattr(send_module, "_send_to_platform", permissive_dispatch)
        result = json.loads(send_module.send_message_tool({
            "action": "send",
            "target": "whatsapp:unresolved-synthetic-marker",
            "message": f"caption MEDIA:{media}",
        }))
        assert len(requests) == (0 if blocked else 1)
        assert entry_counts == (
            {"parse": 0, "resolve": 0, "extract": 0, "filter": 0}
            if blocked else
            {"parse": 2, "resolve": 1, "extract": 1, "filter": 1}
        )
        if blocked:
            assert result == {"error": LEGACY_WHATSAPP_SEND_REFUSAL}
            assert "unresolved-synthetic-marker" not in json.dumps(result) + caplog.text
            assert "synthetic.png" not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("mode", ["absent", "false", "true", "malformed"])
@pytest.mark.parametrize("kind", ["text", "media"])
def test_platform_and_standalone_guards(tmp_path, monkeypatch, mode, kind):
    policy_home(tmp_path, mode)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    blocked = mode in {"true", "malformed"}
    media = tmp_path / "synthetic.png"
    media.write_bytes(b"synthetic")
    pconfig = PlatformConfig(enabled=True)

    with listening_bridge() as (port, requests):
        # This sender deliberately bypasses _standalone_send. The platform
        # dispatch guard must stop it before either text or media route.
        async def permissive_sender(*_args, **_kwargs):
            post_to_bridge(port, "/send-media" if kind == "media" else "/send")
            return {"success": True}

        monkeypatch.setattr(send_module, "_registry_standalone_send", permissive_sender)
        monkeypatch.setattr("hermes_cli.plugins.discover_plugins", lambda: None)
        monkeypatch.setattr(
            "gateway.platform_registry.platform_registry.get",
            lambda _name: SimpleNamespace(standalone_sender_fn=permissive_sender),
        )
        result = asyncio.run(send_module._send_to_platform(
            Platform.WHATSAPP, pconfig, "12345@g.us", "caption" if kind == "media" else "text",
            media_files=[(str(media), False)] if kind == "media" else None,
        ))
        assert len(requests) == (0 if blocked else 1)
        if blocked:
            assert result == {"error": LEGACY_WHATSAPP_SEND_REFUSAL}

        # Direct plugin call uses its real aiohttp path and listener.
        requests.clear()
        pconfig.extra = {"bridge_port": port}
        result = asyncio.run(_standalone_send(
            pconfig, "12345@g.us", "caption" if kind == "media" else "text",
            media_files=[(str(media), False)] if kind == "media" else None,
            caption="caption" if kind == "media" else None,
        ))
        assert len(requests) == (0 if blocked else 1)
        if blocked:
            assert result == {"error": LEGACY_WHATSAPP_SEND_REFUSAL}
        else:
            assert result["success"] is True
            assert requests[0][0] == ("/send-media" if kind == "media" else "/send")


@pytest.mark.parametrize("mode", ["absent", "false", "true"])
def test_increment_zero_send_state(tmp_path, monkeypatch, mode):
    """CLI, tool fallback and direct adapter use real config and imports."""
    policy_home(tmp_path, mode)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    with listening_bridge() as (port, requests):
        with (tmp_path / "config.yaml").open("a") as config_file:
            config_file.write(
                f"platforms:\n  whatsapp:\n    enabled: true\n"
                f"    extra:\n      bridge_port: {port}\n"
            )
        import argparse

        parser = argparse.ArgumentParser()
        send_cmd.register_send_subparser(parser.add_subparsers(dest="command"))
        args = parser.parse_args(["send", "--to", "whatsapp:12345@g.us", "synthetic text"])
        with pytest.raises(SystemExit) as exit_result:
            send_cmd.cmd_send(args)
        assert exit_result.value.code == (1 if mode == "true" else 0)
        assert len(requests) == (0 if mode == "true" else 1)

        requests.clear()
        result = json.loads(send_module.send_message_tool({
            "action": "send", "target": "whatsapp:12345@g.us", "message": "synthetic text",
        }))
        if mode == "true":
            assert result == {"error": LEGACY_WHATSAPP_SEND_REFUSAL}
        else:
            assert result["success"] is True
        assert len(requests) == (0 if mode == "true" else 1)

        requests.clear()
        result = asyncio.run(_standalone_send(
            PlatformConfig(enabled=True, extra={"bridge_port": port}),
            "12345@g.us", "synthetic text",
        ))
        if mode == "true":
            assert result == {"error": LEGACY_WHATSAPP_SEND_REFUSAL}
        else:
            assert result["success"] is True
        assert len(requests) == (0 if mode == "true" else 1)


def test_policy_is_scoped_to_active_home_and_telegram_is_unaffected(tmp_path, monkeypatch):
    required = tmp_path / "required"
    alert = tmp_path / "alert"
    required.mkdir()
    alert.mkdir()
    policy_home(required, "true")
    policy_home(alert, "false")
    monkeypatch.setenv("HERMES_HOME", str(required))

    with listening_bridge() as (port, requests):
        downstream = []
        fake_module = types.ModuleType("tools.send_message_tool")

        def permissive_tool(args):
            downstream.append(args["target"])
            if args["target"].startswith("whatsapp"):
                post_to_bridge(port)
            return json.dumps({"success": True})

        fake_module.send_message_tool = permissive_tool
        monkeypatch.setitem(sys.modules, "tools.send_message_tool", fake_module)
        import argparse

        parser = argparse.ArgumentParser()
        send_cmd.register_send_subparser(parser.add_subparsers(dest="command"))
        for target, expected_exit in (
            ("whatsapp:12345@g.us", 1),
            ("telegram:12345", 0),
        ):
            args = parser.parse_args(["send", "--to", target, "synthetic text"])
            with pytest.raises(SystemExit) as exit_result:
                send_cmd.cmd_send(args)
            assert exit_result.value.code == expected_exit
        assert downstream == ["telegram:12345"]
        assert requests == []

        monkeypatch.setenv("HERMES_HOME", str(alert))
        args = parser.parse_args(["send", "--to", "whatsapp:12345@g.us", "synthetic text"])
        with pytest.raises(SystemExit) as exit_result:
            send_cmd.cmd_send(args)
        assert exit_result.value.code == 0
        assert downstream[-1] == "whatsapp:12345@g.us"
        assert len(requests) == 1
