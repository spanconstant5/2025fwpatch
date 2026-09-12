"""Public command-line boundary for the comma-local EPS workflow."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from eps_patch.paths import ArtifactLayout, DEFAULT_ARTIFACT_ROOT


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def cli_module():
  """Load the root command script without shadowing the eps_patch package."""
  spec = importlib.util.spec_from_file_location("eps_patch_cli", ROOT / "eps_patch.py")
  assert spec is not None and spec.loader is not None
  module = importlib.util.module_from_spec(spec)
  sys.modules[spec.name] = module
  try:
    spec.loader.exec_module(module)
    yield module
  finally:
    sys.modules.pop(spec.name, None)


def _command_action(parser):
  return next(action for action in parser._actions if action.dest == "command")


def test_cli_exposes_exactly_four_commands(cli_module):
  """Adding any legacy phase command must not expand the public surface."""
  parser = cli_module.build_parser()

  assert set(_command_action(parser).choices) == {"probe", "patch", "restore", "identify"}


def test_cli_loads_only_retained_runtime_payloads(cli_module, monkeypatch):
  """A removed payload must not block a workflow before any ECU connection."""
  loaded: list[str] = []

  def load_shellcode(_directory, name):
    loaded.append(name)
    if name == "ram_echo":
      raise AssertionError("obsolete payload was requested")
    return b"shellcode"

  monkeypatch.setattr(cli_module, "load_built_shellcode", load_shellcode)
  monkeypatch.setattr(cli_module, "build_envelope", lambda *_args, **_kwargs: bytes(0x1000))

  payloads = cli_module._load_payloads()

  assert loaded == [
    "probe_pe_cycle", "crc_probe", "crc_intermediate", "crc_verify", "live_read",
  ]
  assert set(vars(payloads)) == set(loaded)


@pytest.mark.parametrize("command", ("probe", "patch", "restore"))
def test_each_command_accepts_only_optional_serial(cli_module, command):
  """A caller must not be able to select or import evidence through the CLI."""
  parser = cli_module.build_parser()

  args = parser.parse_args([command, "--serial", "panda-123"])

  assert vars(args) == {"command": command, "serial": "panda-123"}


@pytest.mark.parametrize("argv", [
  ["patch", "--probe" "-dir", "/tmp/probe"],
  ["patch", "--output", "/tmp/out"],
  ["restore", "--incident-dir", "/tmp/incident"],
])
def test_cli_rejects_user_selected_evidence_paths(cli_module, argv):
  """Restoring user-controlled evidence paths would bypass the trust boundary."""
  with pytest.raises(SystemExit):
    cli_module.build_parser().parse_args(argv)


@pytest.mark.parametrize("command", (
  "verify", "patch" "-crc", "recover" "-sector", "verify" "-restore",
))
def test_cli_rejects_legacy_commands(cli_module, command):
  """Legacy workflow phases must remain inaccessible as public commands."""
  with pytest.raises(SystemExit):
    cli_module.build_parser().parse_args([command])


@pytest.mark.parametrize("command", ("probe", "patch", "restore"))
def test_dispatch_routes_only_the_requested_workflow(cli_module, tmp_path, command, monkeypatch):
  """Routing a command to a different workflow would run an unsafe operation."""
  calls: list[tuple[str, dict[str, object]]] = []
  payloads = SimpleNamespace(probe_pe_cycle="probe", crc_probe="crc-probe")
  templates = SimpleNamespace(write_target_candidate=b"target")
  layout = ArtifactLayout(tmp_path / "artifacts")

  monkeypatch.setattr(cli_module, "_load_payloads", lambda: payloads)
  monkeypatch.setattr(cli_module, "_load_templates", lambda: templates)
  for name in ("probe", "patch", "restore"):
    monkeypatch.setattr(
      cli_module,
      f"run_{name}",
      lambda _name=name, **kwargs: (
        calls.append((_name, kwargs)) or tmp_path / f"{_name}-report.json"
      ),
    )

  result = cli_module.dispatch(
    SimpleNamespace(command=command, serial=None),
    layout=layout,
    preflight=lambda: None,
    transport_factory=lambda: object(),
    confirmation=lambda _prompt: "confirmed",
    power_cycle_checkpoint=lambda _prompt: "",
  )

  assert result == tmp_path / f"{command}-report.json"
  assert [name for name, _kwargs in calls] == [command]
  kwargs = calls[0][1]
  assert kwargs["layout"] == layout
  assert kwargs["preflight"]() is None
  assert kwargs["new_uds"] is False
  if command == "probe":
    assert kwargs["payload"] == "probe"
  else:
    assert kwargs["payloads"] is payloads
    assert kwargs["templates"] is templates


def test_main_uses_the_fixed_artifact_root_and_prints_report(cli_module, monkeypatch, capsys):
  """Changing the default root would make operators use an untrusted evidence store."""
  observed: dict[str, object] = {}

  monkeypatch.setattr(sys, "argv", ["eps_patch.py", "probe", "--serial", "panda-123"])
  monkeypatch.setattr(
    cli_module,
    "dispatch",
    lambda _args, **kwargs: observed.update(kwargs) or Path("/reports/probe.json"),
  )

  assert cli_module.main() == 0
  assert observed["layout"] == ArtifactLayout(DEFAULT_ARTIFACT_ROOT)
  assert observed["confirmation"] is cli_module._confirm_destructive
  assert observed["power_cycle_checkpoint"] is cli_module._print_power_cycle
  assert capsys.readouterr().out == "/reports/probe.json\n"


def test_destructive_confirmation_is_visible_and_accepts_only_exact_yes(
  cli_module,
  monkeypatch,
  capsys,
):
  transaction = "WRITE-TARGET 8965F1208000 0x88000 hashes"
  monkeypatch.setattr("builtins.input", lambda: "YES")

  assert cli_module._confirm_destructive(transaction) == transaction

  output = capsys.readouterr().out
  assert "DESTRUCTIVE OPERATION" in output
  assert transaction in output
  assert "Type YES to continue:" in output


@pytest.mark.parametrize("answer", ("", "yes", "YES ", " YES", "NO"))
def test_destructive_confirmation_rejects_every_nonexact_answer(
  cli_module,
  monkeypatch,
  answer,
):
  monkeypatch.setattr("builtins.input", lambda: answer)

  with pytest.raises(cli_module.CliError, match="exact uppercase YES"):
    cli_module._confirm_destructive("RESTORE-SECTOR transaction")


def test_destructive_confirmation_rejects_eof_before_authorization(
  cli_module,
  monkeypatch,
):
  def end_of_input():
    raise EOFError

  monkeypatch.setattr("builtins.input", end_of_input)

  with pytest.raises(cli_module.CliError, match="interactive input ended"):
    cli_module._confirm_destructive("WRITE-CRC transaction")


@pytest.mark.parametrize("command", ("patch", "restore"))
def test_noninteractive_destructive_command_fails_before_dispatch(
  cli_module,
  monkeypatch,
  capsys,
  command,
):
  class NonInteractiveInput:
    def isatty(self):
      return False

  monkeypatch.setattr(sys, "argv", ["eps_patch.py", command])
  monkeypatch.setattr(cli_module.sys, "stdin", NonInteractiveInput())
  monkeypatch.setattr(
    cli_module,
    "dispatch",
    lambda *_args, **_kwargs: pytest.fail("dispatch reached without a TTY"),
  )

  assert cli_module.main() == 2
  assert "interactive TTY" in capsys.readouterr().err


@pytest.mark.parametrize(("stdin_tty", "stdout_tty"), ((False, True), (True, False)))
def test_destructive_command_rejects_hidden_input_or_output_before_dispatch(
  cli_module,
  monkeypatch,
  capsys,
  stdin_tty,
  stdout_tty,
):
  class Terminal:
    def __init__(self, is_tty):
      self._is_tty = is_tty

    def isatty(self):
      return self._is_tty

  monkeypatch.setattr(sys, "argv", ["eps_patch.py", "patch"])
  monkeypatch.setattr(cli_module.sys, "stdin", Terminal(stdin_tty))
  monkeypatch.setattr(cli_module.sys, "stdout", Terminal(stdout_tty))
  monkeypatch.setattr(
    cli_module,
    "dispatch",
    lambda *_args, **_kwargs: pytest.fail("dispatch reached without visible I/O"),
  )

  assert cli_module.main() == 2
  assert "interactive TTY" in capsys.readouterr().err


def test_background_destructive_command_fails_before_dispatch(
  cli_module,
  monkeypatch,
  capsys,
):
  class Terminal:
    def isatty(self):
      return True

    def fileno(self):
      return 42

  monkeypatch.setattr(sys, "argv", ["eps_patch.py", "restore"])
  monkeypatch.setattr(cli_module.sys, "stdin", Terminal())
  monkeypatch.setattr(cli_module.sys, "stdout", Terminal())
  monkeypatch.setattr(cli_module.os, "tcgetpgrp", lambda fd: 100 if fd == 42 else 0)
  monkeypatch.setattr(cli_module.os, "getpgrp", lambda: 101)
  monkeypatch.setattr(
    cli_module,
    "dispatch",
    lambda *_args, **_kwargs: pytest.fail("background job reached dispatch"),
  )

  assert cli_module.main() == 2
  assert "foreground" in capsys.readouterr().err


def test_operator_messages_are_explicitly_flushed(cli_module, monkeypatch):
  calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

  monkeypatch.setattr(
    "builtins.print",
    lambda *args, **kwargs: calls.append((args, kwargs)),
  )
  monkeypatch.setattr("builtins.input", lambda: "YES")

  cli_module._confirm_destructive("WRITE-TARGET transaction")
  cli_module._print_power_cycle("POWER CYCLE")

  assert calls
  assert all(kwargs.get("flush") is True for _args, kwargs in calls)


def test_main_prints_known_workflow_errors_to_stderr(cli_module, monkeypatch, capsys):
  """Known workflow failures must produce an actionable non-zero CLI result."""
  monkeypatch.setattr(sys, "argv", ["eps_patch.py", "probe"])
  monkeypatch.setattr(cli_module, "dispatch", lambda *_args, **_kwargs: (_ for _ in ()).throw(cli_module.ProbeError("probe failed")))

  assert cli_module.main() == 2
  assert capsys.readouterr().err == "ERROR: probe failed\n"
