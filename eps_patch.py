#!/usr/bin/env python3
"""The deliberately small public interface for the EPS patch workflow."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

from eps_patch.artifacts import ArtifactError
from eps_patch.evidence import EvidenceError
from eps_patch.identify import IdentifyError, run_identify
from eps_patch.patch import PatchError, run_patch
from eps_patch.paths import ArtifactLayout, DEFAULT_ARTIFACT_ROOT
from eps_patch.payload import PayloadError, build_envelope, load_built_shellcode
from eps_patch.preflight import PreflightError, run_preflight
from eps_patch.probe import PayloadImage, ProbeError, run_probe
from eps_patch.restore import RestoreError, run_restore
from eps_patch.transport import EcuTransport, TransportError


class CliError(RuntimeError):
  """The public command cannot safely interact with its operator."""


_BUILD_DIRECTORY = Path(__file__).resolve().parent / "payload" / "build"
_PAYLOAD_NAMES = (
  "probe_pe_cycle",
  "crc_probe",
  "crc_intermediate",
  "crc_verify",
  "live_read",
)
_TEMPLATE_NAMES = (
  "write_target_candidate",
  "write_crc_candidate",
  "restore_sector",
)
_EXPECTED_ERRORS = (
  CliError,
  ArtifactError,
  EvidenceError,
  IdentifyError,
  PreflightError,
  PayloadError,
  TransportError,
  ProbeError,
  PatchError,
  RestoreError,
)


def _confirm_destructive(transaction: str) -> str:
  """Show one transaction clearly and authorize it only with exact `YES`."""
  if type(transaction) is not str or not transaction:
    raise CliError("destructive transaction summary is missing")
  print("\n========== DESTRUCTIVE OPERATION / 破坏性操作 ==========", flush=True)
  print(transaction, flush=True)
  print("输入大写 YES 继续 / Type YES to continue: ", end="", flush=True)
  try:
    answer = input()
  except EOFError as exc:
    raise CliError(
      "destructive confirmation interactive input ended before YES"
    ) from exc
  if answer != "YES":
    raise CliError("destructive confirmation requires exact uppercase YES")
  return transaction


def _print_power_cycle(message: str) -> None:
  """Flush one persisted power-cycle instruction before this process exits."""
  if type(message) is not str or not message:
    raise CliError("power-cycle instruction is missing")
  print(message, end="" if message.endswith("\n") else "\n", flush=True)
  print(
    "本阶段状态已保存，当前命令将退出；断电重启后重新运行同一命令。\n"
    "Checkpoint saved; this command will exit. Rerun it after the power cycle.",
    flush=True,
  )


def _require_foreground_interactive_terminal() -> None:
  """Require visible terminal I/O owned by this foreground process group."""
  if not sys.stdin.isatty() or not sys.stdout.isatty():
    raise CliError(
      "patch and restore require visible input and output on an interactive TTY "
      "before any Panda connection"
    )
  try:
    foreground_group = os.tcgetpgrp(sys.stdin.fileno())
    process_group = os.getpgrp()
  except (AttributeError, OSError, ValueError) as exc:
    raise CliError(
      "patch and restore cannot verify the foreground interactive TTY"
    ) from exc
  if foreground_group != process_group:
    raise CliError(
      "patch and restore must run in the foreground interactive TTY"
    )


def build_parser() -> argparse.ArgumentParser:
  """Build the intentionally narrow public command surface."""
  parser = argparse.ArgumentParser(description=__doc__)
  commands = parser.add_subparsers(dest="command", required=True)
  for name in ("probe", "patch", "restore", "identify"):
    command = commands.add_parser(name)
    command.add_argument("--serial")
  return parser


def _load_payloads() -> SimpleNamespace:
  """Build exact pinned envelopes from the retained reviewed payload binaries."""
  images: dict[str, PayloadImage] = {}
  for name in _PAYLOAD_NAMES:
    shellcode = load_built_shellcode(_BUILD_DIRECTORY, name)
    envelope = build_envelope(
      shellcode,
      did_201=bytes(16),
      did_202=bytes(16),
      iv=bytes(16),
    )
    images[name] = PayloadImage(
      name=name,
      envelope=envelope,
      sha256=hashlib.sha256(envelope).hexdigest(),
    )
  return SimpleNamespace(**images)


def _load_templates() -> SimpleNamespace:
  """Load each writer template through the same pinned payload loader."""
  return SimpleNamespace(**{
    name: load_built_shellcode(_BUILD_DIRECTORY, name)
    for name in _TEMPLATE_NAMES
  })


def dispatch(
  args: argparse.Namespace,
  *,
  layout: ArtifactLayout,
  preflight: Callable[[], object],
  transport_factory: Callable[[], object],
  confirmation: Callable[[str], object],
  power_cycle_checkpoint: Callable[[str], object],
) -> Path:
  """Dispatch one public command with fixed evidence and reviewed inputs."""
  command = getattr(args, "command", None)
  if command == "identify":
    return run_identify(
      layout=layout,
      preflight=preflight,
      transport_factory=transport_factory,
    )
  if command == "probe":
    return run_probe(
      layout=layout,
      payload=_load_payloads().probe_pe_cycle,
      preflight=preflight,
      transport_factory=transport_factory,
      new_uds=False,
    )
  if command == "patch":
    return run_patch(
      layout=layout,
      payloads=_load_payloads(),
      templates=_load_templates(),
      preflight=preflight,
      transport_factory=transport_factory,
      confirmation=confirmation,
      power_cycle_checkpoint=power_cycle_checkpoint,
      new_uds=False,
    )
  if command == "restore":
    return run_restore(
      layout=layout,
      payloads=_load_payloads(),
      templates=_load_templates(),
      preflight=preflight,
      transport_factory=transport_factory,
      confirmation=confirmation,
      power_cycle_checkpoint=power_cycle_checkpoint,
      new_uds=False,
    )
  raise ValueError("unknown command")


def main() -> int:
  """Parse, run one workflow, and translate known failures into exit status 2."""
  args = build_parser().parse_args()
  try:
    if args.command in ("patch", "restore"):
      _require_foreground_interactive_terminal()
    report = dispatch(
      args,
      layout=ArtifactLayout(DEFAULT_ARTIFACT_ROOT),
      preflight=run_preflight,
      transport_factory=lambda: EcuTransport(serial=args.serial),
      confirmation=_confirm_destructive,
      power_cycle_checkpoint=_print_power_cycle,
    )
  except _EXPECTED_ERRORS as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    return 2
  print(report)
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
