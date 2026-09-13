"""Unconditional diagnostic identity read — always enters the programming session."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from .artifacts import _atomic_replace
from .paths import ArtifactLayout
from .transport import IdentityCaptureResult

_DID_BOOT = 0xF180
_DID_APP = 0xF181


class IdentifyError(RuntimeError):
  pass


class IdentifyTransport(Protocol):
  def __enter__(self) -> "IdentifyTransport": ...
  def __exit__(self, exc_type, exc, traceback) -> None: ...
  def read_full_identity(self) -> IdentityCaptureResult: ...


TransportFactory = Callable[[], IdentifyTransport]
Preflight = Callable[[], object]


def _recognition(f181_default: bytes) -> str:
  from .corolla_2025 import APPLICATION_F181
  return "known-2025-corolla-specimen" if f181_default == APPLICATION_F181 else "unrecognized"


def run_identify(
  *,
  layout: ArtifactLayout,
  preflight: Preflight,
  transport_factory: TransportFactory,
) -> Path:
  """Read 0xF181 in default session and both 0xF180/0xF181 in programming session.

  All reads occur before any return session transition so the ECU state is captured
  while it is actually in programming mode.  Always enters programming — the
  FRC/DRCC ignition-cycle fault (Discord, 2026-09-10) will fire; plan a power cycle.

  The written report cannot authorize patch or restore and contains no sector bytes.
  """
  if not isinstance(layout, ArtifactLayout):
    raise TypeError("layout must be an ArtifactLayout")
  if not callable(preflight) or not callable(transport_factory):
    raise TypeError("preflight and transport_factory must be callable")

  preflight()
  with transport_factory() as transport:
    result = transport.read_full_identity()

  report: dict[str, object] = {
    "schema": 2,
    "workflow": "identify",
    "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "authorizes_patch_or_restore": False,
    "recognition": _recognition(result.f181_default_session),
    "panda_serial": result.panda_serial,
    "f181_default_session": result.f181_default_session.hex(),
    "f180_programming_session": (
      result.f180_programming_session.hex()
      if result.f180_programming_session is not None
      else "nrc-not-supported"
    ),
    "f181_programming_session": result.f181_programming_session.hex(),
    "did_notes": {
      "0xF180": "Boot Software Identification — read in programming session; null if ECU returned NRC",
      "0xF181": "Application Software Identification — read in default and programming sessions",
    },
  }
  content = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
  _atomic_replace(layout.identity_capture_report, content)
  return layout.identity_capture_report
