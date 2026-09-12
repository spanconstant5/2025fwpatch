"""Unconditional diagnostic identity read — always enters the programming session."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from .artifacts import _atomic_replace
from .paths import ArtifactLayout
from .probe import _identity_recognition
from .transport import EcuIdentity


class IdentifyError(RuntimeError):
  pass


class IdentifyTransport(Protocol):
  def __enter__(self) -> "IdentifyTransport": ...
  def __exit__(self, exc_type, exc, traceback) -> None: ...
  def read_full_identity(self) -> EcuIdentity: ...


TransportFactory = Callable[[], IdentifyTransport]
Preflight = Callable[[], object]


def run_identify(
  *,
  layout: ArtifactLayout,
  preflight: Preflight,
  transport_factory: TransportFactory,
) -> Path:
  """Read application and boot F181 unconditionally and write a non-authorizing diagnostic.

  Always enters the programming session.  The FRC/DRCC ignition-cycle fault reported
  for this vehicle (Discord, 2026-09-10) will occur; plan a power cycle before running
  this command in a vehicle context.

  The written report cannot authorize patch or restore and contains no sector bytes.
  """
  if not isinstance(layout, ArtifactLayout):
    raise TypeError("layout must be an ArtifactLayout")
  if not callable(preflight) or not callable(transport_factory):
    raise TypeError("preflight and transport_factory must be callable")

  preflight()
  with transport_factory() as transport:
    identity = transport.read_full_identity()

  report: dict[str, object] = {
    "schema": 1,
    "workflow": "identify",
    "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "authorizes_patch_or_restore": False,
    "recognition": _identity_recognition(identity),
    "observed": {
      "application_software_id": identity.application_software_id.hex(),
      "boot_software_id": identity.boot_software_id.hex(),
      "panda_serial": identity.panda_serial,
    },
  }
  content = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
  _atomic_replace(layout.identity_capture_report, content)
  return layout.identity_capture_report
