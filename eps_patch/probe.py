"""One fail-closed comprehensive read-only probe workflow."""

from __future__ import annotations

import binascii
import hashlib
import json
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from .artifacts import _atomic_replace, sha256_bytes
from .evidence import install_probe_pass
from .manifest import TARGET, TargetManifest
from .payload import PROBE_PE_CYCLE_ENVELOPE_SHA256
from .paths import ArtifactLayout
from .protocol import (
  DcraObservation,
  FACI_DIAGNOSTICS,
  FACI_PE_CYCLE_DIAGNOSTICS,
  OP_FACI_PE_CYCLE,
  RegionResult,
  StreamResult,
)
from .transport import EcuIdentity


class ProbeError(RuntimeError):
  pass


class _ProbeOutcomeFailure(ProbeError):
  """A structurally complete probe stream with a non-PASS ECU outcome."""

  def __init__(self, primary: int, cleanup: int, diagnostic: dict[str, object]):
    self.primary = primary
    self.cleanup = cleanup
    self.diagnostic = diagnostic
    super().__init__(f"probe outcome is not PASS: primary={primary}, cleanup={cleanup}")


@dataclass(frozen=True, slots=True)
class PayloadImage:
  name: str
  envelope: bytes
  sha256: str

  def validate(self, target: TargetManifest = TARGET) -> None:
    if self.name != "probe_pe_cycle":
      raise ProbeError("probe payload name is not the comprehensive P/E-cycle payload")
    if type(self.envelope) is not bytes or len(self.envelope) != target.envelope_length:
      raise ProbeError("probe payload envelope does not match the target allocation")
    if (
      type(self.sha256) is not str
      or self.sha256 != hashlib.sha256(self.envelope).hexdigest()
    ):
      raise ProbeError("probe payload SHA-256 mismatch")
    if self.sha256 != PROBE_PE_CYCLE_ENVELOPE_SHA256:
      raise ProbeError("probe payload is not the exact reviewed retained envelope")


class ProbeTransport(Protocol):
  def __enter__(self) -> "ProbeTransport": ...
  def __exit__(self, exc_type, exc, traceback) -> None: ...
  def read_identity(self) -> EcuIdentity: ...
  def run_payload(
    self, image: PayloadImage, *, operation: int, new_uds: bool,
  ) -> StreamResult: ...


TransportFactory = Callable[[], ProbeTransport]
Preflight = Callable[[], object]

_CHECKPOINTS = ("PRE", "UNLOCKED", "WINDOWS", "CONFIGURED", "RESTORED")
_REGISTERS = tuple(name for name, _address, _width in FACI_DIAGNOSTICS)
_REGISTER_WIDTHS = tuple(width for _name, _address, width in FACI_DIAGNOSTICS)
_PRE = (0x80, 0x8000, 0, 0, 0, 0, 0, 0)
_EXPECTED_SNAPSHOTS = (
  _PRE,
  _PRE[:3] + (1,) + _PRE[4:],
  _PRE[:3] + (1,) + _PRE[4:6] + (1, 1),
  _PRE[:3] + (1, 1, 0, 1, 1),
  _PRE,
)


def run_probe(
  *,
  layout: ArtifactLayout,
  payload: PayloadImage,
  preflight: Preflight,
  transport_factory: TransportFactory,
  target: TargetManifest = TARGET,
  new_uds: bool,
) -> Path:
  """Run exactly one comprehensive payload and install evidence only on PASS."""
  if not isinstance(layout, ArtifactLayout):
    raise TypeError("layout must be an ArtifactLayout")
  if type(payload) is not PayloadImage:
    raise TypeError("payload must be a PayloadImage")
  if not callable(preflight) or not callable(transport_factory):
    raise TypeError("preflight and transport_factory must be callable")
  if not isinstance(target, TargetManifest):
    raise TypeError("target must be a TargetManifest")
  try:
    target.validate()
  except ValueError as exc:
    raise ProbeError(f"target manifest is invalid: {exc}") from exc
  if type(new_uds) is not bool or new_uds is not target.new_uds:
    raise ProbeError("probe UDS variant does not match the target")
  payload.validate(target)
  if layout.probe_directory.exists():
    raise ProbeError("trusted probe directory already exists")

  preflight()
  with transport_factory() as transport:
    identity = transport.read_identity()
    try:
      _validate_identity(identity, target)
    except ProbeError as exc:
      if type(identity) is not EcuIdentity:
        raise
      try:
        path = _record_identity_mismatch(layout, identity, payload, target)
      except OSError as write_exc:
        raise ProbeError(
          f"{exc}; identity diagnostic write failed: {write_exc}"
        ) from exc
      raise ProbeError(f"{exc}; diagnostic: {path}") from exc
    result = transport.run_payload(
      payload, operation=OP_FACI_PE_CYCLE, new_uds=new_uds,
    )

  try:
    target_sector, crc_sector, observation, host_checks, snapshots, primary, cleanup = (
      _validate_result(result, target)
    )
  except _ProbeOutcomeFailure as exc:
    try:
      path = _record_probe_outcome_failure(layout, identity, payload, exc)
    except OSError as write_exc:
      raise ProbeError(f"{exc}; failure diagnostic write failed: {write_exc}") from exc
    dcra = exc.diagnostic["dcra"]
    assert isinstance(dcra, dict)
    raise ProbeError(
      f"{exc}; DCRA entry_ctl=0x{dcra['entry_ctl']:08x}, "
      f"entry_cout=0x{dcra['entry_cout']:08x}, "
      f"exit_ctl=0x{dcra['exit_ctl']:08x}, "
      f"exit_cout=0x{dcra['exit_cout']:08x}; diagnostic: {path}"
    ) from exc
  identity_record = _identity_record(identity)
  target_descriptor = _descriptor(target.sector_base, target_sector)
  crc_descriptor = _descriptor(target.crc_sector_base, crc_sector)
  report: dict[str, object] = {
    "workflow": "faci-pe-cycle",
    "result": "PASS",
    "identity": identity_record,
    "payload": {"name": payload.name, "sha256": payload.sha256},
    "new_uds": new_uds,
    "sectors": {"target": target_descriptor, "crc": crc_descriptor},
    "instruction": {
      "address": target.instruction_address,
      "original": target.original_instruction.hex(),
    },
    "snapshots": snapshots,
    "dcra": _dcra_record(observation),
    "host_checks": host_checks,
    "outcome": {"primary_code": primary, "cleanup_code": cleanup},
    "validation_errors": [],
  }
  metadata: dict[str, object] = {
    "identity": identity_record,
    "target_backup": target_descriptor,
    "crc_backup": crc_descriptor,
  }
  return install_probe_pass(layout, target_sector, crc_sector, report, metadata)


def _validate_identity(identity: object, target: TargetManifest) -> None:
  if type(identity) is not EcuIdentity:
    raise ProbeError("ECU identity has the wrong concrete type")
  if (
    identity.part_number != target.part_number
    or identity.application_software_id != target.application_software_id
    or identity.boot_software_id != target.boot_software_id
    or type(identity.panda_serial) is not str
    or not identity.panda_serial
  ):
    raise ProbeError("ECU identity does not exactly match the target")


def _failure_stream_diagnostic(
  result: StreamResult, target: TargetManifest,
) -> dict[str, object]:
  if type(result.magic_words) is not tuple or len(result.magic_words) != 2:
    raise ProbeError("probe diagnostic magic words are incomplete")
  magic_words = [_u32(value, "diagnostic magic word") for value in result.magic_words]

  if type(result.regions) is not tuple or len(result.regions) != 2:
    raise ProbeError("probe diagnostic regions are incomplete")
  descriptors: dict[str, dict[str, int | str]] = {}
  for label, region in zip(("target", "crc"), result.regions, strict=True):
    if type(region) is not RegionResult or type(region.data) is not bytes:
      raise ProbeError(f"probe diagnostic {label} region is malformed")
    if len(region.data) != target.sector_length:
      raise ProbeError(f"probe diagnostic {label} region has the wrong length")
    descriptors[label] = {
      "address": _u32(region.base, f"diagnostic {label} address"),
      "length": len(region.data),
      "sha256": sha256_bytes(region.data),
      "crc32": binascii.crc32(region.data),
    }

  return {
    "magic_words": magic_words,
    "dcra": _failure_dcra_record(result),
    "snapshots": _failure_snapshot_records(result.faci_values),
    "regions": descriptors,
  }


def _identity_recognition(identity: EcuIdentity) -> str:
  """Return a machine-readable label for the observed application software identity.

  Recognition only names what is known from offline firmware evidence.
  It does not authorize patching or widen the runtime allowlist.
  """
  from .corolla_2025 import APPLICATION_F181
  if identity.application_software_id == APPLICATION_F181:
    return "known-2025-corolla-specimen"
  return "unrecognized"


def _record_identity_mismatch(
  layout: ArtifactLayout,
  identity: EcuIdentity,
  payload: PayloadImage,
  target: TargetManifest,
) -> Path:
  """Retain observed F181 values without creating trusted probe evidence."""
  report = {
    "schema": 1,
    "workflow": "probe-identity-check",
    "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "result": "REJECTED",
    "reason": "identity-mismatch",
    "authorizes_patch_or_restore": False,
    "recognition": _identity_recognition(identity),
    "observed": _identity_record(identity),
    "expected": {
      "part_number": target.part_number.decode("ascii", errors="strict"),
      "application_software_id": target.application_software_id.hex(),
      "boot_software_id": target.boot_software_id.hex(),
    },
    "payload": {"name": payload.name, "sha256": payload.sha256},
  }
  content = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
  _atomic_replace(layout.probe_identity_failure_report, content)
  return layout.probe_identity_failure_report


def _failure_dcra_record(result: StreamResult) -> dict[str, int]:
  if type(result.dcra) is not DcraObservation:
    raise ProbeError("probe diagnostic DCRA observation is missing")
  values = tuple(
    _u32(getattr(result.dcra, field.name), f"diagnostic {field.name}")
    for field in fields(DcraObservation)
  )
  if type(result.dcra_values) is not tuple or tuple(result.dcra_values) != values:
    raise ProbeError("probe diagnostic DCRA records are incomplete or contradictory")
  return dict(zip((field.name for field in fields(DcraObservation)), values))


def _failure_snapshot_records(values: object) -> dict[str, dict[str, int]]:
  if type(values) is not tuple or len(values) != len(FACI_PE_CYCLE_DIAGNOSTICS):
    raise ProbeError("probe diagnostic FACI sequence is incomplete")
  snapshots: dict[str, dict[str, int]] = {}
  for checkpoint_index, checkpoint in enumerate(_CHECKPOINTS):
    start = checkpoint_index * len(_REGISTERS)
    raw = values[start:start + len(_REGISTERS)]
    record: dict[str, int] = {}
    for name, width, value in zip(_REGISTERS, _REGISTER_WIDTHS, raw, strict=True):
      checked = _u32(value, f"diagnostic {checkpoint} {name}")
      if checked >= 1 << (width * 8):
        raise ProbeError(f"probe diagnostic {checkpoint} {name} exceeds its width")
      record[name] = checked
    snapshots[checkpoint] = record
  return snapshots


def _record_probe_outcome_failure(
  layout: ArtifactLayout,
  identity: EcuIdentity,
  payload: PayloadImage,
  failure: _ProbeOutcomeFailure,
) -> Path:
  report = {
    "schema": 1,
    "workflow": "faci-pe-cycle-failure",
    "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "identity": _identity_record(identity),
    "payload": {"name": payload.name, "sha256": payload.sha256},
    "outcome": {"primary_code": failure.primary, "cleanup_code": failure.cleanup},
    "magic_words": failure.diagnostic["magic_words"],
    "dcra": failure.diagnostic["dcra"],
    "snapshots": failure.diagnostic["snapshots"],
    "regions": failure.diagnostic["regions"],
    "error": str(failure),
  }
  content = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
  _atomic_replace(layout.probe_failure_report, content)
  return layout.probe_failure_report


def _validate_result(
  result: object, target: TargetManifest,
) -> tuple[
  bytes, bytes, DcraObservation, dict[str, object],
  dict[str, dict[str, int]], int, int,
]:
  if type(result) is not StreamResult:
    raise ProbeError("probe stream result has the wrong concrete type")
  if result.operation != OP_FACI_PE_CYCLE:
    raise ProbeError("probe stream returned the wrong operation")
  if result.sector is not None:
    raise ProbeError("probe stream exposed a forbidden legacy single-sector field")
  if type(result.statuses) is not tuple or len(result.statuses) != 1:
    raise ProbeError("probe outcome status is incomplete")
  status = result.statuses[0]
  if type(status) is not tuple or len(status) != 2 or status[0] != 1:
    raise ProbeError("probe outcome status is malformed")
  raw_status = _u32(status[1], "outcome status")
  primary = raw_status & 0xFFFF
  cleanup = (raw_status >> 16) & 0xFFFF
  if primary != 0 or cleanup != 0:
    raise _ProbeOutcomeFailure(primary, cleanup, _failure_stream_diagnostic(result, target))

  if result.magic_words != (target.magic_word, target.magic_word):
    raise ProbeError("probe boot magic words do not match the target")

  if type(result.regions) is not tuple or len(result.regions) != 2:
    raise ProbeError("probe must return exactly two full sectors")
  regions: list[bytes] = []
  for index, (region, base) in enumerate(zip(
    result.regions, (target.sector_base, target.crc_sector_base),
  )):
    if type(region) is not RegionResult or region.base != base:
      label = "target" if index == 0 else "CRC"
      raise ProbeError(f"probe {label} sector has the wrong address")
    if type(region.data) is not bytes or len(region.data) != target.sector_length:
      label = "target" if index == 0 else "CRC"
      raise ProbeError(f"probe {label} sector has the wrong length")
    regions.append(region.data)
  target_sector, crc_sector = regions
  if sha256_bytes(target_sector) != target.original_sha256:
    raise ProbeError("probe target sector is not the exact reviewed original")
  instruction = target_sector[
    target.instruction_offset:target.instruction_offset + len(target.original_instruction)
  ]
  if instruction != target.original_instruction:
    raise ProbeError("probe target sector has the wrong original instruction context")
  magic_offset = target.magic_addresses[1] - target.crc_sector_base
  if crc_sector[magic_offset:magic_offset + 4] != target.magic_word.to_bytes(4, "little"):
    raise ProbeError("probe CRC sector contains the wrong boot magic")
  live_adjustment = int.from_bytes(
    crc_sector[target.crc_adjust_offset:target.crc_adjust_offset + 4], "little",
  )
  if live_adjustment != target.crc_original_adjust_word:
    raise ProbeError("probe CRC sector contains the wrong reviewed adjustment word")

  snapshots = _validate_diagnostics(result.faci_values)
  observation = _validate_dcra(result, crc_sector, target)
  host_checks = _host_checks(target_sector, crc_sector, target)
  return target_sector, crc_sector, observation, host_checks, snapshots, primary, cleanup


def _validate_diagnostics(values: object) -> dict[str, dict[str, int]]:
  if type(values) is not tuple or len(values) != len(FACI_PE_CYCLE_DIAGNOSTICS):
    raise ProbeError("probe FACI diagnostic sequence is incomplete")
  snapshots: dict[str, dict[str, int]] = {}
  for checkpoint_index, (checkpoint, expected) in enumerate(
    zip(_CHECKPOINTS, _EXPECTED_SNAPSHOTS),
  ):
    start = checkpoint_index * len(_REGISTERS)
    raw = values[start:start + len(_REGISTERS)]
    for name, width, value in zip(_REGISTERS, _REGISTER_WIDTHS, raw):
      if type(value) is not int:
        raise ProbeError(f"probe {checkpoint} FACI diagnostic has a non-integer value")
      if not 0 <= value < (1 << (width * 8)):
        raise ProbeError(
          f"probe {checkpoint} {name} exceeds its declared diagnostic width"
        )
    if checkpoint == "CONFIGURED":
      # FAREASELC is write-triggered but reads back as zero on the reviewed EPS.
      required_indices = (0, 1, 2, 3, 6, 7)
      if any(raw[index] != expected[index] for index in required_indices):
        raise ProbeError(
          "probe CONFIGURED FACI diagnostic does not match the reviewed state"
        )
      if (raw[4] & 1) != 1:
        raise ProbeError("probe CONFIGURED FPROTR bit 0 does not prove P/E entry")
    elif tuple(raw) != expected:
      raise ProbeError(f"probe {checkpoint} FACI diagnostic does not match the reviewed state")
    snapshots[checkpoint] = dict(zip(_REGISTERS, raw))
  if tuple(values[-len(_REGISTERS):]) != tuple(values[:len(_REGISTERS)]):
    raise ProbeError("probe RESTORED FACI state does not exactly match PRE")
  return snapshots


def _validate_dcra(
  result: StreamResult,
  crc_sector: bytes,
  target: TargetManifest,
) -> DcraObservation:
  observation = result.dcra
  if type(observation) is not DcraObservation:
    raise ProbeError("probe DCRA observation is missing")
  values = tuple(
    _u32(getattr(observation, field.name), field.name)
    for field in fields(DcraObservation)
  )
  if type(result.dcra_values) is not tuple or tuple(result.dcra_values) != values:
    raise ProbeError("probe DCRA observation records are incomplete or contradictory")
  if result.crc_values != () or result.crc is not None:
    raise ProbeError("probe stream exposed forbidden payload software CRC evidence")
  if (observation.range_start, observation.range_end) != (
    target.crc_range_start, target.crc_range_end,
  ):
    raise ProbeError("probe DCRA observation range does not match the target")
  if observation.adjust_address != target.crc_adjust_address:
    raise ProbeError("probe DCRA observation adjustment address does not match the target")
  live_adjustment = int.from_bytes(
    crc_sector[target.crc_adjust_offset:target.crc_adjust_offset + 4], "little",
  )
  if observation.old_adjust_word != live_adjustment:
    raise ProbeError("probe CRC sector disagrees with its DCRA observation")
  if observation.new_adjust_word != target.crc_patched_adjust_word:
    raise ProbeError("probe DCRA adjustment does not match the reviewed patched word")
  if (
    observation.original_dcra_raw != target.crc_residue
    or observation.patched_dcra_raw != target.crc_residue
  ):
    raise ProbeError("probe DCRA residue does not satisfy the reviewed boot predicate")
  if (observation.exit_ctl, observation.exit_cout) != (
    observation.entry_ctl, observation.entry_cout,
  ):
    raise ProbeError("probe DCRA state was not exactly restored")
  return observation


def _host_checks(
  target_sector: bytes, crc_sector: bytes, target: TargetManifest,
) -> dict[str, object]:
  if target.crc_patched_prefix_sw ^ target.crc_residue != target.crc_patched_adjust_word:
    raise ProbeError("target CRC adjustment does not match the reviewed residue formula")
  return {
    "target_sector_sha256": sha256_bytes(target_sector),
    "target_sector_crc32": binascii.crc32(target_sector),
    "crc_sector_crc32": binascii.crc32(crc_sector),
    "combined_crc32": binascii.crc32(target_sector + crc_sector),
    "original_adjust_word": target.crc_original_adjust_word,
    "patched_prefix_sw": target.crc_patched_prefix_sw,
    "patched_adjust_word": target.crc_patched_adjust_word,
    "residue": target.crc_residue,
  }


def _u32(value: object, label: str) -> int:
  if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
    raise ProbeError(f"probe {label} is not one unsigned 32-bit value")
  return value


def _identity_record(identity: EcuIdentity) -> dict[str, str]:
  try:
    part_number = identity.part_number.decode("ascii", errors="strict")
  except UnicodeDecodeError as exc:
    raise ProbeError("ECU identity part number is not ASCII") from exc
  return {
    "part_number": part_number,
    "application_software_id": identity.application_software_id.hex(),
    "boot_software_id": identity.boot_software_id.hex(),
    "panda_serial": identity.panda_serial,
  }


def _descriptor(address: int, data: bytes) -> dict[str, object]:
  return {"address": address, "length": len(data), "sha256": sha256_bytes(data)}


def _dcra_record(observation: DcraObservation) -> dict[str, int]:
  return {field.name: getattr(observation, field.name) for field in fields(DcraObservation)}
