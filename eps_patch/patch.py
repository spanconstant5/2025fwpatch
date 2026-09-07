"""Fail-closed comma-local orchestration for the reviewed two-sector patch."""

from __future__ import annotations

import binascii
import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path

from .artifacts import _atomic_create, sha256_bytes
from .candidate_writer import (
  CANDIDATE_ADJUSTMENT,
  CandidateWriterIntent,
  build_crc_candidate_payload_image,
  build_target_candidate_payload_image,
)
from .crc import CrcCandidate, build_crc_candidate
from .evidence import EvidenceError, TrustedProbeEvidence, load_probe_pass
from .manifest import TARGET, TargetManifest
from .operation_lock import exclusive_operation
from .paths import ArtifactLayout
from .payload import REVIEWED_TEMPLATE_MANIFESTS
from .power import PowerCycleCheckpoint, request_power_cycle
from .protocol import (
  CrcObservation,
  OP_CRC_INTERMEDIATE,
  OP_LIVE_READ,
  OP_CRC_PROBE,
  OP_VERIFY_CRC,
  OP_WRITE_CRC_CANDIDATE,
  OP_WRITE_TARGET_CANDIDATE,
  RegionResult,
  StreamResult,
  require_candidate_writer_pass,
  validate_crc_intermediate,
)
from .transport import BootloaderIdentity, EcuIdentity


CRC_PROBE_ENVELOPE_SHA256 = (
  "26dd9f2dcd27eca4021bd06ac4c75e0f09a5884d4b56b9f0a870e12f9bf1948e"
)
CRC_INTERMEDIATE_ENVELOPE_SHA256 = (
  "dd9497c50f81d5def2e93c133292fa721a2505ca2f10009c07bb0a17777b3b4c"
)
CRC_VERIFY_ENVELOPE_SHA256 = (
  "2391fb27522270d19d56fc036500ab2a1447bf0aacbaa04075a555d337713011"
)
LIVE_READ_ENVELOPE_SHA256 = (
  "4efdeeca07e98b3ae9f1df68b49521f9931b0938204d33ca543f6b78ccae4dd0"
)


class PatchError(RuntimeError):
  """Patch inputs, live evidence, or one-shot execution were not exact."""


class PatchState(str, Enum):
  STARTED = "STARTED"
  PROBED = "PROBED"
  TARGET_PRECHECKED = "TARGET_PRECHECKED"
  TARGET_ARMED = "TARGET_ARMED"
  TARGET_INDETERMINATE = "TARGET_INDETERMINATE"
  TARGET_COMMITTED = "TARGET_COMMITTED"
  CRC_PRECHECKED = "CRC_PRECHECKED"
  CRC_ARMED = "CRC_ARMED"
  CRC_INDETERMINATE = "CRC_INDETERMINATE"
  CRC_COMMITTED = "CRC_COMMITTED"
  VERIFY_PENDING = "VERIFY_PENDING"
  RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
  FAILED = "FAILED"
  PASS = "PASS"


_PAYLOAD_DIGESTS = {
  "crc_probe": CRC_PROBE_ENVELOPE_SHA256,
  "crc_intermediate": CRC_INTERMEDIATE_ENVELOPE_SHA256,
  "crc_verify": CRC_VERIFY_ENVELOPE_SHA256,
  "live_read": LIVE_READ_ENVELOPE_SHA256,
}
_TEMPLATE_NAMES = ("write_target_candidate", "write_crc_candidate")
_PATCH_RESUME_NEXT = {
  PatchState.PROBED.value: PatchState.TARGET_PRECHECKED.value,
  PatchState.TARGET_PRECHECKED.value: PatchState.TARGET_ARMED.value,
  PatchState.TARGET_COMMITTED.value: PatchState.CRC_PRECHECKED.value,
  PatchState.CRC_PRECHECKED.value: PatchState.CRC_ARMED.value,
  PatchState.CRC_COMMITTED.value: PatchState.VERIFY_PENDING.value,
}


class _PlannedPowerCycle(Exception):
  def __init__(self, path: Path, checkpoint: PowerCycleCheckpoint) -> None:
    super().__init__(checkpoint.completed_state)
    self.path = path
    self.checkpoint = checkpoint


class _StateRecorder:
  def __init__(
    self,
    directory: Path,
    *,
    timestamp: str,
    evidence: TrustedProbeEvidence,
    transitions: list[dict[str, object]] | None = None,
  ) -> None:
    self.path = directory / "state.json"
    self.timestamp = timestamp
    self.evidence = evidence
    self.transitions = list(transitions or [])

  def record(
    self,
    state: PatchState,
    *,
    restore_order: tuple[str, ...] = (),
    evidence: dict[str, object] | None = None,
    error: str | None = None,
    power_cycle: PowerCycleCheckpoint | None = None,
  ) -> Path:
    if tuple(restore_order) not in ((), ("target",), ("crc", "target")):
      raise PatchError("patch restore order is not canonical")
    transition: dict[str, object] = {
      "sequence": len(self.transitions),
      "result": state.value,
      "recorded_at": _now(),
      "evidence": evidence or {},
    }
    if error is not None:
      transition["error"] = error
    self.transitions.append(transition)
    try:
      report: dict[str, object] = {
        "schema": 2,
        "workflow": "patch",
        "attempt": self.timestamp,
        "sequence": transition["sequence"],
        "result": state.value,
        "restore_order": list(restore_order),
        "created_at": self.transitions[0]["recorded_at"],
        "updated_at": transition["recorded_at"],
        "probe_report_sha256": sha256_bytes(
          json.dumps(
            self.evidence.report,
            sort_keys=True,
            separators=(",", ":"),
          ).encode("utf-8")
        ),
        "automatic_forward_resume": False,
        "automatic_retry": False,
        "power_cycle": None if power_cycle is None else power_cycle.as_dict(),
        "transitions": self.transitions,
        "validation_errors": [],
      }
      _atomic_replace_json(self.path, report)
    except BaseException:
      self.transitions.pop()
      raise
    return self.path


def run_patch(
  *,
  layout: ArtifactLayout,
  payloads,
  templates,
  preflight: Callable[[], object],
  transport_factory: Callable[[], object],
  confirmation: Callable[[str], object],
  power_cycle_checkpoint: Callable[[str], object],
  target: TargetManifest = TARGET,
  new_uds: bool,
) -> Path:
  """Run one patch workflow while excluding every concurrent restore/patch."""
  with exclusive_operation(layout, "patch"):
    return _run_patch_locked(
      layout=layout,
      payloads=payloads,
      templates=templates,
      preflight=preflight,
      transport_factory=transport_factory,
      confirmation=confirmation,
      power_cycle_checkpoint=power_cycle_checkpoint,
      target=target,
      new_uds=new_uds,
    )


def _run_patch_locked(
  *,
  layout: ArtifactLayout,
  payloads,
  templates,
  preflight: Callable[[], object],
  transport_factory: Callable[[], object],
  confirmation: Callable[[str], object],
  power_cycle_checkpoint: Callable[[str], object],
  target: TargetManifest = TARGET,
  new_uds: bool,
) -> Path:
  """Run one safe patch stage or persist one planned restart boundary."""
  _validate_inputs(
    layout=layout,
    preflight=preflight,
    transport_factory=transport_factory,
    confirmation=confirmation,
    power_cycle_checkpoint=power_cycle_checkpoint,
    target=target,
    new_uds=new_uds,
  )
  patch_payloads = _validate_payloads(payloads, target)
  writer_templates = _validate_templates(templates)
  resume = _select_patch_resume(layout)
  _reject_unresolved_patch_incident(
    layout,
    resumable_timestamp=None if resume is None else resume[1].name,
  )
  try:
    trusted = load_probe_pass(layout, target)
  except EvidenceError as exc:
    raise PatchError(f"fixed probe evidence is not a semantic PASS: {exc}") from exc
  candidate = _candidate_from_probe(trusted, target)
  legacy_recovery: str | None = None
  if resume is None:
    timestamp, directory = _create_attempt(layout)
    recorder = _StateRecorder(directory, timestamp=timestamp, evidence=trusted)
    entry: PatchState | None = None
  else:
    state, directory = resume
    semantic_probe_digest = sha256_bytes(json.dumps(
      trusted.report,
      sort_keys=True,
      separators=(",", ":"),
    ).encode("utf-8"))
    if state["probe_report_sha256"] != semantic_probe_digest:
      raise PatchError("resumable patch is not bound to fixed probe evidence")
    timestamp = directory.name
    recorder = _StateRecorder(
      directory,
      timestamp=timestamp,
      evidence=trusted,
      transitions=state["transitions"],
    )
    entry = PatchState(state["result"])
    from .restore import _legacy_crc_trigger_recovery_status

    legacy_recovery = _legacy_crc_trigger_recovery_status(state["transitions"])
    if legacy_recovery in {"pending", "consumed"}:
      _validate_legacy_crc_trigger_evidence(
        state=state,
        trusted=trusted,
        candidate=candidate,
        target=target,
        live_read=patch_payloads["live_read"],
        template=writer_templates["write_crc_candidate"],
      )

  if entry is PatchState.CRC_INDETERMINATE:
    try:
      preflight()
      with transport_factory() as transport:
        boot_identity = transport.read_bootloader_identity()
        _require_boot_identity(boot_identity, trusted.identity)
        live = transport.run_payload(
          patch_payloads["live_read"],
          operation=OP_LIVE_READ,
          new_uds=new_uds,
        )
      classification = _validate_crc_reconciliation(live, candidate, target)
    except PatchError:
      raise
    except Exception as exc:
      raise PatchError(
        f"CRC reconciliation failed before any writer was armed: {exc}"
      ) from exc
    if classification == "source":
      reconciled_state = PatchState.CRC_PRECHECKED
      restore_order = ("target",)
      checkpoint = PowerCycleCheckpoint(
        PatchState.CRC_PRECHECKED.value,
        PatchState.CRC_ARMED.value,
      )
    else:
      reconciled_state = PatchState.CRC_COMMITTED
      restore_order = ("crc", "target")
      checkpoint = PowerCycleCheckpoint(
        PatchState.CRC_COMMITTED.value,
        PatchState.VERIFY_PENDING.value,
      )
    live_target, live_crc = _regions(live, target, "CRC reconciliation")
    reconciliation_evidence = {
      "identity": _boot_identity_record(boot_identity),
      "reconciled_from": PatchState.CRC_INDETERMINATE.value,
      "reconciled_sequence": state["sequence"],
      "classification": classification,
      "target_readback_sha256": sha256_bytes(live_target),
      "crc_readback_sha256": sha256_bytes(live_crc),
      "payload": _payload_record(patch_payloads["live_read"]),
    }
    if legacy_recovery == "pending":
      reconciliation_evidence.update({
        "legacy_trigger_recovery": "nrc31-route-v1",
        "legacy_trigger_rejection_sequence": state["sequence"],
      })
    path = recorder.record(
      reconciled_state,
      restore_order=restore_order,
      evidence=reconciliation_evidence,
      power_cycle=checkpoint,
    )
    request_power_cycle(
      checkpoint.completed_state,
      checkpoint.next_state,
      power_cycle_checkpoint,
    )
    return path
  phase = PatchState.STARTED if entry is None else entry

  target_candidate_crc = binascii.crc32(candidate.target_final)
  crc_candidate_crc = binascii.crc32(candidate.crc_final)
  source_target_crc = binascii.crc32(candidate.target_source)
  source_crc_crc = binascii.crc32(candidate.crc_source)
  planned: _PlannedPowerCycle | None = None

  try:
    if entry is None:
      recorder.record(
        PatchState.STARTED,
        evidence={"probe_report": str(layout.probe_report)},
      )
      preflight()
      checkpoint = PowerCycleCheckpoint(
        PatchState.PROBED.value,
        PatchState.TARGET_PRECHECKED.value,
      )
      path = recorder.record(
        PatchState.PROBED,
        evidence={
          "identity": _identity_record(trusted.identity),
          "target_source_sha256": sha256_bytes(candidate.target_source),
          "crc_source_sha256": sha256_bytes(candidate.crc_source),
          "target_candidate_sha256": sha256_bytes(candidate.target_final),
          "crc_candidate_sha256": sha256_bytes(candidate.crc_final),
        },
        power_cycle=checkpoint,
      )
      raise _PlannedPowerCycle(path, checkpoint)

    preflight()
    if entry is PatchState.PROBED:
      with transport_factory() as transport:
        current_identity = transport.read_identity()
        _require_application_identity(current_identity, trusted.identity, target)
        target_precheck = transport.run_payload(
          patch_payloads["crc_probe"],
          operation=OP_CRC_PROBE,
          new_uds=new_uds,
        )
      _validate_target_precheck(target_precheck, candidate, target)
      precheck_target, precheck_crc = _regions(
        target_precheck, target, "target precheck",
      )
      _persist_sector(directory / "precheck-target-source.bin", precheck_target, target)
      _persist_sector(directory / "precheck-crc-source.bin", precheck_crc, target)
      checkpoint = PowerCycleCheckpoint(
        PatchState.TARGET_PRECHECKED.value,
        PatchState.TARGET_ARMED.value,
      )
      path = recorder.record(
        PatchState.TARGET_PRECHECKED,
        evidence={
          "identity": _identity_record(current_identity),
          "target_readback_sha256": sha256_bytes(precheck_target),
          "crc_readback_sha256": sha256_bytes(precheck_crc),
          "target_candidate_crc32": f"0x{target_candidate_crc:08x}",
          "payload": _payload_record(patch_payloads["crc_probe"]),
        },
        power_cycle=checkpoint,
      )
      raise _PlannedPowerCycle(path, checkpoint)

    if entry is PatchState.TARGET_PRECHECKED:
      target_intent = CandidateWriterIntent.for_target(
        live_target_crc32=source_target_crc,
        live_crc_crc32=source_crc_crc,
        candidate_crc32=target_candidate_crc,
        live_target_instruction=target.original_instruction,
        live_adjustment=candidate.old_adjustment,
        candidate_context=target.patched_instruction,
        candidate_adjustment=candidate.new_adjustment,
      )
      target_writer = build_target_candidate_payload_image(
        template=writer_templates["write_target_candidate"],
        manifest=REVIEWED_TEMPLATE_MANIFESTS["write_target_candidate"],
        intent=target_intent,
      )
      target_prompt = _writer_prompt(
        "TARGET",
        target=target,
        sector_base=target.sector_base,
        source=candidate.target_source,
        candidate=candidate.target_final,
        candidate_crc32=target_candidate_crc,
        envelope_sha256=target_writer.payload.sha256,
      )
      with transport_factory() as transport:
        current_identity = transport.read_identity()
        _require_application_identity(current_identity, trusted.identity, target)
        target_confirmation = _require_exact_confirmation(
          confirmation, target_prompt, label="target writer",
        )
        recorder.record(
          PatchState.TARGET_ARMED,
          restore_order=("target",),
          evidence={
            "identity": _identity_record(current_identity),
            "confirmation": target_confirmation,
            "operation": OP_WRITE_TARGET_CANDIDATE,
            "sector_base": f"0x{target.sector_base:x}",
            "source_sha256": sha256_bytes(candidate.target_source),
            "candidate_sha256": sha256_bytes(candidate.target_final),
            "candidate_crc32": f"0x{target_candidate_crc:08x}",
            "payload": _writer_payload_record(target_writer),
          },
        )
        phase = PatchState.TARGET_ARMED
        target_result = transport.run_payload(
          target_writer.payload,
          operation=OP_WRITE_TARGET_CANDIDATE,
          new_uds=new_uds,
        )
      _validate_writer_result(
        target_result,
        operation=OP_WRITE_TARGET_CANDIDATE,
        expected_sector=candidate.target_final,
      )
      phase = PatchState.TARGET_COMMITTED
      _persist_sector(
        directory / "returned-target-candidate.bin", target_result.sector, target,
      )
      checkpoint = PowerCycleCheckpoint(
        PatchState.TARGET_COMMITTED.value,
        PatchState.CRC_PRECHECKED.value,
      )
      path = recorder.record(
        PatchState.TARGET_COMMITTED,
        restore_order=("target",),
        evidence={
          "returned_sha256": sha256_bytes(target_result.sector),
          "statuses": _status_records(target_result),
        },
        power_cycle=checkpoint,
      )
      raise _PlannedPowerCycle(path, checkpoint)

    if entry is PatchState.TARGET_COMMITTED:
      with transport_factory() as transport:
        boot_identity = transport.read_bootloader_identity()
        _require_boot_identity(boot_identity, trusted.identity)
        crc_precheck = transport.run_payload(
          patch_payloads["crc_intermediate"],
          operation=OP_CRC_INTERMEDIATE,
          new_uds=new_uds,
        )
      _validate_crc_precheck(crc_precheck, candidate, target)
      intermediate_target, intermediate_crc = _regions(
        crc_precheck, target, "CRC intermediate",
      )
      _persist_sector(
        directory / "intermediate-target-candidate.bin", intermediate_target, target,
      )
      _persist_sector(
        directory / "intermediate-crc-source.bin", intermediate_crc, target,
      )
      checkpoint = PowerCycleCheckpoint(
        PatchState.CRC_PRECHECKED.value,
        PatchState.CRC_ARMED.value,
      )
      path = recorder.record(
        PatchState.CRC_PRECHECKED,
        restore_order=("target",),
        evidence={
          "identity": _boot_identity_record(boot_identity),
          "target_readback_sha256": sha256_bytes(intermediate_target),
          "crc_readback_sha256": sha256_bytes(intermediate_crc),
          "crc_candidate_crc32": f"0x{crc_candidate_crc:08x}",
          "payload": _payload_record(patch_payloads["crc_intermediate"]),
        },
        power_cycle=checkpoint,
      )
      raise _PlannedPowerCycle(path, checkpoint)

    if entry is PatchState.CRC_PRECHECKED:
      crc_intent = CandidateWriterIntent.for_crc(
        live_target_crc32=target_candidate_crc,
        live_crc_crc32=source_crc_crc,
        candidate_crc32=crc_candidate_crc,
        live_target_instruction=target.patched_instruction,
        live_adjustment=candidate.old_adjustment,
        candidate_context=CANDIDATE_ADJUSTMENT,
        candidate_adjustment=candidate.new_adjustment,
      )
      crc_writer = build_crc_candidate_payload_image(
        template=writer_templates["write_crc_candidate"],
        manifest=REVIEWED_TEMPLATE_MANIFESTS["write_crc_candidate"],
        intent=crc_intent,
      )
      crc_prompt = _writer_prompt(
        "CRC",
        target=target,
        sector_base=target.crc_sector_base,
        source=candidate.crc_source,
        candidate=candidate.crc_final,
        candidate_crc32=crc_candidate_crc,
        envelope_sha256=crc_writer.payload.sha256,
      )
      with transport_factory() as transport:
        boot_identity = transport.read_bootloader_identity()
        _require_boot_identity(boot_identity, trusted.identity)
        crc_confirmation = _require_exact_confirmation(
          confirmation, crc_prompt, label="CRC writer",
        )
        recorder.record(
          PatchState.CRC_ARMED,
          restore_order=("crc", "target"),
          evidence={
            "identity": _boot_identity_record(boot_identity),
            "confirmation": crc_confirmation,
            "operation": OP_WRITE_CRC_CANDIDATE,
            "sector_base": f"0x{target.crc_sector_base:x}",
            "source_sha256": sha256_bytes(candidate.crc_source),
            "candidate_sha256": sha256_bytes(candidate.crc_final),
            "candidate_crc32": f"0x{crc_candidate_crc:08x}",
            "payload": _writer_payload_record(crc_writer),
          },
        )
        phase = PatchState.CRC_ARMED
        crc_result = transport.run_payload(
          crc_writer.payload,
          operation=OP_WRITE_CRC_CANDIDATE,
          new_uds=new_uds,
        )
      _validate_writer_result(
        crc_result,
        operation=OP_WRITE_CRC_CANDIDATE,
        expected_sector=candidate.crc_final,
      )
      phase = PatchState.CRC_COMMITTED
      _persist_sector(
        directory / "returned-crc-candidate.bin", crc_result.sector, target,
      )
      checkpoint = PowerCycleCheckpoint(
        PatchState.CRC_COMMITTED.value,
        PatchState.VERIFY_PENDING.value,
      )
      path = recorder.record(
        PatchState.CRC_COMMITTED,
        restore_order=("crc", "target"),
        evidence={
          "returned_sha256": sha256_bytes(crc_result.sector),
          "statuses": _status_records(crc_result),
        },
        power_cycle=checkpoint,
      )
      raise _PlannedPowerCycle(path, checkpoint)

    if entry is not PatchState.CRC_COMMITTED:
      raise PatchError("patch state is not restart-resumable")
    phase = PatchState.VERIFY_PENDING
    recorder.record(
      PatchState.VERIFY_PENDING,
      restore_order=("crc", "target"),
      evidence={
        "target_candidate_sha256": sha256_bytes(candidate.target_final),
        "crc_candidate_sha256": sha256_bytes(candidate.crc_final),
      },
    )
    with transport_factory() as transport:
      final_identity = transport.read_identity()
      _require_application_identity(final_identity, trusted.identity, target)
      verify_result = transport.run_payload(
        patch_payloads["crc_verify"], operation=OP_VERIFY_CRC, new_uds=new_uds,
      )
    observation = _validate_final_verify(verify_result, candidate, target)
    final_target, final_crc = _regions(verify_result, target, "final CRC verify")
    _persist_sector(directory / "final-readback-target.bin", final_target, target)
    _persist_sector(directory / "final-readback-crc.bin", final_crc, target)
    verify_report = {
      "schema": 1,
      "workflow": "verify-crc",
      "result": "PASS",
      "created_at": _now(),
      "identity": _identity_record(final_identity),
      "payload": _payload_record(patch_payloads["crc_verify"]),
      "target_sha256": sha256_bytes(final_target),
      "crc_sha256": sha256_bytes(final_crc),
      "software_crc": f"0x{observation.original_sw_full:08x}",
      "dcra_raw": f"0x{observation.original_dcra_raw:08x}",
      "validation_errors": [],
    }
    verify_path = directory / "verify-crc-report.json"
    _atomic_create(verify_path, _json_bytes(verify_report))
    state_path = recorder.record(
      PatchState.PASS,
      evidence={
        "identity": _identity_record(final_identity),
        "verify_report_sha256": sha256_bytes(verify_path.read_bytes()),
        "target_sha256": sha256_bytes(final_target),
        "crc_sha256": sha256_bytes(final_crc),
      },
    )
    final_report = {
      "schema": 1,
      "workflow": "patch",
      "result": "PASS",
      "created_at": _now(),
      "state_sha256": sha256_bytes(state_path.read_bytes()),
      "verify_report_sha256": sha256_bytes(verify_path.read_bytes()),
      "target_candidate_sha256": sha256_bytes(final_target),
      "crc_candidate_sha256": sha256_bytes(final_crc),
      "automatic_retry": False,
      "validation_errors": [],
    }
    report_path = directory / "patch-report.json"
    _atomic_create(report_path, _json_bytes(final_report))
    return report_path
  except _PlannedPowerCycle as exc:
    planned = exc
  except BaseException as exc:
    failure_state, restore_order = _failure_for_phase(phase)
    detail = f"{type(exc).__name__}: {exc}"
    try:
      recorder.record(failure_state, restore_order=restore_order, error=detail)
    except BaseException as state_exc:
      raise PatchError(
        f"patch failed and canonical state could not be persisted: {state_exc}"
      ) from exc
    raise PatchError(
      f"patch stopped in {failure_state.value}; no operation was retried: {exc}"
    ) from exc
  if planned is None:
    raise PatchError("patch did not produce a report or planned checkpoint")
  request_power_cycle(
    planned.checkpoint.completed_state,
    planned.checkpoint.next_state,
    power_cycle_checkpoint,
  )
  return planned.path


def _validate_inputs(
  *,
  layout,
  preflight,
  transport_factory,
  confirmation,
  power_cycle_checkpoint,
  target,
  new_uds,
) -> None:
  if not isinstance(layout, ArtifactLayout):
    raise TypeError("layout must be an ArtifactLayout")
  if not isinstance(target, TargetManifest):
    raise TypeError("target must be a TargetManifest")
  try:
    target.validate()
  except ValueError as exc:
    raise PatchError(f"target manifest is invalid: {exc}") from exc
  if type(new_uds) is not bool or new_uds is not target.new_uds:
    raise PatchError("patch UDS variant does not match the target")
  for callback, name in (
    (preflight, "preflight"),
    (transport_factory, "transport factory"),
    (confirmation, "writer confirmation"),
    (power_cycle_checkpoint, "power-cycle checkpoint"),
  ):
    if not callable(callback):
      raise TypeError(f"{name} must be callable")


def _container_value(container, name: str, *, label: str):
  if isinstance(container, Mapping):
    try:
      return container[name]
    except KeyError as exc:
      raise PatchError(f"{label} is missing {name}") from exc
  try:
    return getattr(container, name)
  except AttributeError as exc:
    raise PatchError(f"{label} is missing {name}") from exc


def _validate_payloads(payloads, target: TargetManifest) -> dict[str, object]:
  validated: dict[str, object] = {}
  for name, pinned_digest in _PAYLOAD_DIGESTS.items():
    payload = _container_value(payloads, name, label="patch payload set")
    try:
      payload_name = payload.name
      envelope = payload.envelope
      digest = payload.sha256
    except AttributeError as exc:
      raise PatchError(f"{name} payload image is malformed") from exc
    if payload_name != name:
      raise PatchError(f"{name} payload image has the wrong name")
    if type(envelope) is not bytes or len(envelope) != target.envelope_length:
      raise PatchError(f"{name} payload envelope is not exact")
    if (
      type(digest) is not str
      or hashlib.sha256(envelope).hexdigest() != digest
      or digest != pinned_digest
    ):
      raise PatchError(f"{name} payload is not the exact reviewed envelope")
    validated[name] = payload
  return validated


def _validate_templates(templates) -> dict[str, bytes]:
  validated: dict[str, bytes] = {}
  for name in _TEMPLATE_NAMES:
    template = _container_value(templates, name, label="patch template set")
    manifest = REVIEWED_TEMPLATE_MANIFESTS[name]
    if (
      type(template) is not bytes
      or len(template) != manifest.size
      or sha256_bytes(template) != manifest.sha256
    ):
      raise PatchError(f"{name} is not the exact reviewed writer template")
    validated[name] = template
  return validated


def _candidate_from_probe(
  trusted: TrustedProbeEvidence,
  target: TargetManifest,
) -> CrcCandidate:
  candidate = build_crc_candidate(
    trusted.target_sector,
    trusted.crc_sector,
    target.crc_patched_adjust_word.to_bytes(4, "little"),
    target=target,
  )
  expected_diffs = (
    (
      target.patch_address,
      target.original_instruction[3],
      target.patched_instruction[3],
    ),
    *tuple(
      (
        target.crc_adjust_address + offset,
        before,
        after,
      )
      for offset, (before, after) in enumerate(zip(
        target.crc_original_adjust_word.to_bytes(4, "little"),
        target.crc_patched_adjust_word.to_bytes(4, "little"),
      ))
      if before != after
    ),
  )
  if (
    sha256_bytes(candidate.target_source) != target.original_sha256
    or sha256_bytes(candidate.target_final) != target.patched_sha256
    or candidate.old_adjustment
      != target.crc_original_adjust_word.to_bytes(4, "little")
    or candidate.new_adjustment
      != target.crc_patched_adjust_word.to_bytes(4, "little")
    or candidate.absolute_diffs != expected_diffs
  ):
    raise PatchError("fixed probe evidence does not produce the exact two-sector candidate")
  return candidate


def _validate_legacy_crc_trigger_writer_evidence(
  *,
  state: dict[str, object],
  candidate: CrcCandidate,
  target: TargetManifest,
  template: bytes,
) -> None:
  target_candidate_crc = binascii.crc32(candidate.target_final)
  source_crc_crc = binascii.crc32(candidate.crc_source)
  crc_candidate_crc = binascii.crc32(candidate.crc_final)
  intent = CandidateWriterIntent.for_crc(
    live_target_crc32=target_candidate_crc,
    live_crc_crc32=source_crc_crc,
    candidate_crc32=crc_candidate_crc,
    live_target_instruction=target.patched_instruction,
    live_adjustment=candidate.old_adjustment,
    candidate_context=CANDIDATE_ADJUSTMENT,
    candidate_adjustment=candidate.new_adjustment,
  )
  try:
    expected_writer = build_crc_candidate_payload_image(
      template=template,
      manifest=REVIEWED_TEMPLATE_MANIFESTS["write_crc_candidate"],
      intent=intent,
    )
  except Exception as exc:
    raise PatchError("legacy CRC writer evidence cannot be reconstructed") from exc
  transitions = state.get("transitions")
  if type(transitions) is not list or len(transitions) < 2:
    raise PatchError("legacy CRC writer evidence is incomplete")
  incidents = [
    index for index, transition in enumerate(transitions)
    if type(transition) is dict
    and transition.get("result") == PatchState.CRC_INDETERMINATE.value
  ]
  if len(incidents) < 2 or incidents[1] < 1:
    raise PatchError("legacy CRC writer evidence is incomplete")
  second_arm = transitions[incidents[1] - 1]
  evidence = second_arm.get("evidence") if type(second_arm) is dict else None
  expected = {
    "operation": OP_WRITE_CRC_CANDIDATE,
    "sector_base": f"0x{target.crc_sector_base:x}",
    "source_sha256": sha256_bytes(candidate.crc_source),
    "candidate_sha256": sha256_bytes(candidate.crc_final),
    "candidate_crc32": f"0x{crc_candidate_crc:08x}",
    "payload": _writer_payload_record(expected_writer),
  }
  if type(evidence) is not dict or any(
    evidence.get(name) != value for name, value in expected.items()
  ):
    raise PatchError("legacy CRC writer evidence does not match the reviewed writer")


def _validate_legacy_crc_trigger_evidence(
  *,
  state: dict[str, object],
  trusted: TrustedProbeEvidence,
  candidate: CrcCandidate,
  target: TargetManifest,
  live_read,
  template: bytes,
) -> None:
  from .restore import _legacy_crc_trigger_recovery_status

  transitions = state.get("transitions")
  if type(transitions) is not list:
    raise PatchError("legacy CRC recovery evidence is incomplete")
  status = _legacy_crc_trigger_recovery_status(transitions)
  if status not in {"pending", "consumed"}:
    raise PatchError("legacy CRC recovery evidence is not exact")
  incidents = [
    index for index, transition in enumerate(transitions)
    if type(transition) is dict
    and transition.get("result") == PatchState.CRC_INDETERMINATE.value
  ]
  if len(incidents) != 2:
    raise PatchError("legacy CRC recovery evidence is incomplete")
  first_index, second_index = incidents
  probed = next(
    (
      transition for transition in transitions[:first_index]
      if type(transition) is dict
      and transition.get("result") == PatchState.PROBED.value
    ),
    None,
  )
  first = transitions[first_index]
  first_reconciliation = transitions[first_index + 1]
  second_arm = transitions[second_index - 1]
  probed_evidence = probed.get("evidence") if type(probed) is dict else None
  first_evidence = (
    first_reconciliation.get("evidence")
    if type(first_reconciliation) is dict else None
  )
  second_arm_evidence = (
    second_arm.get("evidence") if type(second_arm) is dict else None
  )
  expected_boot_identity = {
    "boot_software_id": trusted.identity.boot_software_id.hex(),
    "panda_serial": trusted.identity.panda_serial,
  }
  expected_live_read = _payload_record(live_read)
  expected_probed = {
    "identity": _identity_record(trusted.identity),
    "target_source_sha256": sha256_bytes(candidate.target_source),
    "crc_source_sha256": sha256_bytes(candidate.crc_source),
    "target_candidate_sha256": sha256_bytes(candidate.target_final),
    "crc_candidate_sha256": sha256_bytes(candidate.crc_final),
  }
  expected_first = {
    "identity": expected_boot_identity,
    "reconciled_from": PatchState.CRC_INDETERMINATE.value,
    "reconciled_sequence": first.get("sequence") if type(first) is dict else None,
    "classification": "source",
    "target_readback_sha256": sha256_bytes(candidate.target_final),
    "crc_readback_sha256": sha256_bytes(candidate.crc_source),
    "payload": expected_live_read,
  }
  if (
    type(probed_evidence) is not dict
    or any(probed_evidence.get(name) != value for name, value in expected_probed.items())
    or type(first_evidence) is not dict
    or any(first_evidence.get(name) != value for name, value in expected_first.items())
    or type(second_arm_evidence) is not dict
    or second_arm_evidence.get("identity") != expected_boot_identity
  ):
    raise PatchError("legacy CRC recovery evidence does not match trusted evidence")
  _validate_legacy_crc_trigger_writer_evidence(
    state=state,
    candidate=candidate,
    target=target,
    template=template,
  )
  if status == "pending":
    return
  consuming = transitions[second_index + 1]
  consuming_evidence = (
    consuming.get("evidence") if type(consuming) is dict else None
  )
  classification = {
    PatchState.CRC_PRECHECKED.value: "source",
    PatchState.CRC_COMMITTED.value: "candidate",
  }.get(consuming.get("result") if type(consuming) is dict else None)
  expected_consuming = {
    "identity": expected_boot_identity,
    "reconciled_from": PatchState.CRC_INDETERMINATE.value,
    "reconciled_sequence": second_index,
    "classification": classification,
    "target_readback_sha256": sha256_bytes(candidate.target_final),
    "crc_readback_sha256": sha256_bytes(
      candidate.crc_source if classification == "source" else candidate.crc_final
    ),
    "payload": expected_live_read,
    "legacy_trigger_recovery": "nrc31-route-v1",
    "legacy_trigger_rejection_sequence": second_index,
  }
  if (
    classification is None
    or type(consuming_evidence) is not dict
    or any(
      consuming_evidence.get(name) != value
      for name, value in expected_consuming.items()
    )
  ):
    raise PatchError("legacy CRC consumption does not match trusted evidence")


def _reject_unresolved_patch_incident(
  layout: ArtifactLayout,
  *,
  resumable_timestamp: str | None = None,
) -> None:
  """Require a successful restore for every recoverable patch incident."""
  from .restore import (
    RestoreError,
    _recoverable_restore_plans,
    _reject_prior_restore,
  )

  try:
    incidents = _recoverable_restore_plans(layout)
  except RestoreError as exc:
    raise PatchError("cannot verify persisted patch incident state") from exc
  for incident in incidents:
    if incident.incident_timestamp == resumable_timestamp:
      continue
    try:
      if _reject_prior_restore(layout, incident, allow_selected_pass=True):
        continue
    except RestoreError as exc:
      raise PatchError("cannot verify persisted restore state") from exc
    raise PatchError(
      "unresolved patch incident requires restore before another patch "
      f"({incident.incident_timestamp})"
    )


def _select_patch_resume(
  layout: ArtifactLayout,
) -> tuple[dict[str, object], Path] | None:
  """Select at most one exact schema-2 planned checkpoint."""
  from .restore import (
    RestoreError,
    _ATTEMPT_TIMESTAMP,
    _legacy_crc_trigger_recovery_status,
    _load_patch_state,
    _recoverable_restore_plans,
    _reject_prior_restore,
  )

  try:
    entries = list(layout.patch_root.iterdir())
  except FileNotFoundError:
    return None
  except OSError as exc:
    raise PatchError("cannot inspect persisted patch attempts") from exc
  try:
    incident_by_timestamp = {
      plan.incident_timestamp: plan
      for plan in _recoverable_restore_plans(layout)
    }
  except RestoreError as exc:
    raise PatchError("cannot verify persisted patch incident state") from exc
  resumable: list[tuple[dict[str, object], Path]] = []
  for directory in sorted(entries, key=lambda path: path.name, reverse=True):
    if (
      _ATTEMPT_TIMESTAMP.fullmatch(directory.name) is None
      or not directory.is_dir()
      or directory.is_symlink()
    ):
      raise PatchError("patch state layout contains an invalid attempt entry")
    try:
      state, _raw = _load_patch_state(directory / "state.json", directory.name)
    except RestoreError as exc:
      raise PatchError("cannot validate persisted patch attempt state") from exc
    indeterminate_count = sum(
      transition["result"] == PatchState.CRC_INDETERMINATE.value
      for transition in state["transitions"]
    )
    legacy_recovery = _legacy_crc_trigger_recovery_status(state["transitions"])
    planned_resume = (
      state["schema"] == 2
      and state["power_cycle"] is not None
      and (indeterminate_count <= 1 or legacy_recovery == "consumed")
    )
    indeterminate_resume = (
      state["schema"] == 2
      and state["result"] == PatchState.CRC_INDETERMINATE.value
      and state["power_cycle"] is None
      and (indeterminate_count == 1 or legacy_recovery == "pending")
    )
    if not planned_resume and not indeterminate_resume:
      continue
    incident = incident_by_timestamp.get(directory.name)
    if incident is not None:
      try:
        if _reject_prior_restore(layout, incident, allow_selected_pass=True):
          continue
      except RestoreError as exc:
        raise PatchError("cannot verify persisted restore state") from exc
    resumable.append((state, directory))
  if len(resumable) > 1:
    raise PatchError("multiple resumable patch attempts exist")
  return resumable[0] if resumable else None


def _require_application_identity(
  current: object,
  expected: EcuIdentity,
  target: TargetManifest,
) -> None:
  if (
    type(current) is not EcuIdentity
    or current != expected
    or current.part_number != target.part_number
    or current.application_software_id != target.application_software_id
    or current.boot_software_id != target.boot_software_id
    or not current.panda_serial
  ):
    raise PatchError("fresh application identity does not match fixed probe evidence")


def _require_boot_identity(current: object, expected: EcuIdentity) -> None:
  if (
    type(current) is not BootloaderIdentity
    or current.software_id != expected.boot_software_id
    or current.panda_serial != expected.panda_serial
    or not current.panda_serial
  ):
    raise PatchError("fresh bootloader identity does not match fixed probe evidence")


def _regions(
  result: object,
  target: TargetManifest,
  label: str,
) -> tuple[bytes, bytes]:
  if (
    type(result) is not StreamResult
    or type(result.regions) is not tuple
    or len(result.regions) != 2
    or any(type(region) is not RegionResult for region in result.regions)
    or tuple(region.base for region in result.regions)
      != (target.sector_base, target.crc_sector_base)
    or any(
      type(region.data) is not bytes or len(region.data) != target.sector_length
      for region in result.regions
    )
  ):
    raise PatchError(f"{label} has no complete exact two-sector readback")
  return result.regions[0].data, result.regions[1].data


def _crc_record_values(observation: CrcObservation) -> tuple[int, ...]:
  return tuple(getattr(observation, field.name) for field in fields(CrcObservation))


def _validate_crc_reconciliation(
  result: object,
  candidate: CrcCandidate,
  target: TargetManifest,
) -> str:
  target_live, crc_live = _regions(result, target, "CRC reconciliation")
  if (
    result.operation != OP_LIVE_READ
    or result.sector is not None
    or result.magic_words != (target.magic_word, target.magic_word)
    or result.statuses != ((1, 0),)
    or result.faci_values
    or result.crc_values
    or result.crc is not None
    or result.dcra_values
    or result.dcra is not None
  ):
    raise PatchError("CRC reconciliation live-read contract is not exact")
  if target_live != candidate.target_final:
    raise PatchError("CRC reconciliation target sector is not the exact candidate")
  if crc_live == candidate.crc_source:
    return "source"
  if crc_live == candidate.crc_final:
    return "candidate"
  raise PatchError(
    "CRC reconciliation found a partial or unknown CRC sector; restore is required"
  )


def _validate_crc_structure(
  result: object,
  *,
  operation: int,
  target: TargetManifest,
  label: str,
) -> tuple[bytes, bytes, CrcObservation]:
  target_sector, crc_sector = _regions(result, target, label)
  if (
    result.operation != operation
    or result.sector is not None
    or result.magic_words != (target.magic_word, target.magic_word)
    or result.statuses != ((1, 0),)
    or type(result.crc) is not CrcObservation
  ):
    raise PatchError(f"{label} stream contract is not exact")
  values = _crc_record_values(result.crc)
  if (
    type(result.crc_values) is not tuple
    or result.crc_values != values
    or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in values)
  ):
    raise PatchError(f"{label} CRC/DCRA records are not exact uint32 evidence")
  return target_sector, crc_sector, result.crc


def _validate_target_precheck(
  result: object,
  candidate: CrcCandidate,
  target: TargetManifest,
) -> None:
  target_live, crc_live, observation = _validate_crc_structure(
    result,
    operation=OP_CRC_PROBE,
    target=target,
    label="target precheck",
  )
  if target_live != candidate.target_source or crc_live != candidate.crc_source:
    raise PatchError("target precheck live sectors differ from fixed probe evidence")
  expected_adjustment = int.from_bytes(candidate.new_adjustment, "little")
  if (
    (observation.range_start, observation.range_end, observation.adjust_address)
      != (target.crc_range_start, target.crc_range_end, target.crc_adjust_address)
    or observation.old_adjust_word != int.from_bytes(candidate.old_adjustment, "little")
    or observation.new_adjust_word != expected_adjustment
    or observation.patched_prefix_sw != (expected_adjustment ^ target.crc_residue)
    or any(value != target.crc_residue for value in (
      observation.original_sw_full,
      observation.patched_sw_full,
      observation.original_dcra_raw,
      observation.patched_dcra_raw,
    ))
    or (observation.exit_ctl, observation.exit_cout)
      != (observation.entry_ctl, observation.entry_cout)
    or (observation.sram_echo_length, observation.sram_echo_crc32) != (0, 0)
  ):
    raise PatchError("target precheck CRC/software/DCRA agreement failed")


def _validate_crc_precheck(
  result: object,
  candidate: CrcCandidate,
  target: TargetManifest,
) -> None:
  try:
    validate_crc_intermediate(result)
  except Exception as exc:
    raise PatchError(f"CRC intermediate validation failed: {exc}") from exc
  target_live, crc_live = _regions(result, target, "CRC intermediate")
  if target_live != candidate.target_final or crc_live != candidate.crc_source:
    raise PatchError("CRC intermediate live sectors are not exact")


def _validate_writer_result(
  result: object,
  *,
  operation: int,
  expected_sector: bytes,
) -> None:
  try:
    require_candidate_writer_pass(result)
  except Exception as exc:
    raise PatchError(f"candidate writer PASS evidence failed: {exc}") from exc
  if result.operation != operation or result.sector != expected_sector:
    raise PatchError("candidate writer readback or fixed direction is not exact")


def _validate_final_verify(
  result: object,
  candidate: CrcCandidate,
  target: TargetManifest,
) -> CrcObservation:
  target_live, crc_live, observation = _validate_crc_structure(
    result,
    operation=OP_VERIFY_CRC,
    target=target,
    label="final CRC verify",
  )
  if target_live != candidate.target_final or crc_live != candidate.crc_final:
    raise PatchError("final CRC verify sectors are not the exact candidates")
  adjustment = int.from_bytes(candidate.new_adjustment, "little")
  if (
    (observation.range_start, observation.range_end, observation.adjust_address)
      != (target.crc_range_start, target.crc_range_end, target.crc_adjust_address)
    or observation.old_adjust_word != adjustment
    or observation.new_adjust_word != adjustment
    or observation.patched_prefix_sw != (adjustment ^ target.crc_residue)
    or any(value != target.crc_residue for value in (
      observation.original_sw_full,
      observation.patched_sw_full,
      observation.original_dcra_raw,
      observation.patched_dcra_raw,
    ))
    or (observation.exit_ctl, observation.exit_cout)
      != (observation.entry_ctl, observation.entry_cout)
    or (observation.sram_echo_length, observation.sram_echo_crc32) != (0, 0)
  ):
    raise PatchError("final CRC/software/DCRA agreement failed")
  return observation


def _require_exact_confirmation(
  callback: Callable[[str], object],
  prompt: str,
  *,
  label: str,
) -> str:
  response = callback(prompt)
  if type(response) is not str or response != prompt:
    raise PatchError(f"{label} confirmation text does not match exactly")
  return response


def _writer_prompt(
  label: str,
  *,
  target: TargetManifest,
  sector_base: int,
  source: bytes,
  candidate: bytes,
  candidate_crc32: int,
  envelope_sha256: str,
) -> str:
  return (
    f"WRITE-{label} {target.part_number.decode('ascii')} 0x{sector_base:x} "
    f"{sha256_bytes(source)}->{sha256_bytes(candidate)} "
    f"0x{candidate_crc32:08x} {envelope_sha256}"
  )


def _failure_for_phase(phase: PatchState) -> tuple[PatchState, tuple[str, ...]]:
  if phase is PatchState.TARGET_ARMED:
    return PatchState.TARGET_INDETERMINATE, ("target",)
  if phase in (PatchState.TARGET_COMMITTED, PatchState.CRC_PRECHECKED):
    return PatchState.RECOVERY_REQUIRED, ("target",)
  if phase is PatchState.CRC_ARMED:
    return PatchState.CRC_INDETERMINATE, ("crc", "target")
  if phase in (PatchState.CRC_COMMITTED, PatchState.VERIFY_PENDING):
    return PatchState.RECOVERY_REQUIRED, ("crc", "target")
  return PatchState.FAILED, ()


def _create_attempt(layout: ArtifactLayout) -> tuple[str, Path]:
  instant = datetime.now(timezone.utc).replace(microsecond=0)
  layout.patch_root.mkdir(parents=True, exist_ok=True)
  for offset in range(86_400):
    timestamp = (instant + timedelta(seconds=offset)).strftime("%Y%m%dT%H%M%SZ")
    directory = layout.patch_attempt(timestamp)
    try:
      directory.mkdir(parents=False, exist_ok=False)
    except FileExistsError:
      continue
    return timestamp, directory
  raise PatchError("cannot allocate a unique UTC patch attempt directory")


def _persist_sector(path: Path, sector: bytes, target: TargetManifest) -> None:
  if type(sector) is not bytes or len(sector) != target.sector_length:
    raise PatchError(f"{path.name} is not one exact sector")
  _atomic_create(path, sector)


def _status_records(result: StreamResult) -> list[dict[str, int]]:
  return [{"stage": stage, "code": code} for stage, code in result.statuses]


def _identity_record(identity: EcuIdentity) -> dict[str, str]:
  try:
    part_number = identity.part_number.decode("ascii", errors="strict")
  except UnicodeDecodeError as exc:
    raise PatchError("ECU part number is not ASCII") from exc
  return {
    "part_number": part_number,
    "application_software_id": identity.application_software_id.hex(),
    "boot_software_id": identity.boot_software_id.hex(),
    "panda_serial": identity.panda_serial,
  }


def _boot_identity_record(identity: BootloaderIdentity) -> dict[str, str]:
  return {
    "boot_software_id": identity.software_id.hex(),
    "panda_serial": identity.panda_serial,
  }


def _payload_record(payload) -> dict[str, str]:
  return {"name": payload.name, "sha256": payload.sha256}


def _writer_payload_record(image) -> dict[str, str]:
  return {
    "name": image.payload.name,
    "template_sha256": image.payload.manifest.sha256,
    "review_sha256": image.payload.manifest.review_sha256,
    "intent_sha256": sha256_bytes(image.intent.to_bytes()),
    "envelope_sha256": image.payload.sha256,
  }


def _now() -> str:
  return datetime.now(timezone.utc).isoformat()


def _json_bytes(report: dict[str, object]) -> bytes:
  return (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _atomic_replace_json(path: Path, report: dict[str, object]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  fd, temporary = tempfile.mkstemp(
    prefix=f".{path.name}.",
    suffix=".tmp",
    dir=path.parent,
  )
  try:
    with os.fdopen(fd, "wb") as stream:
      stream.write(_json_bytes(report))
      stream.flush()
      os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
      os.fsync(directory_fd)
    finally:
      os.close(directory_fd)
  finally:
    try:
      os.unlink(temporary)
    except FileNotFoundError:
      pass


__all__ = [
  "CRC_INTERMEDIATE_ENVELOPE_SHA256",
  "CRC_PROBE_ENVELOPE_SHA256",
  "CRC_VERIFY_ENVELOPE_SHA256",
  "PatchError",
  "PatchState",
  "run_patch",
]
