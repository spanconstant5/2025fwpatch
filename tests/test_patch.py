import binascii
import hashlib
import inspect
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from eps_patch.evidence import install_probe_pass
from eps_patch.manifest import TARGET
from eps_patch.paths import ArtifactLayout
from eps_patch.protocol import (
  CrcObservation,
  OP_CRC_INTERMEDIATE,
  OP_LIVE_READ,
  OP_CRC_PROBE,
  OP_VERIFY_CRC,
  OP_WRITE_CRC_CANDIDATE,
  OP_WRITE_TARGET_CANDIDATE,
  RegionResult,
  StreamResult,
)
from eps_patch.transport import (
  BootloaderIdentity, EcuIdentity, PostTriggerTransportError,
)

import test_evidence as evidence_fx


OLD_ADJUSTMENT = TARGET.crc_original_adjust_word.to_bytes(4, "little")
NEW_ADJUSTMENT = TARGET.crc_patched_adjust_word.to_bytes(4, "little")
LIVE_READ_ENVELOPE_SHA256 = (
  "4efdeeca07e98b3ae9f1df68b49521f9931b0938204d33ca543f6b78ccae4dd0"
)
LEGACY_UNKNOWN_FRAME_ERROR = (
  "PostTriggerTransportError: post-trigger destructive outcome is indeterminate: "
  "invalid payload stream: unknown frame type 0x03"
)
LEGACY_NRC31_ERROR = (
  "PostTriggerTransportError: post-trigger destructive outcome is indeterminate: "
  "RoutineControl negative response NRC 0x31; raw=037f313100000000"
)


def _case(layout: ArtifactLayout):
  target_source = bytearray((index * 17) & 0xFF for index in range(TARGET.sector_length))
  target_source[TARGET.instruction_offset:TARGET.instruction_offset + 4] = TARGET.original_instruction
  target_source = bytes(target_source)
  target_candidate = bytearray(target_source)
  target_candidate[TARGET.patch_offset] = TARGET.patched_instruction[3]
  target_candidate = bytes(target_candidate)
  crc_source = bytearray((index * 29) & 0xFF for index in range(TARGET.sector_length))
  crc_source[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4] = OLD_ADJUSTMENT
  magic_offset = TARGET.magic_addresses[1] - TARGET.crc_sector_base
  crc_source[magic_offset:magic_offset + 4] = TARGET.magic_word.to_bytes(4, "little")
  crc_source = bytes(crc_source)
  crc_candidate = bytearray(crc_source)
  crc_candidate[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4] = NEW_ADJUSTMENT
  crc_candidate = bytes(crc_candidate)
  target = replace(
    TARGET,
    original_sha256=hashlib.sha256(target_source).hexdigest(),
    patched_sha256=hashlib.sha256(target_candidate).hexdigest(),
  )
  report = evidence_fx.make_report(target_source, crc_source)
  metadata = evidence_fx.make_metadata(target_source, crc_source)
  install_probe_pass(layout, target_source, crc_source, report, metadata)
  identity = EcuIdentity(
    part_number=target.part_number,
    application_software_id=target.application_software_id,
    boot_software_id=target.boot_software_id,
    panda_serial="test-panda",
  )
  return target, identity, target_source, crc_source, target_candidate, crc_candidate


def _observation(*, old_adjustment, target_candidate, crc_candidate, final=False):
  return CrcObservation(
    entry_ctl=0x10203040,
    entry_cout=0x50607080,
    range_start=TARGET.crc_range_start,
    range_end=TARGET.crc_range_end,
    adjust_address=TARGET.crc_adjust_address,
    old_adjust_word=int.from_bytes(old_adjustment, "little"),
    patched_prefix_sw=TARGET.crc_patched_prefix_sw,
    new_adjust_word=TARGET.crc_patched_adjust_word,
    original_sw_full=TARGET.crc_residue,
    patched_sw_full=TARGET.crc_residue,
    original_dcra_raw=TARGET.crc_residue,
    patched_dcra_raw=TARGET.crc_residue,
    exit_ctl=0x10203040,
    exit_cout=0x50607080,
    sram_echo_length=0,
    sram_echo_crc32=0,
  )


def _crc_result(operation, target_sector, crc_sector, observation):
  values = tuple(
    getattr(observation, name)
    for name in (
      "entry_ctl", "entry_cout", "range_start", "range_end", "adjust_address",
      "old_adjust_word", "patched_prefix_sw", "new_adjust_word",
      "original_sw_full", "patched_sw_full", "original_dcra_raw",
      "patched_dcra_raw", "exit_ctl", "exit_cout", "sram_echo_length",
      "sram_echo_crc32",
    )
  )
  return StreamResult(
    operation=operation,
    sector=None,
    magic_words=(TARGET.magic_word, TARGET.magic_word),
    statuses=((1, 0),),
    regions=(
      RegionResult(TARGET.sector_base, target_sector),
      RegionResult(TARGET.crc_sector_base, crc_sector),
    ),
    crc_values=values,
    crc=observation,
  )


def _writer_result(operation, sector_base, sector):
  return StreamResult(
    operation=operation,
    sector=sector,
    magic_words=(TARGET.magic_word, TARGET.magic_word),
    statuses=tuple((stage, 0) for stage in range(1, 7)),
    regions=(RegionResult(sector_base, sector),),
  )


def _live_read_result(target_sector, crc_sector):
  return StreamResult(
    operation=OP_LIVE_READ,
    sector=None,
    magic_words=(TARGET.magic_word, TARGET.magic_word),
    statuses=((1, 0),),
    regions=(
      RegionResult(TARGET.sector_base, target_sector),
      RegionResult(TARGET.crc_sector_base, crc_sector),
    ),
  )


class FakeTransport:
  def __init__(self, label, events, identity, result, *, failure=None, boot=False):
    self.label = label
    self.events = events
    self.identity = identity
    self.result = result
    self.failure = failure
    self.boot = boot

  def __enter__(self):
    self.events.append((self.label, "open"))
    return self

  def __exit__(self, *_args):
    self.events.append((self.label, "close"))

  def read_identity(self):
    self.events.append((self.label, "identity"))
    return self.identity

  def read_bootloader_identity(self):
    self.events.append((self.label, "boot-identity"))
    return BootloaderIdentity(self.identity.boot_software_id, self.identity.panda_serial)

  def run_payload(self, _image, *, operation, new_uds):
    self.events.append((self.label, "payload", operation))
    if self.failure is not None:
      raise self.failure
    return self.result


def _payloads():
  from eps_patch.payload import build_envelope, load_built_shellcode

  build = Path(__file__).resolve().parents[1] / "payload" / "build"
  digests = {
    "crc_probe": "26dd9f2dcd27eca4021bd06ac4c75e0f09a5884d4b56b9f0a870e12f9bf1948e",
    "crc_intermediate": "dd9497c50f81d5def2e93c133292fa721a2505ca2f10009c07bb0a17777b3b4c",
    "crc_verify": "2391fb27522270d19d56fc036500ab2a1447bf0aacbaa04075a555d337713011",
    "live_read": LIVE_READ_ENVELOPE_SHA256,
  }
  payloads = {}
  for name, digest in digests.items():
    shellcode = load_built_shellcode(build, name)
    envelope = build_envelope(
      shellcode, did_201=bytes(16), did_202=bytes(16), iv=bytes(16),
    )
    assert hashlib.sha256(envelope).hexdigest() == digest
    payloads[name] = SimpleNamespace(name=name, envelope=envelope, sha256=digest)
  return payloads


def test_patch_requires_the_exact_reviewed_live_read_payload(tmp_path):
  from eps_patch.patch import PatchError, _validate_payloads

  target, *_case_values = _case(ArtifactLayout(tmp_path / "artifacts"))
  payloads = _payloads()
  payloads.pop("live_read")

  with pytest.raises(PatchError, match="missing live_read"):
    _validate_payloads(payloads, target)


@pytest.mark.parametrize(
  ("crc_state", "expected"),
  (("source", "source"), ("candidate", "candidate")),
)
def test_crc_reconciliation_classifies_only_complete_exact_sectors(
  tmp_path, crc_state, expected,
):
  from eps_patch.crc import build_crc_candidate
  from eps_patch.patch import _validate_crc_reconciliation

  layout = ArtifactLayout(tmp_path / "artifacts")
  target, _identity, target_source, crc_source, target_candidate, crc_candidate = (
    _case(layout)
  )
  candidate = build_crc_candidate(
    target_source, crc_source, NEW_ADJUSTMENT, target=target,
  )
  crc_live = {"source": crc_source, "candidate": crc_candidate}[crc_state]

  assert _validate_crc_reconciliation(
    _live_read_result(target_candidate, crc_live), candidate, target,
  ) == expected


@pytest.mark.parametrize(
  "mutation",
  (
    "partial-crc", "wrong-target", "wrong-operation", "wrong-magic",
    "wrong-base", "wrong-length", "faci", "crc-records", "dcra-records",
  ),
)
def test_crc_reconciliation_rejects_every_nonexact_live_read(tmp_path, mutation):
  from eps_patch.crc import build_crc_candidate
  from eps_patch.patch import PatchError, _validate_crc_reconciliation

  layout = ArtifactLayout(tmp_path / "artifacts")
  target, _identity, target_source, crc_source, target_candidate, _crc_candidate = (
    _case(layout)
  )
  candidate = build_crc_candidate(
    target_source, crc_source, NEW_ADJUSTMENT, target=target,
  )
  result = _live_read_result(target_candidate, crc_source)
  if mutation == "partial-crc":
    partial = bytearray(crc_source)
    partial[0x1234] ^= 1
    result = _live_read_result(target_candidate, bytes(partial))
  elif mutation == "wrong-target":
    result = _live_read_result(target_source, crc_source)
  elif mutation == "wrong-operation":
    result = replace(result, operation=OP_CRC_INTERMEDIATE)
  elif mutation == "wrong-magic":
    result = replace(result, magic_words=(TARGET.magic_word, 0))
  elif mutation == "wrong-base":
    result = replace(result, regions=(
      RegionResult(TARGET.crc_sector_base, target_candidate),
      RegionResult(TARGET.sector_base, crc_source),
    ))
  elif mutation == "wrong-length":
    result = replace(result, regions=(
      RegionResult(TARGET.sector_base, target_candidate[:-1]),
      RegionResult(TARGET.crc_sector_base, crc_source),
    ))
  elif mutation == "faci":
    result = replace(result, faci_values=(1,))
  elif mutation == "crc-records":
    result = replace(result, crc_values=(1,))
  elif mutation == "dcra-records":
    result = replace(result, dcra_values=(1,))

  with pytest.raises(PatchError, match="CRC reconciliation"):
    _validate_crc_reconciliation(result, candidate, target)


def _templates():
  build = Path(__file__).resolve().parents[1] / "payload" / "build"
  return {
    name: (build / f"{name}.bin").read_bytes()
    for name in ("write_target_candidate", "write_crc_candidate")
  }


def _run_patch(tmp_path, *, failure_stage=None, crc_writer_failure=None):
  from eps_patch.patch import PatchError, run_patch

  layout = ArtifactLayout(tmp_path / "artifacts")
  target, identity, target_source, crc_source, target_candidate, crc_candidate = _case(layout)
  target_precheck = _crc_result(
    OP_CRC_PROBE,
    target_source,
    crc_source,
    _observation(
      old_adjustment=OLD_ADJUSTMENT,
      target_candidate=target_candidate,
      crc_candidate=crc_candidate,
    ),
  )
  intermediate_observation = replace(
    _observation(
      old_adjustment=OLD_ADJUSTMENT,
      target_candidate=crc_candidate,
      crc_candidate=crc_candidate,
    ),
    original_sw_full=0x12345678,
    original_dcra_raw=0x12345678,
  )
  intermediate = _crc_result(
    OP_CRC_INTERMEDIATE, target_candidate, crc_source, intermediate_observation,
  )
  final = _crc_result(
    OP_VERIFY_CRC,
    target_candidate,
    crc_candidate,
    _observation(
      old_adjustment=NEW_ADJUSTMENT,
      target_candidate=target_candidate,
      crc_candidate=crc_candidate,
      final=True,
    ),
  )
  events = []
  transports = [
    FakeTransport("target-precheck", events, identity, target_precheck),
    FakeTransport(
      "target-writer", events, identity,
      _writer_result(OP_WRITE_TARGET_CANDIDATE, target.sector_base, target_candidate),
      failure=TimeoutError("target response lost") if failure_stage == "target-armed" else None,
    ),
    FakeTransport("crc-precheck", events, identity, intermediate, boot=True),
    FakeTransport(
      "crc-writer", events, identity,
      _writer_result(OP_WRITE_CRC_CANDIDATE, target.crc_sector_base, crc_candidate),
      failure=(
        crc_writer_failure or TimeoutError("CRC response lost")
        if failure_stage == "crc-armed" else None
      ),
      boot=True,
    ),
    FakeTransport("verify", events, identity, final),
  ]

  if failure_stage == "before-target-arm":
    transports[0].failure = RuntimeError("precheck failed")
  if failure_stage == "target-committed":
    transports[2].failure = RuntimeError("CRC precheck failed")
  if failure_stage == "crc-committed":
    transports[4].failure = RuntimeError("final verify failed")

  def factory():
    assert transports
    return transports.pop(0)

  def power(prompt):
    events.append(("power", prompt))

  confirmations = []

  def confirmation(prompt):
    confirmations.append(prompt)
    return prompt

  result = None
  for _invocation in range(6):
    try:
      result = run_patch(
        layout=layout,
        payloads=_payloads(),
        templates=_templates(),
        preflight=lambda: events.append(("preflight",)),
        transport_factory=factory,
        confirmation=confirmation,
        power_cycle_checkpoint=power,
        target=target,
        new_uds=False,
      )
    except PatchError:
      result = None
      break
    if result.name == "patch-report.json":
      break
  attempts = sorted(layout.patch_root.iterdir())
  assert len(attempts) == 1
  return result, attempts[0] / "state.json", events, confirmations


def test_run_patch_discovers_fixed_probe_and_attempt_paths_from_layout_only():
  from eps_patch.patch import run_patch

  parameters = inspect.signature(run_patch).parameters
  assert "layout" in parameters
  assert not {"probe_directory", "probe_report", "artifact_directory", "output"} & set(parameters)


def test_patch_preserves_two_sector_order_confirmations_and_reconnects(tmp_path):
  result, state_path, events, confirmations = _run_patch(tmp_path)

  assert result == state_path.parent / "patch-report.json"
  state = json.loads(state_path.read_text())
  assert state["result"] == "PASS"
  assert state["restore_order"] == []
  power_prompts = [event[1] for event in events if event[0] == "power"]
  assert len(power_prompts) == 5
  assert "PROBED -> TARGET_PRECHECKED" in power_prompts[0]
  assert "TARGET_PRECHECKED -> TARGET_ARMED" in power_prompts[1]
  assert "TARGET_COMMITTED -> CRC_PRECHECKED" in power_prompts[2]
  assert "CRC_PRECHECKED -> CRC_ARMED" in power_prompts[3]
  assert "CRC_COMMITTED -> VERIFY_PENDING" in power_prompts[4]
  assert [event[0] for event in events if len(event) > 1 and event[1] in {
    "open", "identity", "boot-identity",
  }] == [
    "target-precheck", "target-precheck",
    "target-writer", "target-writer",
    "crc-precheck", "crc-precheck",
    "crc-writer", "crc-writer",
    "verify", "verify",
  ]
  assert len(confirmations) == 2
  assert confirmations[0].startswith("WRITE-TARGET 8965F1208000 0x88000 ")
  assert confirmations[1].startswith("WRITE-CRC 8965F1208000 0xf8000 ")
  assert all("->" in prompt for prompt in confirmations)


@pytest.mark.parametrize(
  ("failure_stage", "expected_result", "restore_order"),
  [
    ("before-target-arm", "FAILED", []),
    ("target-armed", "TARGET_INDETERMINATE", ["target"]),
    ("target-committed", "RECOVERY_REQUIRED", ["target"]),
    ("crc-armed", "CRC_INDETERMINATE", ["crc", "target"]),
    ("crc-committed", "RECOVERY_REQUIRED", ["crc", "target"]),
  ],
)
def test_patch_failure_persists_restore_plan(
  tmp_path, failure_stage, expected_result, restore_order,
):
  result, state_path, _events, _confirmations = _run_patch(
    tmp_path, failure_stage=failure_stage,
  )

  assert result is None
  state = json.loads(state_path.read_text())
  assert state["result"] == expected_result
  assert state["restore_order"] == restore_order


def _crc_indeterminate_case(tmp_path):
  result, state_path, _events, _confirmations = _run_patch(
    tmp_path, failure_stage="crc-armed",
  )
  assert result is None
  layout = ArtifactLayout(tmp_path / "artifacts")
  target_source = layout.target_backup.read_bytes()
  crc_source = layout.crc_backup.read_bytes()
  target_candidate = bytearray(target_source)
  target_candidate[TARGET.patch_offset] = TARGET.patched_instruction[3]
  target_candidate = bytes(target_candidate)
  crc_candidate = bytearray(crc_source)
  crc_candidate[
    TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4
  ] = NEW_ADJUSTMENT
  crc_candidate = bytes(crc_candidate)
  target = replace(
    TARGET,
    original_sha256=hashlib.sha256(target_source).hexdigest(),
    patched_sha256=hashlib.sha256(target_candidate).hexdigest(),
  )
  identity = EcuIdentity(
    part_number=target.part_number,
    application_software_id=target.application_software_id,
    boot_software_id=target.boot_software_id,
    panda_serial="test-panda",
  )
  return (
    layout, state_path, target, identity, target_source, crc_source,
    target_candidate, crc_candidate,
  )


def _legacy_crc_trigger_case(tmp_path):
  from eps_patch.patch import PatchError

  first_failure = PostTriggerTransportError(RuntimeError(
    "invalid payload stream: unknown frame type 0x03"
  ))
  result, state_path, _events, _confirmations = _run_patch(
    tmp_path,
    failure_stage="crc-armed",
    crc_writer_failure=first_failure,
  )
  assert result is None
  layout = ArtifactLayout(tmp_path / "artifacts")
  target_source = layout.target_backup.read_bytes()
  crc_source = layout.crc_backup.read_bytes()
  target_candidate = bytearray(target_source)
  target_candidate[TARGET.patch_offset] = TARGET.patched_instruction[3]
  target_candidate = bytes(target_candidate)
  crc_candidate = bytearray(crc_source)
  crc_candidate[
    TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4
  ] = NEW_ADJUSTMENT
  crc_candidate = bytes(crc_candidate)
  target = replace(
    TARGET,
    original_sha256=hashlib.sha256(target_source).hexdigest(),
    patched_sha256=hashlib.sha256(target_candidate).hexdigest(),
  )
  identity = EcuIdentity(
    part_number=target.part_number,
    application_software_id=target.application_software_id,
    boot_software_id=target.boot_software_id,
    panda_serial="test-panda",
  )
  events = []
  _invoke_patch_resume(
    layout=layout,
    target=target,
    transport=FakeTransport(
      "first-reconcile",
      events,
      identity,
      _live_read_result(target_candidate, crc_source),
      boot=True,
    ),
    events=events,
    confirmations=[],
    powers=[],
  )
  second_failure = PostTriggerTransportError(RuntimeError(
    "RoutineControl negative response NRC 0x31; raw=037f313100000000"
  ))
  with pytest.raises(PatchError, match="CRC_INDETERMINATE"):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=FakeTransport(
        "second-writer", events, identity, None,
        failure=second_failure, boot=True,
      ),
      events=events,
      confirmations=[],
      powers=[],
    )
  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert [transition["result"] for transition in state["transitions"]] == [
    "STARTED", "PROBED", "TARGET_PRECHECKED", "TARGET_ARMED",
    "TARGET_COMMITTED", "CRC_PRECHECKED", "CRC_ARMED",
    "CRC_INDETERMINATE", "CRC_PRECHECKED", "CRC_ARMED",
    "CRC_INDETERMINATE",
  ]
  assert state["transitions"][7]["error"] == LEGACY_UNKNOWN_FRAME_ERROR
  assert state["transitions"][10]["error"] == LEGACY_NRC31_ERROR
  return (
    layout, state_path, target, identity, target_source, crc_source,
    target_candidate, crc_candidate,
  )


def _consumed_legacy_crc_trigger_case(tmp_path, classification="source"):
  case = _legacy_crc_trigger_case(tmp_path)
  (
    layout, _state_path, target, identity, _target_source, crc_source,
    target_candidate, crc_candidate,
  ) = case
  crc_live = {"source": crc_source, "candidate": crc_candidate}[classification]
  _invoke_patch_resume(
    layout=layout,
    target=target,
    transport=FakeTransport(
      "legacy-reconcile", [], identity,
      _live_read_result(target_candidate, crc_live), boot=True,
    ),
    events=[],
    confirmations=[],
    powers=[],
  )
  return case


def _legacy_crc_trigger_third_indeterminate_case(tmp_path):
  from eps_patch.patch import PatchError

  case = _consumed_legacy_crc_trigger_case(tmp_path, "source")
  layout, state_path, target, identity, *_case = case
  with pytest.raises(PatchError, match="CRC_INDETERMINATE"):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=FakeTransport(
        "corrected-route-writer", [], identity, None,
        failure=PostTriggerTransportError(TimeoutError("response lost")),
        boot=True,
      ),
      events=[],
      confirmations=[],
      powers=[],
    )
  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert [transition["result"] for transition in state["transitions"]][-4:] == [
    "CRC_INDETERMINATE", "CRC_PRECHECKED", "CRC_ARMED",
    "CRC_INDETERMINATE",
  ]
  assert sum(
    transition["result"] == "CRC_INDETERMINATE"
    for transition in state["transitions"]
  ) == 3
  return case


def _mutate_legacy_state(state, mutation):
  transitions = state["transitions"]
  probed = transitions[1]["evidence"]
  if mutation == "nrc22":
    transitions[10]["error"] = LEGACY_NRC31_ERROR.replace("0x31", "0x22", 1)
  elif mutation == "wrong-raw":
    transitions[10]["error"] = LEGACY_NRC31_ERROR.replace(
      "037f313100000000", "037f313101000000",
    )
  elif mutation == "first-error":
    transitions[7]["error"] = LEGACY_UNKNOWN_FRAME_ERROR + " "
  elif mutation == "missing-classification":
    transitions[8]["evidence"].pop("classification")
  elif mutation == "changed-classification":
    transitions[8]["evidence"]["classification"] = "candidate"
  elif mutation == "wrong-reconciled-sequence":
    transitions[8]["evidence"]["reconciled_sequence"] = 6
  elif mutation == "reconcile-target-hash":
    transitions[8]["evidence"]["target_readback_sha256"] = probed[
      "target_source_sha256"
    ]
  elif mutation == "reconcile-crc-hash":
    transitions[8]["evidence"]["crc_readback_sha256"] = probed[
      "crc_candidate_sha256"
    ]
  elif mutation == "arm-operation":
    transitions[9]["evidence"]["operation"] = OP_WRITE_TARGET_CANDIDATE
  elif mutation == "arm-base":
    transitions[9]["evidence"]["sector_base"] = "0x88000"
  elif mutation == "arm-source":
    transitions[9]["evidence"]["source_sha256"] = probed["crc_candidate_sha256"]
  elif mutation == "arm-candidate":
    transitions[9]["evidence"]["candidate_sha256"] = probed["crc_source_sha256"]
  elif mutation == "arm-crc32":
    transitions[9]["evidence"]["candidate_crc32"] = "0x00000000"
  elif mutation == "arm-payload":
    transitions[9]["evidence"]["payload"]["intent_sha256"] = "0" * 64
  elif mutation == "extra-transition":
    extra = {
      "sequence": 11,
      "result": "CRC_PRECHECKED",
      "recorded_at": state["updated_at"],
      "evidence": {"state": "unreviewed extra reconciliation"},
    }
    transitions.append(extra)
    state["sequence"] = 11
    state["result"] = "CRC_PRECHECKED"
    state["restore_order"] = ["target"]
    state["power_cycle"] = {
      "completed_state": "CRC_PRECHECKED",
      "next_state": "CRC_ARMED",
    }
  else:
    raise AssertionError(f"unknown legacy state mutation: {mutation}")
  return state


def _invoke_patch_resume(
  *, layout, target, transport, events, confirmations, powers,
):
  from eps_patch.patch import run_patch

  return run_patch(
    layout=layout,
    payloads=_payloads(),
    templates=_templates(),
    preflight=lambda: events.append(("resume", "preflight")),
    transport_factory=lambda: transport,
    confirmation=lambda prompt: confirmations.append(prompt) or prompt,
    power_cycle_checkpoint=lambda prompt: powers.append(prompt),
    target=target,
    new_uds=False,
  )


def _complete_legacy_crc_recovery(tmp_path, classification):
  (
    layout, state_path, target, identity, _target_source, crc_source,
    target_candidate, crc_candidate,
  ) = _legacy_crc_trigger_case(tmp_path)
  events = []
  confirmations = []
  powers = []
  crc_live = {"source": crc_source, "candidate": crc_candidate}[classification]
  _invoke_patch_resume(
    layout=layout,
    target=target,
    transport=FakeTransport(
      "legacy-reconcile", events, identity,
      _live_read_result(target_candidate, crc_live), boot=True,
    ),
    events=events,
    confirmations=confirmations,
    powers=powers,
  )
  if classification == "source":
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=FakeTransport(
        "corrected-route-writer", events, identity,
        _writer_result(
          OP_WRITE_CRC_CANDIDATE, target.crc_sector_base, crc_candidate,
        ),
        boot=True,
      ),
      events=events,
      confirmations=confirmations,
      powers=powers,
    )
  final = _crc_result(
    OP_VERIFY_CRC,
    target_candidate,
    crc_candidate,
    _observation(
      old_adjustment=NEW_ADJUSTMENT,
      target_candidate=target_candidate,
      crc_candidate=crc_candidate,
      final=True,
    ),
  )
  report_path = _invoke_patch_resume(
    layout=layout,
    target=target,
    transport=FakeTransport("legacy-verify", events, identity, final),
    events=events,
    confirmations=confirmations,
    powers=powers,
  )
  return layout, state_path, report_path, events, confirmations


def test_patch_reconciles_crc_source_read_only_before_one_manual_retry(tmp_path):
  (
    layout, state_path, target, identity, _target_source, crc_source,
    target_candidate, crc_candidate,
  ) = _crc_indeterminate_case(tmp_path)
  events = []
  confirmations = []
  powers = []
  live_transport = FakeTransport(
    "reconcile", events, identity,
    _live_read_result(target_candidate, crc_source), boot=True,
  )

  assert _invoke_patch_resume(
    layout=layout, target=target, transport=live_transport, events=events,
    confirmations=confirmations, powers=powers,
  ) == state_path

  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert state["result"] == "CRC_PRECHECKED"
  assert state["restore_order"] == ["target"]
  assert state["power_cycle"] == {
    "completed_state": "CRC_PRECHECKED",
    "next_state": "CRC_ARMED",
  }
  assert [event for event in events if len(event) > 2 and event[1] == "payload"] == [
    ("reconcile", "payload", OP_LIVE_READ),
  ]
  assert confirmations == []

  events.clear()
  writer_transport = FakeTransport(
    "retry-writer", events, identity,
    _writer_result(OP_WRITE_CRC_CANDIDATE, target.crc_sector_base, crc_candidate),
    boot=True,
  )
  assert _invoke_patch_resume(
    layout=layout, target=target, transport=writer_transport, events=events,
    confirmations=confirmations, powers=powers,
  ) == state_path
  assert [event for event in events if len(event) > 2 and event[1] == "payload"] == [
    ("retry-writer", "payload", OP_WRITE_CRC_CANDIDATE),
  ]
  assert len(confirmations) == 1
  assert confirmations[0].startswith("WRITE-CRC 8965F1208000 0xf8000 ")


def test_patch_reconciles_complete_crc_candidate_without_rewriting(tmp_path):
  (
    layout, state_path, target, identity, _target_source, _crc_source,
    target_candidate, crc_candidate,
  ) = _crc_indeterminate_case(tmp_path)
  events = []
  confirmations = []
  powers = []

  assert _invoke_patch_resume(
    layout=layout,
    target=target,
    transport=FakeTransport(
      "reconcile", events, identity,
      _live_read_result(target_candidate, crc_candidate), boot=True,
    ),
    events=events,
    confirmations=confirmations,
    powers=powers,
  ) == state_path

  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert state["result"] == "CRC_COMMITTED"
  assert state["restore_order"] == ["crc", "target"]
  assert state["power_cycle"] == {
    "completed_state": "CRC_COMMITTED",
    "next_state": "VERIFY_PENDING",
  }
  assert [event for event in events if len(event) > 2 and event[1] == "payload"] == [
    ("reconcile", "payload", OP_LIVE_READ),
  ]
  assert confirmations == []

  events.clear()
  final = _crc_result(
    OP_VERIFY_CRC,
    target_candidate,
    crc_candidate,
    _observation(
      old_adjustment=NEW_ADJUSTMENT,
      target_candidate=target_candidate,
      crc_candidate=crc_candidate,
      final=True,
    ),
  )
  report_path = _invoke_patch_resume(
    layout=layout,
    target=target,
    transport=FakeTransport("verify", events, identity, final),
    events=events,
    confirmations=confirmations,
    powers=powers,
  )
  assert report_path.name == "patch-report.json"
  assert [event for event in events if len(event) > 2 and event[1] == "payload"] == [
    ("verify", "payload", OP_VERIFY_CRC),
  ]
  assert confirmations == []


@pytest.mark.parametrize(
  ("classification", "expected_result", "expected_order", "expected_checkpoint"),
  (
    (
      "source", "CRC_PRECHECKED", ["target"],
      {"completed_state": "CRC_PRECHECKED", "next_state": "CRC_ARMED"},
    ),
    (
      "candidate", "CRC_COMMITTED", ["crc", "target"],
      {"completed_state": "CRC_COMMITTED", "next_state": "VERIFY_PENDING"},
    ),
  ),
)
def test_exact_legacy_nrc_history_gets_one_read_only_reconciliation(
  tmp_path, classification, expected_result, expected_order, expected_checkpoint,
):
  (
    layout, state_path, target, identity, _target_source, crc_source,
    target_candidate, crc_candidate,
  ) = _legacy_crc_trigger_case(tmp_path)
  events = []
  confirmations = []
  powers = []
  crc_live = {"source": crc_source, "candidate": crc_candidate}[classification]

  assert _invoke_patch_resume(
    layout=layout,
    target=target,
    transport=FakeTransport(
      "legacy-reconcile", events, identity,
      _live_read_result(target_candidate, crc_live), boot=True,
    ),
    events=events,
    confirmations=confirmations,
    powers=powers,
  ) == state_path

  state = json.loads(state_path.read_text(encoding="utf-8"))
  evidence = state["transitions"][-1]["evidence"]
  assert state["result"] == expected_result
  assert state["restore_order"] == expected_order
  assert state["power_cycle"] == expected_checkpoint
  assert evidence["legacy_trigger_recovery"] == "nrc31-route-v1"
  assert evidence["legacy_trigger_rejection_sequence"] == 10
  assert evidence["target_readback_sha256"] == hashlib.sha256(
    target_candidate,
  ).hexdigest()
  assert evidence["crc_readback_sha256"] == hashlib.sha256(crc_live).hexdigest()
  assert [
    event[2] for event in events if len(event) > 2 and event[1] == "payload"
  ] == [OP_LIVE_READ]
  assert confirmations == []
  assert len(powers) == 1
  assert f"{expected_checkpoint['completed_state']} -> " in powers[0]


@pytest.mark.parametrize("classification", ("source", "candidate"))
def test_exact_legacy_recovery_remains_auditable_through_final_pass(
  tmp_path, classification,
):
  from eps_patch.restore import _legacy_crc_trigger_recovery_status

  _layout, state_path, report_path, events, confirmations = (
    _complete_legacy_crc_recovery(tmp_path, classification)
  )

  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert report_path.name == "patch-report.json"
  assert state["result"] == "PASS"
  assert _legacy_crc_trigger_recovery_status(state["transitions"]) == "consumed"
  operations = [
    event[2] for event in events if len(event) > 2 and event[1] == "payload"
  ]
  assert operations == (
    [OP_LIVE_READ, OP_WRITE_CRC_CANDIDATE, OP_VERIFY_CRC]
    if classification == "source"
    else [OP_LIVE_READ, OP_VERIFY_CRC]
  )
  assert len(confirmations) == (1 if classification == "source" else 0)


@pytest.mark.parametrize(
  "mutation",
  (
    "nrc22", "wrong-raw", "first-error", "missing-classification",
    "changed-classification", "wrong-reconciled-sequence",
    "reconcile-target-hash", "reconcile-crc-hash", "arm-operation",
    "arm-base", "arm-source", "arm-candidate", "arm-crc32", "arm-payload",
    "extra-transition",
  ),
)
def test_legacy_recovery_structural_near_miss_stops_before_hardware(
  tmp_path, mutation,
):
  from eps_patch.patch import PatchError

  layout, state_path, target, *_case = _legacy_crc_trigger_case(tmp_path)
  state = json.loads(state_path.read_text(encoding="utf-8"))
  _mutate_legacy_state(state, mutation)
  state_path.write_text(json.dumps(state), encoding="utf-8")
  mutated_bytes = state_path.read_bytes()
  events = []

  with pytest.raises(PatchError):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=lambda: events.append("transport"),
      events=events,
      confirmations=events,
      powers=events,
    )

  assert state_path.read_bytes() == mutated_bytes
  assert events == []


@pytest.mark.parametrize(
  ("status", "sequence", "field", "missing"),
  (
    ("pending", 8, "identity", True),
    ("pending", 8, "identity", False),
    ("pending", 8, "payload", True),
    ("pending", 8, "payload", False),
    ("consumed", 11, "identity", True),
    ("consumed", 11, "identity", False),
    ("consumed", 11, "payload", True),
    ("consumed", 11, "payload", False),
  ),
)
def test_legacy_recovery_requires_exact_reconciliation_identity_and_live_read(
  tmp_path, status, sequence, field, missing,
):
  from eps_patch.patch import PatchError

  case = (
    _legacy_crc_trigger_case(tmp_path)
    if status == "pending"
    else _consumed_legacy_crc_trigger_case(tmp_path)
  )
  layout, state_path, target, *_case = case
  state = json.loads(state_path.read_text(encoding="utf-8"))
  evidence = state["transitions"][sequence]["evidence"]
  if missing:
    evidence.pop(field)
  elif field == "identity":
    evidence[field]["panda_serial"] = "forged-panda"
  else:
    evidence[field]["sha256"] = "0" * 64
  state_path.write_text(json.dumps(state), encoding="utf-8")
  mutated_bytes = state_path.read_bytes()
  events = []

  with pytest.raises(PatchError):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=lambda: events.append("transport"),
      events=events,
      confirmations=events,
      powers=events,
    )

  assert state_path.read_bytes() == mutated_bytes
  assert events == []


@pytest.mark.parametrize("status", ("pending", "consumed"))
@pytest.mark.parametrize(
  "mutation",
  (
    "target-source", "target-candidate", "crc-source", "crc-candidate",
    "identity",
  ),
)
def test_legacy_recovery_binds_correlated_state_to_current_trusted_evidence(
  tmp_path, status, mutation,
):
  from eps_patch.patch import PatchError
  from eps_patch.restore import (
    _legacy_crc_trigger_recovery_status, _load_patch_state,
  )

  case = (
    _legacy_crc_trigger_case(tmp_path)
    if status == "pending"
    else _consumed_legacy_crc_trigger_case(tmp_path)
  )
  layout, state_path, target, *_case = case
  state = json.loads(state_path.read_text(encoding="utf-8"))
  transitions = state["transitions"]
  probed = transitions[1]["evidence"]
  first_reconciliation = transitions[8]["evidence"]
  second_arm = transitions[9]["evidence"]
  consuming = transitions[11]["evidence"] if status == "consumed" else None
  forged_hash = "1" * 64
  if mutation == "target-source":
    probed["target_source_sha256"] = forged_hash
  elif mutation == "target-candidate":
    probed["target_candidate_sha256"] = forged_hash
    first_reconciliation["target_readback_sha256"] = forged_hash
    if consuming is not None:
      consuming["target_readback_sha256"] = forged_hash
  elif mutation == "crc-source":
    probed["crc_source_sha256"] = forged_hash
    first_reconciliation["crc_readback_sha256"] = forged_hash
    second_arm["source_sha256"] = forged_hash
    if consuming is not None:
      consuming["crc_readback_sha256"] = forged_hash
  elif mutation == "crc-candidate":
    probed["crc_candidate_sha256"] = forged_hash
    second_arm["candidate_sha256"] = forged_hash
  else:
    probed["identity"]["panda_serial"] = "forged-panda"
    first_reconciliation["identity"]["panda_serial"] = "forged-panda"
    second_arm["identity"]["panda_serial"] = "forged-panda"
    if consuming is not None:
      consuming["identity"]["panda_serial"] = "forged-panda"
  state_path.write_text(json.dumps(state), encoding="utf-8")
  loaded, _raw = _load_patch_state(state_path, state_path.parent.name)
  assert _legacy_crc_trigger_recovery_status(loaded["transitions"]) == status
  mutated_bytes = state_path.read_bytes()
  events = []

  with pytest.raises(PatchError, match="legacy CRC"):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=lambda: events.append("transport"),
      events=events,
      confirmations=events,
      powers=events,
    )

  assert state_path.read_bytes() == mutated_bytes
  assert events == []


@pytest.mark.parametrize("classification", ("source", "candidate"))
@pytest.mark.parametrize(
  "mutation",
  (
    "target-hash", "crc-hash", "classification", "marker",
    "rejection-sequence", "reconciled-sequence",
  ),
)
def test_consumed_legacy_recovery_rejects_mutated_readback_and_marker_before_hardware(
  tmp_path, classification, mutation,
):
  from eps_patch.patch import PatchError

  layout, state_path, target, *_case = _consumed_legacy_crc_trigger_case(
    tmp_path, classification,
  )
  state = json.loads(state_path.read_text(encoding="utf-8"))
  probed = state["transitions"][1]["evidence"]
  evidence = state["transitions"][11]["evidence"]
  if mutation == "target-hash":
    evidence["target_readback_sha256"] = probed["target_source_sha256"]
  elif mutation == "crc-hash":
    other = "crc_candidate_sha256" if classification == "source" else "crc_source_sha256"
    evidence["crc_readback_sha256"] = probed[other]
  elif mutation == "classification":
    evidence["classification"] = (
      "candidate" if classification == "source" else "source"
    )
  elif mutation == "marker":
    evidence["legacy_trigger_recovery"] = "nrc31-route-v2"
  elif mutation == "rejection-sequence":
    evidence["legacy_trigger_rejection_sequence"] = 9
  else:
    evidence["reconciled_sequence"] = 9
  state_path.write_text(json.dumps(state), encoding="utf-8")
  mutated_bytes = state_path.read_bytes()
  events = []

  with pytest.raises(PatchError):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=lambda: events.append("transport"),
      events=events,
      confirmations=events,
      powers=events,
    )

  assert state_path.read_bytes() == mutated_bytes
  assert events == []


@pytest.mark.parametrize("mutation", ("correlated-crc32", "correlated-payload"))
@pytest.mark.parametrize("status", ("pending", "consumed"))
def test_legacy_recovery_revalidates_current_writer_before_hardware(
  tmp_path, mutation, status,
):
  from eps_patch.patch import PatchError
  from eps_patch.restore import _legacy_crc_trigger_recovery_status

  layout, state_path, target, *_case = (
    _legacy_crc_trigger_case(tmp_path)
    if status == "pending"
    else _consumed_legacy_crc_trigger_case(tmp_path)
  )
  state = json.loads(state_path.read_text(encoding="utf-8"))
  for arm_sequence in (6, 9):
    evidence = state["transitions"][arm_sequence]["evidence"]
    if mutation == "correlated-crc32":
      evidence["candidate_crc32"] = "0x00000000"
    else:
      evidence["payload"]["intent_sha256"] = "0" * 64
  assert _legacy_crc_trigger_recovery_status(state["transitions"]) == status
  state_path.write_text(json.dumps(state), encoding="utf-8")
  mutated_bytes = state_path.read_bytes()
  events = []

  with pytest.raises(PatchError, match="reviewed writer"):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=lambda: events.append("transport"),
      events=events,
      confirmations=events,
      powers=events,
    )

  assert state_path.read_bytes() == mutated_bytes
  assert events == []


@pytest.mark.parametrize(
  "failure", ("partial-crc", "source-target", "identity", "transport"),
)
def test_legacy_recovery_live_read_failure_never_mutates_state(tmp_path, failure):
  from eps_patch.patch import PatchError

  (
    layout, state_path, target, identity, target_source, crc_source,
    target_candidate, _crc_candidate,
  ) = _legacy_crc_trigger_case(tmp_path)
  original_state = state_path.read_bytes()
  events = []
  confirmations = []
  current_identity = identity
  transport_failure = None
  live_target = target_candidate
  live_crc = crc_source
  if failure == "partial-crc":
    partial = bytearray(crc_source)
    partial[0x1234] ^= 1
    live_crc = bytes(partial)
  elif failure == "source-target":
    live_target = target_source
  elif failure == "identity":
    current_identity = replace(identity, panda_serial="other-panda")
  else:
    transport_failure = TimeoutError("legacy live-read response lost")

  with pytest.raises(PatchError):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=FakeTransport(
        "legacy-reconcile", events, current_identity,
        _live_read_result(live_target, live_crc),
        failure=transport_failure, boot=True,
      ),
      events=events,
      confirmations=confirmations,
      powers=[],
    )

  assert state_path.read_bytes() == original_state
  assert confirmations == []
  assert ("legacy-reconcile", "open") in events


def test_consumed_legacy_third_indeterminate_is_patch_terminal_before_preflight(
  tmp_path,
):
  from eps_patch.patch import PatchError

  layout, state_path, target, *_case = (
    _legacy_crc_trigger_third_indeterminate_case(tmp_path)
  )
  state_after_writer = state_path.read_bytes()
  blocked = []

  with pytest.raises(PatchError, match="unresolved patch incident"):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=lambda: blocked.append("transport"),
      events=blocked,
      confirmations=blocked,
      powers=blocked,
    )

  assert state_path.read_bytes() == state_after_writer
  assert blocked == []


@pytest.mark.parametrize("failure", ("partial", "identity", "transport"))
def test_failed_crc_reconciliation_never_mutates_the_incident(
  tmp_path, failure,
):
  from eps_patch.patch import PatchError

  (
    layout, state_path, target, identity, _target_source, crc_source,
    target_candidate, _crc_candidate,
  ) = _crc_indeterminate_case(tmp_path)
  original_state = state_path.read_bytes()
  events = []
  if failure == "partial":
    partial = bytearray(crc_source)
    partial[0x1234] ^= 1
    result = _live_read_result(target_candidate, bytes(partial))
    current_identity = identity
    transport_failure = None
  elif failure == "identity":
    result = _live_read_result(target_candidate, crc_source)
    current_identity = replace(identity, panda_serial="wrong-panda")
    transport_failure = None
  else:
    result = _live_read_result(target_candidate, crc_source)
    current_identity = identity
    transport_failure = TimeoutError("live-read response lost")
  transport = FakeTransport(
    "reconcile", events, current_identity, result,
    failure=transport_failure, boot=True,
  )

  with pytest.raises(PatchError):
    _invoke_patch_resume(
      layout=layout, target=target, transport=transport, events=events,
      confirmations=[], powers=[],
    )

  assert state_path.read_bytes() == original_state
  assert ("reconcile", "open") in events
  if failure != "identity":
    assert ("reconcile", "payload", OP_LIVE_READ) in events


def test_second_indeterminate_crc_writer_blocks_every_future_hardware_call(tmp_path):
  from eps_patch.patch import PatchError

  (
    layout, state_path, target, identity, _target_source, crc_source,
    target_candidate, _crc_candidate,
  ) = _crc_indeterminate_case(tmp_path)
  events = []
  _invoke_patch_resume(
    layout=layout,
    target=target,
    transport=FakeTransport(
      "reconcile", events, identity,
      _live_read_result(target_candidate, crc_source), boot=True,
    ),
    events=events,
    confirmations=[],
    powers=[],
  )
  _invoke_error_events = []
  with pytest.raises(PatchError, match="CRC_INDETERMINATE"):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=FakeTransport(
        "retry-writer", _invoke_error_events, identity, None,
        failure=TimeoutError("second response lost"), boot=True,
      ),
      events=_invoke_error_events,
      confirmations=[],
      powers=[],
    )
  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert sum(
    transition["result"] == "CRC_INDETERMINATE"
    for transition in state["transitions"]
  ) == 2

  blocked_events = []
  with pytest.raises(PatchError, match="unresolved patch incident"):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=lambda: blocked_events.append("transport"),
      events=blocked_events,
      confirmations=blocked_events,
      powers=blocked_events,
    )
  assert blocked_events == []

  forged = json.loads(state_path.read_text(encoding="utf-8"))
  forged_transition = {
    "sequence": len(forged["transitions"]),
    "result": "CRC_PRECHECKED",
    "recorded_at": forged["updated_at"],
    "evidence": {"forged": "second-indeterminate recovery"},
  }
  forged["transitions"].append(forged_transition)
  forged["sequence"] = forged_transition["sequence"]
  forged["result"] = "CRC_PRECHECKED"
  forged["restore_order"] = ["target"]
  forged["updated_at"] = forged_transition["recorded_at"]
  forged["power_cycle"] = {
    "completed_state": "CRC_PRECHECKED",
    "next_state": "CRC_ARMED",
  }
  state_path.write_text(json.dumps(forged), encoding="utf-8")
  forged_events = []

  with pytest.raises(PatchError, match=r"cannot (verify|validate) persisted patch"):
    _invoke_patch_resume(
      layout=layout,
      target=target,
      transport=lambda: forged_events.append("transport"),
      events=forged_events,
      confirmations=forged_events,
      powers=forged_events,
    )
  assert forged_events == []


def test_patch_rejects_unresolved_incident_before_preflight_or_transport(tmp_path):
  """A new patch must not obscure an incident whose restore scope is persisted."""
  from eps_patch.patch import PatchError, run_patch

  _result, state_path, _events, _confirmations = _run_patch(
    tmp_path, failure_stage="target-armed",
  )
  layout = ArtifactLayout(tmp_path / "artifacts")
  target_source = layout.target_backup.read_bytes()
  target_candidate = bytearray(target_source)
  target_candidate[TARGET.patch_offset] = TARGET.patched_instruction[3]
  target = replace(
    TARGET,
    original_sha256=hashlib.sha256(target_source).hexdigest(),
    patched_sha256=hashlib.sha256(target_candidate).hexdigest(),
  )
  events = []

  with pytest.raises(PatchError, match="unresolved patch incident"):
    run_patch(
      layout=layout,
      payloads=_payloads(),
      templates=_templates(),
      preflight=lambda: events.append("preflight"),
      transport_factory=lambda: events.append("transport"),
      confirmation=lambda _prompt: "",
      power_cycle_checkpoint=lambda _prompt: "",
      target=target,
      new_uds=False,
    )

  assert events == []
  assert tuple(layout.patch_root.iterdir()) == (state_path.parent,)


def test_patch_allows_a_new_attempt_after_the_incident_restore_passes(tmp_path, monkeypatch):
  """A PASS restore resolves the incident; it must not permanently lock patching."""
  import eps_patch.restore as restore_module
  import test_restore as restore_fx
  from eps_patch.patch import PatchError, run_patch

  monkeypatch.setattr(
    restore_module,
    "LIVE_READ_ENVELOPE_SHA256",
    restore_fx.TEST_LIVE_READ_ENVELOPE_SHA256,
  )
  report, _restore_state, _incident, _events, _confirmations, _prompts = (
    restore_fx._run_restore(tmp_path)
  )
  assert report is not None
  layout = ArtifactLayout(tmp_path / "artifacts")
  target_source = layout.target_backup.read_bytes()
  target_candidate = bytearray(target_source)
  target_candidate[TARGET.patch_offset] = TARGET.patched_instruction[3]
  target = replace(
    TARGET,
    original_sha256=hashlib.sha256(target_source).hexdigest(),
    patched_sha256=hashlib.sha256(target_candidate).hexdigest(),
  )
  events = []

  arguments = {
    "layout": layout,
    "payloads": _payloads(),
    "templates": _templates(),
    "preflight": lambda: events.append("preflight"),
    "transport_factory": lambda: events.append("transport"),
    "confirmation": lambda _prompt: "",
    "power_cycle_checkpoint": lambda _prompt: None,
    "target": target,
    "new_uds": False,
  }
  assert run_patch(**arguments).name == "state.json"
  with pytest.raises(PatchError, match="patch stopped in FAILED"):
    run_patch(**arguments)

  assert events == ["preflight", "preflight", "transport"]


def test_patch_rejects_an_older_unresolved_incident_masked_by_a_newer_restore(
  tmp_path,
):
  """Every recoverable incident needs its own successful restore before patching."""
  import test_restore as restore_fx
  from eps_patch.patch import PatchError, run_patch
  from eps_patch.restore import select_restore_plan

  layout = ArtifactLayout(tmp_path / "artifacts")
  target, *_unused = _case(layout)
  restore_fx._patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
    timestamp="20260817T010203Z",
  )
  restore_fx._patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
    timestamp="20260817T010204Z",
  )
  newer_incident = select_restore_plan(layout)
  restore_fx._write_prior_restore_state(layout, newer_incident, result="PASS")
  events = []

  with pytest.raises(PatchError, match="unresolved patch incident"):
    run_patch(
      layout=layout,
      payloads=_payloads(),
      templates=_templates(),
      preflight=lambda: events.append("preflight"),
      transport_factory=lambda: events.append("transport"),
      confirmation=lambda _prompt: "",
      power_cycle_checkpoint=lambda _prompt: "",
      target=target,
      new_uds=False,
    )

  assert events == []
