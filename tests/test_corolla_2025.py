"""Real-corpus checks are opt-in; ordinary unit tests need no firmware files."""

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from eps_patch.corolla_2025 import APPLICATION_F181, verify_codeflash
from eps_patch.manifest import TARGET


@pytest.fixture(scope="module")
def evidence_root():
  root = os.environ.get("COROLLA_EVIDENCE_ROOT")
  if root is None:
    pytest.skip("set COROLLA_EVIDENCE_ROOT to the pinned ghidra_rh850 checkout")
  path = Path(root)
  assert path.is_dir(), "supplied evidence checkout is missing"
  return path


@pytest.fixture(scope="module")
def corpus(evidence_root):
  session = evidence_root / "community/spanconstant/raw-20260821/span-corolla-2025.20260821-1511"
  raw = (session / "dump_codeflash_00000000_00200000_20260821-152033.bin").read_bytes()
  preflight = json.loads((session / "preflight_8965012N50E12H030731_20260821-151149.json").read_text())
  return raw, preflight


@pytest.mark.parametrize("raw", [None, b"", bytes(0x100000), bytes(0x200001), bytearray(0x200000)],
                         ids=["none", "empty", "normalized-only", "oversized", "mutable"])
def test_rejects_wrong_input_shape(raw):
  with pytest.raises(ValueError, match="exact 2-MiB"):
    verify_codeflash(raw)


def test_rejects_unrecognized_full_size_image():
  with pytest.raises(ValueError, match="SHA-256"):
    verify_codeflash(bytes(0x200000))


def test_offline_identity_does_not_widen_runtime_allowlist():
  assert len(APPLICATION_F181) == 33
  assert APPLICATION_F181 != TARGET.application_software_id
  with pytest.raises(ValueError, match="exact target F181"):
    replace(TARGET, application_software_id=APPLICATION_F181).validate()
  TARGET.validate()


def test_real_2025_identity_route_sectors_and_crc(corpus, evidence_root):
  raw, preflight = corpus
  report = verify_codeflash(raw)
  assert report["runtime_identity_matches"] is False
  assert report["unresolved"]
  assert report["ecu_serial"] == preflight["identity"]["ecu_serial"]
  assert report["observed_acquisition_route"] == preflight["route"] == {"bus": 1, "param": 1}
  assert preflight["identity"]["app_sw_id"] == "8965F12080008A3111213000"
  assert report["changed_addresses"] == [0x88C63, 0xFFDEC, 0xFFDED, 0xFFDEE, 0xFFDEF]
  gate = json.loads((evidence_root / "data/generated/secoc_gate_resolution_8965F1208000_minimal.json").read_text())
  assert gate["program_sha256"] == report["normalized_sha256"]
  assert int(gate["patch"]["address"], 16) + 1 == TARGET.patch_address
  assert bytes.fromhex(gate["patch"]["original"]) == TARGET.original_instruction[2:]
  assert bytes.fromhex(gate["patch"]["replacement"]) == TARGET.patched_instruction[2:]


@pytest.mark.parametrize("address", [0xA004, 0x17DC4, 0x88C63, 0xFFDEC, 0x100000])
def test_rejects_corruption_even_outside_patch_sectors(corpus, address):
  changed = bytearray(corpus[0])
  changed[address] ^= 1
  with pytest.raises(ValueError, match="SHA-256"):
    verify_codeflash(bytes(changed))


def test_2023_matches_high_code_but_is_not_the_target(corpus, evidence_root):
  baseline = (evidence_root / "community/albinoelephant/raw-20260818/albinoelephant-corolla-2023.20260814-0023/dump_codeflash_00000000_00200000_20260814-025814.bin").read_bytes()
  assert hashlib.sha256(baseline).hexdigest() == "97f9d42d936b97a99e7ab3d3ef20c6fb4c1fc3cc2ba199f6b158675a1709aee6"
  target = corpus[0]
  differences = [i for i, (a, b) in enumerate(zip(baseline, target)) if a != b]
  assert (len(differences), differences[0], differences[-1]) == (2190, 0xA004, 0x17DFF)
  assert baseline[0x17E00:] == target[0x17E00:]
  with pytest.raises(ValueError, match="SHA-256"):
    verify_codeflash(baseline)
