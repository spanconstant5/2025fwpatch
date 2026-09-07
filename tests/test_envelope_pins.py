"""Independently check retained zero-DID envelopes without importing hardware orchestration."""

import ast
import binascii
import hashlib
import struct
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from eps_patch.payload import (
  PAYLOAD_BUILD_SECRET, PayloadError, build_envelope, load_built_shellcode,
  verify_envelope,
)


ROOT = Path(__file__).resolve().parents[1]
CASES = [
  ("probe_pe_cycle", "payload.py", "PROBE_PE_CYCLE_ENVELOPE_SHA256"),
  ("crc_probe", "patch.py", "CRC_PROBE_ENVELOPE_SHA256"),
  ("crc_intermediate", "patch.py", "CRC_INTERMEDIATE_ENVELOPE_SHA256"),
  ("crc_verify", "patch.py", "CRC_VERIFY_ENVELOPE_SHA256"),
  ("live_read", "patch.py", "LIVE_READ_ENVELOPE_SHA256"),
  ("live_read", "restore.py", "LIVE_READ_ENVELOPE_SHA256"),
]


def literal_pin(filename, name):
  # Read literal trust anchors without importing the Linux-only fcntl workflow.
  tree = ast.parse((ROOT / "eps_patch" / filename).read_text(encoding="utf-8"))
  for node in tree.body:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
    if any(isinstance(target, ast.Name) and target.id == name for target in targets):
      return ast.literal_eval(node.value)
  raise AssertionError(f"missing literal pin: {filename}:{name}")


@pytest.mark.parametrize("name,filename,pin_name", CASES)
def test_retained_envelope_matches_independent_construction_and_literal_pin(name, filename, pin_name):
  binary = load_built_shellcode(ROOT / "payload/build", name)
  zero = bytes(16)
  # Independent fixed-offset construction, including CRC and CMAC. No call to
  # build_plaintext/derive_payload_key, and no runtime-derived allowlist.
  key = AES.new(PAYLOAD_BUILD_SECRET, AES.MODE_ECB).encrypt(zero)
  plaintext = bytearray(4096)
  plaintext[:len(binary)] = binary
  struct.pack_into("<I", plaintext, 0xFD0, 0xFEBF0000)
  struct.pack_into("<II", plaintext, 0xFE0, 0xFEBF0000, 0xFF0)
  struct.pack_into("<I", plaintext, 0xFEC, binascii.crc32(plaintext[:0xFEC]) ^ 0xFFFFFFFF)
  cmac = CMAC.new(key, ciphermod=AES)
  cmac.update(zero + plaintext[:0xFF0])
  plaintext[0xFF0:] = cmac.digest()
  independent = AES.new(key, AES.MODE_CBC, iv=zero).encrypt(bytes(plaintext))
  envelope = build_envelope(binary, did_201=zero, did_202=zero, iv=zero)
  assert envelope == independent
  assert hashlib.sha256(envelope).hexdigest() == literal_pin(filename, pin_name)
  assert verify_envelope(envelope, did_201=zero, did_202=zero) == plaintext
  corrupt = bytearray(envelope)
  corrupt[0] ^= 1
  with pytest.raises(PayloadError, match="CMAC"):
    verify_envelope(bytes(corrupt), did_201=zero, did_202=zero)


@pytest.mark.parametrize("name,filename,pin_name", CASES[:4])
def test_changed_binary_cannot_be_repinned_by_editing_build_manifest(tmp_path, name, filename, pin_name):
  import json

  build = ROOT / "payload/build"
  binary = bytearray((build / f"{name}.bin").read_bytes())
  binary[0] ^= 1
  manifest = json.loads((build / "manifest.json").read_text())
  manifest["payloads"][name]["sha256"] = hashlib.sha256(binary).hexdigest()
  (tmp_path / f"{name}.bin").write_bytes(binary)
  (tmp_path / "manifest.json").write_text(json.dumps(manifest))
  with pytest.raises(PayloadError, match="pinned size/SHA-256"):
    load_built_shellcode(tmp_path, name)
