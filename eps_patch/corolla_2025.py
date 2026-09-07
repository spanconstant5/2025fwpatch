"""Offline specimen verification; this module grants no runtime eligibility.

Authority: kaikozlov/ghidra_rh850 at a747ee291b94ffecbee69cf062aec72b23c4dc8d,
docs/variants/corolla-8965F1208000.md and verify_spanconstant_* tests.
F181 below is reconstructed from firmware, not a raw 2025 wire capture.
"""

from __future__ import annotations

import binascii
import hashlib

from .crc import build_crc_candidate
from .manifest import TARGET


CODEFLASH_SHA256 = "b8fa3d951f59fb75c190ce1b2c73164adb952f871650cfcd3b7656f08a9c448d"
NORMALIZED_SHA256 = "fdb35b76891cf84a8b89e0a05c9c7c5cfcd27994cf85ccc01ff32828f53091f6"
APPLICATION_F181 = b"\x02" + b"8965F1208000" + bytes(4) + b"8A3111213000" + bytes(4)
ECU_SERIAL = b"8965012N50E12H030731"
CRC_SECTOR_SHA256 = "617f2b88ee1041160f9ce2369e45b3b7bed9d68a77ecb5473a601261bccf7efb"


def verify_codeflash(raw: bytes) -> dict[str, object]:
  """Check only the exact retained 2-MiB Span acquisition, entirely in memory.

  The return value is analysis, never a probe report or recovery artifact.
  Unknown inputs fail before deriving any target facts or candidate bytes.
  """
  if type(raw) is not bytes or len(raw) != 0x200000:
    raise ValueError("expected the exact 2-MiB Span CodeFlash acquisition")
  if hashlib.sha256(raw).hexdigest() != CODEFLASH_SHA256:
    raise ValueError("CodeFlash SHA-256 is not the pinned 2025 specimen")
  image = raw[:0x100000]
  if raw[0x100000:] != b"\xff" * 0x100000 or hashlib.sha256(image).hexdigest() != NORMALIZED_SHA256:
    raise ValueError("CodeFlash normalization does not match the pinned physical image")
  f181 = b"\x02" + image[0x20860:0x20870] + image[0x17DC0:0x17DD0]
  if f181 != APPLICATION_F181 or image[0xA4DC:0xA4F0] != ECU_SERIAL:
    raise ValueError("2025 F181 or ECU serial does not match firmware evidence")
  if image[0x180:0x1A8] != b"BOOT INFO AREA  R7F701383       72114350":
    raise ValueError("2025 MCU identity does not match firmware evidence")

  target_sector = image[TARGET.sector_base:TARGET.sector_end]
  crc_sector = image[TARGET.crc_sector_base:TARGET.crc_sector_end]
  if hashlib.sha256(target_sector).hexdigest() != TARGET.original_sha256:
    raise ValueError("complete target source sector does not match runtime pin")
  if hashlib.sha256(crc_sector).hexdigest() != CRC_SECTOR_SHA256:
    raise ValueError("complete CRC source sector does not match specimen pin")
  candidate = build_crc_candidate(
    target_sector, crc_sector, TARGET.crc_patched_adjust_word.to_bytes(4, "little"),
  )
  if hashlib.sha256(candidate.target_final).hexdigest() != TARGET.patched_sha256:
    raise ValueError("target candidate does not match runtime pin")
  if candidate.old_adjustment != TARGET.crc_original_adjust_word.to_bytes(4, "little"):
    raise ValueError("original CRC adjustment differs")
  revised = bytearray(image)
  revised[TARGET.sector_base:TARGET.sector_end] = candidate.target_final
  revised[TARGET.crc_sector_base:TARGET.crc_sector_end] = candidate.crc_final
  if any(binascii.crc32(data[TARGET.crc_range_start:TARGET.crc_range_end]) != TARGET.crc_residue
         for data in (image, revised)):
    raise ValueError("original or candidate high-region CRC residue differs")
  return {
    "scope": "offline-specimen-analysis",
    "codeflash_sha256": CODEFLASH_SHA256,
    "normalized_sha256": NORMALIZED_SHA256,
    "application_f181_hex": f181.hex(),
    "application_f181_evidence": "firmware-reconstructed; live ASCII pair observed",
    "ecu_serial": ECU_SERIAL.decode("ascii"),
    "mcu": "R7F701383",
    "observed_acquisition_route": {"bus": 1, "param": 1},
    "runtime_identity_matches": f181 == TARGET.application_software_id,
    "target_source_sha256": hashlib.sha256(target_sector).hexdigest(),
    "target_candidate_sha256": hashlib.sha256(candidate.target_final).hexdigest(),
    "crc_source_sha256": hashlib.sha256(crc_sector).hexdigest(),
    "crc_candidate_sha256": hashlib.sha256(candidate.crc_final).hexdigest(),
    "changed_addresses": [address for address, _, _ in candidate.absolute_diffs],
    "unresolved": [
      "2025 raw application/boot F181 wire captures",
      "mapping acquisition bus 1 / param 1 to the patch transport and payload CAN channel",
      "2025 runtime stack/stub/buffer and FACI/DCRA behavior for these retained payloads",
      "actual lateral-command interface and functional steering compatibility",
    ],
  }
