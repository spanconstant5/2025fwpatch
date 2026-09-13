from dataclasses import FrozenInstanceError, replace

import pytest


def test_target_manifest_locks_patch_to_one_known_byte():
  from eps_patch.manifest import TARGET

  assert TARGET.part_number == b"8965F1208000"
  assert (TARGET.sector_base, TARGET.sector_length) == (0x88000, 0x8000)
  assert TARGET.sector_end == 0x90000
  assert TARGET.instruction_address == 0x88C60
  assert TARGET.patch_address == 0x88C63
  assert TARGET.patch_offset == 0x0C63
  assert TARGET.instruction_offset == 0x0C60
  assert TARGET.pure_code_file_offset(TARGET.patch_address) == 0x88C63
  assert TARGET.wide_image_file_offset(TARGET.patch_address) == 0x88C63 + 0x8000
  assert TARGET.original_instruction == bytes.fromhex("1d 30 e0 d1")
  assert TARGET.patched_instruction == bytes.fromhex("1d 30 e0 01")
  assert TARGET.original_sha256 == "30cf2e0907cbbec3401cc1650e6bd298f5aa1e5e72dab4f39335d499243dd539"
  assert TARGET.patched_sha256 == "272f303f877702b339ed7d9cfd1700888829a147ce6d89102d1b27610b9938f3"


def test_target_manifest_locks_transport_and_boot_markers():
  from eps_patch.manifest import TARGET

  assert TARGET.magic_addresses == (0x17E00, 0xFFE00)
  assert TARGET.magic_word == 0x5AA5A55A
  assert (TARGET.uds_request_id, TARGET.uds_response_id, TARGET.bus) == (0x7A1, 0x7A9, 0)
  assert (TARGET.ram_address, TARGET.envelope_length) == (0xFEBF0000, 0x1000)
  assert TARGET.application_software_id == (
    b"\x02" + b"8965F1208000" + bytes(4) + b"8A3111213000" + bytes(4)
  )
  assert TARGET.boot_software_id == b"\x02" + (b"!" * 32)
  assert TARGET.new_uds is False


def test_crc_manifest_uses_physical_addresses_without_translation():
  from eps_patch.manifest import TARGET

  assert (TARGET.crc_range_start, TARGET.crc_range_end) == (0x18000, 0xFFDF0)
  assert (TARGET.crc_sector_base, TARGET.crc_sector_end) == (0xF8000, 0x100000)
  assert TARGET.crc_adjust_address == 0xFFDEC
  assert TARGET.crc_original_adjust_word == 0xAD59D70C
  assert TARGET.crc_patched_prefix_sw == 0x22A0EB88
  assert TARGET.crc_patched_adjust_word == 0xDD5F1477
  assert TARGET.crc_residue == 0xFFFFFFFF
  assert TARGET.crc_patched_prefix_sw ^ TARGET.crc_residue == TARGET.crc_patched_adjust_word
  assert TARGET.pure_code_file_offset(TARGET.crc_adjust_address) == 0xFFDEC
  assert TARGET.sram_buffer == 0xFEBF2000
  assert TARGET.sram_buffer + TARGET.sector_length <= TARGET.sram_end
  assert (TARGET.runtime_stack_address, TARGET.runtime_stack_length) == (0xFEBF1000, 0x188)
  assert (TARGET.runtime_stub_address, TARGET.runtime_stub_length) == (0xFEBF1188, 0x78)
  assert (TARGET.intent_address, TARGET.intent_length) == (0xFEBF0600, 0x80)


@pytest.mark.parametrize(
  ("field", "value"),
  (
    ("crc_original_adjust_word", 0),
    ("crc_patched_prefix_sw", 0),
    ("crc_patched_adjust_word", 0),
    ("crc_residue", 0),
  ),
)
def test_manifest_rejects_reviewed_crc_constant_drift(field, value):
  from eps_patch.manifest import TARGET

  with pytest.raises(ValueError, match="CRC"):
    replace(TARGET, **{field: value}).validate()


@pytest.mark.parametrize(
  "changes",
  (
    {"runtime_stack_address": 0xFEBF0000},
    {"runtime_stub_address": 0xFEBF1100},
    {"sram_buffer": 0xFEBF1188},
    {"intent_address": 0xFEBF2000},
    {"intent_length": 0x81},
  ),
)
def test_manifest_rejects_stack_stub_buffer_or_intent_range_drift(changes):
  from eps_patch.manifest import TARGET

  with pytest.raises(ValueError):
    replace(TARGET, **changes).validate()


def test_target_manifest_is_immutable():
  from eps_patch.manifest import TARGET

  with pytest.raises(FrozenInstanceError):
    TARGET.sector_base = 0  # type: ignore[misc]
