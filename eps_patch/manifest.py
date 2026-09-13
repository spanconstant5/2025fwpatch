"""Immutable identity and flash bounds for the single supported EPS."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TargetManifest:
  part_number: bytes
  application_software_id: bytes
  boot_software_id: bytes
  new_uds: bool
  sector_base: int
  sector_length: int
  instruction_address: int
  patch_address: int
  original_instruction: bytes
  patched_instruction: bytes
  original_sha256: str
  patched_sha256: str
  magic_addresses: tuple[int, int]
  magic_word: int
  uds_request_id: int
  uds_response_id: int
  bus: int
  ram_address: int
  envelope_length: int
  runtime_stack_address: int
  runtime_stack_length: int
  runtime_stub_address: int
  runtime_stub_length: int
  intent_address: int
  intent_length: int
  sram_buffer: int
  sram_end: int
  crc_range_start: int
  crc_range_end: int
  crc_sector_base: int
  crc_sector_end: int
  crc_adjust_address: int
  crc_original_adjust_word: int
  crc_patched_prefix_sw: int
  crc_patched_adjust_word: int
  crc_residue: int

  @property
  def sector_end(self) -> int:
    return self.sector_base + self.sector_length

  @property
  def instruction_offset(self) -> int:
    return self.instruction_address - self.sector_base

  @property
  def patch_offset(self) -> int:
    return self.patch_address - self.sector_base

  @property
  def crc_adjust_offset(self) -> int:
    return self.crc_adjust_address - self.crc_sector_base

  def pure_code_file_offset(self, address: int) -> int:
    if not 0 <= address < 0x100000:
      raise ValueError("address is outside the 1 MiB Code Flash")
    return address

  def wide_image_file_offset(self, address: int) -> int:
    return 0x8000 + self.pure_code_file_offset(address)

  def validate(self) -> None:
    if self.part_number != b"8965F1208000" or not self.part_number.isascii():
      raise ValueError("unsupported EPS part number")
    _expected_app_sw_id = (
      b"\x02" + b"8965F1208000" + bytes(4) + b"8A3111213000" + bytes(4)
    )
    if self.application_software_id != _expected_app_sw_id:
      raise ValueError("application software identity is not the exact target F181 record")
    if self.boot_software_id != b"\x02" + (b"!" * 32):
      raise ValueError("boot software identity is not the exact target boot F181 record")
    if self.new_uds is not False:
      raise ValueError("target is locked to the verified old UDS routine variant")
    if self.sector_length != 0x8000:
      raise ValueError("target sector must be exactly 32 KiB")
    if not self.sector_base <= self.instruction_address < self.sector_end:
      raise ValueError("instruction lies outside target sector")
    if self.patch_address != self.instruction_address + 3:
      raise ValueError("patch byte is not the control-flow byte of the instruction")
    if len(self.original_instruction) != 4 or len(self.patched_instruction) != 4:
      raise ValueError("instruction contexts must be four bytes")
    diffs = [i for i, pair in enumerate(zip(self.original_instruction, self.patched_instruction)) if pair[0] != pair[1]]
    if diffs != [3] or self.original_instruction[3] != 0xD1 or self.patched_instruction[3] != 0x01:
      raise ValueError("manifest must describe only 0xD1 -> 0x01 at instruction byte 3")
    for digest in (self.original_sha256, self.patched_sha256):
      if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("sector digest must be lowercase SHA-256")
    if (self.crc_range_start, self.crc_range_end) != (0x18000, 0xFFDF0):
      raise ValueError("CRC range is not the exact physical Code Flash range")
    if (self.crc_sector_base, self.crc_sector_end) != (0xF8000, 0x100000):
      raise ValueError("CRC sector is not the exact final 32 KiB Code Flash sector")
    if self.crc_adjust_address != 0xFFDEC or self.crc_adjust_address + 4 != self.crc_range_end:
      raise ValueError("CRC adjustment word is not the exact range terminator")
    if (
      self.crc_original_adjust_word,
      self.crc_patched_prefix_sw,
      self.crc_patched_adjust_word,
      self.crc_residue,
    ) != (0xAD59D70C, 0x22A0EB88, 0xDD5F1477, 0xFFFFFFFF):
      raise ValueError("CRC constants do not match the reviewed original and patched states")
    if self.crc_patched_prefix_sw ^ self.crc_residue != self.crc_patched_adjust_word:
      raise ValueError("CRC patched adjustment does not match the reviewed residue formula")
    if not self.crc_sector_base <= self.crc_adjust_address < self.crc_sector_end - 3:
      raise ValueError("CRC adjustment word lies outside the CRC sector")
    if (self.ram_address, self.envelope_length) != (0xFEBF0000, 0x1000):
      raise ValueError("payload envelope is not the exact RAM allocation")
    if (self.runtime_stack_address, self.runtime_stack_length) != (0xFEBF1000, 0x188):
      raise ValueError("runtime stack allocation is not the exact reviewed SRAM range")
    if (self.runtime_stub_address, self.runtime_stub_length) != (0xFEBF1188, 0x78):
      raise ValueError("runtime stub allocation is not the exact SRAM range")
    if (self.intent_address, self.intent_length) != (0xFEBF0600, 0x80):
      raise ValueError("payload intent allocation is not the exact reviewed range")
    if self.sram_buffer != 0xFEBF2000:
      raise ValueError("CRC SRAM buffer is not the exact SRAM allocation")
    ranges = (
      (self.ram_address, self.ram_address + self.envelope_length),
      (self.runtime_stack_address, self.runtime_stack_address + self.runtime_stack_length),
      (self.runtime_stub_address, self.runtime_stub_address + self.runtime_stub_length),
      (self.sram_buffer, self.sram_buffer + self.sector_length),
    )
    if any(start < 0 or end <= start for start, end in ranges):
      raise ValueError("SRAM allocations must be non-empty")
    if self.sram_buffer + self.sector_length > self.sram_end:
      raise ValueError("CRC SRAM buffer exceeds SRAM")
    if any(left[0] < right[1] and right[0] < left[1] for index, left in enumerate(ranges) for right in ranges[index + 1:]):
      raise ValueError("envelope, stack, runtime stubs, and CRC buffer must not overlap")
    intent_end = self.intent_address + self.intent_length
    if not self.ram_address <= self.intent_address < intent_end <= self.ram_address + self.envelope_length:
      raise ValueError("payload intent must be contained in the reviewed envelope")
    for start, end in ranges[1:]:
      if self.intent_address < end and start < intent_end:
        raise ValueError("payload intent overlaps stack, runtime stubs, or CRC buffer")


TARGET = TargetManifest(
  part_number=b"8965F1208000",
  application_software_id=(
    b"\x02" + b"8965F1208000" + bytes(4) + b"8A3111213000" + bytes(4)
  ),
  boot_software_id=b"\x02" + (b"!" * 32),
  new_uds=False,
  sector_base=0x88000,
  sector_length=0x8000,
  instruction_address=0x88C60,
  patch_address=0x88C63,
  original_instruction=bytes.fromhex("1d 30 e0 d1"),
  patched_instruction=bytes.fromhex("1d 30 e0 01"),
  original_sha256="30cf2e0907cbbec3401cc1650e6bd298f5aa1e5e72dab4f39335d499243dd539",
  patched_sha256="272f303f877702b339ed7d9cfd1700888829a147ce6d89102d1b27610b9938f3",
  magic_addresses=(0x17E00, 0xFFE00),
  magic_word=0x5AA5A55A,
  uds_request_id=0x7A1,
  uds_response_id=0x7A9,
  bus=0,
  ram_address=0xFEBF0000,
  envelope_length=0x1000,
  runtime_stack_address=0xFEBF1000,
  runtime_stack_length=0x188,
  runtime_stub_address=0xFEBF1188,
  runtime_stub_length=0x78,
  intent_address=0xFEBF0600,
  intent_length=0x80,
  sram_buffer=0xFEBF2000,
  sram_end=0xFEBFA000,
  crc_range_start=0x18000,
  crc_range_end=0xFFDF0,
  crc_sector_base=0xF8000,
  crc_sector_end=0x100000,
  crc_adjust_address=0xFFDEC,
  crc_original_adjust_word=0xAD59D70C,
  crc_patched_prefix_sw=0x22A0EB88,
  crc_patched_adjust_word=0xDD5F1477,
  crc_residue=0xFFFFFFFF,
)
TARGET.validate()
