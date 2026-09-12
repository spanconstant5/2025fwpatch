"""Narrow adapter over the current openpilot Panda and opendbc UDS APIs."""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable

from .manifest import TARGET, TargetManifest
from .payload import PayloadError, SECURITY_ACCESS_SECRET, SpecializedPayloadImage
from .protocol import (
  FrameType, OP_CRC_INTERMEDIATE, OP_CRC_PROBE, OP_FACI_PE_CYCLE,
  OP_LIVE_READ, OP_RAM_ECHO,
  OP_RESTORE_SECTOR, OP_VERIFY_CRC, OP_WRITE_CRC_CANDIDATE,
  OP_WRITE_TARGET_CANDIDATE,
  ProtocolError, StreamCollector, StreamResult,
)


class TransportError(RuntimeError):
  pass


class PostTriggerTransportError(TransportError):
  """Destructive trigger may have executed; automatic cleanup is forbidden."""

  def __init__(self, primary: Exception):
    self.primary = primary
    self.safe_cleanup_attempts: tuple[str, ...] = ()
    super().__init__(f"post-trigger destructive outcome is indeterminate: {primary}")


_UDS_TRIGGER_BASE = 0xE0000


@dataclass(frozen=True, slots=True)
class EcuIdentity:
  part_number: bytes
  boot_software_id: bytes
  application_software_id: bytes = b""
  panda_serial: str = ""


@dataclass(frozen=True, slots=True)
class BootloaderIdentity:
  software_id: bytes
  panda_serial: str


def load_openpilot_bindings() -> SimpleNamespace:
  from panda import Panda
  from opendbc.car.isotp import isotp_send
  from opendbc.car.structs import CarParams
  from opendbc.car.uds import (
    ACCESS_TYPE,
    DATA_IDENTIFIER_TYPE,
    ROUTINE_CONTROL_TYPE,
    SERVICE_TYPE,
    SESSION_TYPE,
    UdsClient,
  )

  return SimpleNamespace(
    Panda=Panda,
    UdsClient=UdsClient,
    elm327=CarParams.SafetyModel.elm327,
    session_default=SESSION_TYPE.DEFAULT,
    session_extended=SESSION_TYPE.EXTENDED_DIAGNOSTIC,
    session_programming=SESSION_TYPE.PROGRAMMING,
    access_request_seed=ACCESS_TYPE.REQUEST_SEED,
    access_send_key=ACCESS_TYPE.SEND_KEY,
    service_request_download=SERVICE_TYPE.REQUEST_DOWNLOAD,
    routine_start=ROUTINE_CONTROL_TYPE.START,
    did_application=DATA_IDENTIFIER_TYPE.APPLICATION_SOFTWARE_IDENTIFICATION,
    isotp_send=isotp_send,
  )


class EcuTransport:
  def __init__(
    self,
    *,
    bindings: Any | None = None,
    serial: str | None = None,
    sleeper: Callable[[float], None] | None = None,
  ):
    self._bindings = bindings
    self._serial = serial
    self._sleeper = time.sleep if sleeper is None else sleeper
    self.panda: Any | None = None
    self.uds: Any | None = None

  def __enter__(self) -> "EcuTransport":
    bindings = self._bindings or load_openpilot_bindings()
    self._bindings = bindings
    self.panda = bindings.Panda(self._serial)
    try:
      self.panda.set_safety_mode(bindings.elm327)
      self.uds = bindings.UdsClient(
        self.panda,
        TARGET.uds_request_id,
        TARGET.uds_response_id,
        TARGET.bus,
        timeout=0.2,
        response_pending_timeout=10.0,
      )
    except Exception:
      self.panda.close()
      self.panda = None
      raise
    return self

  def __exit__(self, exc_type, exc, traceback) -> None:
    if self.panda is not None:
      self.panda.close()
    self.panda = None
    self.uds = None

  def _require_open(self) -> tuple[Any, Any, Any]:
    if self._bindings is None or self.panda is None or self.uds is None:
      raise TransportError("transport is not open")
    return self._bindings, self.panda, self.uds

  def _switch_session(self, uds: Any, session: Any, settle_seconds: float) -> None:
    uds.diagnostic_session_control(session)
    self._sleeper(settle_seconds)

  def read_identity(self) -> EcuIdentity:
    bindings, panda, uds = self._require_open()
    application = bytes(uds.read_data_by_identifier(bindings.did_application))
    panda_serial = str(panda.get_usb_serial())

    if application != TARGET.application_software_id:
      # Application F181 already differs from the runtime allowlist.  Skip
      # the programming-session transition: entering and relaunching the
      # application session is reported (Discord, 2026-09-10) to leave FRC
      # unhappy for the ignition cycle, faulting DRCC/TSS longitudinal.
      # Boot F181 is left unread; the identity mismatch is detected before
      # any payload is run.
      return EcuIdentity(
        part_number=b"",
        boot_software_id=b"",
        application_software_id=application,
        panda_serial=panda_serial,
      )

    # Application matches the runtime allowlist.  Enter the programming
    # session to read the boot F181.
    self._switch_session(uds, bindings.session_default, 0.5)
    self._switch_session(uds, bindings.session_extended, 0.7)
    self._switch_session(uds, bindings.session_programming, 1.0)
    self._switch_session(uds, bindings.session_default, 0.5)
    self._switch_session(uds, bindings.session_extended, 0.7)
    boot = bytes(uds.read_data_by_identifier(bindings.did_application))
    return EcuIdentity(
      part_number=TARGET.part_number,
      boot_software_id=boot,
      application_software_id=application,
      panda_serial=panda_serial,
    )

  def read_bootloader_identity(self) -> BootloaderIdentity:
    """Read F181 directly in the current bootloader session without transitions."""
    bindings, panda, uds = self._require_open()
    software_id = bytes(uds.read_data_by_identifier(bindings.did_application))
    if len(software_id) != 33:
      raise TransportError("bootloader F181 must be exactly 33 bytes")
    return BootloaderIdentity(
      software_id=software_id,
      panda_serial=str(panda.get_usb_serial()),
    )

  def enter_programming_and_unlock(self, *, new_uds: bool) -> bytes:
    bindings, _panda, uds = self._require_open()
    from Crypto.Cipher import AES

    def enter() -> None:
      self._switch_session(uds, bindings.session_default, 0.5)
      self._switch_session(uds, bindings.session_extended, 0.7)
      self._switch_session(uds, bindings.session_programming, 1.0)

    enter()
    if not new_uds:
      enter()
    seed_record = bytes(16)
    seed = bytes(uds.security_access(bindings.access_request_seed, data_record=seed_record))
    if len(seed) != 16:
      raise TransportError("SecurityAccess seed is not 16 bytes")
    intermediate = AES.new(SECURITY_ACCESS_SECRET, AES.MODE_ECB).decrypt(seed_record)
    key = AES.new(intermediate, AES.MODE_ECB).encrypt(seed)
    uds.security_access(bindings.access_send_key, security_key=key)
    return seed

  def prepare_and_upload(self, envelope: bytes, *, expected_sha256: str, new_uds: bool) -> None:
    bindings, _panda, uds = self._require_open()
    try:
      TARGET.validate()
    except ValueError as exc:
      raise TransportError(f"target manifest is invalid: {exc}") from exc
    if type(envelope) is not bytes or len(envelope) != TARGET.envelope_length:
      raise TransportError("payload envelope must be exactly 4096 bytes")
    if (
      type(expected_sha256) is not str or len(expected_sha256) != 64
      or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
      raise TransportError("payload SHA-256 pin is malformed")
    if type(new_uds) is not bool:
      raise TransportError("UDS variant flag must be boolean")
    actual_digest = hashlib.sha256(envelope).hexdigest()
    if actual_digest != expected_sha256:
      raise TransportError(
        f"payload SHA-256 mismatch: expected {expected_sha256}, got {actual_digest}"
      )
    self._prevalidate_download(TARGET.ram_address, envelope)
    self.enter_programming_and_unlock(new_uds=new_uds)
    did_201 = bytes(16)
    did_202 = bytes(16)
    uds.write_data_by_identifier(0x203, b"\x01\x00\x00\x00\x00")
    uds.write_data_by_identifier(0x201, did_201)
    uds.write_data_by_identifier(0x202, did_202)

    self._download_memory(uds, TARGET.ram_address, envelope)
    self._authenticate_envelope(uds, new_uds=new_uds)

  def _download_memory(self, uds: Any, address: int, data: bytes) -> None:
    bindings, _panda, active_uds = self._require_open()
    if uds is not active_uds:
      raise TransportError("RequestDownload used an unexpected UDS client")
    self._prevalidate_download(address, data)

    request = b"\x01\x46\x01\x00" + struct.pack("!II", address, len(data))
    download_response = bytes(
      uds._uds_request(bindings.service_request_download, data=request)
    )
    if not download_response:
      raise TransportError("RequestDownload response is empty")
    length_width = download_response[0] >> 4
    if (
      length_width == 0
      or (download_response[0] & 0x0F) != 0
      or len(download_response) != length_width + 1
    ):
      raise TransportError("RequestDownload response has an invalid length format")
    max_block_length = int.from_bytes(download_response[1:], "big")
    max_payload = max_block_length - 2  # SID + blockSequenceCounter
    if max_payload <= 0:
      raise TransportError("RequestDownload negotiated an unusable block length")
    chunk_size = min(0x400, max_payload)
    transfer_count = (len(data) + chunk_size - 1) // chunk_size
    if transfer_count > 0xFF:
      raise TransportError("RequestDownload block length would overflow the transfer counter")
    for offset in range(0, len(data), chunk_size):
      uds.transfer_data(offset // chunk_size + 1, data[offset:offset + chunk_size])
    uds.request_transfer_exit()

  @staticmethod
  def _prevalidate_download(address: int, data: bytes) -> None:
    if (
      type(address) is not int
      or not 0 <= address <= 0xFFFFFFFF
      or type(data) is not bytes
      or not data
      or len(data) > 0xFFFFFFFF
      or address + len(data) > 0x100000000
    ):
      raise TransportError("RequestDownload memory range is invalid")
    transfer_count_at_max_chunk = (len(data) + 0x3FF) // 0x400
    if transfer_count_at_max_chunk > 0xFF:
      raise TransportError("RequestDownload block length would overflow the transfer counter")

  def _authenticate_envelope(self, uds: Any, *, new_uds: bool) -> None:
    bindings, _panda, active_uds = self._require_open()
    if uds is not active_uds:
      raise TransportError("payload authentication used an unexpected UDS client")
    routine_magic = b"\x45\x01" if new_uds else b"\x45\x00"
    option = routine_magic + struct.pack("!II", TARGET.ram_address, TARGET.envelope_length)
    uds.routine_control(bindings.routine_start, 0x10F0, option)

  def trigger(
    self, *, operation: int, new_uds: bool, sector_base: int | None = None,
  ) -> None:
    bindings, panda, _uds = self._require_open()
    if operation not in (
      OP_FACI_PE_CYCLE, OP_CRC_PROBE, OP_RAM_ECHO, OP_RESTORE_SECTOR,
      OP_VERIFY_CRC, OP_CRC_INTERMEDIATE, OP_WRITE_TARGET_CANDIDATE,
      OP_WRITE_CRC_CANDIDATE, OP_LIVE_READ,
    ):
      raise TransportError("unknown payload operation")
    expected_base = {
      OP_WRITE_TARGET_CANDIDATE: TARGET.sector_base,
      OP_WRITE_CRC_CANDIDATE: TARGET.crc_sector_base,
    }.get(operation)
    if operation == OP_RESTORE_SECTOR:
      if sector_base not in (
        TARGET.sector_base, TARGET.crc_sector_base,
      ):
        raise TransportError("payload trigger sector base is not allowed")
    elif expected_base is not None:
      if sector_base != expected_base:
        raise TransportError("candidate-writer trigger base is not its fixed direction")
    elif sector_base is not None:
      raise TransportError("payload trigger sector base is not allowed")
    routine_magic = b"\x45\x01" if new_uds else b"\x45\x00"
    option = routine_magic + struct.pack(
      "!II", _UDS_TRIGGER_BASE, TARGET.sector_length,
    )
    bindings.isotp_send(
      panda,
      b"\x31\x01\xff\x00" + option,
      TARGET.uds_request_id,
      bus=TARGET.bus,
      recvaddr=TARGET.uds_response_id,
    )

  def collect_stream(self, *, operation: int, timeout: float = 60.0) -> StreamResult:
    _bindings, panda, _uds = self._require_open()
    if timeout <= 0:
      raise TransportError("stream timeout must be positive")
    collector = StreamCollector(expected_operation=operation)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
      for can_id, data, bus in panda.can_recv():
        if can_id != TARGET.uds_response_id or bus != TARGET.bus:
          continue
        frame = bytes(data)
        if len(frame) == 8 and frame[0] == 0x03 and frame[1:3] == b"\x7f\x31":
          nrc = frame[3]
          if nrc == 0x78:
            continue
          raise TransportError(
            f"RoutineControl negative response NRC 0x{nrc:02x}; raw={frame.hex()}"
          )
        try:
          collector.consume(can_id, bus, frame)
          if frame[0] == FrameType.END:
            return collector.finish()
        except ProtocolError as exc:
          raise TransportError(
            f"invalid payload stream: {exc}; raw={frame.hex()}"
          ) from exc
    raise TransportError(f"timed out waiting for payload stream after {timeout:.1f}s")

  def run_payload(self, image: Any, *, operation: int, new_uds: bool) -> StreamResult:
    destructive = operation in (
      OP_RESTORE_SECTOR, OP_WRITE_TARGET_CANDIDATE, OP_WRITE_CRC_CANDIDATE,
    )
    sector_base = None
    if destructive:
      if type(image) is not SpecializedPayloadImage:
        raise TransportError("destructive operation requires an exact specialized payload")
      try:
        image.validate()
      except PayloadError as exc:
        raise TransportError(f"destructive payload specialization is invalid: {exc}") from exc
      sector_base = image.sector_base
    triggered = False
    try:
      self.prepare_and_upload(
        bytes(image.envelope), expected_sha256=str(image.sha256), new_uds=new_uds,
      )
      triggered = True
      self.trigger(operation=operation, new_uds=new_uds, sector_base=sector_base)
      return self.collect_stream(operation=operation)
    except Exception as exc:
      if destructive and triggered:
        raise PostTriggerTransportError(exc) from exc
      raise

  def reconnect_reset(self) -> None:
    _bindings, panda, _uds = self._require_open()
    panda.reset(reconnect=True)
