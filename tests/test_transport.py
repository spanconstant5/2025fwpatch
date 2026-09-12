import hashlib
import binascii
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from eps_patch.protocol import (
  OP_CRC_INTERMEDIATE, OP_CRC_PROBE, OP_FACI_PE_CYCLE, OP_LIVE_READ,
  OP_RAM_ECHO, OP_RESTORE_SECTOR, OP_VERIFY_CRC, OP_WRITE_CRC_CANDIDATE,
  OP_WRITE_TARGET_CANDIDATE,
)


class FakePanda:
  instances = []

  def __init__(self, serial=None):
    self.serial = serial
    self.safety = []
    self.resets = []
    self.closed = False
    self.can_batches = []
    FakePanda.instances.append(self)

  def set_safety_mode(self, mode):
    self.safety.append(mode)

  def reset(self, *, reconnect):
    self.resets.append(reconnect)

  def close(self):
    self.closed = True

  def get_usb_serial(self):
    return self.serial or "PANDA-DEFAULT"

  def can_recv(self):
    if self.can_batches:
      return self.can_batches.pop(0)
    return []


class FakeUds:
  instances = []

  def __init__(self, panda, tx_addr, rx_addr, bus, *, timeout, response_pending_timeout):
    self.constructor = (panda, tx_addr, rx_addr, bus, timeout, response_pending_timeout)
    self.calls = []
    self.identity_reads = 0
    self.download_response = b"\x20\x04\x02"
    FakeUds.instances.append(self)

  def read_data_by_identifier(self, did):
    self.calls.append(("read", did))
    assert did == 0xF181
    entered_programming = ("session", 2) in self.calls
    return (
      b"\x02" + (b"!" * 32)
      if entered_programming
      else b"\x02" + b"8965F1208000" + bytes(4) + b"8A3111202000" + bytes(4)
    )

  def diagnostic_session_control(self, session):
    self.calls.append(("session", session))

  def security_access(self, access, security_key=b"", data_record=b""):
    self.calls.append(("security", access, security_key, data_record))
    if access == 1:
      return bytes.fromhex("00112233445566778899aabbccddeeff")

  def write_data_by_identifier(self, did, data):
    self.calls.append(("write", did, data))

  def _uds_request(self, service, *, data):
    self.calls.append(("private_request", service, data))
    return self.download_response

  def transfer_data(self, counter, data):
    self.calls.append(("transfer", counter, data))

  def request_transfer_exit(self):
    self.calls.append(("exit",))

  def routine_control(self, kind, identifier, data):
    self.calls.append(("routine", kind, identifier, data))
    return b""


def fake_bindings(isotp_calls):
  return SimpleNamespace(
    Panda=FakePanda,
    UdsClient=FakeUds,
    elm327=42,
    session_default=1,
    session_extended=3,
    session_programming=2,
    access_request_seed=1,
    access_send_key=2,
    service_request_download=0x34,
    routine_start=1,
    did_application=0xF181,
    isotp_send=lambda *args, **kwargs: isotp_calls.append((args, kwargs)),
  )


@pytest.fixture(autouse=True)
def clear_fakes(monkeypatch):
  monkeypatch.setattr("eps_patch.transport.time.sleep", lambda _seconds: None)
  FakePanda.instances.clear()
  FakeUds.instances.clear()


def test_transport_opens_current_panda_and_uds_shape_and_closes():
  from eps_patch.transport import EcuTransport

  calls = []
  with EcuTransport(bindings=fake_bindings(calls), serial="abc") as transport:
    panda = FakePanda.instances[-1]
    uds = FakeUds.instances[-1]
    assert panda.serial == "abc"
    assert panda.safety == [42]
    assert uds.constructor[1:] == (0x7A1, 0x7A9, 0, 0.2, 10.0)
    identity = transport.read_identity()
    assert identity.part_number == b"8965F1208000"
    assert identity.panda_serial == "abc"
    assert identity.boot_software_id == b"\x02" + (b"!" * 32)
    assert [call for call in uds.calls if call[0] == "read"] == [
      ("read", 0xF181),
      ("read", 0xF181),
    ]
    assert [call for call in uds.calls if call[0] == "session"] == [
      ("session", 1), ("session", 3), ("session", 2), ("session", 1), ("session", 3),
    ]
  assert panda.closed


def test_transport_rejectable_identity_preserves_raw_application_bytes():
  from eps_patch.transport import EcuTransport

  application = b"\x02" + b"8965F1208000" + bytes(4) + b"8A3111202000" + bytes(4)
  with EcuTransport(bindings=fake_bindings([])) as transport:
    reads = iter((application, b"\x01" + b"8965H0000000" + bytes(4)))
    FakeUds.instances[-1].read_data_by_identifier = lambda _did: next(reads)
    identity = transport.read_identity()

  assert identity.part_number == b"8965F1208000"
  assert identity.application_software_id == application


def test_transport_skips_programming_session_when_application_does_not_match():
  """Application F181 mismatch: no session transition, boot F181 left empty."""
  from eps_patch.transport import EcuTransport

  # 2025 secondary — matches the offline specimen but not the runtime target.
  application_2025 = b"\x02" + b"8965F1208000" + bytes(4) + b"8A3111213000" + bytes(4)
  with EcuTransport(bindings=fake_bindings([])) as transport:
    uds = FakeUds.instances[-1]
    reads = iter([application_2025])
    uds.read_data_by_identifier = lambda _did: next(reads)
    identity = transport.read_identity()

  assert identity.application_software_id == application_2025
  assert identity.boot_software_id == b""
  assert identity.part_number == b""
  # No session transitions: programming mode is not entered when app already fails.
  assert not any(call[0] == "session" for call in uds.calls)


def test_read_bootloader_identity_rejects_malformed_f181_without_session_switch():
  from eps_patch.transport import EcuTransport, TransportError

  with EcuTransport(bindings=fake_bindings([])) as transport:
    uds = FakeUds.instances[-1]
    uds.read_data_by_identifier = lambda did: (
      uds.calls.append(("read", did)) or bytes(32)
    )
    with pytest.raises(TransportError, match="exactly 33 bytes"):
      transport.read_bootloader_identity()

  assert uds.calls == [("read", 0xF181)]


def test_read_bootloader_identity_propagates_uds_negative_response():
  from eps_patch.transport import EcuTransport

  with EcuTransport(bindings=fake_bindings([])) as transport:
    uds = FakeUds.instances[-1]

    def fail(_did):
      raise RuntimeError("NRC 0x31")

    uds.read_data_by_identifier = fail
    with pytest.raises(RuntimeError, match="NRC 0x31"):
      transport.read_bootloader_identity()

  assert not any(call[0] == "session" for call in uds.calls)


def test_read_full_identity_always_enters_programming_session():
  """read_full_identity enters programming regardless of application F181."""
  from eps_patch.transport import EcuTransport

  application_2025 = b"\x02" + b"8965F1208000" + bytes(4) + b"8A3111213000" + bytes(4)
  boot_bytes = b"\x02" + b"8965H0000000" + bytes(4) + b"8A0000000000" + bytes(4)
  with EcuTransport(bindings=fake_bindings([])) as transport:
    uds = FakeUds.instances[-1]
    reads = iter([application_2025, boot_bytes])
    uds.read_data_by_identifier = lambda _did: next(reads)
    identity = transport.read_full_identity()

  assert identity.application_software_id == application_2025
  assert identity.boot_software_id == boot_bytes
  assert identity.part_number == b""
  assert identity.panda_serial == "PANDA-DEFAULT"
  # Programming session must be entered even though application differs from runtime target.
  sessions = [call[1] for call in uds.calls if call[0] == "session"]
  assert sessions == [1, 3, 2, 1, 3]


def test_transport_uploads_only_hash_checked_envelope_with_private_download():
  from eps_patch.transport import EcuTransport

  isotp_calls = []
  envelope = bytes(range(256)) * 16
  digest = hashlib.sha256(envelope).hexdigest()
  with EcuTransport(bindings=fake_bindings(isotp_calls)) as transport:
    transport.prepare_and_upload(envelope, expected_sha256=digest, new_uds=True)
    uds = FakeUds.instances[-1]

  private = [call for call in uds.calls if call[0] == "private_request"]
  assert private == [(
    "private_request", 0x34,
    bytes.fromhex("01 46 01 00 fe bf 00 00 00 00 10 00"),
  )]
  transfers = [call for call in uds.calls if call[0] == "transfer"]
  assert [call[1] for call in transfers] == [1, 2, 3, 4]
  assert b"".join(call[2] for call in transfers) == envelope
  assert uds.calls[-1][0] == "routine"


def test_specialized_writer_uses_one_fixed_four_kib_download(monkeypatch):
  from eps_patch.manifest import TARGET
  from eps_patch.payload import SpecializedPayloadImage
  from eps_patch.protocol import OP_WRITE_TARGET_CANDIDATE
  from eps_patch.transport import EcuTransport

  envelope = bytes(range(256)) * 16
  image = object.__new__(SpecializedPayloadImage)
  object.__setattr__(image, "envelope", envelope)
  object.__setattr__(image, "sha256", hashlib.sha256(envelope).hexdigest())
  object.__setattr__(image, "sector_base", TARGET.sector_base)
  monkeypatch.setattr(SpecializedPayloadImage, "validate", lambda _self: b"")
  with EcuTransport(bindings=fake_bindings([])) as transport:
    transport.collect_stream = lambda *, operation: ("stream", operation)
    assert transport.run_payload(
      image, operation=OP_WRITE_TARGET_CANDIDATE, new_uds=False,
    ) == ("stream", OP_WRITE_TARGET_CANDIDATE)
    uds = FakeUds.instances[-1]

  downloads = [call for call in uds.calls if call[0] == "private_request"]
  assert downloads == [(
    "private_request", 0x34,
    bytes.fromhex("01 46 01 00 fe bf 00 00 00 00 10 00"),
  )]


def test_transport_has_no_sector_staging_api():
  import eps_patch.transport as transport

  assert not hasattr(transport, "RamBlob")
  assert not hasattr(transport.EcuTransport, "run_staged_payload")


def test_transport_honors_negotiated_request_download_block_length():
  from eps_patch.transport import EcuTransport

  envelope = bytes(range(256)) * 16
  digest = hashlib.sha256(envelope).hexdigest()
  with EcuTransport(bindings=fake_bindings([])) as transport:
    FakeUds.instances[-1].download_response = b"\x20\x02\x02"
    transport.prepare_and_upload(envelope, expected_sha256=digest, new_uds=False)
    transfers = [call for call in FakeUds.instances[-1].calls if call[0] == "transfer"]

  assert len(transfers) == 8
  assert all(len(call[2]) == 0x200 for call in transfers)


def _download_records(uds):
  records = []
  current = None
@pytest.mark.parametrize(
  "operation,base",
  ((OP_WRITE_TARGET_CANDIDATE, 0xF8000), (OP_WRITE_CRC_CANDIDATE, 0x88000)),
)
def test_candidate_writer_trigger_rejects_cross_direction_base(operation, base):
  from eps_patch.transport import EcuTransport, TransportError

  with EcuTransport(bindings=fake_bindings([])) as transport:
    with pytest.raises(TransportError, match="fixed direction"):
      transport.trigger(operation=operation, new_uds=False, sector_base=base)


@pytest.mark.parametrize(
  ("operation", "actual_base"),
  (
    (OP_WRITE_TARGET_CANDIDATE, 0x88000),
    (OP_WRITE_CRC_CANDIDATE, 0xF8000),
  ),
)
def test_candidate_writer_validates_actual_sector_then_uses_fixed_trigger_route(
  operation, actual_base,
):
  from eps_patch.transport import EcuTransport

  calls = []
  with EcuTransport(bindings=fake_bindings(calls)) as transport:
    transport.trigger(
      operation=operation, new_uds=False, sector_base=actual_base,
    )
  assert calls[0][0][1] == bytes.fromhex(
    "31 01 ff 00 45 00 00 0e 00 00 00 00 80 00"
  )


@pytest.mark.parametrize("actual_base", (0x88000, 0xF8000))
def test_restore_validates_actual_sector_then_uses_fixed_trigger_route(actual_base):
  from eps_patch.transport import EcuTransport

  calls = []
  with EcuTransport(bindings=fake_bindings(calls)) as transport:
    transport.trigger(
      operation=OP_RESTORE_SECTOR, new_uds=False, sector_base=actual_base,
    )
  assert calls[0][0][1] == bytes.fromhex(
    "31 01 ff 00 45 00 00 0e 00 00 00 00 80 00"
  )


def test_actual_sector_differences_cannot_change_fixed_trigger_bytes():
  from eps_patch.transport import EcuTransport

  isotp_calls = []
  with EcuTransport(bindings=fake_bindings(isotp_calls)) as transport:
    transport.trigger(
      operation=OP_WRITE_TARGET_CANDIDATE,
      new_uds=False,
      sector_base=0x88000,
    )
    transport.trigger(
      operation=OP_WRITE_CRC_CANDIDATE,
      new_uds=False,
      sector_base=0xF8000,
    )
    transport.trigger(
      operation=OP_RESTORE_SECTOR,
      new_uds=False,
      sector_base=0x88000,
    )
    transport.trigger(
      operation=OP_RESTORE_SECTOR,
      new_uds=False,
      sector_base=0xF8000,
    )

  expected = bytes.fromhex(
    "31 01 ff 00 45 00 00 0e 00 00 00 00 80 00"
  )
  assert [call[0][1] for call in isotp_calls] == [expected] * 4


@pytest.mark.parametrize(
  "operation",
  (OP_WRITE_TARGET_CANDIDATE, OP_WRITE_CRC_CANDIDATE, OP_RESTORE_SECTOR),
)
def test_caller_cannot_supply_an_arbitrary_trigger_base(operation):
  from eps_patch.transport import EcuTransport, TransportError

  isotp_calls = []
  with EcuTransport(bindings=fake_bindings(isotp_calls)) as transport:
    with pytest.raises(TransportError):
      transport.trigger(
        operation=operation,
        new_uds=False,
        sector_base=0x70000,
      )

  assert isotp_calls == []


def test_restore_trigger_rejects_uds_route_as_actual_sector():
  from eps_patch.transport import EcuTransport, TransportError

  with EcuTransport(bindings=fake_bindings([])) as transport:
    with pytest.raises(TransportError, match="not allowed"):
      transport.trigger(
        operation=OP_RESTORE_SECTOR, new_uds=False, sector_base=0xE0000,
      )


def test_restore_trigger_rejects_missing_actual_sector():
  from eps_patch.transport import EcuTransport, TransportError

  isotp_calls = []
  with EcuTransport(bindings=fake_bindings(isotp_calls)) as transport:
    with pytest.raises(TransportError, match="sector base is not allowed"):
      transport.trigger(
        operation=OP_RESTORE_SECTOR, new_uds=False, sector_base=None,
      )

  assert isotp_calls == []


def test_live_read_trigger_uses_fixed_bench_route_and_rejects_override():
  from eps_patch.transport import EcuTransport, TransportError

  isotp_calls = []
  with EcuTransport(bindings=fake_bindings(isotp_calls)) as transport:
    transport.trigger(operation=OP_LIVE_READ, new_uds=False)
    with pytest.raises(TransportError, match="base is not allowed"):
      transport.trigger(
        operation=OP_LIVE_READ,
        new_uds=False,
        sector_base=0xF8000,
      )

  assert len(isotp_calls) == 1
  assert isotp_calls[0][0][1] == bytes.fromhex(
    "31 01 ff 00 45 00 00 0e 00 00 00 00 80 00"
  )


@pytest.mark.parametrize("response", [b"", b"\x10\x04", b"\x21\x04\x02", b"\x20\x00\x01"])
def test_transport_rejects_malformed_request_download_response(response):
  from eps_patch.transport import EcuTransport, TransportError

  envelope = bytes(0x1000)
  digest = hashlib.sha256(envelope).hexdigest()
  with EcuTransport(bindings=fake_bindings([])) as transport:
    FakeUds.instances[-1].download_response = response
    with pytest.raises(TransportError, match="RequestDownload"):
      transport.prepare_and_upload(envelope, expected_sha256=digest, new_uds=False)
    assert not any(call[0] == "transfer" for call in FakeUds.instances[-1].calls)


def test_transport_rejects_payload_before_programming_when_hash_is_wrong():
  from eps_patch.transport import EcuTransport, TransportError

  with EcuTransport(bindings=fake_bindings([])) as transport:
    with pytest.raises(TransportError, match="SHA-256"):
      transport.prepare_and_upload(bytes(0x1000), expected_sha256="0" * 64, new_uds=True)
    assert FakeUds.instances[-1].calls == []


def test_transport_formats_current_isotp_trigger_call():
  from eps_patch.transport import EcuTransport

  isotp_calls = []
  with EcuTransport(bindings=fake_bindings(isotp_calls)) as transport:
    transport.trigger(operation=OP_FACI_PE_CYCLE, new_uds=True)

  args, kwargs = isotp_calls[0]
  assert args[1] == bytes.fromhex("31 01 ff 00 45 01 00 0e 00 00 00 00 80 00")
  assert args[2] == 0x7A1
  assert kwargs == {"bus": 0, "recvaddr": 0x7A9}


def test_transport_accepts_pe_cycle_operation_for_the_fixed_bench_route():
  from eps_patch.transport import EcuTransport

  isotp_calls = []
  with EcuTransport(bindings=fake_bindings(isotp_calls)) as transport:
    transport.trigger(operation=OP_FACI_PE_CYCLE, new_uds=False)
  assert isotp_calls[0][0][1] == bytes.fromhex(
    "31 01 ff 00 45 00 00 0e 00 00 00 00 80 00"
  )


@pytest.mark.parametrize(
  "operation",
  (
    OP_FACI_PE_CYCLE, OP_CRC_PROBE, OP_RAM_ECHO, OP_VERIFY_CRC,
    OP_CRC_INTERMEDIATE, OP_LIVE_READ,
  ),
)
def test_every_nondestructive_payload_uses_the_fixed_bench_route(operation):
  from eps_patch.transport import EcuTransport

  isotp_calls = []
  with EcuTransport(bindings=fake_bindings(isotp_calls)) as transport:
    transport.trigger(operation=operation, new_uds=False)

  assert isotp_calls[0][0][1] == bytes.fromhex(
    "31 01 ff 00 45 00 00 0e 00 00 00 00 80 00"
  )


def test_transport_security_access_uses_distinct_seed_key_secret():
  from eps_patch.transport import EcuTransport

  with EcuTransport(bindings=fake_bindings([])) as transport:
    transport.enter_programming_and_unlock(new_uds=True)
    security_calls = [call for call in FakeUds.instances[-1].calls if call[0] == "security"]

  assert security_calls[0] == ("security", 1, b"", bytes(16))
  assert security_calls[1][0:2] == ("security", 2)
  assert security_calls[1][2].hex() == "9d7b16ff9c7bb92ba0890a6766a93cd8"


def test_old_uds_session_order_is_preserved_with_exact_settling_delays():
  from eps_patch.transport import EcuTransport

  events = []
  with EcuTransport(bindings=fake_bindings([]), sleeper=lambda seconds: events.append(("sleep", seconds))) as transport:
    uds = FakeUds.instances[-1]
    uds.diagnostic_session_control = lambda session: events.append(("session", session))
    transport.enter_programming_and_unlock(new_uds=False)

  assert events == [
    ("session", 1), ("sleep", 0.5),
    ("session", 3), ("sleep", 0.7),
    ("session", 2), ("sleep", 1.0),
    ("session", 1), ("sleep", 0.5),
    ("session", 3), ("sleep", 0.7),
    ("session", 2), ("sleep", 1.0),
  ]


def test_failed_session_transition_is_not_slept_or_retried():
  from eps_patch.transport import EcuTransport

  events = []
  with EcuTransport(bindings=fake_bindings([]), sleeper=lambda seconds: events.append(("sleep", seconds))) as transport:
    uds = FakeUds.instances[-1]

    def fail(session):
      events.append(("session", session))
      raise RuntimeError("transition failed")

    uds.diagnostic_session_control = fail
    with pytest.raises(RuntimeError, match="transition failed"):
      transport.enter_programming_and_unlock(new_uds=False)

  assert events == [("session", 1)]


def _ram_echo_frames(sector):
  from eps_patch.protocol import FrameType, OP_RAM_ECHO, PROTOCOL_VERSION

  frames = [
    bytes([FrameType.BEGIN0, PROTOCOL_VERSION, OP_RAM_ECHO, 0])
    + struct.pack("<I", 0xFEBF2000),
    bytes([FrameType.BEGIN1, PROTOCOL_VERSION, OP_RAM_ECHO, 1])
    + struct.pack("<I", len(sector)),
  ]
  frames.extend(
    bytes([FrameType.DATA]) + struct.pack("<H", index) + b"\x00"
    + sector[index * 4:index * 4 + 4]
    for index in range(0x2000)
  )
  frames.extend((
    bytes([FrameType.MAGIC, 0, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.MAGIC, 1, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.STATUS, 1, 0, 0]) + bytes(4),
    bytes([FrameType.END, 0, 0, 0]) + struct.pack("<I", binascii.crc32(sector)),
  ))
  return frames


def test_transport_collects_ram_echo_as_one_exact_sram_region():
  from eps_patch.protocol import OP_RAM_ECHO
  from eps_patch.transport import EcuTransport

  sector = bytes((index * 17) & 0xFF for index in range(0x8000))
  frames = _ram_echo_frames(sector)

  with EcuTransport(bindings=fake_bindings([])) as transport:
    FakePanda.instances[-1].can_batches = [
      [(0x7A9, frame, 0) for frame in frames]
    ]
    result = transport.collect_stream(operation=OP_RAM_ECHO, timeout=1.0)

  assert result.operation == OP_RAM_ECHO
  assert result.sector == sector
  assert result.statuses == ((1, 0),)


def test_collect_stream_ignores_routine_pending_with_arbitrary_padding():
  from eps_patch.protocol import OP_RAM_ECHO
  from eps_patch.transport import EcuTransport

  pending = bytes.fromhex("03 7f 31 78 aa bb cc dd")
  sector = bytes((index * 17) & 0xFF for index in range(0x8000))
  with EcuTransport(bindings=fake_bindings([])) as transport:
    FakePanda.instances[-1].can_batches = [[
      (0x7A9, pending, 0),
      *((0x7A9, frame, 0) for frame in _ram_echo_frames(sector)),
    ]]
    result = transport.collect_stream(operation=OP_RAM_ECHO, timeout=1.0)

  assert result.operation == OP_RAM_ECHO
  assert result.sector == sector


def test_collect_stream_reports_nonpending_routine_nrc_and_raw_frame():
  from eps_patch.protocol import OP_RAM_ECHO
  from eps_patch.transport import EcuTransport, TransportError

  frame = bytes.fromhex("03 7f 31 22 aa bb cc dd")
  with EcuTransport(bindings=fake_bindings([])) as transport:
    FakePanda.instances[-1].can_batches = [[(0x7A9, frame, 0)]]
    with pytest.raises(
      TransportError, match=r"NRC 0x22.*037f3122aabbccdd",
    ):
      transport.collect_stream(operation=OP_RAM_ECHO, timeout=0.1)


def test_collect_stream_reports_unknown_payload_frame_raw_bytes():
  from eps_patch.protocol import OP_RAM_ECHO
  from eps_patch.transport import EcuTransport, TransportError

  frame = bytes.fromhex("03 01 02 03 04 05 06 07")
  with EcuTransport(bindings=fake_bindings([])) as transport:
    FakePanda.instances[-1].can_batches = [[(0x7A9, frame, 0)]]
    with pytest.raises(TransportError, match="0301020304050607"):
      transport.collect_stream(operation=OP_RAM_ECHO, timeout=0.1)


def test_transport_converts_payload_protocol_errors_to_transport_errors():
  from eps_patch.protocol import OP_RAM_ECHO
  from eps_patch.transport import EcuTransport, TransportError

  with EcuTransport(bindings=fake_bindings([])) as transport:
    FakePanda.instances[-1].can_batches = [[(0x7A9, bytes(8), 0)]]
    with pytest.raises(TransportError, match="payload stream"):
      transport.collect_stream(operation=OP_RAM_ECHO, timeout=0.1)
