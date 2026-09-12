import json
from pathlib import Path

import pytest

from eps_patch.identify import IdentifyError, run_identify
from eps_patch.paths import ArtifactLayout
from eps_patch.transport import EcuIdentity


_APP_F181 = b"\x02" + b"8965F1208000" + bytes(4) + b"8A3111213000" + bytes(4)
_BOOT_F181 = b"\x02" + b"8965H0000000" + bytes(4) + b"8A0000000000" + bytes(4)
_PANDA_SERIAL = "PANDA-IDENTIFY-TEST"


class _FakeTransport:
  def __init__(self, *, application=_APP_F181, boot=_BOOT_F181, serial=_PANDA_SERIAL):
    self._application = application
    self._boot = boot
    self._serial = serial
    self.read_full_identity_called = False

  def __enter__(self):
    return self

  def __exit__(self, *_):
    pass

  def read_full_identity(self) -> EcuIdentity:
    self.read_full_identity_called = True
    return EcuIdentity(
      part_number=b"",
      boot_software_id=self._boot,
      application_software_id=self._application,
      panda_serial=self._serial,
    )


def _layout(tmp_path: Path) -> ArtifactLayout:
  return ArtifactLayout(tmp_path / "artifacts")


def test_identify_returns_identity_capture_report_path(tmp_path):
  layout = _layout(tmp_path)
  transport = _FakeTransport()
  result = run_identify(
    layout=layout,
    preflight=lambda: None,
    transport_factory=lambda: transport,
  )
  assert result == layout.identity_capture_report
  assert transport.read_full_identity_called


def test_identify_report_is_valid_json(tmp_path):
  layout = _layout(tmp_path)
  run_identify(
    layout=layout,
    preflight=lambda: None,
    transport_factory=lambda: _FakeTransport(),
  )
  content = layout.identity_capture_report.read_bytes()
  report = json.loads(content)
  assert report["schema"] == 1
  assert report["workflow"] == "identify"
  assert "created_at" in report


def test_identify_report_never_authorizes(tmp_path):
  layout = _layout(tmp_path)
  run_identify(
    layout=layout,
    preflight=lambda: None,
    transport_factory=lambda: _FakeTransport(),
  )
  report = json.loads(layout.identity_capture_report.read_bytes())
  assert report["authorizes_patch_or_restore"] is False


def test_identify_report_observed_fields(tmp_path):
  layout = _layout(tmp_path)
  run_identify(
    layout=layout,
    preflight=lambda: None,
    transport_factory=lambda: _FakeTransport(),
  )
  report = json.loads(layout.identity_capture_report.read_bytes())
  observed = report["observed"]
  assert observed["application_software_id"] == _APP_F181.hex()
  assert observed["boot_software_id"] == _BOOT_F181.hex()
  assert observed["panda_serial"] == _PANDA_SERIAL


def test_identify_report_known_specimen_recognition(tmp_path):
  layout = _layout(tmp_path)
  run_identify(
    layout=layout,
    preflight=lambda: None,
    transport_factory=lambda: _FakeTransport(application=_APP_F181),
  )
  report = json.loads(layout.identity_capture_report.read_bytes())
  assert report["recognition"] == "known-2025-corolla-specimen"


def test_identify_report_unrecognized_specimen(tmp_path):
  layout = _layout(tmp_path)
  unknown_app = b"\x02" + b"0000F0000000" + bytes(4) + b"0000F0000000" + bytes(4)
  run_identify(
    layout=layout,
    preflight=lambda: None,
    transport_factory=lambda: _FakeTransport(application=unknown_app),
  )
  report = json.loads(layout.identity_capture_report.read_bytes())
  assert report["recognition"] == "unrecognized"


def test_identify_overwrites_previous_capture(tmp_path):
  layout = _layout(tmp_path)
  for i in range(2):
    run_identify(
      layout=layout,
      preflight=lambda: None,
      transport_factory=lambda: _FakeTransport(serial=f"PANDA-{i}"),
    )
  # After two runs the file must still exist and be parseable; no crash.
  report = json.loads(layout.identity_capture_report.read_bytes())
  assert report["workflow"] == "identify"


def test_identify_calls_preflight(tmp_path):
  layout = _layout(tmp_path)
  called = []
  run_identify(
    layout=layout,
    preflight=lambda: called.append(True),
    transport_factory=lambda: _FakeTransport(),
  )
  assert called == [True]


def test_identify_rejects_bad_layout_type(tmp_path):
  with pytest.raises(TypeError, match="ArtifactLayout"):
    run_identify(
      layout=object(),  # type: ignore[arg-type]
      preflight=lambda: None,
      transport_factory=lambda: _FakeTransport(),
    )


def test_identify_rejects_non_callable_preflight(tmp_path):
  layout = _layout(tmp_path)
  with pytest.raises(TypeError, match="callable"):
    run_identify(
      layout=layout,
      preflight=None,  # type: ignore[arg-type]
      transport_factory=lambda: _FakeTransport(),
    )
