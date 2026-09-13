import json
from pathlib import Path

import pytest

from eps_patch.identify import IdentifyError, run_identify
from eps_patch.paths import ArtifactLayout
from eps_patch.transport import IdentityCaptureResult


_APP_F181 = b"\x02" + b"8965F1208000" + bytes(4) + b"8A3111213000" + bytes(4)
_BOOT_F180 = b"\x02" + b"8965H0000000" + bytes(4) + b"8A0000000000" + bytes(4)
_APP_F181_IN_PROG = b"\x02" + b"PROG00000000" + bytes(4) + b"PROG00000000" + bytes(4)
_PANDA_SERIAL = "PANDA-IDENTIFY-TEST"


def _capture(
  *,
  f181_default=_APP_F181,
  f180_prog: bytes | None = _BOOT_F180,
  f181_prog=_APP_F181_IN_PROG,
  serial=_PANDA_SERIAL,
) -> IdentityCaptureResult:
  return IdentityCaptureResult(
    panda_serial=serial,
    f181_default_session=f181_default,
    f180_programming_session=f180_prog,
    f181_programming_session=f181_prog,
  )


class _FakeTransport:
  def __init__(self, result: IdentityCaptureResult | None = None):
    self._result = result or _capture()
    self.called = False

  def __enter__(self):
    return self

  def __exit__(self, *_):
    pass

  def read_full_identity(self) -> IdentityCaptureResult:
    self.called = True
    return self._result


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
  assert transport.called


def test_identify_report_schema_and_workflow(tmp_path):
  layout = _layout(tmp_path)
  run_identify(layout=layout, preflight=lambda: None, transport_factory=lambda: _FakeTransport())
  report = json.loads(layout.identity_capture_report.read_bytes())
  assert report["schema"] == 2
  assert report["workflow"] == "identify"
  assert "created_at" in report


def test_identify_report_never_authorizes(tmp_path):
  layout = _layout(tmp_path)
  run_identify(layout=layout, preflight=lambda: None, transport_factory=lambda: _FakeTransport())
  report = json.loads(layout.identity_capture_report.read_bytes())
  assert report["authorizes_patch_or_restore"] is False


def test_identify_report_all_captured_fields(tmp_path):
  layout = _layout(tmp_path)
  run_identify(layout=layout, preflight=lambda: None, transport_factory=lambda: _FakeTransport())
  report = json.loads(layout.identity_capture_report.read_bytes())
  assert report["panda_serial"] == _PANDA_SERIAL
  assert report["f181_default_session"] == _APP_F181.hex()
  assert report["f180_programming_session"] == _BOOT_F180.hex()
  assert report["f181_programming_session"] == _APP_F181_IN_PROG.hex()


def test_identify_report_f180_nrc_recorded_as_string(tmp_path):
  layout = _layout(tmp_path)
  run_identify(
    layout=layout,
    preflight=lambda: None,
    transport_factory=lambda: _FakeTransport(_capture(f180_prog=None)),
  )
  report = json.loads(layout.identity_capture_report.read_bytes())
  assert report["f180_programming_session"] == "nrc-not-supported"
  assert report["f181_programming_session"] == _APP_F181_IN_PROG.hex()


def test_identify_report_known_specimen_recognition(tmp_path):
  layout = _layout(tmp_path)
  run_identify(
    layout=layout,
    preflight=lambda: None,
    transport_factory=lambda: _FakeTransport(_capture(f181_default=_APP_F181)),
  )
  report = json.loads(layout.identity_capture_report.read_bytes())
  assert report["recognition"] == "known-2025-corolla-specimen"


def test_identify_report_unrecognized_when_f181_default_differs(tmp_path):
  layout = _layout(tmp_path)
  unknown = b"\x02" + b"0000F0000000" + bytes(4) + b"0000F0000000" + bytes(4)
  run_identify(
    layout=layout,
    preflight=lambda: None,
    transport_factory=lambda: _FakeTransport(_capture(f181_default=unknown)),
  )
  report = json.loads(layout.identity_capture_report.read_bytes())
  assert report["recognition"] == "unrecognized"


def test_identify_overwrites_previous_capture(tmp_path):
  layout = _layout(tmp_path)
  for i in range(2):
    run_identify(
      layout=layout,
      preflight=lambda: None,
      transport_factory=lambda: _FakeTransport(_capture(serial=f"PANDA-{i}")),
    )
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


def test_identify_rejects_bad_layout_type():
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
