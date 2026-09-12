"""Fixed comma-local locations for EPS patch evidence and attempts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


DEFAULT_ARTIFACT_ROOT = Path("/data/eps-patch/artifacts")
_ATTEMPT_TIMESTAMP = re.compile(r"\A\d{8}T\d{6}Z\Z")


@dataclass(frozen=True, slots=True)
class ArtifactLayout:
  """The only runtime-artifact layout accepted by patch and restore workflows."""

  root: Path = DEFAULT_ARTIFACT_ROOT

  def __post_init__(self) -> None:
    object.__setattr__(self, "root", Path(self.root))

  @property
  def probe_directory(self) -> Path:
    return self.root / "probe"

  @property
  def probe_report(self) -> Path:
    return self.probe_directory / "faci-pe-cycle-report.json"

  @property
  def target_backup(self) -> Path:
    return self.probe_directory / "original-sector-0x88000.bin"

  @property
  def crc_backup(self) -> Path:
    return self.probe_directory / "original-sector-0xf8000.bin"

  @property
  def recovery_metadata(self) -> Path:
    return self.probe_directory / "recovery-metadata.json"

  @property
  def probe_failure_report(self) -> Path:
    """Fixed non-trusted diagnostic retained after a complete failed probe."""
    return self.root / "failures" / "last-probe-failure.json"

  @property
  def probe_identity_failure_report(self) -> Path:
    """Fixed non-trusted diagnostic retained after an identity rejection."""
    return self.root / "failures" / "last-probe-identity-mismatch.json"

  @property
  def identity_capture_report(self) -> Path:
    """Fixed non-trusted diagnostic written by the identify command."""
    return self.root / "failures" / "last-identity-capture.json"

  @property
  def patch_root(self) -> Path:
    return self.root / "patch"

  @property
  def restore_root(self) -> Path:
    return self.root / "restore"

  def patch_attempt(self, timestamp: str) -> Path:
    return self.patch_root / _require_timestamp(timestamp)

  def restore_attempt(self, timestamp: str) -> Path:
    return self.restore_root / _require_timestamp(timestamp)


def _require_timestamp(timestamp: str) -> str:
  if not isinstance(timestamp, str) or _ATTEMPT_TIMESTAMP.fullmatch(timestamp) is None:
    raise ValueError("attempt timestamp must be UTC in YYYYMMDDTHHMMSSZ format")
  return timestamp
