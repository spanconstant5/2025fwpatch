from eps_patch.artifacts import _atomic_replace
from eps_patch.paths import ArtifactLayout


def test_probe_failure_report_uses_one_fixed_nontrusted_path(tmp_path):
  layout = ArtifactLayout(tmp_path)

  assert layout.probe_failure_report == (
    tmp_path / "failures" / "last-probe-failure.json"
  )
  assert layout.probe_failure_report.parent != layout.probe_directory
  assert layout.probe_identity_failure_report == (
    tmp_path / "failures" / "last-probe-identity-mismatch.json"
  )
  assert layout.probe_identity_failure_report.parent != layout.probe_directory


def test_atomic_replace_replaces_an_existing_complete_file(tmp_path):
  path = tmp_path / "failures" / "last-probe-failure.json"

  _atomic_replace(path, b"first")
  _atomic_replace(path, b"second")

  assert path.read_bytes() == b"second"
