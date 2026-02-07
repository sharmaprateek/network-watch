import json
import pathlib
import subprocess


def test_render_smoke(tmp_path: pathlib.Path):
    repo = pathlib.Path(__file__).resolve().parents[1]
    fixture_state = repo / "tests" / "fixtures" / "state"

    # Arrange isolated run dirs
    root = tmp_path / "root"
    (root / "state").mkdir(parents=True)
    (root / "site").mkdir(parents=True)
    (root / "data").mkdir(parents=True)
    (root / "logs").mkdir(parents=True)

    # Copy one snapshot
    snap = fixture_state / "20260207T000000Z.json"
    (root / "state" / snap.name).write_text(snap.read_text())

    # Also provide config files expected by render pipeline
    (root / "state" / "aliases.json").write_text("{}")
    (root / "state" / "overrides.json").write_text('{"types":{},"names":{}}')
    (root / "state" / "alerts.json").write_text('{"mode":"off"}')

    # Copy site templates/assets from repo
    subprocess.check_call(["bash", "-lc", f"rsync -a {repo}/site/ {root}/site/"])

    # Act
    subprocess.check_call([
        "python3",
        str(repo / "render.py"),
        "--root",
        str(root),
        "--timestamp-utc",
        "20260207T000000Z",
        "--timestamp-human",
        "2026-02-07 00:00:00 UTC",
        "--host-ip",
        "192.168.1.2",
        "--subnet",
        "192.168.1.0/24",
    ])

    # Assert key outputs exist
    assert (root / "site" / "latest.json").exists()
    assert (root / "site" / "history.json").exists()
    assert (root / "site" / "device_stats.json").exists()

    latest = json.loads((root / "site" / "latest.json").read_text())
    assert "devices" in latest and len(latest["devices"]) >= 1
