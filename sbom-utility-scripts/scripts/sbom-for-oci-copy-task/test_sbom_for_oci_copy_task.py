import datetime
import json
import sys
import uuid
from pathlib import Path

import pytest
import sbom_for_oci_copy_task

TEST_DATA: Path = Path(__file__).parent / "test_data"


@pytest.mark.parametrize("sbom_type", ["cyclonedx", "spdx"])
def test_main(sbom_type: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock out external factors for SPDX (randomness, date and time)
    monkeypatch.setattr(uuid, "uuid4", lambda: "a29a127a-daf6-44d3-a840-4eca194e9b41")
    monkeypatch.setattr(
        sbom_for_oci_copy_task,
        "_datetime_utc_now",
        lambda: datetime.datetime(2025, 1, 14, 11, 46, 34, tzinfo=datetime.UTC),
    )

    monkeypatch.setattr(
        sys, "argv", ["__unused_script_name__", str(TEST_DATA / "oci-copy.yaml"), "--sbom-type", sbom_type]
    )
    sbom_for_oci_copy_task.main()
    out, _ = capsys.readouterr()

    got_sbom = json.loads(out)
    expect_sbom = json.loads(TEST_DATA.joinpath(f"{sbom_type}.json").read_text())
    assert got_sbom == expect_sbom
