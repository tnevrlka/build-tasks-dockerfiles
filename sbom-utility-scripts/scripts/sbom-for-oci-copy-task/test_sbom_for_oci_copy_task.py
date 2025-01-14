import json
import sys
from pathlib import Path

import pytest
from sbom_for_oci_copy_task import main

TEST_DATA: Path = Path(__file__).parent / "test_data"


def test_main(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["__unused_script_name__", str(TEST_DATA / "oci-copy.yaml")])
    main()
    out, _ = capsys.readouterr()

    got_sbom = json.loads(out)
    expect_sbom = json.loads(TEST_DATA.joinpath("cyclonedx.json").read_text())
    assert got_sbom == expect_sbom
