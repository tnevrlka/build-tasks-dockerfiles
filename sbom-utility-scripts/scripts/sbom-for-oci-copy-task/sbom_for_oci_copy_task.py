#!/usr/bin/env python
import argparse
import json
from typing import IO, Any, TypedDict

import yaml
from packageurl import PackageURL


class Artifact(TypedDict):
    # https://github.com/konflux-ci/build-definitions/blob/main/task/oci-copy/0.1/README.md#oci-copyyaml-schema
    source: str
    filename: str
    type: str
    sha256sum: str


def to_purl(artifact: Artifact) -> str:
    return PackageURL(
        type="generic",
        name=artifact["filename"],
        qualifiers={
            "download_url": artifact["source"],
            "checksum": f"sha256:{artifact['sha256sum']}",
        },
    ).to_string()


def to_cyclonedx_component(artifact: Artifact) -> dict[str, Any]:
    return {
        "type": "file",
        "name": artifact["filename"],
        "purl": to_purl(artifact),
        "hashes": [{"alg": "SHA-256", "content": artifact["sha256sum"]}],
        "externalReferences": [{"type": "distribution", "url": artifact["source"]}],
    }


def to_cyclonedx_sbom(artifacts: list[Artifact]) -> dict[str, Any]:
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {},
        "components": list(map(to_cyclonedx_component, artifacts)),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("oci_copy_yaml", type=argparse.FileType(), default="-")
    ap.add_argument("-o", "--output-file", type=argparse.FileType(mode="w"), default="-")
    ap.add_argument("--sbom-type", choices=["cyclonedx", "spdx"], default="cyclonedx")
    args = ap.parse_args()

    oci_copy_yaml: IO[str] = args.oci_copy_yaml
    output_file: IO[str] = args.output_file
    sbom_type: str = args.sbom_type

    oci_copy_data = yaml.safe_load(oci_copy_yaml)
    artifacts: list[Artifact] = oci_copy_data["artifacts"]

    if sbom_type == "cyclonedx":
        sbom = to_cyclonedx_sbom(artifacts)
    else:
        raise NotImplementedError("SPDX not implemented")

    json.dump(sbom, output_file, indent=2)
    output_file.write("\n")


if __name__ == "__main__":
    main()
