#!/usr/bin/env python
import argparse
import datetime
import hashlib
import json
import re
import uuid
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


def to_spdx_package(artifact: Artifact) -> dict[str, Any]:
    purl = to_purl(artifact)
    purl_hex_digest = hashlib.sha256(purl.encode()).hexdigest()
    # based on a validation error from https://github.com/spdx/tools-java
    #   Invalid SPDX ID: ...  Must match the pattern SPDXRef-([0-9a-zA-Z\.\-\+]+)$
    sanitized_filename = re.sub(r"[^0-9a-zA-Z\.\-\+]", "-", artifact["filename"])
    return {
        "SPDXID": f"SPDXRef-Package-{sanitized_filename}-{purl_hex_digest}",
        "name": artifact["filename"],
        "externalRefs": [
            {
                "referenceType": "purl",
                "referenceLocator": purl,
                "referenceCategory": "PACKAGE-MANAGER",
            },
        ],
        "checksums": [{"algorithm": "SHA256", "checksumValue": artifact["sha256sum"]}],
        "downloadLocation": artifact["source"],
    }


def to_spdx_sbom(artifacts: list[Artifact]) -> dict[str, Any]:
    real_packages = list(map(to_spdx_package, artifacts))

    def relationship(a: str, relationship_type: str, b: str) -> dict[str, Any]:
        return {"spdxElementId": a, "relationshipType": relationship_type, "relatedSpdxElement": b}

    # The only purpose of this package is to be the "root" of the relationships graph
    fake_root = {
        "SPDXID": "SPDXRef-DocumentRoot-Unknown",
        "downloadLocation": "NOASSERTION",
        "name": "",
    }

    relationships = [relationship("SPDXRef-DOCUMENT", "DESCRIBES", fake_root["SPDXID"])]
    relationships.extend(relationship(fake_root["SPDXID"], "CONTAINS", package["SPDXID"]) for package in real_packages)

    packages = [fake_root] + real_packages

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"https://konflux-ci.dev/spdxdocs/sbom-for-oci-copy-task/{uuid.uuid4()}",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": _datetime_utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: Konflux"],
        },
        "name": "sbom-for-oci-copy-task",
        "packages": packages,
        "relationships": relationships,
    }


def _datetime_utc_now() -> datetime.datetime:
    # a mockable datetime.datetime.now
    return datetime.datetime.now(datetime.UTC)


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
        sbom = to_spdx_sbom(artifacts)

    json.dump(sbom, output_file, indent=2)
    output_file.write("\n")


if __name__ == "__main__":
    main()
