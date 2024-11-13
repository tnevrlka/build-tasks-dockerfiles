# Add image reference script

The script aims to enrich the SBOM file with additional information about the output image used in the build process.
Based on a input SBOM type, the script updates certain fields with the image reference information. This is needed
to provide a complete SBOM file that can be used for further analysis.

## Usage

```bash
python add_image_reference.py \
    --input-file ./input-sbom.json \
    --output-file ./updated-sbom.json \
    --image-url quay.io/foo/bar/ubi8:1.1 \
    --image-digest sha256:011ff0cd8f34588d3eca86da97619f7baf99c8cc12e24cc3a7f337873c8d36cc
```
The script stores the updated SBOM in the output path provided.

## List of updates
### SPDX
The script updates the following fields in the SPDX SBOM:SHA256
- `packages` - the script adds a new package with the image reference information
- `relationships` - the script adds a new relationship between the package and the image reference
- `name` - the script adds the image reference as a name

The logic of adding new packages and updating replationships is visualized in the following diagram:
```
example SPDX SBOM:

                ROOT
             /        \
            /          \
        DESCRIBES   DESCRIBES
          /              \
         /                \
<pip main package>  <npm main package>
        |                  |
        |                  |
     CONTAINS           CONTAINS
        |                  |
        |                  |
    <pip deps>         <npm deps>


SBOM after enrichment:

                ROOT
                 |
                 |
              DESCRIBES
                 |
                 |
             <container>
             /        \
            /          \
        CONTAINS    CONTAINS
          /              \
         /                \
<pip main package>  <npm main package>
        |                  |
        |                  |
     CONTAINS           CONTAINS
        |                  |
        |                  |
    <pip deps>         <npm deps>

```

#### Example
```json
{
  "name": "quay.io/foo/bar/ubi8@sha256:011ff0cd8f34588d3eca86da97619f7baf99c8cc12e24cc3a7f337873c8d36cc",
  "packages": [
    {
      "SPDXID": "SPDXRef-image",
      "name": "ubi8",
      "versionInfo": "1.1",
      "downloadLocation": "NOASSERTION",
      "licenseConcluded": "NOASSERTION",
      "supplier": "NOASSERTION",
      "externalRefs": [
        {
          "referenceLocator": "pkg:oci/ubi8@sha256:011ff0cd8f34588d3eca86da97619f7baf99c8cc12e24cc3a7f337873c8d36cc?repository_url=quay.io/foo/bar/ubi8",
          "referenceType": "purl",
          "referenceCategory": "PACKAGE-MANAGER"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "011ff0cd8f34588d3eca86da97619f7baf99c8cc12e24cc3a7f337873c8d36cc"
        }
      ]
    },
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-image"
    },
  ]
}

```

### CycloneDX
- `components` - the script adds a new component with the image reference information
- `metadata.component` - the script adds the image reference as a metadata.component

#### Example
```json
{
  "metadata": {
    "component": {
      "type": "container",
      "name": "ubi8",
      "purl": "pkg:oci/ubi8@sha256:011ff0cd8f34588d3eca86da97619f7baf99c8cc12e24cc3a7f337873c8d36cc?repository_url=quay.io/foo/bar/ubi8",
      "version": "1.1",
      "publisher": "Red Hat, Inc.",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "011ff0cd8f34588d3eca86da97619f7baf99c8cc12e24cc3a7f337873c8d36cc"
        }
      ]
    },
  },
  "components": [
    {
      "type": "container",
      "name": "ubi8",
      "purl": "pkg:oci/ubi8@sha256:011ff0cd8f34588d3eca86da97619f7baf99c8cc12e24cc3a7f337873c8d36cc?repository_url=quay.io/foo/bar/ubi8",
      "version": "1.1",
      "publisher": "Red Hat, Inc.",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "011ff0cd8f34588d3eca86da97619f7baf99c8cc12e24cc3a7f337873c8d36cc"
        }
      ]
    },
  ]
}
```