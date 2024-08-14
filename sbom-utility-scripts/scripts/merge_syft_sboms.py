import json

# load SBOMs
with open("./sbom-image.json") as f:
    image_sbom = json.load(f)

with open("./sbom-source.json") as f:
    source_sbom = json.load(f)

# fetch unique components from available SBOMs
def get_identifier(component):
    return component["name"] + '@' + component.get("version", "")

image_sbom_components = image_sbom.setdefault("components", [])
existing_components = [get_identifier(component) for component in image_sbom_components]

source_sbom_components = source_sbom.get("components", [])
for component in source_sbom_components:
    if get_identifier(component) not in existing_components:
        image_sbom_components.append(component)
        existing_components.append(get_identifier(component))

image_sbom_components.sort(key=lambda c: get_identifier(c))

# write the CycloneDX unified SBOM
with open("./sbom-cyclonedx.json", "w") as f:
    json.dump(image_sbom, f, indent=4)
