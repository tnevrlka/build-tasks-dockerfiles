import json

with open("./sbom-cyclonedx.json") as f:
    cyclonedx_sbom = json.load(f)

purls = [{"purl": component["purl"]} for component in cyclonedx_sbom.get("components", []) if "purl" in component]
purl_content = {"image_contents": {"dependencies": purls}}

with open("sbom-purl.json", "w") as output_file:
    json.dump(purl_content, output_file, indent=4)
