ORG := redhat-appstudio
IMAGE = quay.io/$(ORG)/build-definitions-source-image-build-utils:latest

.PHONY: image
image:
	podman build -t $(IMAGE) .

.PHONY: clean
clean:
	podman rmi $(IMAGE)

.PHONY: check
check:
	@cd app; tox
