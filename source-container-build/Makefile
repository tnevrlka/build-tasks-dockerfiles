IMAGE ?= quay.io/mytestworkload/build-definitions-source-image-build-utils:test-$(shell git rev-parse HEAD)

.PHONY: image
image:
	podman build -t $(IMAGE) .

.PHONY: clean
clean:
	podman rmi $(IMAGE)

.PHONY: check
check:
	@cd app; tox
