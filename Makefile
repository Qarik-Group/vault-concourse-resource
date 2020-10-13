ifdef VERSION
docker_registry = starkandwayne/vault-concourse-resource:$(VERSION)
else
docker_registry = starkandwayne/vault-concourse-resource
endif

docker:
	docker build -t $(docker_registry) .

publish: docker
	docker push $(docker_registry)

test:
	go test -v ./...

fmt:
	find . -name '*.go' | while read -r f; do \
		gofmt -w -s "$$f"; \
	done

.DEFAULT_GOAL := docker

.PHONY: go-mod docker-build docker-push docker test fmt
