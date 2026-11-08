.PHONY: build build-release test test-race vet generate-sql test-integration test-integration-runner

build:
	mkdir -p bin
	go build -o bin/cheesetrap ./cmd/cheesetrap

# Install the pinned web dependencies with npm --prefix web ci first.
build-release:
	npm --prefix web run build
	mkdir -p bin
	go build -tags=release -o bin/cheesetrap ./cmd/cheesetrap

test:
	go test ./... -count=1

test-race:
	go test -race ./... -count=1

vet:
	go vet ./...

generate-sql:
	./scripts/generate-sql.sh

test-integration: test-integration-runner
	./scripts/test-integration.sh ./...

test-integration-runner:
	python3 -B -m unittest discover -s scripts -p test_integration_runner.py

.PHONY: test-acceptance test-acceptance-automated
test-acceptance:
	./scripts/test-acceptance.sh

test-acceptance-automated:
	./scripts/test-acceptance.sh --automated-only
