MAKEFLAGS += --no-print-directory

GOBIN ?= $(shell go env GOPATH)/bin

.DEFAULT_GOAL := check

.PHONY: deps
deps:
	go mod download -x

.PHONY: testdeps
testdeps: deps
	go install honnef.co/go/tools/cmd/staticcheck@latest

.PHONY: generate
generate: deps
	go generate ./...

.PHONY: tidy
tidy:
	go mod verify
	go mod tidy

.PHONY: vet
vet: testdeps
	go vet ./...

.PHONY: staticcheck
staticcheck: testdeps
	$(GOBIN)/staticcheck ./...

.PHONY: lint
lint: vet staticcheck

.PHONY: test
test:
	go test -v -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...

.PHONY: check
check: generate test lint

.PHONY: clean
clean:
	go clean ./...
