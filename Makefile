VERSION := $(shell git describe --always --tags --dirty)
ldflags := "-X github.com/kjsanger/sqyrrl/internal.Version=${VERSION}"
build_path = "build/sqyrrl-${VERSION}"

.PHONY: build coverage install lint test check clean

all: build

install:
	go install -ldflags ${ldflags}

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -v -ldflags ${ldflags} -o sqyrrl-linux-amd64 ./cmd/sqyrrl.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -a -v -ldflags ${ldflags} -o sqyrrl-darwin-amd64 ./cmd/sqyrrl.go

lint:
	golangci-lint run ./...

check: test

test:
	ginkgo -r --race

coverage:
	ginkgo -r --cover -coverprofile=coverage.out

clean:
	go clean
	rm sqyrrl-*
