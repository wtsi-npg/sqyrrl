VERSION := $(shell git describe --always --tags --dirty)
ldflags := "-X sqyrrl/server.Version=${VERSION}"
build_args := -a -v -ldflags ${ldflags}

build_path = "build/sqyrrl-${VERSION}"

CGO_ENABLED := 1
GOARCH := amd64

.PHONY: build build-linux build-darwin build-windows check clean coverage install lint test

all: build

build: build-linux build-darwin build-windows

build-linux:
	mkdir -p ${build_path}
	GOOS=linux go build ${build_args} -o ${build_path}/sqyrrl-linux-${GOARCH} ./main.go

build-darwin:
	mkdir -p ${build_path}
	GOOS=darwin go build ${build_args} -o ${build_path}/sqyrrl-darwin-${GOARCH} ./main.go

build-windows:
	mkdir -p ${build_path}
	GOOS=windows go build ${build_args} -o ${build_path}/sqyrrl-windows-${GOARCH}.exe ./main.go

install:
	go install ${build_args}

lint:
	golangci-lint run ./...

check: test

test:
	ginkgo -r --race

coverage:
	ginkgo -r --cover -coverprofile=coverage.out

dist: build
	cp README.md COPYING ${build_path}
	tar -C ./build -cvj -f ./build/sqyrrl-${VERSION}.tar.bz2 sqyrrl-${VERSION}
	shasum -a 256 ./build/sqyrrl-${VERSION}.tar.bz2 > ./build/sqyrrl-${VERSION}.tar.bz2.sha256

clean:
	go clean
	$(RM) -r ./build
