# syntax = docker/dockerfile:1.2

FROM golang:1.22 as builder

ARG VERSION=dev

WORKDIR /app

COPY ./Makefile .
COPY ./go.* .
COPY ./cmd ./cmd
COPY ./server ./server
COPY ./templates ./templates

RUN go mod download

# Mount the .git directory to allow the build to get the version from git
RUN --mount=source=.git,target=.git,type=bind make build-linux

FROM alpine:latest

COPY --from=builder /app/sqyrrl-linux-amd64 /app/sqyrrl

WORKDIR /app

RUN adduser -D sqyrrl

EXPOSE 3333

USER sqyrrl

ENTRYPOINT ["/app/sqyrrl"]

CMD ["--version"]
