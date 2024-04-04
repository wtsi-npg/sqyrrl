# syntax = docker/dockerfile:1.2

FROM golang:1.22 as builder

WORKDIR /app

COPY . .

RUN go mod download

RUN make build-linux

FROM alpine:latest

COPY --from=builder /app/sqyrrl-linux-amd64 /app/sqyrrl

WORKDIR /app

RUN adduser -D sqyrrl

EXPOSE 3333

USER sqyrrl

ENTRYPOINT ["/app/sqyrrl"]

CMD ["--version"]
