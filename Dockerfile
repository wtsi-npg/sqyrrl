
FROM golang:1.24 AS builder

WORKDIR /app

COPY . .

RUN go mod download

RUN make build-linux CGO_ENABLED=0

FROM alpine:latest

COPY --from=builder /app/build/*/sqyrrl-linux-* /app/sqyrrl

WORKDIR /app

RUN adduser -D sqyrrl

EXPOSE 3333

USER sqyrrl

ENTRYPOINT ["/app/sqyrrl"]

CMD ["--version"]
