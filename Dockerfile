FROM golang:1.22

WORKDIR /app

COPY go.mod go.sum ./
COPY ./cmd ./cmd
COPY ./internal ./internal
COPY ./templates ./templates

RUN go mod download
RUN ls -la  /app/templates

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -a -v -ldflags "-X sqyrrl/internal.Version=${VERSION}" -o sqyrrl ./cmd/sqyrrl.go

FROM scratch
COPY --from=0 /app /app

WORKDIR /app

EXPOSE 3333

ENTRYPOINT ["/app/sqyrrl"]
