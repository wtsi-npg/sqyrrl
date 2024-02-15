FROM golang:1.21.5

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go account.yml lorem.txt ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o /app/server

FROM scratch
COPY --from=0 /app /app

EXPOSE 3333

CMD ["/app/server"]
