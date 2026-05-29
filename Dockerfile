FROM golang:latest

WORKDIR /app

COPY go.mod .

RUN go mod download

COPY .. .

RUN go build -o auth-service ./cmd/auth-service/main.go

CMD ["./auth-service"]

