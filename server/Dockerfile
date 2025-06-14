FROM golang:1.24.4-bookworm AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o app .
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/app .
CMD ["./app"]