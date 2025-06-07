# Build stage
FROM golang:1.23 AS builder

WORKDIR /app

# Copy go.mod and go.sum first, for caching dependencies
COPY go.mod go.sum ./

RUN go mod download

# Copy all source code
COPY . .

# Build the binary from cmd/api with static linking
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/api

# Final stage
FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/main .

EXPOSE 8000

CMD ["./main"]
