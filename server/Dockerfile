FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code (excluding generate-commands.go)
COPY main.go database.go ./
COPY migrations/ migrations/

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o server main.go database.go

FROM alpine:latest

# Install curl and wget for health checks
RUN apk --no-cache add curl wget ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/server .
COPY --from=builder /app/migrations ./migrations

# Create directory for database
RUN mkdir -p /app/data

# Expose port
EXPOSE 8080

CMD ["./server"]
