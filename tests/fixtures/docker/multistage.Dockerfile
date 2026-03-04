FROM golang:1.21-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /app/server

FROM alpine:3.19

WORKDIR /app

RUN adduser -D -u 1001 appuser

COPY --chown=appuser:appuser --from=builder /app/server .

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://localhost:8080/health || exit 1

USER appuser

ENTRYPOINT ["./server"]
