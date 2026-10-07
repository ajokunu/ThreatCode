# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.22.5

FROM golang:${GO_VERSION}-bookworm@sha256:5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809102 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot@sha256:6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80910213
WORKDIR /app
COPY --from=build --chown=65532:65532 /out/app /app/app
EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=3s CMD ["/app/app", "-healthcheck"]
ENTRYPOINT ["/app/app"]
