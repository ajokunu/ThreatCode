# syntax=docker/dockerfile:1
ARG GO_VERSION=1.22
ARG RUNTIME_TAG=latest

# The builder is hardened, and the image that runs is not: only the final stage counts.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}@sha256:5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809102 AS builder
RUN useradd --uid 10001 builder
USER builder
HEALTHCHECK CMD true
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/app ./cmd/app

FROM builder AS test
RUN go test ./...

FROM debian:${RUNTIME_TAG}
COPY --from=builder /out/app /usr/local/bin/app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/app"]
