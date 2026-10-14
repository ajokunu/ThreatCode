# syntax=docker/dockerfile:1
ARG GO_VERSION=1.22
ARG RUNTIME_TAG=nonroot

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/app ./cmd/app

FROM build AS test
RUN go test ./...

FROM gcr.io/distroless/static-debian12:${RUNTIME_TAG} AS runtime
COPY --from=build /out/app /app
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/app"]
