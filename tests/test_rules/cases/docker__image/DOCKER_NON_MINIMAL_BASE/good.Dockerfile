FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
USER 65532
CMD ["app"]
