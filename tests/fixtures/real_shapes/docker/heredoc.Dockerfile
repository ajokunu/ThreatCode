# syntax=docker/dockerfile:1.7
FROM alpine:3.20

RUN <<EOF
set -eux
apk add --no-cache curl ca-certificates
adduser -D -u 10001 app
EOF

COPY <<EOF /etc/app/config.toml
[server]
listen = "0.0.0.0:8080"
EOF

USER app
CMD ["/usr/local/bin/app"]
