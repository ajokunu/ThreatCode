FROM debian:12-slim
WORKDIR /app
RUN --mount=type=secret,id=server_key cat /run/secrets/server_key > /dev/null
COPY server.crt /etc/ssl/certs/server.crt
