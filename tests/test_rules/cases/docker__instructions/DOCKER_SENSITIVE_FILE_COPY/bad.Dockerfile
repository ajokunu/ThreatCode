FROM debian:12-slim
WORKDIR /app
COPY server.key /etc/ssl/private/server.key
