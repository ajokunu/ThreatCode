FROM debian:12-slim
WORKDIR /app
COPY config/app.conf /etc/app/app.conf
ADD rootfs.tar.gz /
