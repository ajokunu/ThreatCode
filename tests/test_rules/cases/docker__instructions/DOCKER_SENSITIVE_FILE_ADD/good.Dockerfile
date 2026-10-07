FROM debian:12-slim
WORKDIR /app
ADD config/app.conf /etc/app/app.conf
