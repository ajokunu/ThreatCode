FROM debian:12-slim

# Not secrets: locations, labels and variable references
ENV KEYBOARD_LAYOUT=us AUTHORS=platform-team PUBLIC_KEY_PATH=/etc/keys/pub.pem SECRET_FILE=/run/secrets/db
ENV API_TOKEN=${CI_TOKEN} DB_PASSWORD= ADMIN_SECRET=changeme
# A secret in a multi-pair line, and one in the legacy form
ENV APP=web DB_PASSWORD=hunter2 PORT=80
ENV SERVICE_SECRET shh-this-is-real
ARG TOKEN

# A checksum pipe is not a shell pipe
RUN curl -fsSL https://get.example.com/tool.sha256 | sha256sum -c -
RUN apt-get update && apt-get install -y --no-install-recommends sudo && rm -rf /var/lib/apt/lists/*
RUN wget -qO- https://get.example.com/install.sh | sudo bash

ADD rootfs.tar.gz /
ADD --checksum=sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 https://downloads.example.com/tool.tar.gz /opt/
ADD https://downloads.example.com/other.tar.gz /opt/
COPY ["server.key", "/etc/ssl/"]
EXPOSE 8000-8010 ${PORT} 22-25 53/udp

ONBUILD RUN curl -fsSL https://get.example.com/hook.sh | bash
ONBUILD USER root
USER 10001
