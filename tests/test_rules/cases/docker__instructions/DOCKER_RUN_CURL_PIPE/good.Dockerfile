FROM debian:12-slim
RUN curl -fsSLo /tmp/install.sh https://get.example.com/install.sh \
 && echo "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  /tmp/install.sh" | sha256sum -c - \
 && sh /tmp/install.sh
