FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
EXPOSE 22 8080
USER 10001
CMD ["/usr/sbin/sshd", "-D"]
