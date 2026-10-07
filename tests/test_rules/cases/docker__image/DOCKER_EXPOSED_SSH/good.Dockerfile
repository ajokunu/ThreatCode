FROM debian:12-slim
WORKDIR /srv
COPY app /srv/app
EXPOSE 8080
USER 10001
CMD ["/srv/app"]
