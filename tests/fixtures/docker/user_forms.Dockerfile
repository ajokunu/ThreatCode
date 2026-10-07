# Every spelling of the root user, and a user that comes from an unresolved variable.
FROM debian:12-slim AS root-numeric
USER 0:0

FROM debian:12-slim AS root-named
USER ROOT:root

FROM debian:12-slim AS variable-user
ARG APP_USER
USER ${APP_USER}

FROM debian:12-slim AS app
WORKDIR /app
COPY --chown=10001:10001 app.py /app/
USER 0
HEALTHCHECK CMD ["/app/app.py", "--health"]
