FROM debian:12-slim

# The comment line inside the continuation below is legal Dockerfile syntax.
RUN apt-get update && \
    # build tooling is removed again at the end of this layer
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git && \
    # clean the apt cache
    rm -rf /var/lib/apt/lists/*

ENV APP_HOME=/opt/app \
    APP_PORT=8080 \
    LOG_LEVEL=info

COPY --chown=app:app ./bin /opt/app/bin

USER app
HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS http://localhost:8080/healthz || exit 1
ENTRYPOINT ["/opt/app/bin/serve"]
