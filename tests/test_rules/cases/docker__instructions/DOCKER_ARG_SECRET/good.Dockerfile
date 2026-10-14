FROM debian:12-slim
ARG NPM_TOKEN
RUN --mount=type=secret,id=npm_token echo "building"
