# Dockerfiles

Source shape: Dockerfiles as teams write them, beyond the uppercase single-line form.
source: handbuilt.

| File | Contents |
| --- | --- |
| `lowercase.Dockerfile` | Lowercase instructions, which BuildKit accepts. |
| `continuations.Dockerfile` | Line continuations with comment lines inside them, multi-line `ENV`, `COPY --chown`, a `HEALTHCHECK` with flags. |
| `heredoc.Dockerfile` | `# syntax=` directive, a `RUN <<EOF` heredoc and a `COPY <<EOF` heredoc. |
| `multistage.Dockerfile` | `ARG` before the first `FROM`, `FROM --platform=$BUILDPLATFORM ... AS build`, a stage that inherits another stage, a distroless final stage whose tag comes from an `ARG`, `COPY --from`. |
| `onbuild.Dockerfile` | `ONBUILD` triggers. |
| `Containerfile` | A Podman-style Containerfile on a UBI base. |
