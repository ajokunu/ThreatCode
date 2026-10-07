FROM debian:12-slim
RUN useradd --uid 10001 app
WORKDIR /app
COPY --chown=app:app app.py /app/app.py
USER app
