FROM debian:12-slim
RUN useradd --uid 10001 app
WORKDIR /app
COPY app.py /app/app.py
USER app
