FROM python:3.12.1-slim-bookworm AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12.1-slim-bookworm

WORKDIR /app

RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY --chown=appuser:appuser --from=builder /build /app
COPY --chown=appuser:appuser app.py .

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1

USER appuser

ENTRYPOINT ["python", "app.py"]
