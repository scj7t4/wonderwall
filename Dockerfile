FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml ./
COPY wonderwall/ ./wonderwall/

RUN pip install --no-cache-dir . && \
    mkdir -p static && \
    useradd -r -u 999 appuser && \
    chown -R appuser:appuser /app

USER appuser

VOLUME ["/app/static"]

EXPOSE 80 443

ENV LOG_LEVEL=INFO

CMD ["python", "-m", "wonderwall"]
