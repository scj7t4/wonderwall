FROM python:3.13-slim

WORKDIR /app

COPY wonderwall/ ./wonderwall/

RUN mkdir -p static && \
    useradd -r -u 999 appuser && \
    chown -R appuser:appuser /app

USER appuser

VOLUME ["/app/static"]

EXPOSE 80 443

ENV LOG_LEVEL=INFO

CMD ["python", "-m", "wonderwall"]
