# One container, demo-proof: the web UI on :8000 with the demo captures baked in.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SECUREMAILSCOPE_CACHE=/app/.cache
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY securemailscope ./securemailscope
COPY tests ./tests
COPY pyproject.toml README.md ./

# Pre-build the demo captures and the bootstrap risk model so the first request is fast
RUN python -m securemailscope samples samples && python -m securemailscope train

RUN useradd --create-home --uid 10001 scope && chown -R scope /app
USER scope

EXPOSE 8000
CMD ["python", "-m", "securemailscope", "serve", "--host", "0.0.0.0", "--port", "8000", "--trust-store", "samples/demo-ca.pem"]
