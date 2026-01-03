FROM python:3.12-slim

# Create non-root user
RUN useradd -m -u 1000 wafproxy

WORKDIR /app

# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=wafproxy:wafproxy . .

# Switch to non-root user
USER wafproxy

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

# Command to run the application with production settings
CMD ["uvicorn", "waf_proxy.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]

