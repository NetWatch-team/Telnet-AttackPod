FROM --platform=linux/amd64 python:3.10-slim

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser -m appuser

WORKDIR /home/appuser/code

# Install dependencies as root, then switch
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY monitor.py .
RUN chown -R appuser:appuser /home/appuser/code

USER appuser

# Expose the internal non-privileged port
EXPOSE 2323

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import socket; s = socket.socket(); s.settimeout(3); s.connect(('127.0.0.1', 2323)); s.close()" || exit 1

CMD ["python", "monitor.py"]