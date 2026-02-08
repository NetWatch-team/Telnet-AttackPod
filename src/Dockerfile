FROM python:3.10-slim

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

CMD ["python", "monitor.py"]