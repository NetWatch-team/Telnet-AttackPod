FROM python:3.10-slim

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser -m appuser

# Set working directory
WORKDIR /home/appuser/code
RUN chown -R appuser:appuser /home/appuser

# Switch to non-root user
USER appuser

# Copy runtime requirements and install them
COPY requirements.txt /home/appuser/code/

# Install python3-venv (required for creating venv)
USER root
RUN apt-get update && apt-get install -y python3-venv && rm -rf /var/lib/apt/lists/*

# Back to appuser for security
USER appuser

# Create virtual environment and install dependencies
RUN python3 -m venv /home/appuser/venv && \
    /home/appuser/venv/bin/pip install --no-cache-dir -r requirements.txt

# Use venv Python and pip as default
ENV PATH="/home/appuser/venv/bin:$PATH"

# Copy application code
COPY monitor.py /home/appuser/code/

# Expose SSH port
EXPOSE 23

# Command to run your application
CMD ["python3", "monitor.py"]
