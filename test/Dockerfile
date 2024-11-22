# Use slim version to minimize image size
FROM python:3.11-slim

# Install only the necessary system packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    nano


# Set working directory
WORKDIR /app

# Copy only the required files
COPY memoryRead.py /app/memoryRead.py

# Install Python dependencies
RUN pip install --no-cache-dir psutil

# Run the memory monitor
CMD ["python", "memoryRead.py"]