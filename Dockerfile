# Use a lightweight Debian-based Python image to save SSD space
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Install 'curl' - useful for healthchecks and debugging container networking
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# STEP 1: Copy only requirements first (Optimizes Docker Cache)
# As long as this file doesn't change, Docker skips the 'pip install' on rebuilds
COPY requirements.txt .

# STEP 2: Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# STEP 3: Copy your actual code (This layer changes frequently)
# Placing this last ensures the heavy 'pip install' layer remains cached
COPY main_agent.py .

# Inform Docker that the container listens on port 8000
EXPOSE 8000

# The command to launch the FastAPI server when the container starts
CMD ["python", "main_agent.py"]