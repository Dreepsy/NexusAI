# NEXUS-AI Docker Container
# Your AI-powered network security analysis companion
#
# This Dockerfile creates a containerized version of NEXUS-AI
# with all dependencies and configurations pre-installed.
#
# Build: docker build -t nexusai .
# Run:   docker run --rm -v $(pwd):/data nexusai --input /data/scan.xml

# =============================================================================
# BASE IMAGE SELECTION
# =============================================================================

# Use Python 3.9 slim image for smaller size and security
FROM python:3.9-slim

# Set maintainer information
LABEL maintainer="NEXUS-AI Team <team@nexus-ai.com>"
LABEL description="AI-powered network security analysis tool"
LABEL version="1.0.0"

# =============================================================================
# SYSTEM DEPENDENCIES AND ENVIRONMENT SETUP
# =============================================================================

# Set environment variables for Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Essential build tools
    build-essential \
    gcc \
    g++ \
    # Network tools (optional, for debugging)
    curl \
    wget \
    # Security and SSL
    ca-certificates \
    # Clean up package cache
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# WORKING DIRECTORY AND USER SETUP
# =============================================================================

# Create application directory
WORKDIR /app

# Create non-root user for security
RUN groupadd -r nexusai && useradd -r -g nexusai nexusai

# =============================================================================
# PYTHON DEPENDENCIES INSTALLATION
# =============================================================================

# Copy requirements file first (for better Docker layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# =============================================================================
# APPLICATION CODE INSTALLATION
# =============================================================================

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/data /app/models /app/logs

# Set proper permissions
RUN chown -R nexusai:nexusai /app

# Switch to non-root user
USER nexusai

# =============================================================================
# VOLUME MOUNTS AND PORTS
# =============================================================================

# Create volume for persistent data
VOLUME ["/app/data", "/app/models"]

# Expose port for web interface (if implemented)
EXPOSE 8080

# =============================================================================
# HEALTH CHECK
# =============================================================================

# Health check to ensure the application is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# =============================================================================
# ENTRY POINT AND DEFAULT COMMAND
# =============================================================================

# Set the entry point to the NEXUS-AI CLI
ENTRYPOINT ["python", "-m", "src.nexus.cli.commands"]

# Default command (can be overridden)
CMD ["--help"]

# =============================================================================
# METADATA AND DOCUMENTATION
# =============================================================================

# Add metadata labels
LABEL org.opencontainers.image.title="NEXUS-AI"
LABEL org.opencontainers.image.description="AI-powered network security analysis"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="NEXUS-AI Team"

# =============================================================================
# USAGE EXAMPLES
# =============================================================================
#
# Basic usage:
#   docker run --rm -v $(pwd):/data nexusai --input /data/scan.xml
#
# With environment variables:
#   docker run --rm -e VIRUSTOTAL_API_KEY=your_key -v $(pwd):/data nexusai --input /data/scan.xml
#
# Interactive mode:
#   docker run -it --rm -v $(pwd):/data nexusai bash
#
# Production deployment:
#   docker run -d --name nexusai-container -v /path/to/data:/app/data nexusai
#
# =============================================================================