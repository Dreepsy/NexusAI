# NEXUS-AI Installation Guide

This guide will help you install and set up NEXUS-AI on your system.

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Git (for cloning the repository)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/Dreepsy/Project_Nexus.git
cd Project_Nexus
```

### 2. Create a Virtual Environment (Recommended)

```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify Installation

```bash
python test_project_setup.py
```

This will test that all components are properly installed.

### 5. Create a Sample Model

```bash
python scripts/training/create_sample_model.py
```

This creates a sample model for testing purposes.

## Quick Start

After installation, you can:

1. **Run the training system:**
   ```bash
   python src/main.py
   ```

2. **Use the CLI interface:**
   ```bash
   python -m src.nexus.cli.commands --help
   ```

3. **Check IP reputation:**
   ```bash
   python -m src.nexus.cli.commands --check-ips 8.8.8.8
   ```

4. **Run the core training directly:**
   ```bash
   python -m src.nexus.core.main
   ```

## Configuration

The project uses `config/config.yaml` for all settings. You can:

1. Set API keys as environment variables:
   ```bash
   export VIRUSTOTAL_API_KEY="your_key_here"
   export SHODAN_API_KEY="your_key_here"
   ```

2. Modify configuration settings in `config/config.yaml`

## Troubleshooting

### Common Issues

1. **Import errors:**
   - Make sure you're in the correct directory
   - Verify Python version (3.8+)
   - Check that all dependencies are installed

2. **Configuration not found:**
   - Ensure `config/config.yaml` exists
   - Check file permissions

3. **Model not found:**
   - Run `python scripts/training/create_sample_model.py`
   - Check that the `models/` directory exists

### Getting Help

- Check the [README.md](README.md) for detailed documentation
- Review the [CHANGELOG.md](CHANGELOG.md) for recent changes
- Open an issue on GitHub if you encounter problems

## Development Setup

For developers:

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
python test_project_setup.py

# Code formatting
black src/
flake8 src/
```

## Docker Installation

If you prefer Docker:

```bash
# Build the Docker image
docker build -t nexus-ai .

# Run the container
docker run -it nexus-ai
```

See the [Dockerfile](docker/Dockerfile) for more details. 