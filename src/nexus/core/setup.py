#!/usr/bin/env python3
"""
Setup script for NEXUS-AI
"""

import os
from setuptools import setup, find_packages

# Try to import ConfigManager, fallback to default if not available
try:
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from core.config import get_config
    config = get_config()
except ImportError:
    # Fallback to default config if ConfigManager not available
    config = {
        'project': {
            'name': 'nexus-ai',
            'version': '1.0.0',
            'description': 'AI-powered network security analysis with multi-dataset ensemble learning and threat intelligence'
        }
    }

# Read the README file
try:
    readme_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'README.md')
    with open(readme_path, "r", encoding="utf-8") as fh:
        long_description = fh.read()
except FileNotFoundError:
    # Try alternative paths
    alt_paths = [
        os.path.join(os.path.dirname(__file__), '..', '..', '..', 'README.md'),
        'README.md',
        os.path.join(os.getcwd(), 'README.md')
    ]
    for path in alt_paths:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                long_description = fh.read()
            break
    else:
        long_description = "AI-powered network security analysis with multi-dataset ensemble learning and threat intelligence"

setup(
    name=config.get('project.name', 'nexus-ai'),
    version=config.get('project.version', '1.0.0'),
    author="NEXUS-AI Team",
    author_email="team@nexus-ai.com",
    description=config.get('project.description', 'AI-powered network security analysis with multi-dataset ensemble learning and threat intelligence'),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Dreepsy/Project_Nexus",
    project_urls={
        "Homepage": "https://github.com/Dreepsy/Project_Nexus",
        "Documentation": "https://github.com/Dreepsy/Project_Nexus#readme",
        "Repository": "https://github.com/Dreepsy/Project_Nexus.git",
        "Bug Tracker": "https://github.com/Dreepsy/Project_Nexus/issues",
        "Changelog": "https://github.com/Dreepsy/Project_Nexus/blob/main/CHANGELOG.md",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.21.0",
        "pandas>=1.3.0",
        "scikit-learn>=1.0.0",
        "tensorflow>=2.8.0",
        "keras>=2.8.0",
        "torch>=1.12.0",
        "transformers>=4.20.0",
        "shap>=0.40.0",
        "imbalanced-learn>=0.9.0",
        "pydantic>=1.9.0",
        "pyyaml>=6.0",
        "requests>=2.28.0",
        "aiohttp>=3.8.0",
        "httpx>=0.24.0",
        "beautifulsoup4>=4.11.0",
        "lxml>=4.9.0",
        "xmltodict>=0.13.0",
        "colorama>=0.4.5",
        "rich>=12.0.0",
        "click>=8.1.0",
        "argparse>=1.4.0",
        "psutil>=5.8.0",
        "joblib>=1.1.0",
        "matplotlib>=3.5.0",
        "seaborn>=0.11.0",
        "plotly>=5.10.0",
        "jupyter>=1.0.0",
        "ipywidgets>=7.7.0",
        "cryptography>=3.4.0",
        "python-dotenv>=0.19.0",
        "structlog>=21.5.0",
        "prometheus-client>=0.14.0",
        "redis>=4.3.0",
        "diskcache>=5.2.0",
        "ratelimit>=2.2.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
            "pytest-mock>=3.8.0",
            "pytest-asyncio>=0.21.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
            "bandit>=1.7.0",
            "safety>=2.3.0",
            "pre-commit>=2.19.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
            "myst-parser>=0.17.0",
        ],
        "docker": [
            "docker>=6.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "nexus-ai=nexus.cli.commands:main",
        ],
    },
    include_package_data=True,
    package_data={
        "nexus": ["*.yaml", "*.yml", "*.json", "*.md"],
    },
) 