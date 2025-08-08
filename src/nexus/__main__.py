#!/usr/bin/env python3
"""
NexusAI - AI-Powered Network Security Analysis Tool
Main entry point for command-line usage.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.nexus.cli.commands import main

if __name__ == "__main__":
    main() 