"""
Command line interface for NEXUS-AI
"""

try:
    from .commands import main as cli_main
    from .parser import parse_nmap_xml
    from .predictor import Predictor
    
    __all__ = [
        "cli_main",
        "parse_nmap_xml",
        "Predictor"
    ]
except ImportError:
    # Handle case where modules aren't available yet
    __all__ = [] 