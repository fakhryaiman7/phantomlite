#!/usr/bin/env python3
"""
PhantomLite - Lightweight Bug Bounty Reconnaissance Tool

A free, self-contained CLI tool for bug bounty reconnaissance.
Auto-sets up its own environment on first run.

Usage:
    python main.py recon example.com
    python main.py subdomains example.com
"""
import sys
import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()


def main():
    sys.path.insert(0, str(SCRIPT_DIR))
    
    bootstrap_path = SCRIPT_DIR / "bootstrap.py"
    
    if bootstrap_path.exists():
        os.execv(sys.executable, [sys.executable, str(bootstrap_path)] + sys.argv[1:])
    else:
        print("ERROR: bootstrap.py not found!")
        sys.exit(1)


if __name__ == "__main__":
    main()
