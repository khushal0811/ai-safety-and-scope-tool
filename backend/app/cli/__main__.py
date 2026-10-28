"""Execution entry point for python -m app.cli."""

import sys
from app.cli.shim import main

if __name__ == "__main__":
    sys.exit(main())
