"""
Main entry point for the Purple Team CLI tool.
"""

import sys
from typing import Optional

import typer

from purple_cli import __version__
from purple_cli.cli import app


def main() -> None:
    """
    Main entry point function for the Purple Team CLI.
    
    Returns:
        None
    """
    app(prog_name="purpletool")


if __name__ == "__main__":
    main()