"""
Entry point for the Purple Team CLI.

This module serves as the entry point for the Purple Team CLI tool,
supporting both command line and interactive modes.
"""

import sys
import typer

from purple_cli.cli import app as cli_app
from purple_cli.interactive import run_interactive_cli


def main() -> None:
    """
    Main entry point for the Purple Team CLI.
    
    If the --interactive flag is provided, launches in interactive mode.
    Otherwise, passes control to the Typer CLI app.
    """
    # Check for interactive mode flag
    if "--interactive" in sys.argv or "-i" in sys.argv:
        # Remove the flag from sys.argv to not confuse the Typer app
        if "--interactive" in sys.argv:
            sys.argv.remove("--interactive")
        if "-i" in sys.argv:
            sys.argv.remove("-i")
        
        # Launch interactive mode
        run_interactive_cli()
    else:
        # Launch CLI mode with Typer
        cli_app(prog_name="purpletool")


if __name__ == "__main__":
    main()