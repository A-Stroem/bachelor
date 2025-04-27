"""
Main CLI definition for the Purple Team CLI tool.

This module sets up the Typer app and includes the CLI command groups.
"""

import typer
from rich import print as rprint
from typing import Optional

from purple_cli import __version__
from purple_cli.commands import run, config, list_cmd, playbook
from purple_cli.interactive import run_interactive_cli


# Create the main Typer app instance
app = typer.Typer(
    help="Purple Team CLI - A tool for executing Atomic Red Team tests",
    no_args_is_help=True,
)

# Add the command groups to the main app
app.add_typer(run.app, name="run")
app.add_typer(config.app, name="config")
app.add_typer(list_cmd.app, name="list")
app.add_typer(playbook.app, name="playbook")


@app.callback()
def callback() -> None:
    """
    Purple Team CLI - A tool for executing Atomic Red Team tests.
    """
    pass


@app.command("version")
def version_cmd() -> None:
    """
    Show the version of the tool.
    """
    rprint(f"[bold green]Purple CLI version:[/bold green] {__version__}")


@app.command("interactive")
def interactive_cmd() -> None:
    """
    Launch the interactive menu-driven interface.
    
    This mode provides a full-screen menu system for easier navigation
    and execution of Atomic Red Team tests.
    """
    run_interactive_cli()


if __name__ == "__main__":
    app()