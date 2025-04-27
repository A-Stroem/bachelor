"""
List command group for the Purple Team CLI.

This module implements the 'list' subcommand for displaying available tests and playbooks.
"""

from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table
from rich.console import Console

from purple_cli.core.executor import list_available_tests
from purple_cli.core.playbook import get_available_playbooks


app = typer.Typer(
    help="List available tests, playbooks, and other resources",
    no_args_is_help=True,
)


@app.callback()
def callback() -> None:
    """
    List available tests, playbooks, and other resources.
    """
    pass


@app.command("tests")
def list_tests(
    filter_str: Optional[str] = typer.Argument(None, help="Optional filter string to search for specific techniques")
) -> None:
    """
    List available Atomic Red Team tests.
    """
    success, result = list_available_tests()
    
    if not success:
        rprint(f"[bold red]Error:[/bold red] {result}")
        raise typer.Exit(code=1)
    
    # Create a table to display the results
    table = Table(title="Available Atomic Red Team Tests")
    table.add_column("Technique ID", style="cyan")
    table.add_column("Name")
    
    # Filter the techniques if a filter string is provided
    filtered_results = result
    if filter_str:
        filter_str = filter_str.lower()
        filtered_results = [
            t for t in result 
            if filter_str in t["id"].lower() or filter_str in t["name"].lower()
        ]
    
    # Add rows to the table
    for technique in filtered_results:
        table.add_row(
            technique["id"],
            technique["name"]
        )
    
    # Display the table
    console = Console()
    console.print(table)
    
    # Show count of filtered vs total techniques
    if filter_str:
        rprint(f"\nShowing {len(filtered_results)} of {len(result)} techniques matching filter: '{filter_str}'")


@app.command("playbooks")
def list_playbooks() -> None:
    """
    List available predefined playbooks.
    """
    playbooks = get_available_playbooks()
    
    # Create a table to display the results
    table = Table(title="Available Playbooks")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    
    # Add rows to the table
    for playbook in playbooks:
        table.add_row(
            playbook["name"],
            playbook["description"]
        )
    
    # Display the table
    console = Console()
    console.print(table)