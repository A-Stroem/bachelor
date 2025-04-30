"""
List command group for the Purple Team CLI.

This module implements the 'list' subcommand for displaying available tests and playbooks.
"""

from typing import Optional, List, Dict, Any

import typer
from rich import print as rprint
from rich.table import Table
from rich.console import Console
import re

from purple_cli.core.executor import list_available_tests, get_test_details
from purple_cli.core.playbook import get_available_playbooks
from purple_cli.interactive import TACTICS


app = typer.Typer(
    help="List available tests, playbooks, and other resources",
    no_args_is_help=True,
)

# Initialize app state
class AppState:
    def __init__(self):
        self.last_filtered_results = None
        self.last_playbooks = None

app.state = AppState()


@app.callback()
def callback() -> None:
    """
    List available tests, playbooks, and other resources.
    """
    pass


@app.command("tests")
def list_tests(
    filter_str: Optional[str] = typer.Argument(None, help="Optional filter string or technique ID to search for specific techniques"),
    platform: Optional[str] = typer.Option(None, "--platform", "-p", help="Filter tests by platform (e.g., 'windows', 'macos', 'linux')"),
    tactic: Optional[str] = typer.Option(None, "--tactic", "-t", help="Filter tests by tactic (e.g., 'persistence', 'discovery')"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Show detailed information including platforms and tactics")
) -> None:
    """
    List available Atomic Red Team tests.
    
    Examples:
        purple-cli list tests
        purple-cli list tests T1003
        purple-cli list tests --platform windows
        purple-cli list tests --tactic persistence
        purple-cli list tests "credential" --detailed
    """
    success, result = list_available_tests()
    
    if not success:
        rprint(f"[bold red]Error:[/bold red] {result}")
        raise typer.Exit(code=1)
    
    # Create a table to display the results
    title = "Available Atomic Red Team Tests"
    if platform:
        title += f" for Platform: {platform.title()}"
    if tactic:
        title += f" in Tactic: {TACTICS.get(tactic.lower(), tactic.title())}"
        
    table = Table(title=title)
    table.add_column("#", style="cyan", width=3)
    table.add_column("Technique ID", style="cyan")
    table.add_column("Name")
    
    if detailed:
        table.add_column("Platforms", style="green")
        table.add_column("Tactics", style="yellow")
    
    # Filter the techniques based on criteria
    filtered_results = result
    
    if filter_str:
        filter_str = filter_str.lower()
        filtered_results = [
            t for t in filtered_results 
            if filter_str in t["id"].lower() or filter_str in t["name"].lower()
        ]
    
    if platform:
        platform_lower = platform.lower()
        filtered_results = [
            t for t in filtered_results
            if "platforms" in t and platform_lower in [p.lower() for p in t.get("platforms", [])]
        ]
        
    if tactic:
        tactic_lower = tactic.lower()
        filtered_results = [
            t for t in filtered_results
            if "tactics" in t and tactic_lower in [tac.lower() for tac in t.get("tactics", [])]
        ]
    
    # Add rows to the table
    for i, technique in enumerate(filtered_results, 1):
        if detailed:
            platforms = ", ".join([p.title() for p in technique.get("platforms", [])]) if "platforms" in technique else "N/A"
            tactics = ", ".join([TACTICS.get(t.lower(), t.title()) for t in technique.get("tactics", [])]) if "tactics" in technique else "N/A"
            table.add_row(
                str(i),
                technique["id"],
                technique["name"],
                platforms,
                tactics
            )
        else:
            table.add_row(
                str(i),
                technique["id"],
                technique["name"]
            )
    
    # Display the table
    console = Console()
    console.print(table)
    
    # Show count of filtered vs total techniques
    filter_description = []
    if filter_str:
        filter_description.append(f"matching '{filter_str}'")
    if platform:
        filter_description.append(f"on platform '{platform}'")
    if tactic:
        filter_description.append(f"in tactic '{tactic}'")
    
    filter_text = " ".join(filter_description)
    if filter_text:
        rprint(f"\nShowing {len(filtered_results)} of {len(result)} techniques {filter_text}")
    
    # Provide instructions for running tests
    if filtered_results:
        rprint("\n[bold]To run a test:[/bold]")
        rprint("  Use: [cyan]purple-cli run test <TECHNIQUE_ID>[/cyan]")
        rprint("  or select by number: [cyan]purple-cli run test --index <INDEX_NUMBER>[/cyan]")
        
        # Store the filtered results for potential selection by index
        app.state.last_filtered_results = filtered_results
        

@app.command("playbooks")
def list_playbooks() -> None:
    """
    List available predefined playbooks.
    
    Examples:
        purple-cli list playbooks
    """
    playbooks = get_available_playbooks()
    
    # Create a table to display the results
    table = Table(title="Available Playbooks")
    table.add_column("#", style="cyan", width=3)
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    
    # Add rows to the table
    for i, playbook in enumerate(playbooks, 1):
        # Ensure playbook is a dictionary before accessing its keys
        if isinstance(playbook, dict):
            table.add_row(
                str(i),
                playbook.get("name", "Unknown"),
                playbook.get("description", "")
            )
        else:
            # Handle the case where playbook is not a dictionary
            table.add_row(
                str(i),
                str(playbook) if playbook else "Unknown",
                ""
            )
    
    # Display the table
    console = Console()
    console.print(table)
    
    # Provide instructions for running playbooks
    if playbooks:
        rprint("\n[bold]To run a playbook:[/bold]")
        rprint("  Use: [cyan]purple-cli playbook run <PLAYBOOK_NAME>[/cyan]")
        rprint("  or select by number: [cyan]purple-cli playbook run --index <INDEX_NUMBER>[/cyan]")
        
        # Store the playbooks for potential selection by index
        app.state.last_playbooks = playbooks


@app.command("test-details")
def test_details(
    technique_id: str = typer.Argument(..., help="The technique ID to get details for (e.g., T1003)"),
    test_number: Optional[int] = typer.Option(None, "--test", "-t", help="Show details for a specific test number only")
) -> None:
    """
    Show detailed information about a specific technique or test.
    
    Examples:
        purple-cli list test-details T1003
        purple-cli list test-details T1003 --test 1
    """
    # Validate technique ID format
    if not re.match(r"^T\d{4}(\.\d{3})?$", technique_id, re.IGNORECASE):
        rprint(f"[bold red]Error:[/bold red] Invalid technique ID format: '{technique_id}'")
        rprint("Technique ID should be in the format T1234 or T1234.567")
        raise typer.Exit(code=1)
    
    success, result = get_test_details(technique_id, show_details=True, test_numbers=[test_number] if test_number else None)
    
    if not success:
        rprint(f"[bold red]Error:[/bold red] {result}")
        raise typer.Exit(code=1)
        
    console = Console()
    console.print(result)