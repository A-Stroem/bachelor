"""
Playbook command group for the Purple Team CLI.

This module implements the 'playbook' subcommands for managing and executing playbooks.
"""

from typing import Optional

import typer
from rich import print as rprint
from rich.markdown import Markdown
from rich.console import Console

from purple_cli.core.playbook import execute_playbook, get_playbook, get_available_playbooks


app = typer.Typer(
    help="Manage and execute playbooks",
    no_args_is_help=True,
)

# Initialize app state
class AppState:
    def __init__(self):
        self.last_playbooks = None

app.state = AppState()


@app.callback()
def callback() -> None:
    """
    Manage and execute playbooks.
    
    Playbooks are predefined collections of Atomic Red Team tests that can be executed together.
    They often represent common attack scenarios or red team engagement patterns.
    """
    pass


@app.command("run")
def run_playbook(
    name: Optional[str] = typer.Argument(None, help="Name of the playbook to run"),
    index: Optional[int] = typer.Option(
        None, "--index", "-i", help="Select playbook by index number from the last list command"
    ),
    check_prereqs: bool = typer.Option(
        False, "--check-prereqs", help="Check prerequisites for each test in the playbook"
    ),
    get_prereqs: bool = typer.Option(
        False, "--get-prereqs", help="Install prerequisites for each test in the playbook"
    ),
    cleanup: bool = typer.Option(
        False, "--cleanup", help="Run cleanup commands after each test in the playbook"
    ),
    session: Optional[str] = typer.Option(
        None, "--session", "-s", help="PowerShell session name for remote execution"
    ),
) -> None:
    """
    Execute a predefined playbook by name or index number.
    
    Examples:
        purple-cli playbook run persistence-techniques
        purple-cli playbook run --index 3
        purple-cli playbook run credential-access --check-prereqs
        purple-cli playbook run credential-access --get-prereqs
        purple-cli playbook run credential-access --cleanup
    """
    # Handle selection by index
    if index is not None:
        # Check if we have stored results from a previous list command
        if not hasattr(app.state, "last_playbooks") or not app.state.last_playbooks:
            rprint("[bold yellow]Warning:[/bold yellow] No recent playbook listing found. Run 'purple-cli list playbooks' first.")
            # Fall back to getting all playbooks
            playbooks = get_available_playbooks()
            
            # Ensure playbooks is a list
            if not isinstance(playbooks, list):
                rprint(f"[bold red]Error:[/bold red] Expected a list of playbooks but got {type(playbooks).__name__}")
                raise typer.Exit(code=1)
            
            if not playbooks or index < 1 or index > len(playbooks):
                rprint(f"[bold red]Error:[/bold red] Index {index} is out of range. Available indices: 1-{len(playbooks) if playbooks else 0}")
                raise typer.Exit(code=1)
                
            # Make sure we can safely access the playbook by index
            try:
                playbook_item = playbooks[index-1]
                if isinstance(playbook_item, dict) and "name" in playbook_item:
                    name = playbook_item["name"]
                    rprint(f"[bold cyan]Selected playbook:[/bold cyan] {name} (index {index})")
                else:
                    # Handle case where playbook_item isn't a dict with a name field
                    name = str(playbook_item)
                    rprint(f"[bold cyan]Selected playbook:[/bold cyan] {name} (index {index})")
            except (IndexError, TypeError) as e:
                rprint(f"[bold red]Error:[/bold red] Could not access playbook at index {index}: {str(e)}")
                raise typer.Exit(code=1)
        else:
            playbooks = app.state.last_playbooks
            
            # Ensure playbooks is a list
            if not isinstance(playbooks, list):
                rprint(f"[bold red]Error:[/bold red] Expected a list of playbooks but got {type(playbooks).__name__}")
                raise typer.Exit(code=1)
            
            if not playbooks or index < 1 or index > len(playbooks):
                rprint(f"[bold red]Error:[/bold red] Index {index} is out of range. Available indices: 1-{len(playbooks) if playbooks else 0}")
                raise typer.Exit(code=1)
                
            # Make sure we can safely access the playbook by index
            try:
                playbook_item = playbooks[index-1]
                if isinstance(playbook_item, dict) and "name" in playbook_item:
                    name = playbook_item["name"]
                    rprint(f"[bold cyan]Selected playbook:[/bold cyan] {name} (index {index})")
                else:
                    # Handle case where playbook_item isn't a dict with a name field
                    name = str(playbook_item)
                    rprint(f"[bold cyan]Selected playbook:[/bold cyan] {name} (index {index})")
            except (IndexError, TypeError) as e:
                rprint(f"[bold red]Error:[/bold red] Could not access playbook at index {index}: {str(e)}")
                raise typer.Exit(code=1)
    
    # Ensure we have a playbook name at this point
    if not name:
        rprint("[bold red]Error:[/bold red] No playbook name provided.")
        rprint("Provide a playbook name directly or use --index to select from a previous listing.")
        raise typer.Exit(code=1)
    
    playbook_obj = get_playbook(name)
    if not playbook_obj:
        rprint(f"[bold red]Error:[/bold red] Playbook '{name}' not found")
        rprint("Use 'purple-cli list playbooks' to see available playbooks")
        raise typer.Exit(code=1)
    
    rprint(f"[bold cyan]Executing Playbook:[/bold cyan] {playbook_obj.name}")
    rprint(f"[bold cyan]Description:[/bold cyan] {playbook_obj.description}")
    rprint(f"[bold cyan]Tests to run:[/bold cyan] {len(playbook_obj.tests)}")
    
    if check_prereqs:
        rprint("[bold yellow]Mode:[/bold yellow] Checking prerequisites only")
    elif get_prereqs:
        rprint("[bold yellow]Mode:[/bold yellow] Installing prerequisites")
    elif cleanup:
        rprint("[bold yellow]Mode:[/bold yellow] Running cleanup commands")
    else:
        rprint("[bold yellow]Mode:[/bold yellow] Executing tests")
    
    if session:
        rprint(f"[bold yellow]Remote Execution:[/bold yellow] Using PowerShell session '{session}'")
    
    rprint("\n[bold]Starting playbook execution...[/bold]\n")
    
    success, results = execute_playbook(
        playbook_name=name,
        check_prereqs=check_prereqs,
        get_prereqs=get_prereqs,
        cleanup=cleanup,
        session=session,
    )
    
    # Handle case where results might not be a list
    if not isinstance(results, list):
        rprint("[bold red]Error:[/bold red] Playbook execution failed to return valid results")
        raise typer.Exit(code=1)
    
    # Display summary of results
    successful_tests = sum(1 for r in results if r.get("success", False))
    failed_tests = len(results) - successful_tests
    
    rprint(f"\n[bold]{'=' * 50}[/bold]")
    rprint(f"[bold]Playbook Execution Summary[/bold]")
    rprint(f"[bold]{'=' * 50}[/bold]")
    rprint(f"Total tests: {len(results)}")
    rprint(f"Successful: [bold green]{successful_tests}[/bold green]")
    rprint(f"Failed: [bold red]{failed_tests}[/bold red]")
    
    if not success:
        raise typer.Exit(code=1)


@app.command("info")
def playbook_info(
    name: Optional[str] = typer.Argument(None, help="Name of the playbook to show information about"),
    index: Optional[int] = typer.Option(
        None, "--index", "-i", help="Select playbook by index number from the last list command"
    )
) -> None:
    """
    Show detailed information about a playbook.
    
    Examples:
        purple-cli playbook info persistence-techniques
        purple-cli playbook info --index 2
    """
    # Handle selection by index
    if index is not None:
        # Check if we have stored results from a previous list command
        if not hasattr(app.state, "last_playbooks") or not app.state.last_playbooks:
            rprint("[bold yellow]Warning:[/bold yellow] No recent playbook listing found. Run 'purple-cli list playbooks' first.")
            # Fall back to getting all playbooks
            playbooks = get_available_playbooks()
            
            if index < 1 or index > len(playbooks):
                rprint(f"[bold red]Error:[/bold red] Index {index} is out of range. Available indices: 1-{len(playbooks)}")
                raise typer.Exit(code=1)
                
            # Make sure we can safely access the playbook by index
            if len(playbooks) > 0 and isinstance(playbooks[index-1], dict):
                name = playbooks[index-1].get("name")
                if name:
                    rprint(f"[bold cyan]Selected playbook:[/bold cyan] {name} (index {index})")
                else:
                    rprint(f"[bold red]Error:[/bold red] Playbook at index {index} does not have a name property.")
                    raise typer.Exit(code=1)
            else:
                rprint(f"[bold red]Error:[/bold red] Could not retrieve playbook information at index {index}.")
                raise typer.Exit(code=1)
        else:
            playbooks = app.state.last_playbooks
            if index < 1 or index > len(playbooks):
                rprint(f"[bold red]Error:[/bold red] Index {index} is out of range. Available indices: 1-{len(playbooks)}")
                raise typer.Exit(code=1)
                
            # Make sure we can safely access the playbook by index
            if len(playbooks) > 0 and isinstance(playbooks[index-1], dict):
                name = playbooks[index-1].get("name")
                if name:
                    rprint(f"[bold cyan]Selected playbook:[/bold cyan] {name} (index {index})")
                else:
                    rprint(f"[bold red]Error:[/bold red] Playbook at index {index} does not have a name property.")
                    raise typer.Exit(code=1)
            else:
                rprint(f"[bold red]Error:[/bold red] Could not retrieve playbook information at index {index}.")
                raise typer.Exit(code=1)
    
    # Ensure we have a playbook name at this point
    if not name:
        rprint("[bold red]Error:[/bold red] No playbook name provided.")
        rprint("Provide a playbook name directly or use --index to select from a previous listing.")
        raise typer.Exit(code=1)
    
    playbook_obj = get_playbook(name)
    if not playbook_obj:
        rprint(f"[bold red]Error:[/bold red] Playbook '{name}' not found")
        rprint("Use 'purple-cli list playbooks' to see available playbooks")
        raise typer.Exit(code=1)
    
    console = Console()
    
    console.print(f"[bold cyan]{'=' * 60}[/bold cyan]")
    console.print(f"[bold cyan]Playbook: {playbook_obj.name}[/bold cyan]")
    console.print(f"[bold cyan]{'=' * 60}[/bold cyan]\n")
    
    console.print(f"[bold]Description:[/bold] {playbook_obj.description}\n")
    
    console.print("[bold]Tests:[/bold]")
    for i, test in enumerate(playbook_obj.tests, 1):
        console.print(f"  {i}. [cyan]{test.technique_id}[/cyan]: {test.description}")
        if test.test_numbers:
            console.print(f"     Test numbers: {', '.join(map(str, test.test_numbers))}")
    
    console.print("\n[bold]Blue Team Guidance:[/bold]")
    console.print(Markdown(playbook_obj.blue_team_guidance))


@app.command("guidance")
def blue_team_guidance(
    name: Optional[str] = typer.Argument(None, help="Name of the playbook to show blue team guidance for"),
    index: Optional[int] = typer.Option(
        None, "--index", "-i", help="Select playbook by index number from the last list command"
    )
) -> None:
    """
    Show blue team guidance for a specific playbook.
    
    This command displays defensive recommendations and detection strategies
    for the techniques included in the playbook.
    
    Examples:
        purple-cli playbook guidance persistence-techniques
        purple-cli playbook guidance --index 2
    """
    # Handle selection by index
    if index is not None:
        # Check if we have stored results from a previous list command
        if not hasattr(app.state, "last_playbooks") or not app.state.last_playbooks:
            rprint("[bold yellow]Warning:[/bold yellow] No recent playbook listing found. Run 'purple-cli list playbooks' first.")
            # Fall back to getting all playbooks
            playbooks = get_available_playbooks()
            
            if index < 1 or index > len(playbooks):
                rprint(f"[bold red]Error:[/bold red] Index {index} is out of range. Available indices: 1-{len(playbooks)}")
                raise typer.Exit(code=1)
                
            # Make sure we can safely access the playbook by index
            if len(playbooks) > 0 and isinstance(playbooks[index-1], dict):
                name = playbooks[index-1].get("name")
                if name:
                    rprint(f"[bold cyan]Selected playbook:[/bold cyan] {name} (index {index})")
                else:
                    rprint(f"[bold red]Error:[/bold red] Playbook at index {index} does not have a name property.")
                    raise typer.Exit(code=1)
            else:
                rprint(f"[bold red]Error:[/bold red] Could not retrieve playbook information at index {index}.")
                raise typer.Exit(code=1)
        else:
            playbooks = app.state.last_playbooks
            if index < 1 or index > len(playbooks):
                rprint(f"[bold red]Error:[/bold red] Index {index} is out of range. Available indices: 1-{len(playbooks)}")
                raise typer.Exit(code=1)
                
            # Make sure we can safely access the playbook by index
            if len(playbooks) > 0 and isinstance(playbooks[index-1], dict):
                name = playbooks[index-1].get("name")
                if name:
                    rprint(f"[bold cyan]Selected playbook:[/bold cyan] {name} (index {index})")
                else:
                    rprint(f"[bold red]Error:[/bold red] Playbook at index {index} does not have a name property.")
                    raise typer.Exit(code=1)
            else:
                rprint(f"[bold red]Error:[/bold red] Could not retrieve playbook information at index {index}.")
                raise typer.Exit(code=1)
    
    # Ensure we have a playbook name at this point
    if not name:
        rprint("[bold red]Error:[/bold red] No playbook name provided.")
        rprint("Provide a playbook name directly or use --index to select from a previous listing.")
        raise typer.Exit(code=1)
    
    playbook_obj = get_playbook(name)
    if not playbook_obj:
        rprint(f"[bold red]Error:[/bold red] Playbook '{name}' not found")
        rprint("Use 'purple-cli list playbooks' to see available playbooks")
        raise typer.Exit(code=1)
    
    console = Console()
    
    console.print(f"[bold cyan]{'=' * 60}[/bold cyan]")
    console.print(f"[bold cyan]Blue Team Guidance for: {playbook_obj.name}[/bold cyan]")
    console.print(f"[bold cyan]{'=' * 60}[/bold cyan]\n")
    
    console.print(Markdown(playbook_obj.blue_team_guidance))