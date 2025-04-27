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


@app.callback()
def callback() -> None:
    """
    Manage and execute playbooks.
    """
    pass


@app.command("run")
def run_playbook(
    name: str = typer.Argument(..., help="Name of the playbook to run"),
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
    Execute a predefined playbook.
    """
    playbook_obj = get_playbook(name)
    if not playbook_obj:
        rprint(f"[bold red]Error:[/bold red] Playbook '{name}' not found")
        rprint("Use 'purpletool list playbooks' to see available playbooks")
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
    name: str = typer.Argument(..., help="Name of the playbook to show information about")
) -> None:
    """
    Show detailed information about a playbook.
    """
    playbook_obj = get_playbook(name)
    if not playbook_obj:
        rprint(f"[bold red]Error:[/bold red] Playbook '{name}' not found")
        rprint("Use 'purpletool list playbooks' to see available playbooks")
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
    name: str = typer.Argument(..., help="Name of the playbook to show blue team guidance for")
) -> None:
    """
    Show blue team guidance for a specific playbook.
    """
    playbook_obj = get_playbook(name)
    if not playbook_obj:
        rprint(f"[bold red]Error:[/bold red] Playbook '{name}' not found")
        rprint("Use 'purpletool list playbooks' to see available playbooks")
        raise typer.Exit(code=1)
    
    console = Console()
    
    console.print(f"[bold cyan]{'=' * 60}[/bold cyan]")
    console.print(f"[bold cyan]Blue Team Guidance for: {playbook_obj.name}[/bold cyan]")
    console.print(f"[bold cyan]{'=' * 60}[/bold cyan]\n")
    
    console.print(Markdown(playbook_obj.blue_team_guidance))