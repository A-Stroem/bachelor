"""
Run command group for the Purple Team CLI.

This module implements the 'run' subcommand for executing Atomic Red Team tests.
"""

from typing import List, Optional
import typer
from rich import print as rprint
import re

from purple_cli.core.executor import run_atomic_test, validate_technique_id, list_available_tests


app = typer.Typer(
    help="Execute Atomic Red Team tests",
    no_args_is_help=True,
)

# Initialize app state
class AppState:
    def __init__(self):
        self.last_filtered_results = None

app.state = AppState()


@app.callback()
def callback() -> None:
    """
    Execute Atomic Red Team tests.
    """
    pass


@app.command("test")
def run_test(
    technique_id: Optional[str] = typer.Argument(None, help="MITRE ATT&CK Technique ID (e.g., T1053.005)"),
    test_numbers: Optional[List[int]] = typer.Option(
        None, "--test-numbers", "-n", help="Specific test numbers to run (comma-separated)"
    ),
    index: Optional[int] = typer.Option(
        None, "--index", "-i", help="Select technique by index number from the last list command"
    ),
    check_prereqs: bool = typer.Option(
        False, "--check-prereqs", help="Check prerequisites for the test"
    ),
    get_prereqs: bool = typer.Option(
        False, "--get-prereqs", help="Install prerequisites for the test"
    ),
    cleanup: bool = typer.Option(
        False, "--cleanup", help="Run cleanup commands after test"
    ),
    session: Optional[str] = typer.Option(
        None, "--session", "-s", help="PowerShell session name for remote execution"
    ),
    show_details_brief: bool = typer.Option(
        True, "--show-details", help="Show details about test execution"
    ),
    interactive: bool = typer.Option(
        True, "--interactive/--non-interactive", help="Allow interactive GUI applications to display"
    ),
) -> None:
    """
    Execute a specific Atomic Red Team test by technique ID or index number.
    
    Examples:
        purple-cli run test T1003
        purple-cli run test T1003 --test-numbers 1,2
        purple-cli run test --index 5
        purple-cli run test T1003 --check-prereqs
        purple-cli run test T1003 --get-prereqs
        purple-cli run test T1003 --cleanup
        purple-cli run test T1003 --non-interactive
    """
    # Handle selection by index
    if index is not None:
        # Check if we have stored results from a previous list command
        if not hasattr(app.state, "last_filtered_results") or not app.state.last_filtered_results:
            rprint("[bold yellow]Warning:[/bold yellow] No recent test listing found. Run 'purple-cli list tests' first.")
            # Fall back to listing all tests and selecting by index
            success, result = list_available_tests()
            if not success:
                rprint(f"[bold red]Error:[/bold red] {result}")
                raise typer.Exit(code=1)
            
            if index < 1 or index > len(result):
                rprint(f"[bold red]Error:[/bold red] Index {index} is out of range. Available indices: 1-{len(result)}")
                raise typer.Exit(code=1)
                
            technique_id = result[index-1]["id"]
            rprint(f"[bold cyan]Selected technique:[/bold cyan] {technique_id} (index {index})")
        else:
            results = app.state.last_filtered_results
            if index < 1 or index > len(results):
                rprint(f"[bold red]Error:[/bold red] Index {index} is out of range. Available indices: 1-{len(results)}")
                raise typer.Exit(code=1)
                
            technique_id = results[index-1]["id"]
            rprint(f"[bold cyan]Selected technique:[/bold cyan] {technique_id} (index {index})")
    
    # Ensure we have a technique ID at this point
    if not technique_id:
        rprint("[bold red]Error:[/bold red] No technique ID provided.")
        rprint("Provide a technique ID directly or use --index to select from a previous listing.")
        raise typer.Exit(code=1)
    
    # Validate technique ID
    if not validate_technique_id(technique_id):
        rprint(f"[bold red]Error:[/bold red] Invalid technique ID format: {technique_id}")
        rprint("Technique ID should be in the format T1234 or T1234.001")
        raise typer.Exit(code=1)
    
    rprint(f"[bold cyan]Executing test[/bold cyan]: {technique_id}")
    
    if check_prereqs:
        rprint("[bold yellow]Mode:[/bold yellow] Checking prerequisites only")
    elif get_prereqs:
        rprint("[bold yellow]Mode:[/bold yellow] Installing prerequisites")
    elif cleanup:
        rprint("[bold yellow]Mode:[/bold yellow] Running cleanup commands")
    else:
        rprint("[bold yellow]Mode:[/bold yellow] Executing test")
    
    if test_numbers:
        rprint(f"[bold yellow]Test Numbers:[/bold yellow] {', '.join(map(str, test_numbers))}")
    
    if session:
        rprint(f"[bold yellow]Remote Execution:[/bold yellow] Using PowerShell session '{session}'")
    
    if not interactive:
        rprint("[bold yellow]Interactive Mode:[/bold yellow] Disabled (output will be captured)")
    
    success, output = run_atomic_test(
        technique_id=technique_id,
        test_numbers=test_numbers,
        check_prereqs=check_prereqs,
        get_prereqs=get_prereqs,
        cleanup=cleanup,
        session=session,
        show_details_brief=show_details_brief,
        capture_output=not interactive,  # Invert the interactive flag for capture_output
    )
    
    if success:
        rprint("\n[bold green]Test execution completed successfully[/bold green]\n")
        if not interactive:  # Only print the output if we captured it
            rprint(output)
    else:
        rprint("\n[bold red]Test execution failed[/bold red]\n")
        rprint(output)
        raise typer.Exit(code=1)