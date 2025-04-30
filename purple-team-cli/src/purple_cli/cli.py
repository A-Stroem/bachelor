"""
Main CLI definition for the Purple Team CLI tool.

This module sets up the Typer app and includes the CLI command groups.
"""

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table
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
    
    This tool provides a command-line interface for executing Atomic Red Team tests,
    which are small, highly portable tests mapped to the MITRE ATT&CK framework.
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
    
    Examples:
        purple-cli interactive
    """
    run_interactive_cli()


@app.command("help")
def help_cmd(
    topic: Optional[str] = typer.Argument(None, help="Topic to get help for (e.g., 'run', 'list', 'playbook', 'config')")
) -> None:
    """
    Show detailed help information and examples.
    
    Examples:
        purple-cli help
        purple-cli help run
        purple-cli help list
    """
    console = Console()
    
    if not topic:
        # Show overview help
        console.print(Panel("[bold]Purple Team CLI[/bold]", expand=False))
        console.print("\nWelcome to the Purple Team CLI, a tool for executing Atomic Red Team tests in various environments.")
        console.print("\nThe tool offers both command-line and interactive interfaces for working with Atomic Red Team tests.")
        
        console.print("\n[bold]Main Commands:[/bold]")
        
        table = Table(show_header=True)
        table.add_column("Command", style="cyan")
        table.add_column("Description")
        table.add_column("Examples", style="green")
        
        table.add_row(
            "interactive",
            "Launch the interactive menu-driven interface",
            "purple-cli interactive"
        )
        table.add_row(
            "list",
            "List available tests and playbooks",
            "purple-cli list tests\npurple-cli list playbooks"
        )
        table.add_row(
            "run",
            "Execute Atomic Red Team tests",
            "purple-cli run test T1003\npurple-cli run test --index 5"
        )
        table.add_row(
            "playbook",
            "Manage and execute playbooks",
            "purple-cli playbook run persistence\npurple-cli playbook info --index 2"
        )
        table.add_row(
            "config",
            "Configure tool settings",
            "purple-cli config set atomics_path /path/to/atomics"
        )
        table.add_row(
            "version",
            "Display the version of the tool",
            "purple-cli version"
        )
        
        console.print(table)
        
        console.print("\n[bold]Getting Started:[/bold]")
        console.print("1. Set the path to your Atomic Red Team atomics directory:")
        console.print("   [cyan]purple-cli config set atomics_path /path/to/atomics[/cyan]")
        console.print("2. List available tests:")
        console.print("   [cyan]purple-cli list tests[/cyan]")
        console.print("3. Run a test:")
        console.print("   [cyan]purple-cli run test T1003[/cyan]")
        console.print("\nFor detailed help on a specific command, use:")
        console.print("   [cyan]purple-cli help <command>[/cyan]")
        console.print("\nOr use the interactive mode for a guided experience:")
        console.print("   [cyan]purple-cli interactive[/cyan]")
    
    elif topic.lower() == "run":
        console.print(Panel("[bold]Run Command Help[/bold]", expand=False))
        console.print("\nThe 'run' command is used to execute Atomic Red Team tests.")
        
        console.print("\n[bold]Subcommands:[/bold]")
        console.print("  [cyan]test[/cyan] - Execute a specific test by technique ID or index")
        
        console.print("\n[bold]Examples:[/bold]")
        console.print("  Execute a test by technique ID:")
        console.print("    [green]purple-cli run test T1003[/green]")
        console.print("  Execute a test by index number (after listing tests):")
        console.print("    [green]purple-cli run test --index 5[/green]")
        console.print("  Execute specific test numbers for a technique:")
        console.print("    [green]purple-cli run test T1003 --test-numbers 1,2[/green]")
        console.print("  Check prerequisites for a test:")
        console.print("    [green]purple-cli run test T1003 --check-prereqs[/green]")
        console.print("  Install prerequisites for a test:")
        console.print("    [green]purple-cli run test T1003 --get-prereqs[/green]")
        console.print("  Run cleanup after a test:")
        console.print("    [green]purple-cli run test T1003 --cleanup[/green]")
        console.print("  Run a test in non-interactive mode (capture output):")
        console.print("    [green]purple-cli run test T1003 --non-interactive[/green]")
    
    elif topic.lower() == "list":
        console.print(Panel("[bold]List Command Help[/bold]", expand=False))
        console.print("\nThe 'list' command is used to display available tests, playbooks, and other resources.")
        
        console.print("\n[bold]Subcommands:[/bold]")
        console.print("  [cyan]tests[/cyan] - List available Atomic Red Team tests")
        console.print("  [cyan]playbooks[/cyan] - List available predefined playbooks")
        console.print("  [cyan]test-details[/cyan] - Show detailed information about a specific test")
        
        console.print("\n[bold]Examples:[/bold]")
        console.print("  List all available tests:")
        console.print("    [green]purple-cli list tests[/green]")
        console.print("  Search for tests by keyword:")
        console.print("    [green]purple-cli list tests credential[/green]")
        console.print("  List tests for a specific platform:")
        console.print("    [green]purple-cli list tests --platform windows[/green]")
        console.print("  List tests for a specific tactic:")
        console.print("    [green]purple-cli list tests --tactic persistence[/green]")
        console.print("  Show detailed information for tests:")
        console.print("    [green]purple-cli list tests credential --detailed[/green]")
        console.print("  List all available playbooks:")
        console.print("    [green]purple-cli list playbooks[/green]")
        console.print("  Show detailed information about a test:")
        console.print("    [green]purple-cli list test-details T1003[/green]")
        console.print("  Show details for a specific test number:")
        console.print("    [green]purple-cli list test-details T1003 --test 1[/green]")
    
    elif topic.lower() == "playbook":
        console.print(Panel("[bold]Playbook Command Help[/bold]", expand=False))
        console.print("\nThe 'playbook' command is used to manage and execute predefined collections of Atomic Red Team tests.")
        
        console.print("\n[bold]Subcommands:[/bold]")
        console.print("  [cyan]run[/cyan] - Execute a playbook by name or index")
        console.print("  [cyan]info[/cyan] - Show detailed information about a playbook")
        console.print("  [cyan]guidance[/cyan] - Show blue team guidance for a playbook")
        
        console.print("\n[bold]Examples:[/bold]")
        console.print("  Execute a playbook by name:")
        console.print("    [green]purple-cli playbook run persistence-techniques[/green]")
        console.print("  Execute a playbook by index number (after listing playbooks):")
        console.print("    [green]purple-cli playbook run --index 2[/green]")
        console.print("  Check prerequisites for all tests in a playbook:")
        console.print("    [green]purple-cli playbook run persistence-techniques --check-prereqs[/green]")
        console.print("  Install prerequisites for all tests in a playbook:")
        console.print("    [green]purple-cli playbook run persistence-techniques --get-prereqs[/green]")
        console.print("  Run cleanup for all tests in a playbook:")
        console.print("    [green]purple-cli playbook run persistence-techniques --cleanup[/green]")
        console.print("  Show detailed information about a playbook:")
        console.print("    [green]purple-cli playbook info persistence-techniques[/green]")
        console.print("  Show blue team guidance for a playbook:")
        console.print("    [green]purple-cli playbook guidance persistence-techniques[/green]")
    
    elif topic.lower() == "config":
        console.print(Panel("[bold]Config Command Help[/bold]", expand=False))
        console.print("\nThe 'config' command is used to configure tool settings.")
        
        console.print("\n[bold]Subcommands:[/bold]")
        console.print("  [cyan]set[/cyan] - Set a configuration value")
        console.print("  [cyan]get[/cyan] - Get a configuration value")
        console.print("  [cyan]show[/cyan] - Show all configuration values")
        
        console.print("\n[bold]Available Settings:[/bold]")
        console.print("  [cyan]atomics_path[/cyan] - Path to the Atomic Red Team atomics directory")
        console.print("  [cyan]powershell_path[/cyan] - Path to the PowerShell executable")
        console.print("  [cyan]timeout[/cyan] - Timeout in seconds for commands")
        
        console.print("\n[bold]Examples:[/bold]")
        console.print("  Set the path to the atomics directory:")
        console.print("    [green]purple-cli config set atomics_path /path/to/atomics[/green]")
        console.print("  Set the path to the PowerShell executable:")
        console.print("    [green]purple-cli config set powershell_path /usr/bin/pwsh[/green]")
        console.print("  Set the command timeout:")
        console.print("    [green]purple-cli config set timeout 300[/green]")
        console.print("  Get a specific configuration value:")
        console.print("    [green]purple-cli config get atomics_path[/green]")
        console.print("  Show all configuration values:")
        console.print("    [green]purple-cli config show[/green]")
    
    elif topic.lower() == "interactive":
        console.print(Panel("[bold]Interactive Mode Help[/bold]", expand=False))
        console.print("\nThe 'interactive' command launches a full-screen menu-driven interface for easier navigation and execution of Atomic Red Team tests.")
        
        console.print("\n[bold]Features:[/bold]")
        console.print("  - Browse tests by tactic or platform")
        console.print("  - Filter tests by various criteria")
        console.print("  - Execute tests with various options")
        console.print("  - Manage and execute playbooks")
        console.print("  - Configure tool settings")
        
        console.print("\n[bold]Usage:[/bold]")
        console.print("  [green]purple-cli interactive[/green]")
        
    else:
        console.print(f"[bold red]Error:[/bold red] Unknown help topic: {topic}")
        console.print("Available topics: run, list, playbook, config, interactive")


if __name__ == "__main__":
    app()