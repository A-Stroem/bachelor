"""
Interactive mode for the Purple Team CLI.

This module provides an interactive, menu-driven interface for the Purple Team CLI,
allowing users to navigate through menus for different options.
"""

import os
import sys
from typing import Dict, List, Optional, Any, Callable

from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from purple_cli.core.executor import run_atomic_test, list_available_tests
from purple_cli.core.playbook import get_available_playbooks, get_playbook, execute_playbook
from purple_cli.core.config import get_config, set_config


console = Console()


def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header(title: str) -> None:
    """Print a styled header with the given title."""
    clear_screen()
    console.print(Panel(f"[bold purple]{title}[/bold purple]", expand=False))
    console.print("\n")


def pause() -> None:
    """Wait for the user to press Enter to continue."""
    console.print("\n")
    Prompt.ask("[italic]Press Enter to continue[/italic]")


def show_main_menu() -> str:
    """Display the main menu and return the user's choice."""
    print_header("Purple Team CLI - Interactive Mode")
    
    options = [
        "List Tests",
        "Run Test",
        "List Playbooks",
        "Run Playbook",
        "Configuration",
        "Exit"
    ]
    
    for i, option in enumerate(options, 1):
        console.print(f"[bold cyan]{i}.[/bold cyan] {option}")
    
    console.print("\n")
    choice = IntPrompt.ask("Enter your choice", default=1)
    
    if 1 <= choice <= len(options):
        return options[choice-1]
    return "Invalid"


def list_tests_menu() -> None:
    """Display the list tests menu and show test details."""
    print_header("List Atomic Red Team Tests")
    
    # Ask if user wants to filter tests
    filter_option = Prompt.ask(
        "Do you want to filter tests? Enter a search term or leave empty for all tests", 
        default=""
    )
    
    # Ask about platform filtering
    platform_option = Prompt.ask(
        "Show tests for: [C]urrent platform only or [A]ll platforms", 
        choices=["C", "A"], 
        default="C"
    )
    any_os = platform_option.upper() == "A"
    
    # Ask about detail level
    detail_level = Prompt.ask(
        "Display: [B]rief details or [F]ull details", 
        choices=["B", "F"], 
        default="B"
    )
    show_details = detail_level.upper() == "F"
    
    console.print("[bold yellow]Fetching available tests...[/bold yellow]")
    
    # Execute PowerShell command to get test details
    command = build_list_tests_command(
        filter_str=filter_option if filter_option else None,
        show_details=show_details,
        any_os=any_os
    )
    
    success, result = execute_ps_command(command)
    
    if success:
        # If success, result will be the output of the command
        console.print(result)
    else:
        console.print(f"[bold red]Error:[/bold red] {result}")
    
    pause()


def run_test_menu() -> None:
    """Display the run test menu and execute the selected test."""
    print_header("Run Atomic Red Team Test")
    
    # Get technique ID
    technique_id = Prompt.ask(
        "Enter the MITRE ATT&CK Technique ID (e.g., T1003)",
        default="T1003"
    )
    
    # Get test numbers (optional)
    test_numbers_str = Prompt.ask(
        "Enter specific test numbers to run (comma-separated) or leave empty for all tests",
        default=""
    )
    test_numbers = [int(n.strip()) for n in test_numbers_str.split(",")] if test_numbers_str.strip() else None
    
    # Options for test execution
    options = [
        "Execute Test",
        "Check Prerequisites Only",
        "Install Prerequisites",
        "Cleanup After Test"
    ]
    
    console.print("\n[bold]Select operation:[/bold]")
    for i, option in enumerate(options, 1):
        console.print(f"[bold cyan]{i}.[/bold cyan] {option}")
    
    operation = IntPrompt.ask("Enter your choice", default=1)
    
    # Determine operation parameters
    check_prereqs = operation == 2
    get_prereqs = operation == 3
    cleanup = operation == 4
    
    # Ask about interactive mode
    interactive_mode = Prompt.ask(
        "\nAllow interactive GUI applications to display? [Y/n]",
        choices=["Y", "n"],
        default="Y"
    ).upper() == "Y"
    
    # Confirm execution
    technique_str = f"{technique_id}" + (f" (Tests: {test_numbers_str})" if test_numbers_str else "")
    operation_str = options[operation-1]
    
    console.print(f"\n[bold]About to perform:[/bold] {operation_str} for {technique_str}")
    if interactive_mode:
        console.print("[bold]Interactive mode:[/bold] Enabled (GUI applications will display)")
    else:
        console.print("[bold]Interactive mode:[/bold] Disabled (output will be captured)")
    
    confirm = Prompt.ask("Continue? (y/n)", choices=["y", "n"], default="y")
    
    if confirm.lower() != "y":
        console.print("[yellow]Operation cancelled.[/yellow]")
        pause()
        return
    
    # Execute the test
    console.print(f"\n[bold yellow]Executing {operation_str}...[/bold yellow]")
    
    success, output = run_atomic_test(
        technique_id=technique_id,
        test_numbers=test_numbers,
        check_prereqs=check_prereqs,
        get_prereqs=get_prereqs,
        cleanup=cleanup,
        show_details_brief=True,
        capture_output=not interactive_mode  # Invert interactive_mode for capture_output
    )
    
    if success:
        console.print("\n[bold green]Operation completed successfully[/bold green]")
        if not interactive_mode:  # Only print output if we captured it
            console.print(output)
    else:
        console.print(f"\n[bold red]Operation failed:[/bold red] {output}")
    
    pause()


def list_playbooks_menu() -> None:
    """Display the list of available playbooks."""
    print_header("Available Playbooks")
    
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
    console.print(table)
    
    # Option to view playbook details
    console.print("\n")
    view_details = Prompt.ask(
        "Enter a playbook name to view details, or press Enter to return to the main menu",
        default=""
    )
    
    if view_details:
        playbook = get_playbook(view_details)
        if playbook:
            print_header(f"Playbook: {playbook.name}")
            
            console.print(f"[bold]Description:[/bold] {playbook.description}")
            console.print("\n[bold]Tests:[/bold]")
            
            for i, test in enumerate(playbook.tests, 1):
                test_nums = f" (Tests: {', '.join(map(str, test.test_numbers))})" if test.test_numbers else ""
                console.print(f"{i}. {test.technique_id}{test_nums} - {test.description}")
            
            if playbook.blue_team_guidance:
                console.print("\n[bold]Blue Team Guidance:[/bold]")
                console.print(playbook.blue_team_guidance)
        else:
            console.print(f"[bold red]Playbook '{view_details}' not found.[/bold red]")
    
    pause()


def run_playbook_menu() -> None:
    """Display the run playbook menu and execute the selected playbook."""
    print_header("Run Playbook")
    
    # List available playbooks
    playbooks = get_available_playbooks()
    
    # Create a table to display the results
    table = Table(title="Available Playbooks")
    table.add_column("#", style="cyan")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    
    # Add rows to the table
    for i, playbook in enumerate(playbooks, 1):
        table.add_row(
            str(i),
            playbook["name"],
            playbook["description"]
        )
    
    # Display the table
    console.print(table)
    
    # Get playbook selection
    selection = IntPrompt.ask(
        "\nEnter the number of the playbook to run",
        default=1
    )
    
    if 1 <= selection <= len(playbooks):
        playbook_name = playbooks[selection-1]["name"]
        
        # Options for playbook execution
        options = [
            "Execute Playbook",
            "Check Prerequisites Only",
            "Install Prerequisites",
            "Cleanup After Tests"
        ]
        
        console.print("\n[bold]Select operation:[/bold]")
        for i, option in enumerate(options, 1):
            console.print(f"[bold cyan]{i}.[/bold cyan] {option}")
        
        operation = IntPrompt.ask("Enter your choice", default=1)
        
        # Determine operation parameters
        check_prereqs = operation == 2
        get_prereqs = operation == 3
        cleanup = operation == 4
        
        # Confirm execution
        operation_str = options[operation-1]
        console.print(f"\n[bold]About to perform:[/bold] {operation_str} for playbook '{playbook_name}'")
        confirm = Prompt.ask("Continue? (y/n)", choices=["y", "n"], default="y")
        
        if confirm.lower() != "y":
            console.print("[yellow]Operation cancelled.[/yellow]")
            pause()
            return
        
        # Execute the playbook
        console.print(f"\n[bold yellow]Executing {operation_str}...[/bold yellow]")
        
        success, results = execute_playbook(
            playbook_name=playbook_name,
            check_prereqs=check_prereqs,
            get_prereqs=get_prereqs,
            cleanup=cleanup
        )
        
        if success:
            console.print("\n[bold green]Playbook execution completed successfully[/bold green]")
        else:
            console.print("\n[bold red]Playbook execution had some failures[/bold red]")
        
        # Display test results summary
        for i, result in enumerate(results, 1):
            status = "[green]✓ Success[/green]" if result.get("success", False) else "[red]✗ Failed[/red]"
            console.print(f"{i}. {result.get('technique_id', 'Unknown')} - {status}")
    else:
        console.print("[bold red]Invalid selection.[/bold red]")
    
    pause()


def configuration_menu() -> None:
    """Display the configuration menu."""
    while True:
        print_header("Configuration")
        
        config = get_config()
        
        # Display current configuration
        console.print("[bold]Current Configuration:[/bold]")
        console.print(f"Atomics Path: {config.atomics_path or 'Not set'}")
        console.print(f"PowerShell Path: {config.powershell_path or 'Not set'}")
        console.print(f"Command Timeout: {config.timeout} seconds")
        
        # Configuration options
        options = [
            "Set Atomics Path",
            "Set PowerShell Path",
            "Set Command Timeout",
            "Return to Main Menu"
        ]
        
        console.print("\n[bold]Options:[/bold]")
        for i, option in enumerate(options, 1):
            console.print(f"[bold cyan]{i}.[/bold cyan] {option}")
        
        choice = IntPrompt.ask("\nEnter your choice", default=len(options))
        
        if choice == 1:
            # Set Atomics Path
            path = Prompt.ask(
                "Enter the path to the atomic-red-team/atomics directory",
                default=config.atomics_path or ""
            )
            if path:
                set_config("atomics_path", path)
                console.print(f"[bold green]Atomics path set to:[/bold green] {path}")
                pause()
        
        elif choice == 2:
            # Set PowerShell Path
            path = Prompt.ask(
                "Enter the path to the PowerShell executable",
                default=config.powershell_path or "powershell"
            )
            if path:
                set_config("powershell_path", path)
                console.print(f"[bold green]PowerShell path set to:[/bold green] {path}")
                pause()
        
        elif choice == 3:
            # Set Command Timeout
            timeout = IntPrompt.ask(
                "Enter the command timeout in seconds",
                default=config.timeout
            )
            set_config("timeout", timeout)
            console.print(f"[bold green]Command timeout set to:[/bold green] {timeout} seconds")
            pause()
        
        elif choice == 4 or choice > len(options):
            # Return to main menu
            break


def build_list_tests_command(filter_str: Optional[str] = None, show_details: bool = False, any_os: bool = False) -> List[str]:
    """
    Build the PowerShell command to list Atomic Red Team tests.
    
    Args:
        filter_str: Optional filter string to search for specific techniques.
        show_details: Whether to show full details of the tests.
        any_os: Whether to show tests for all platforms or just the current one.
        
    Returns:
        A list representing the PowerShell command to execute.
    """
    config = get_config()
    
    # Base command
    command = [config.powershell_path, "-Command"]
    
    # Choose technique ID (All or specific filter)
    technique = "All" if not filter_str else filter_str
    
    # Build the Invoke-AtomicTest command
    if show_details:
        invoke_cmd = f"Invoke-AtomicTest {technique} -ShowDetails"
    else:
        invoke_cmd = f"Invoke-AtomicTest {technique} -ShowDetailsBrief"
    
    if any_os:
        invoke_cmd += " -AnyOS"
    
    command.append(invoke_cmd)
    return command


def execute_ps_command(command: List[str]) -> tuple[bool, str]:
    """
    Execute a PowerShell command and return the results.
    
    Args:
        command: The PowerShell command to execute as a list of strings.
        
    Returns:
        A tuple containing (success_flag, output_or_error_text).
    """
    import subprocess
    
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=get_config().timeout
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed with exit code {e.returncode}.\n"
        if e.stderr:
            error_msg += f"Details: {e.stderr}"
        return False, error_msg
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {get_config().timeout} seconds."
    except Exception as e:
        return False, f"An unexpected error occurred: {str(e)}"


def run_interactive_cli() -> None:
    """Run the interactive CLI menu system."""
    while True:
        choice = show_main_menu()
        
        if choice == "List Tests":
            list_tests_menu()
        elif choice == "Run Test":
            run_test_menu()
        elif choice == "List Playbooks":
            list_playbooks_menu()
        elif choice == "Run Playbook":
            run_playbook_menu()
        elif choice == "Configuration":
            configuration_menu()
        elif choice == "Exit":
            print_header("Exiting Purple Team CLI")
            console.print("Thank you for using Purple Team CLI!")
            sys.exit(0)
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")
            pause()


if __name__ == "__main__":
    run_interactive_cli()