"""
Configuration command group for the Purple Team CLI.

This module implements the 'config' subcommands for managing tool configuration.
"""

from pathlib import Path
import os
from typing import Optional

import typer
from rich import print as rprint

from purple_cli.core.config import get_config


app = typer.Typer(
    help="Manage Purple Team CLI configuration",
    no_args_is_help=True,
)


@app.callback()
def callback() -> None:
    """
    Manage Purple Team CLI configuration.
    """
    pass


@app.command("get")
def get_setting(
    key: str = typer.Argument(..., help="The configuration key to retrieve")
) -> None:
    """
    Get a configuration value.
    """
    config = get_config()
    value = config.get_setting(key)
    if value is not None:
        rprint(f"[bold cyan]{key}:[/bold cyan] {value}")
    else:
        rprint(f"[bold yellow]Warning:[/bold yellow] Configuration key '{key}' not found")


@app.command("set")
def set_setting(
    key: str = typer.Argument(..., help="The configuration key to set"),
    value: str = typer.Argument(..., help="The value to set for the configuration key")
) -> None:
    """
    Set a configuration value.
    """
    config = get_config()
    config.update_setting(key, value)
    success = config.save_config()
    
    if success:
        rprint(f"[bold green]Success:[/bold green] Updated configuration key '{key}' to '{value}'")
    else:
        rprint(f"[bold red]Error:[/bold red] Failed to save configuration")


@app.command("show")
def show_config() -> None:
    """
    Show all current configuration settings.
    """
    config = get_config()
    
    rprint("[bold underline]Current Configuration:[/bold underline]")
    for key, value in config.config.items():
        rprint(f"[bold cyan]{key}:[/bold cyan] {value}")


@app.command("set-atomics-path")
def set_atomics_path(
    path: str = typer.Argument(..., help="Path to the Atomic Red Team atomics directory")
) -> None:
    """
    Set the path to the Atomic Red Team atomics directory.
    """
    atomics_path = Path(path)
    
    # Validate the path exists
    if not atomics_path.exists():
        rprint(f"[bold red]Error:[/bold red] Path does not exist: {atomics_path}")
        raise typer.Exit(code=1)
    
    if not atomics_path.is_dir():
        rprint(f"[bold red]Error:[/bold red] Path is not a directory: {atomics_path}")
        raise typer.Exit(code=1)
    
    config = get_config()
    config.atomics_path = str(atomics_path.absolute())
    success = config.save_config()
    
    if success:
        rprint(f"[bold green]Success:[/bold green] Set atomics path to '{atomics_path.absolute()}'")
    else:
        rprint(f"[bold red]Error:[/bold red] Failed to save configuration")


@app.command("set-powershell-path")
def set_powershell_path(
    path: str = typer.Argument(..., help="Path to the PowerShell executable")
) -> None:
    """
    Set the path to the PowerShell executable.
    """
    ps_path = Path(path)
    
    # Validate the path exists
    if not ps_path.exists():
        rprint(f"[bold red]Error:[/bold red] Path does not exist: {ps_path}")
        raise typer.Exit(code=1)
    
    if not ps_path.is_file():
        rprint(f"[bold red]Error:[/bold red] Path is not a file: {ps_path}")
        raise typer.Exit(code=1)
    
    config = get_config()
    config.powershell_path = str(ps_path.absolute())
    success = config.save_config()
    
    if success:
        rprint(f"[bold green]Success:[/bold green] Set PowerShell path to '{ps_path.absolute()}'")
    else:
        rprint(f"[bold red]Error:[/bold red] Failed to save configuration")


@app.command("set-timeout")
def set_timeout(
    seconds: int = typer.Argument(..., help="Timeout in seconds for command execution")
) -> None:
    """
    Set the timeout for command execution.
    """
    if seconds <= 0:
        rprint(f"[bold red]Error:[/bold red] Timeout must be a positive number")
        raise typer.Exit(code=1)
    
    config = get_config()
    config.timeout = seconds
    success = config.save_config()
    
    if success:
        rprint(f"[bold green]Success:[/bold green] Set command timeout to {seconds} seconds")
    else:
        rprint(f"[bold red]Error:[/bold red] Failed to save configuration")