import os
import sys
from typing import Dict, List, Optional, Callable, Tuple, Any, Set # Added Any, Set
import yaml
from pathlib import Path
import re 
import subprocess
import shutil
import importlib.util
import time
import json # Added for parsing credentials

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm 
from rich.panel import Panel
from rich.table import Table
from rich import markup # Added for escaping markup
# Removed unused rprint import

# Removed unused list_available_tests import
from purple_cli.core.executor import run_atomic_test, get_test_details, build_command 
from purple_cli.core.playbook import get_available_playbooks, get_playbook, execute_playbook
from purple_cli.core.config import get_config, set_config


console = Console()

# Dictionary mapping MITRE ATT&CK tactics to their friendly names
TACTICS = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence", 
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact"
}

# Enhanced cache structure to store more detailed technique information
# {platform: {tactic: {technique_id: {name, platforms, phases, has_tests}}}}
INDEX_DATA_CACHE: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}
AVAILABLE_PLATFORMS: List[str] = []

# Prerequisites for Phishing Simulation
REQUIRED_PYTHON_PACKAGES_PHISHING: List[str] = ["requests", "python-dotenv"] # Example: adjust as needed

# Global variable to store the phishing server process
PHISHING_SERVER_PROCESS: Optional[subprocess.Popen] = None


def get_index_dir() -> Optional[Path]:
    """Gets the path to the Indexes directory within the configured atomics path."""
    config = get_config()
    if not config.atomics_path:
        console.print("[bold red]Error:[/bold red] Atomics path is not configured.")
        return None
    
    atomics_path = Path(config.atomics_path)
    index_dir = atomics_path / "Indexes"
    
    if not index_dir.is_dir():
        console.print(f"[bold red]Error:[/bold red] Indexes directory not found at '{index_dir}'.")
        console.print("Please ensure your atomics path is correct and the Indexes directory exists.")
        return None
    return index_dir

def load_index_data() -> Tuple[List[str], Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]]:
    """
    Loads index data from YAML files for all platforms.
    Returns the available platforms and the loaded index data with enhanced technique details.
    Filters out techniques without atomic tests.
    """
    index_dir = get_index_dir()
    if not index_dir:
        return [], {} # Return empty if index dir not found

    local_available_platforms = []
    loaded_data: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}

    console.print("[italic]Loading index data...[/italic]")
    for index_file in index_dir.glob("*-index.yaml"):
        platform_match = re.match(r"(.+)-index\.yaml", index_file.name)
        if platform_match:
            platform = platform_match.group(1).lower()
            local_available_platforms.append(platform)
            try:
                with open(index_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data:
                        # Normalize tactic names (lowercase, replace space with hyphen) for consistency
                        normalized_platform_data = {}
                        for tactic, techniques_in_tactic in data.items():
                            norm_tactic = tactic.lower().replace(' ', '-')
                            
                            # Ensure techniques_in_tactic is a dictionary and validate its values
                            if isinstance(techniques_in_tactic, dict):
                                validated_techniques = {}
                                for tech_id, tech_value in techniques_in_tactic.items():
                                    # Skip techniques without atomic tests
                                    if isinstance(tech_value, dict) and 'atomic_tests' in tech_value:
                                        if not tech_value['atomic_tests']:  # Skip if atomic_tests is empty
                                            continue
                                        
                                        # Extract technique details
                                        technique_info = {
                                            'name': 'Unknown',  # Default name
                                            'platforms': set(),
                                            'phases': set(),
                                            'has_tests': True  # We already know it has tests
                                        }
                                        
                                        # Get technique name
                                        if 'technique' in tech_value and isinstance(tech_value['technique'], dict):
                                            if 'name' in tech_value['technique']:
                                                technique_info['name'] = tech_value['technique']['name']
                                                
                                            # Extract platforms
                                            if 'x_mitre_platforms' in tech_value['technique']:
                                                platforms = tech_value['technique']['x_mitre_platforms']
                                                if isinstance(platforms, list):
                                                    technique_info['platforms'].update(p.lower() for p in platforms)
                                            
                                            # Extract kill chain phases
                                            if 'kill_chain_phases' in tech_value['technique']:
                                                phases = tech_value['technique']['kill_chain_phases']
                                                if isinstance(phases, list):
                                                    for phase in phases:
                                                        if isinstance(phase, dict) and 'phase_name' in phase:
                                                            technique_info['phases'].add(phase['phase_name'].lower())
                                        
                                        validated_techniques[tech_id] = technique_info
                                    elif isinstance(tech_value, str):
                                        # Simple string case - create basic structure but mark as no tests
                                        validated_techniques[tech_id] = {
                                            'name': tech_value,
                                            'platforms': set(),
                                            'phases': set(),
                                            'has_tests': False
                                        }
                                normalized_platform_data[norm_tactic] = validated_techniques
                            else:
                                # Handle cases where techniques might not be a dict
                                console.print(f"[yellow]Warning:[/yellow] Invalid data format for tactic '{tactic}' in platform '{platform}'. Expected a dictionary of techniques.")
                                normalized_platform_data[norm_tactic] = {}

                        loaded_data[platform] = normalized_platform_data
            except yaml.YAMLError as e:
                console.print(f"[yellow]Warning:[/yellow] Could not parse index file '{index_file.name}': {e}")
            except FileNotFoundError:
                console.print(f"[yellow]Warning:[/yellow] Index file not found: '{index_file.name}'")
            except IOError as e:
                console.print(f"[yellow]Warning:[/yellow] Could not read index file '{index_file.name}': {e}")

    local_available_platforms.sort()
    
    # Update module-level cache after loading
    global INDEX_DATA_CACHE, AVAILABLE_PLATFORMS
    INDEX_DATA_CACHE = loaded_data
    AVAILABLE_PLATFORMS = local_available_platforms

    if not INDEX_DATA_CACHE:
        console.print("[bold red]Error:[/bold red] No valid index data could be loaded.")
        console.print("Please check the 'Indexes' directory in your atomics path.")
         
    return AVAILABLE_PLATFORMS, INDEX_DATA_CACHE


def ensure_index_data_loaded() -> None:
    """Checks if index data is loaded, and loads it if not."""
    if not INDEX_DATA_CACHE:
        load_index_data()


def get_techniques(platform: Optional[str] = None, tactic: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Retrieves techniques based on platform and/or tactic from the cached index data.

    Args:
        platform: The platform name (e.g., 'windows', 'linux') or None for all.
        tactic: The tactic name (e.g., 'persistence') or None for all.

    Returns:
        A dictionary of {technique_id: technique_info}.
    """
    ensure_index_data_loaded() # Ensure data is loaded
    results: Dict[str, Dict[str, Any]] = {}
    
    platforms_to_search = [platform] if platform else AVAILABLE_PLATFORMS

    for p_key in platforms_to_search:
        platform_data = INDEX_DATA_CACHE.get(p_key)
        if not platform_data:
            continue

        tactics_to_search = [tactic] if tactic else platform_data.keys()
        
        for t_key in tactics_to_search:
            # Normalize the requested tactic key for matching
            norm_tactic_key = t_key.lower().replace(' ', '-')
            techniques = platform_data.get(norm_tactic_key)
            if techniques:
                # Ensure techniques is a dictionary before processing
                if isinstance(techniques, dict):
                    # Only include techniques that have atomic tests
                    for tech_id, tech_info in techniques.items():
                        if tech_id not in results:
                            results[tech_id] = tech_info
                        elif isinstance(tech_info, dict) and isinstance(results[tech_id], dict):
                            # If we already have this technique, merge platforms and phases
                            if 'platforms' in tech_info and 'platforms' in results[tech_id]:
                                results[tech_id]['platforms'].update(tech_info['platforms'])
                            if 'phases' in tech_info and 'phases' in results[tech_id]:
                                results[tech_id]['phases'].update(tech_info['phases'])
                else:
                    console.print(f"[yellow]Warning:[/yellow] Invalid technique data format for tactic '{t_key}' in platform '{p_key}'. Expected a dictionary.")

    return results

def get_tactics_for_platform(platform: str) -> List[str]:
    """Gets a list of tactics available for a specific platform."""
    ensure_index_data_loaded()
    platform_data = INDEX_DATA_CACHE.get(platform.lower())
    if platform_data:
        # Return the original tactic names used as keys in the index file if possible
        # We need to map back from the normalized keys used internally
        return sorted(platform_data.keys())
    return []

def get_all_tactics() -> List[str]:
    """Gets a unique list of all tactics across all platforms."""
    ensure_index_data_loaded()
    all_tactics = set()
    for platform_data in INDEX_DATA_CACHE.values():
        all_tactics.update(platform_data.keys())
    return sorted(list(all_tactics))


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
        "Help",
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
    """Display the list tests menu and options for filtering/browsing."""
    print_header("List Atomic Red Team Tests")
    ensure_index_data_loaded() # Ensure index is loaded before showing options

    if not INDEX_DATA_CACHE:
        console.print("[bold red]Could not load test index data. Cannot browse.[/bold red]")
        pause()
        return

    options = [
        "Search by keyword or technique ID",
        "Browse by Tactic",
        "Browse by Platform",
        "Show All Tests (using Invoke-AtomicTest)",
        "Back to Main Menu"
    ]

    for i, option in enumerate(options, 1):
        console.print(f"[bold cyan]{i}.[/bold cyan] {option}")
    console.print("\n")

    choice = IntPrompt.ask("Enter your choice", default=1)

    if choice == 1:
        # Search by keyword or technique ID (using Invoke-AtomicTest)
        filter_option = Prompt.ask(
            "Enter a search term or technique ID (e.g., T1003 or credential)",
            default=""
        )
        show_filtered_tests_powershell(filter_option)
    elif choice == 2:
        # Browse by Tactic (using index data)
        browse_by_tactic()
    elif choice == 3:
        # Browse by Platform (using index data)
        browse_by_platform()
    elif choice == 4:
        # Show All Tests (using Invoke-AtomicTest)
        # Corrected indentation
        if Confirm.ask("Showing all tests via PowerShell can take time. Continue?", default=True):
            # Corrected indentation
            show_filtered_tests_powershell(None) # None filter means show all
        else:
            # Corrected indentation
            list_tests_menu() # Go back
    elif choice == 5:
        return # Back to main menu
    else:
        console.print("[bold red]Invalid choice.[/bold red]")
        pause()
        list_tests_menu()


def browse_by_tactic() -> None:
    """Display tactics and allow filtering techniques by tactic and platform."""
    print_header("Browse Tests by Tactic")
    all_tactics = get_all_tactics()

    if not all_tactics:
        console.print("[bold red]No tactics found in index data.[/bold red]")
        pause()
        return

    table = Table(title="MITRE ATT&CK Tactics")
    table.add_column("#", style="cyan", width=3)
    table.add_column("Tactic Name", style="green")

    # Map normalized tactic IDs back to friendly names if possible
    tactic_display_map = {t_id: TACTICS.get(t_id, t_id.replace('-', ' ').title()) for t_id in all_tactics}
    
    # Sort by display name
    sorted_display_tactics = sorted(tactic_display_map.items(), key=lambda item: item[1])

    # Use _tactic_id as it's not used in the loop body
    for i, (_tactic_id, tactic_name) in enumerate(sorted_display_tactics, 1):
        table.add_row(str(i), tactic_name)

    console.print(table)
    console.print("\n")

    tactic_choice_num = IntPrompt.ask(
        "Select a tactic number to view related techniques (0 to go back)",
        default=0
    )

    if 0 < tactic_choice_num <= len(sorted_display_tactics):
        selected_tactic_id, selected_tactic_name = sorted_display_tactics[tactic_choice_num - 1]

        # Ask for platform
        platform_options = ["All"] + AVAILABLE_PLATFORMS
        console.print("\n[bold]Filter by platform:[/bold]")
        for i, plat in enumerate(platform_options, 1):
            console.print(f"[bold cyan]{i}.[/bold cyan] {plat.title()}")
        
        platform_choice_num = IntPrompt.ask("Select platform", default=1)

        selected_platform = None
        if 0 < platform_choice_num <= len(platform_options):
            # Corrected indentation
            selected_platform_name = platform_options[platform_choice_num - 1]
            # Corrected indentation
            if selected_platform_name != "All":
                # Corrected indentation
                selected_platform = selected_platform_name.lower() # Use lowercase platform ID

        show_techniques_for_tactic(selected_tactic_id, selected_tactic_name, selected_platform)
    else:
        list_tests_menu() # Go back


def browse_by_platform() -> None:
    """Display platforms and allow filtering techniques by platform and tactic."""
    print_header("Browse Tests by Platform")

    if not AVAILABLE_PLATFORMS:
        console.print("[bold red]No platforms found in index data.[/bold red]")
        pause()
        return

    table = Table(title="Available Platforms")
    table.add_column("#", style="cyan", width=3)
    table.add_column("Platform Name", style="green")

    for i, platform_name in enumerate(AVAILABLE_PLATFORMS, 1):
        table.add_row(str(i), platform_name.title()) # Display title case

    console.print(table)
    console.print("\n")

    platform_choice_num = IntPrompt.ask(
        "Select a platform number to view its tactics (0 to go back)",
        default=0
    )

    if 0 < platform_choice_num <= len(AVAILABLE_PLATFORMS):
        selected_platform = AVAILABLE_PLATFORMS[platform_choice_num - 1]
        show_tactics_for_platform(selected_platform)
    else:
        list_tests_menu() # Go back


def show_tactics_for_platform(platform: str) -> None:
    """Show tactics available for a specific platform."""
    print_header(f"Tactics for Platform: {platform.title()}")
    
    tactics = get_tactics_for_platform(platform)

    if not tactics:
        console.print(f"[yellow]No tactics found for platform '{platform}'.[/yellow]")
        pause()
        browse_by_platform() # Go back to platform selection
        return

    table = Table(title=f"Tactics on {platform.title()}")
    table.add_column("#", style="cyan", width=3)
    table.add_column("Tactic Name", style="green")

    # Map normalized tactic IDs back to friendly names if possible
    tactic_display_map = {t_id: TACTICS.get(t_id, t_id.replace('-', ' ').title()) for t_id in tactics}
    sorted_display_tactics = sorted(tactic_display_map.items(), key=lambda item: item[1])

    # Use _tactic_id as it's not used in the loop body
    for i, (_tactic_id, tactic_name) in enumerate(sorted_display_tactics, 1):
        table.add_row(str(i), tactic_name)

    console.print(table)
    console.print("\n")

    tactic_choice_num = IntPrompt.ask(
        "Select a tactic number to view its techniques (0 to go back)",
        default=0
    )

    if 0 < tactic_choice_num <= len(sorted_display_tactics):
        selected_tactic_id, selected_tactic_name = sorted_display_tactics[tactic_choice_num - 1]
        show_techniques_for_platform_tactic(platform, selected_tactic_id, selected_tactic_name)
    else:
        browse_by_platform() # Go back to platform selection


def show_techniques_for_platform_tactic(platform: str, tactic_id: str, tactic_name: str) -> None:
    """Show techniques for a specific platform and tactic using index data with enhanced details."""
    title = f"Techniques for Tactic '{tactic_name}' on Platform '{platform.title()}'"
    print_header(title)

    techniques = get_techniques(platform=platform, tactic=tactic_id)

    if not techniques:
        console.print("[yellow]No techniques found for this platform/tactic combination.[/yellow]")
        pause()
        show_tactics_for_platform(platform) # Go back to tactic selection for this platform
        return

    table = Table(title=title)
    table.add_column("#", style="cyan", width=3)
    table.add_column("Technique ID", style="cyan")
    table.add_column("Name")
    table.add_column("Platforms", style="green")
    table.add_column("Tactics", style="yellow")

    # Sort by technique ID
    sorted_techniques = sorted(techniques.items())

    for i, (tech_id, tech_info) in enumerate(sorted_techniques, 1):
        # Format platforms list
        platforms_list = list(tech_info.get('platforms', set()))
        platforms_str = ", ".join([p.title() for p in sorted(platforms_list)]) if platforms_list else "N/A"
        
        # Format tactics list
        phases_list = list(tech_info.get('phases', set()))
        phases_str = ", ".join([TACTICS.get(p, p.title()) for p in sorted(phases_list)]) if phases_list else "N/A"
        
        table.add_row(str(i), tech_id, tech_info.get('name', 'Unknown'), platforms_str, phases_str)

    console.print(table)
    console.print(f"\n[bold]Found {len(sorted_techniques)} techniques with atomic tests.[/bold]")

    handle_technique_details_prompt(
        go_back_func=lambda: show_tactics_for_platform(platform), # Go back to tactic list for this platform
        techniques=techniques
    )


def show_techniques_for_tactic(tactic_id: str, tactic_name: str, platform: Optional[str] = None) -> None:
    """Show techniques for a specific tactic, optionally filtered by platform, using index data."""
    platform_filter_desc = f"on Platform '{platform.title()}'" if platform else "across All Platforms"
    title = f"Techniques for Tactic '{tactic_name}' {platform_filter_desc}"
    print_header(title)

    techniques = get_techniques(platform=platform, tactic=tactic_id)

    if not techniques:
        console.print(f"[yellow]No techniques found for this tactic {platform_filter_desc}.[/yellow]")
        pause()
        browse_by_tactic() # Go back to tactic selection
        return

    table = Table(title=title)
    table.add_column("#", style="cyan", width=3)
    table.add_column("Technique ID", style="cyan")
    table.add_column("Name")
    table.add_column("Platforms", style="green")
    table.add_column("Tactics", style="yellow")

    # Sort by technique ID
    sorted_techniques = sorted(techniques.items())
    
    for i, (tech_id, tech_info) in enumerate(sorted_techniques, 1):
        # Format platforms list
        platforms_list = list(tech_info.get('platforms', set()))
        platforms_str = ", ".join([p.title() for p in sorted(platforms_list)]) if platforms_list else "N/A"
        
        # Format tactics list
        phases_list = list(tech_info.get('phases', set()))
        phases_str = ", ".join([TACTICS.get(p, p.title()) for p in sorted(phases_list)]) if phases_list else "N/A"
        
        table.add_row(str(i), tech_id, tech_info.get('name', 'Unknown'), platforms_str, phases_str)

    console.print(table)
    console.print(f"\n[bold]Found {len(sorted_techniques)} techniques with atomic tests.[/bold]")

    handle_technique_details_prompt(
        go_back_func=browse_by_tactic, # Go back to tactic selection
        techniques=techniques
    )


def handle_technique_details_prompt(go_back_func: Callable[[], None], techniques: Dict[str, Dict[str, Any]] = None) -> None:
    """
    Prompts user to enter a technique ID or index number for details or go back.
    
    Args:
        go_back_func: Function to call when going back to previous menu
        techniques: Dictionary of techniques with keys as technique IDs, values as technique info
    """
    # Create a mapping of index numbers to technique IDs if techniques are provided
    technique_mapping = {}
    if techniques:
        # Get the sorted list of technique IDs that was displayed to the user
        sorted_tech_ids = sorted(techniques.keys())
        # Create a mapping from index (1-based) to technique ID
        technique_mapping = {str(i): tech_id for i, tech_id in enumerate(sorted_tech_ids, 1)}
        
        prompt_text = "\nEnter a technique number (1-{}) or ID to view details (using PowerShell), or press Enter to go back".format(len(sorted_tech_ids))
    else:
        prompt_text = "\nEnter a technique ID to view details (using PowerShell), or press Enter to go back"
    
    user_input = Prompt.ask(prompt_text, default="").strip()
    
    if not user_input:
        go_back_func()  # Go back if input is empty
        return
    
    # Check if the input is a number and maps to a technique
    technique_id = None
    if user_input in technique_mapping:
        technique_id = technique_mapping[user_input]
        console.print(f"[italic]Selected technique {technique_id} at index {user_input}[/italic]")
    else:
        # Assume it's a technique ID and validate format
        if re.match(r"^T\d{4}(\.\d{3})?$", user_input, re.IGNORECASE):
            technique_id = user_input
        else:
            console.print("[bold red]Invalid Technique ID format or index number.[/bold red] Example: T1003 or T1053.005")
            pause()
            go_back_func()  # Go back
            return
    
    print_header(f"Details for Technique: {technique_id}")
    console.print("[italic]Fetching details using PowerShell...[/italic]")
    # Use the PowerShell command for details
    success, details = get_test_details(technique_id, show_details=True)  # Show full details
    if success:
        console.print(details)
    else:
        console.print(f"[bold red]Error fetching details:[/bold red] {details}")
    pause()
    go_back_func()  # Go back to the previous technique list view


# Remove the old get_techniques_by_tactic function that parsed individual files
# def get_techniques_by_tactic(tactic_id: str) -> List[str]: ...


def show_filtered_tests_powershell(filter_str: Optional[str] = None) -> None:
    """Show filtered test results based on a search string using PowerShell."""
    # Determine detail level
    detail_level = Prompt.ask(
        "Display: [B]rief details or [F]ull details",
        choices=["B", "F"],
        default="B"
    )
    show_details = detail_level.upper() == "F"

    # Ask about platform filtering
    platform_option = Prompt.ask(
        "Show tests for: [C]urrent platform only or [A]ll platforms",
        choices=["C", "A"],
        default="C"
    )
    any_os = platform_option.upper() == "A"

    console.print("\n[bold yellow]Fetching available tests via PowerShell...[/bold yellow]")

    # Build the PowerShell command using the executor's build_command
    # We need the command list, not the direct execution result from list_available_tests
    command_list = build_command(
        technique_id=filter_str if filter_str else "All",
        show_details=show_details,
        show_details_brief=not show_details,
        any_os=any_os,
        # Flags not relevant for listing details:
        test_numbers=None,
        check_prereqs=False,
        get_prereqs=False,
        cleanup=False,
        session=None,
    )

    # Execute the command
    success, result = execute_ps_command(command_list)

    if success:
        console.print(result)
    else:
        console.print(f"[bold red]Error executing PowerShell command:[/bold red]\n{result}")

    pause()
    list_tests_menu() # Go back to list tests menu


def run_test_menu() -> None:
    """Display the run test menu and execute the selected test."""
    print_header("Run Atomic Red Team Test")
    
    # Show available techniques to select from
    console.print("[bold]Select a technique to run:[/bold]")
    console.print("1. Enter technique ID directly")
    console.print("2. Browse available techniques")
    console.print("3. Custom tests")
    
    choice = IntPrompt.ask("Enter your choice", default=1)
    
    technique_id = None
    if choice == 1:
        # Get technique ID directly
        technique_id = Prompt.ask(
            "Enter the MITRE ATT&CK Technique ID (e.g., T1003)",
            default="T1003"
        )
    elif choice == 2:
        # Browse available techniques
        browse_choice = IntPrompt.ask(
            "\nBrowse by:\n1. Tactic\n2. Platform\nEnter your choice",
            default=1
        )
        
        if browse_choice == 1:
            # Browse by tactic to select technique
            all_tactics = get_all_tactics()
            if not all_tactics:
                console.print("[bold red]No tactics found in index data.[/bold red]")
                pause()
                return
            
            table = Table(title="MITRE ATT&CK Tactics")
            table.add_column("#", style="cyan", width=3)
            table.add_column("Tactic Name", style="green")
            
            # Map normalized tactic IDs back to friendly names if possible
            tactic_display_map = {t_id: TACTICS.get(t_id, t_id.replace('-', ' ').title()) for t_id in all_tactics}
            sorted_display_tactics = sorted(tactic_display_map.items(), key=lambda item: item[1])
            
            for i, (_tactic_id, tactic_name) in enumerate(sorted_display_tactics, 1):
                table.add_row(str(i), tactic_name)
            
            console.print(table)
            console.print("\n")
            
            tactic_choice = IntPrompt.ask(
                "Select a tactic number (0 to go back)",
                default=0
            )
            
            if 0 < tactic_choice <= len(sorted_display_tactics):
                selected_tactic_id, selected_tactic_name = sorted_display_tactics[tactic_choice - 1]
                
                # Get all techniques for this tactic
                techniques = get_techniques(tactic=selected_tactic_id)
                
                if not techniques:
                    console.print(f"[yellow]No techniques found for tactic '{selected_tactic_name}'.[/yellow]")
                    pause()
                    return
                
                print_header(f"Techniques for '{selected_tactic_name}'")
                technique_table = Table(title=f"Available Techniques for {selected_tactic_name}")
                technique_table.add_column("#", style="cyan", width=3)
                technique_table.add_column("Technique ID", style="cyan")
                technique_table.add_column("Name")
                
                # Sort techniques by ID and display
                sorted_tech_items = sorted(techniques.items())
                for i, (tech_id, tech_info) in enumerate(sorted_tech_items, 1):
                    technique_table.add_row(str(i), tech_id, tech_info.get('name', 'Unknown'))
                
                console.print(technique_table)
                
                tech_choice = IntPrompt.ask(
                    "\nSelect a technique number (0 to go back)",
                    default=0
                )
                
                if 0 < tech_choice <= len(sorted_tech_items):
                    technique_id = sorted_tech_items[tech_choice - 1][0]
                    console.print(f"[italic]Selected technique: {technique_id}[/italic]")
                else:
                    return  # Go back
            else:
                return  # Go back
            
        elif browse_choice == 2:
            # Browse by platform
            if not AVAILABLE_PLATFORMS:
                console.print("[bold red]No platforms found in index data.[/bold red]")
                pause()
                return
                
            table = Table(title="Available Platforms")
            table.add_column("#", style="cyan", width=3)
            table.add_column("Platform Name", style="green")
            
            for i, platform_name in enumerate(AVAILABLE_PLATFORMS, 1):
                table.add_row(str(i), platform_name.title())
            
            console.print(table)
            console.print("\n")
            
            platform_choice = IntPrompt.ask(
                "Select a platform number (0 to go back)",
                default=0
            )
            
            if 0 < platform_choice <= len(AVAILABLE_PLATFORMS):
                selected_platform = AVAILABLE_PLATFORMS[platform_choice - 1]
                
                # Get tactics for this platform
                tactics = get_tactics_for_platform(selected_platform)
                
                if not tactics:
                    console.print(f"[yellow]No tactics found for platform '{selected_platform}'.[/yellow]")
                    pause()
                    return
                
                print_header(f"Tactics for Platform: {selected_platform.title()}")
                tactic_table = Table(title=f"Tactics on {selected_platform.title()}")
                tactic_table.add_column("#", style="cyan", width=3)
                tactic_table.add_column("Tactic Name", style="green")
                
                # Map normalized tactic IDs back to friendly names
                tactic_display_map = {t_id: TACTICS.get(t_id, t_id.replace('-', ' ').title()) for t_id in tactics}
                sorted_display_tactics = sorted(tactic_display_map.items(), key=lambda item: item[1])
                
                for i, (_tactic_id, tactic_name) in enumerate(sorted_display_tactics, 1):
                    tactic_table.add_row(str(i), tactic_name)
                
                console.print(tactic_table)
                console.print("\n")
                
                tactic_choice = IntPrompt.ask(
                    "Select a tactic number (0 to go back)",
                    default=0
                )
                
                if 0 < tactic_choice <= len(sorted_display_tactics):
                    selected_tactic_id, selected_tactic_name = sorted_display_tactics[tactic_choice - 1]
                    
                    # Get techniques for this platform and tactic
                    techniques = get_techniques(platform=selected_platform, tactic=selected_tactic_id)
                    
                    if not techniques:
                        console.print(f"[yellow]No techniques found for tactic '{selected_tactic_name}' on platform '{selected_platform}'.[/yellow]")
                        pause()
                        return
                    
                    print_header(f"Techniques for '{selected_tactic_name}' on '{selected_platform.title()}'")
                    technique_table = Table(title=f"Available Techniques")
                    technique_table.add_column("#", style="cyan", width=3)
                    technique_table.add_column("Technique ID", style="cyan")
                    technique_table.add_column("Name")
                    
                    # Sort techniques by ID and display
                    sorted_tech_items = sorted(techniques.items())
                    for i, (tech_id, tech_info) in enumerate(sorted_tech_items, 1):
                        technique_table.add_row(str(i), tech_id, tech_info.get('name', 'Unknown'))
                    
                    console.print(technique_table)
                    
                    tech_choice = IntPrompt.ask(
                        "\nSelect a technique number (0 to go back)",
                        default=0
                    )
                    
                    if 0 < tech_choice <= len(sorted_tech_items):
                        technique_id = sorted_tech_items[tech_choice - 1][0]
                        console.print(f"[italic]Selected technique: {technique_id}[/italic]")
                    else:
                        return  # Go back
                else:
                    return  # Go back
            else:
                return  # Go back
        else:
            console.print("[bold red]Invalid choice.[/bold red]")
            pause()
            return
    elif choice == 3:
        # Custom tests menu
        custom_test_menu()
        return
    else:
        console.print("[bold red]Invalid choice.[/bold red]")
        pause()
        return
    
    # If we get here, we should have a technique_id
    if not technique_id:
        console.print("[bold red]No technique selected.[/bold red]")
        pause()
        return
        
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
    interactive_mode = Confirm.ask(
        "\nAllow interactive GUI applications to display?",
        default=True
    )
    
    # Confirm execution
    technique_str = f"{technique_id}" + (f" (Tests: {test_numbers_str})" if test_numbers_str else "")
    operation_str = options[operation-1]
    
    console.print(f"\n[bold]About to perform:[/bold] {operation_str} for {technique_str}")
    if interactive_mode:
        console.print("[bold]Interactive mode:[/bold] Enabled (GUI applications will display)")
    else:
        console.print("[bold]Interactive mode:[/bold] Disabled (output will be captured)")
    
    if not Confirm.ask("Continue?", default=True):
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
        show_details_brief=True, # Keep brief details for execution context
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
    table.add_column("#", style="cyan", width=3)
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    
    # Add rows to the table - ensure playbooks is a list and each item is a dictionary
    if playbooks and isinstance(playbooks, list):
        for i, playbook in enumerate(playbooks, 1):
            if isinstance(playbook, dict):
                name = playbook.get("name", "Unknown")
                description = playbook.get("description", "")
                table.add_row(str(i), name, description)
            else:
                # Handle non-dictionary items safely
                table.add_row(str(i), str(playbook) if playbook else "Unknown", "")
    
    # Display the table
    console.print(table)
    
    # Option to view playbook details
    console.print("\n")
    
    if not playbooks:
        console.print("[yellow]No playbooks found.[/yellow]")
        pause()
        return
        
    user_input = Prompt.ask(
        "Enter a playbook number or name to view details, or press Enter to return to the main menu",
        default=""
    ).strip()
    
    if user_input:
        playbook_name = None
        
        # Check if input is a number and within valid range
        try:
            index = int(user_input)
            if playbooks and 1 <= index <= len(playbooks):
                # Make sure we safely access the playbook name
                if isinstance(playbooks[index-1], dict):
                    playbook_name = playbooks[index-1].get("name")
                    if playbook_name:
                        console.print(f"[italic]Selected playbook: {playbook_name}[/italic]")
                    else:
                        console.print("[bold red]Error:[/bold red] Could not get playbook name.")
                        pause()
                        return
                else:
                    playbook_name = str(playbooks[index-1])
                    console.print(f"[italic]Selected playbook: {playbook_name}[/italic]")
            else:
                console.print(f"[bold red]Invalid number. Please enter a number between 1 and {len(playbooks)}.[/bold red]")
                pause()
                return
        except ValueError:
            # Not a number, treat as playbook name
            playbook_name = user_input
        except Exception as e:
            console.print(f"[bold red]Error selecting playbook:[/bold red] {str(e)}")
            pause()
            return
        
        if playbook_name:
            playbook = get_playbook(playbook_name)
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
                console.print(f"[bold red]Playbook '{playbook_name}' not found.[/bold red]")
            
            pause() # Pause after showing details or not found message
    
    # No automatic pause if user just pressed Enter


def run_playbook_menu() -> None:
    """Display the run playbook menu and execute the selected playbook."""
    print_header("Run Playbook")
    
    # List available playbooks
    playbooks = get_available_playbooks()
    if not playbooks:
        console.print("[yellow]No playbooks found.[/yellow]")
        pause()
        return
    
    # Create a table to display the results
    table = Table(title="Available Playbooks")
    table.add_column("#", style="cyan", width=3)
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
    user_input = Prompt.ask(
        "\nEnter the number or name of the playbook to run (or press Enter to go back)",
        default=""
    ).strip()
    
    if not user_input:
        return  # Go back to main menu
    
    playbook_name = None
    # Check if input is a number and within valid range
    try:
        index = int(user_input)
        if 1 <= index <= len(playbooks):
            playbook_name = playbooks[index-1]["name"]
            console.print(f"[italic]Selected playbook: {playbook_name}[/italic]")
        else:
            console.print(f"[bold red]Invalid number. Please enter a number between 1 and {len(playbooks)}.[/bold red]")
            pause()
            run_playbook_menu()  # Restart menu
            return
    except ValueError:
        # Not a number, treat as playbook name
        playbook_name = user_input
    
    if not playbook_name:
        return  # Should not happen, but just in case
    
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
    
    if not Confirm.ask("Continue?", default=True):
        console.print("[yellow]Operation cancelled.[/yellow]")
        pause()
        run_playbook_menu()  # Go back to playbook selection
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
    if results:
        console.print("\n[bold]Test Summary:[/bold]")
        for i, result in enumerate(results, 1):
            status = "[green]✓ Success[/green]" if result.get("success", False) else "[red]✗ Failed[/red]"
            tech_id = result.get('technique_id', 'Unknown')
            test_num = result.get('test_number', '')
            test_id_str = f"{tech_id}{f' #{test_num}' if test_num else ''}"
            console.print(f"{i}. {test_id_str:<15} - {status}")
    else:
        console.print("[yellow]No detailed results available for this operation.[/yellow]")
    
    pause()


def configuration_menu() -> None:
    """Display the configuration menu."""
    # Declare globals at the top of the function scope
    global INDEX_DATA_CACHE, AVAILABLE_PLATFORMS

    while True:
        print_header("Configuration")
        
        config = get_config()
        
        # Display current configuration
        atomics_display = markup.escape(config.atomics_path) if config.atomics_path else "[italic yellow]Not set[/italic]"
        powershell_display = markup.escape(config.powershell_path) if config.powershell_path else "[italic yellow]Not set (using default)[/italic]"
        # Timeout is an int, no need to escape
        phishing_site_display = markup.escape(config.phishing_site_path) if config.phishing_site_path else "[italic yellow]Not set[/italic]"
        phishing_module_display = markup.escape(config.phishing_module_path) if config.phishing_module_path else "[italic yellow]Not set[/italic]"

        console.print("[bold]Current Configuration:[/bold]")
        console.print(f"1. Atomics Path:    {atomics_display}")
        console.print(f"2. PowerShell Path: {powershell_display}")
        console.print(f"3. Command Timeout: {config.timeout} seconds")
        console.print(f"4. Phishing Site Path:  {phishing_site_display}")
        console.print(f"5. Phishing Module Path: {phishing_module_display}")

        # Determine the base for option numbering
        # Number of displayed config items + 1 for the first actual option
        # Current config items: Atomics Path, PowerShell Path, Timeout, Phishing Site Path, Phishing Module Path (5 items)
        # So, options start at 5 + 1 = 6
        options_start_num = 6

        
        # Configuration options
        options = [
            "Set Atomics Path",
            "Set PowerShell Path",
            "Set Command Timeout",
            "Set Phishing Site Path",
            "Set Phishing Module Path", # New
            "Return to Main Menu"
        ]
        
        console.print("\n[bold]Options:[/bold]")
        for i, option in enumerate(options, 1):
            console.print(f"[bold cyan]{options_start_num + i -1}.[/bold cyan] {option}")
        
        choice = IntPrompt.ask("\nEnter number to modify or return", default=options_start_num + len(options) - 1) # Default to return
        
        if choice == 1: # Corresponds to Atomics Path display line
            # Corrected indentation
            path = Prompt.ask(
                 "Enter the path to the atomic-red-team/atomics directory",
                 default=config.atomics_path or ""
            ).strip()
            # Basic validation: check if path exists and is a directory
            # Corrected indentation
            if path and Path(path).is_dir():
                # Corrected indentation
                set_config("atomics_path", path)
                # Corrected indentation
                console.print(f"[bold green]Atomics path set to:[/bold green] {path}")
                # Clear cache as index path might change
                # Corrected indentation
                # global INDEX_DATA_CACHE, AVAILABLE_PLATFORMS # Removed from here
                # Corrected indentation
                INDEX_DATA_CACHE = {}
                # Corrected indentation
                AVAILABLE_PLATFORMS = []
            # Corrected indentation
            elif path:
                # Corrected indentation
                console.print(f"[bold red]Error:[/bold red] Path '{path}' does not exist or is not a directory.")
            # Corrected indentation
            else:
                # Corrected indentation
                console.print("[yellow]Atomics path not changed.[/yellow]")
            # Corrected indentation
            pause()

        elif choice == 2: # Corresponds to PowerShell Path display line
            path = Prompt.ask(
                "Enter the path to the PowerShell executable (e.g., 'powershell' or '/usr/bin/pwsh')",
                default=config.powershell_path or "powershell"
            ).strip()
            # No easy validation here, just set it
            if path:
                set_config("powershell_path", path)
                console.print(f"[bold green]PowerShell path set to:[/bold green] {path}")
            else:
                # Corrected indentation
                console.print("[yellow]PowerShell path not changed.[/yellow]")
            pause()
        
        elif choice == 3: # Corresponds to Timeout display line
            timeout = IntPrompt.ask(
                "Enter the command timeout in seconds (e.g., 300)",
                default=config.timeout,
                show_default=True
            )
            if timeout > 0:
                set_config("timeout", timeout)
                console.print(f"[bold green]Command timeout set to:[/bold green] {timeout} seconds")
            else:
                # Corrected indentation
                console.print("[yellow]Timeout must be a positive number. Not changed.[/yellow]")
            pause()
        
        elif choice == options_start_num: # 6. Set Atomics Path option
            # Corrected indentation
            path = Prompt.ask(
                 "Enter the path to the atomic-red-team/atomics directory",
                 default=config.atomics_path or ""
            ).strip()
            # Corrected indentation
            if path and Path(path).is_dir():
                # Corrected indentation
                set_config("atomics_path", path)
                # Corrected indentation
                console.print(f"[bold green]Atomics path set to:[/bold green] {path}")
                # Corrected indentation - Need global here too
                # global INDEX_DATA_CACHE, AVAILABLE_PLATFORMS # Removed from here
                INDEX_DATA_CACHE = {} # Clear cache
                # Corrected indentation
                AVAILABLE_PLATFORMS = []
            # Corrected indentation
            elif path:
                # Corrected indentation
                console.print(f"[bold red]Error:[/bold red] Path '{path}' does not exist or is not a directory.")
            # Corrected indentation
            else:
                # Corrected indentation
                console.print("[yellow]Atomics path not changed.[/yellow]")
            # Corrected indentation
            pause()

        elif choice == options_start_num + 1: # 7. Set PowerShell Path option
            path = Prompt.ask(
                "Enter the path to the PowerShell executable (e.g., 'powershell' or '/usr/bin/pwsh')",
                default=config.powershell_path or "powershell"
            ).strip()
            if path:
                set_config("powershell_path", path)
                console.print(f"[bold green]PowerShell path set to:[/bold green] {path}")
            else:
                # Corrected indentation
                console.print("[yellow]PowerShell path not changed.[/yellow]")
            pause()

        elif choice == options_start_num + 2: # 8. Set Command Timeout option
            timeout = IntPrompt.ask(
                "Enter the command timeout in seconds (e.g., 300)",
                default=config.timeout,
                show_default=True
            )
            if timeout > 0:
                set_config("timeout", timeout)
                console.print(f"[bold green]Command timeout set to:[/bold green] {timeout} seconds")
            else:
                # Corrected indentation
                console.print("[yellow]Timeout must be a positive number. Not changed.[/yellow]")
            pause()

        elif choice == options_start_num + 3: # 9. Set Phishing Site Path option
            path_str = Prompt.ask(
                "Enter the path to your 'phishing_site' directory",
                default=config.phishing_site_path or ""
            ).strip()
            if path_str:
                phishing_path = Path(path_str)
                if phishing_path.is_dir() and (phishing_path / "api" / "index.js").exists():
                    set_config("phishing_site_path", str(phishing_path.resolve()))
                    console.print(f"[bold green]Phishing site path set to:[/bold green] {phishing_path.resolve()}")
                else:
                    console.print(f"[bold red]Error:[/bold red] Path '{phishing_path}' does not seem to be a valid phishing_site directory (missing api/index.js).")
            pause()
        elif choice == options_start_num + 4: # 10. Set Phishing Module Path option
            path_str = Prompt.ask(
                "Enter the path to your 'phishing-module' directory (containing send_email.py)",
                default=config.phishing_module_path or ""
            ).strip()
            if path_str:
                module_path = Path(path_str)
                if module_path.is_dir() and (module_path / "send_email.py").exists():
                    set_config("phishing_module_path", str(module_path.resolve()))
                    console.print(f"[bold green]Phishing module path set to:[/bold green] {module_path.resolve()}")
                else:
                    console.print(f"[bold red]Error:[/bold red] Path '{module_path}' does not seem to be a valid phishing-module directory (missing send_email.py).")
            pause()

        elif choice == options_start_num + 5: # 11. Return to Main Menu option
            break
        else:
            console.print("[red]Invalid choice.[/red]")
            pause()


# Removed build_list_tests_command as we now use executor.build_command directly


def execute_ps_command(command: List[str]) -> tuple[bool, str]:
    """
    Execute a PowerShell command and return the results.
    
    Args:
        command: The PowerShell command to execute as a list of strings.
        
    Returns:
        A tuple containing (success_flag, output_or_error_text).
    """
    import subprocess
    
    config = get_config()
    ps_path = config.powershell_path or "powershell" # Use default if not set
    
    # Ensure the command uses the configured path
    if command[0] != ps_path:
        command = [ps_path] + command[1:]

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=config.timeout,
            shell=False # Important for security and correct argument handling
        )
        return True, result.stdout
    except FileNotFoundError:
        # Corrected indentation
        return False, f"Error: PowerShell executable not found at '{ps_path}'. Please check configuration."
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed with exit code {e.returncode}.\n"
        error_msg += f"Command: {' '.join(command)}\n" # Show command that failed
        if e.stdout: # Include stdout for context
            # Corrected indentation
            error_msg += f"Stdout:\n{e.stdout}\n"
        if e.stderr:
            error_msg += f"Stderr:\n{e.stderr}"
        return False, error_msg
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {config.timeout} seconds.\nCommand: {' '.join(command)}"
    except OSError as e: # Catch OSError for broader system-level errors like permissions
        return False, f"An OS error occurred: {str(e)}\nCommand: {' '.join(command)}"
    # Removed broad Exception catch


def run_interactive_cli() -> None:
    """Run the interactive CLI menu system."""
    # Load index data once at the start
    ensure_index_data_loaded() # Changed to use ensure function
    
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
        elif choice == "Help":
            show_help()
        elif choice == "Configuration":
            configuration_menu()
        elif choice == "Exit":
            print_header("Exiting Purple Team CLI")
            console.print("Thank you for using Purple Team CLI!")
            sys.exit(0)
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")
            pause()


def show_help() -> None:
    """Display the help screen."""
    print_header("Help - Purple Team CLI")
    console.print("""
Welcome to the Purple Team CLI! This tool allows you to interact with Atomic Red Team tests and playbooks.

[bold cyan]Main Menu Options:[/bold cyan]
1. [bold]List Tests[/bold] - Browse and search for available Atomic Red Team tests.
2. [bold]Run Test[/bold] - Execute a specific Atomic Red Team test.
3. [bold]List Playbooks[/bold] - View available playbooks.
4. [bold]Run Playbook[/bold] - Execute a specific playbook.
5. [bold]Help[/bold] - Display this help screen.
6. [bold]Configuration[/bold] - Configure paths and settings for the CLI.
7. [bold]Exit[/bold] - Exit the CLI.

For more information, please refer to the documentation or visit the Atomic Red Team repository.

[italic]Press Enter to return to the main menu.[/italic]
""")
    pause()


def custom_test_menu() -> None:
    """Display menu of available custom tests."""
    print_header("Custom Tests")
    
    # Show available custom test options
    console.print("[bold]Available Custom Tests:[/bold]")
    console.print("1. Phishing Simulation")
    console.print("2. ClickFix Simulation")
    console.print("3. Back to Run Test Menu")
    
    choice = IntPrompt.ask("Enter your choice", default=1)
    
    if choice == 1:
        # Run phishing simulation
        phishing_simulation_menu()
    elif choice == 2:
        # Run ClickFix simulation
        clickfix_simulation_menu()
    elif choice == 3:
        # Go back
        return
    else:
        console.print("[bold red]Invalid choice.[/bold red]")
        pause()
        custom_test_menu()  # Show the menu again



def check_phishing_prerequisites(verbose: bool = True) -> bool:
    """Checks if all prerequisites for the phishing simulation are present."""
    all_present = True
    missing_prereqs: List[str] = []

    if verbose:
        console.print("\n[bold]Checking Phishing Simulation Prerequisites:[/bold]")

    # 1. Check for Node.js
    try:
        result = subprocess.run(["node", "--version"], capture_output=True, text=True, check=True, shell=False, timeout=10)
        if verbose:
            console.print(f"[green]✓ Node.js found:[/green] {result.stdout.strip()}")
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        if verbose:
            console.print("[bold red]✗ Node.js not found or 'node --version' failed.[/bold red] Node.js is required for the phishing website.")
        all_present = False
        missing_prereqs.append("Node.js")

    # 2. Check for required Python packages using pip list
    if verbose and REQUIRED_PYTHON_PACKAGES_PHISHING:
        console.print("[bold]Checking Python packages:[/bold]")
    
    try:
        # Get the list of installed packages using pip
        pip_result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, check=True, shell=False, timeout=30
        )
        
        # Parse the JSON output
        installed_packages = {}
        try:
            packages_data = json.loads(pip_result.stdout)
            for package in packages_data:
                installed_packages[package['name'].lower()] = package['version']
        except json.JSONDecodeError:
            if verbose:
                console.print("[yellow]Warning: Could not parse pip list output. Falling back to importlib.[/yellow]")
            # Fall back to importlib if pip list JSON parsing fails
            for package_name in REQUIRED_PYTHON_PACKAGES_PHISHING:
                spec = importlib.util.find_spec(package_name)
                if spec is None:
                    if verbose:
                        console.print(f"[bold red]✗ Python package '{package_name}' not found.[/bold red]")
                    all_present = False
                    missing_prereqs.append(f"Python package: {package_name}")
                elif verbose:
                    console.print(f"[green]✓ Python package '{package_name}' found.[/green]")
            
            # Skip the rest of the function since we already checked with importlib
            if verbose:
                if not all_present:
                    console.print("\n[bold yellow]Some prerequisites are missing.[/bold yellow]")
                else:
                    console.print("\n[bold green]All phishing prerequisites appear to be present.[/bold green]")
            return all_present
        
        # Check if required packages are installed
        for package_name in REQUIRED_PYTHON_PACKAGES_PHISHING:
            package_lower = package_name.lower().replace('-', '_')  # Convert to lowercase and handle potential dashes
            alternative_name = package_name.lower().replace('_', '-')  # Try the opposite naming convention
            
            if package_lower in installed_packages:
                if verbose:
                    console.print(f"[green]✓ Python package '{package_name}' found (version: {installed_packages[package_lower]}).[/green]")
            elif alternative_name in installed_packages:
                if verbose:
                    console.print(f"[green]✓ Python package '{package_name}' found as '{alternative_name}' (version: {installed_packages[alternative_name]}).[/green]")
            else:
                # Try a secondary check with importlib for packages that might be installed but named differently
                spec = importlib.util.find_spec(package_name)
                if spec is None:
                    if verbose:
                        console.print(f"[bold red]✗ Python package '{package_name}' not found.[/bold red]")
                    all_present = False
                    missing_prereqs.append(f"Python package: {package_name}")
                elif verbose:
                    console.print(f"[green]✓ Python package '{package_name}' found via importlib.[/green]")
    
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        if verbose:
            console.print(f"[yellow]Warning: Could not run pip list command: {str(e)}. Falling back to importlib.[/yellow]")
        
        # Fall back to importlib if pip list fails
        for package_name in REQUIRED_PYTHON_PACKAGES_PHISHING:
            spec = importlib.util.find_spec(package_name)
            if spec is None:
                if verbose:
                    console.print(f"[bold red]✗ Python package '{package_name}' not found.[/bold red]")
                all_present = False
                missing_prereqs.append(f"Python package: {package_name}")
            elif verbose:
                console.print(f"[green]✓ Python package '{package_name}' found via importlib.[/green]")
    
    if verbose:
        if not all_present:
            console.print("\n[bold yellow]Some prerequisites are missing.[/bold yellow]")
        else:
            console.print("\n[bold green]All phishing prerequisites appear to be present.[/bold green]")
        
    return all_present


def install_phishing_prerequisites() -> None:
    """Guides the user or attempts to install missing prerequisites for phishing simulation."""
    console.print("\n[bold]Addressing Missing Phishing Simulation Prerequisites...[/bold]")
    
    # 1. Guide for Node.js
    try:
        subprocess.run(["node", "--version"], capture_output=True, text=True, check=True, shell=False, timeout=10)
        console.print("[green]✓ Node.js seems to be installed.[/green]")
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        console.print("[bold yellow]Node.js is not installed or not found in PATH.[/bold yellow]")
        console.print("  Please install Node.js manually from [link=https://nodejs.org/]https://nodejs.org/[/link]")
        console.print("  After installation, ensure 'node' is available in your system's PATH and restart this CLI.")

    # 2. Attempt to install Python packages
    installed_any_python_package = False
    if REQUIRED_PYTHON_PACKAGES_PHISHING:
        console.print("\n[bold]Checking and installing Python packages via pip:[/bold]")

    for package_name in REQUIRED_PYTHON_PACKAGES_PHISHING:
        if importlib.util.find_spec(package_name) is None:
            console.print(f"\n[yellow]Python package '{package_name}' is missing.[/yellow]")
            if Confirm.ask(f"Attempt to install '{package_name}' using pip?", default=True):
                console.print(f"[italic]Installing {package_name}...[/italic]")
                try:
                    console.print(f"[dim]Using Python interpreter for pip: {sys.executable}[/dim]") # Debug line added
                    pip_command = [sys.executable, "-m", "pip", "install", package_name]
                    result = subprocess.run(pip_command, capture_output=True, text=True, check=True, timeout=120)
                    console.print(f"[green]✓ Successfully installed {package_name}.[/green]")
                    if result.stdout.strip():
                        console.print(f"[dim]Pip output:\n{result.stdout}[/dim]")
                    installed_any_python_package = True
                    importlib.invalidate_caches() # Invalidate import caches
                except subprocess.CalledProcessError as e:
                    console.print(f"[bold red]✗ Failed to install {package_name}.[/bold red]")
                    error_output = e.stderr or e.stdout
                    console.print(f"  Error: {error_output.strip() if error_output else 'No error output from pip.'}")
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    console.print("[bold red]✗ pip command failed or timed out. Ensure Python and pip are correctly installed and in PATH.[/bold red]")
                    break 
            else:
                console.print(f"[yellow]Skipped installation of {package_name}.[/yellow]")
        else:
            console.print(f"[green]✓ Python package '{package_name}' is already installed.[/green]")

    console.print("\n[bold]Prerequisite addressing process finished.[/bold]")
    pause()

def phishing_simulation_menu() -> None:
    """Display the phishing simulation menu and execute the selected operation."""
    print_header("Phishing Simulation")
    
    # Options for phishing simulation
    options = [
        "Execute Phishing Simulation",
        "Check Prerequisites Only",
        "Install Prerequisites",
        "Cleanup After Simulation",
        "Back to Custom Tests Menu"
    ]
    
    for i, option in enumerate(options, 1):
        console.print(f"[bold cyan]{i}.[/bold cyan] {option}")
    
    choice = IntPrompt.ask("\nEnter your choice", default=1)
    
    if choice == 1:
        # Execute the simulation
        run_phishing_simulation() # Actually run it
        phishing_simulation_menu() # Then return to menu
    elif choice == 2:
        # Check prerequisites
        check_phishing_prerequisites(verbose=True)
        pause()
        phishing_simulation_menu()
    elif choice == 3:
        # Install prerequisites
        install_phishing_prerequisites()
        # install_phishing_prerequisites already has a pause
        phishing_simulation_menu()
    elif choice == 4:
        # Cleanup
        cleanup_phishing_simulation()
        phishing_simulation_menu()
    elif choice == 5:
        # Go back
        custom_test_menu()
        return
    else:
        console.print("[bold red]Invalid choice.[/bold red]")
        pause()
        phishing_simulation_menu()  # Show the menu again


def run_phishing_simulation() -> None:
    """Executes the phishing simulation."""
    global PHISHING_SERVER_PROCESS
    print_header("Executing Phishing Simulation")

    config = get_config()
    phishing_site_dir_str = config.phishing_site_path
    phishing_module_dir_str = config.phishing_module_path # New
    
    console.print("[italic]Checking prerequisites before starting simulation...[/italic]")
    if not check_phishing_prerequisites(verbose=False): # Keep this check less verbose initially
        console.print("[bold red]✗ Prerequisites for phishing simulation are not met.[/bold red]")
        if Confirm.ask("Do you want to view details and attempt to install/address them now?", default=True):
            # Show detailed check
            check_phishing_prerequisites(verbose=True) 
            install_phishing_prerequisites() # This function includes its own prompts and pause
            
            console.print("[italic]Re-checking prerequisites after installation attempt...[/italic]")
            if not check_phishing_prerequisites(verbose=True):
                console.print("[bold red]Prerequisites are still not met. Aborting simulation.[/bold red]")
                pause()
                return
            console.print("[bold green]Prerequisites now seem to be met. Proceeding with simulation...[/bold green]")
            # A short pause to acknowledge before continuing
            time.sleep(1)
        else:
            console.print("[yellow]Phishing simulation aborted due to missing prerequisites.[/yellow]")
            pause()
            return

    if not phishing_site_dir_str:
        console.print("[bold red]Phishing site path is not configured.[/bold red]")
        console.print("Please set it in the Configuration menu.")
        pause()
        return
    
    if not phishing_module_dir_str: # New check
        console.print("[bold red]Phishing module path is not configured.[/bold red]")
        console.print("Please set it in the Configuration menu (path to directory containing send_email.py).")
        pause()
        return

    phishing_site_dir = Path(phishing_site_dir_str)
    api_dir = phishing_site_dir / "api"
    log_dir = phishing_site_dir / "logs"
    credential_log_file = log_dir / "detailed_credentials.json"

    if not (api_dir.is_dir() and (api_dir / "index.js").exists()):
        console.print(f"[bold red]Invalid phishing_site_path: '{phishing_site_dir}'. 'api/index.js' not found.[/bold red]")
        pause()
        return

    phishing_module_dir = Path(phishing_module_dir_str) # New
    email_script_path = phishing_module_dir / "send_email.py" # New
    if not email_script_path.exists():
        console.print(f"[bold red]Email sending script not found at '{email_script_path}'. Check Phishing Module Path configuration.[/bold red]")
        pause()
        return

    # Ensure logs directory exists
    log_dir.mkdir(parents=True, exist_ok=True)

    # 1. Start the Node.js phishing server
    if PHISHING_SERVER_PROCESS and PHISHING_SERVER_PROCESS.poll() is None:
        console.print("[yellow]Phishing server already seems to be running.[/yellow]")
    else:
        console.print(f"[italic]Starting phishing website server from {api_dir}...[/italic]")
        try:
            # For Windows, shell=True might be needed if 'node' is a .cmd or .bat file,
            # but it's generally safer to ensure 'node' is directly executable.
            # shell=False is preferred.
            PHISHING_SERVER_PROCESS = subprocess.Popen(
                ["node", "index.js"],
                cwd=api_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=sys.platform == "win32" # Use shell=True on Windows if node is a script/batch file
            )
            console.print("[green]✓ Phishing server started in background (PID: {PHISHING_SERVER_PROCESS.pid}).[/green]")
            console.print("  URL: [link=http://localhost:3000/microsoft_login.html]http://localhost:3000/microsoft_login.html[/link]")
            console.print("  KEA URL: [link=http://localhost:3000/kea_microsoft_login.html]http://localhost:3000/kea_microsoft_login.html[/link]")
            time.sleep(3) # Give server a moment to start
            if PHISHING_SERVER_PROCESS.poll() is not None: # Check if it exited immediately
                stderr_output = PHISHING_SERVER_PROCESS.stderr.read() if PHISHING_SERVER_PROCESS.stderr else "No stderr."
                raise Exception(f"Server failed to start. Exit code: {PHISHING_SERVER_PROCESS.returncode}. Stderr: {stderr_output}")
        except Exception as e:
            console.print(f"[bold red]✗ Failed to start phishing server: {e}[/bold red]")
            PHISHING_SERVER_PROCESS = None
            pause()
            return

    # 2. Run the email sending script (placeholder)
    console.print("\n[italic]Executing email sending script...[/italic]")
    try:
        # The user's send_email.py handles its own config for recipients and template.
        # The phishing_url is displayed when the server starts; user must ensure their template uses it.
        # target_email = Prompt.ask("Enter target email address for the phishing test", default="victim@example.com") # Not used by user's script
        # phishing_url = "http://localhost:3000/microsoft_login.html" # Displayed when server starts
        
        console.print(f"  [dim]Your email script '{email_script_path.name}' will use its own configuration (recipients, template).[/dim]")
        console.print(f"  [dim]Ensure your email template points to the phishing URLs displayed above.[/dim]")
        email_script_command = [sys.executable, str(email_script_path)]
        email_result = subprocess.run(email_script_command, capture_output=True, text=True, check=True, timeout=120, cwd=phishing_module_dir) # Added cwd
        console.print(f"[green]✓ Email sending script executed.[/green]\n[dim]{email_result.stdout}[/dim]")
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]✗ Email sending script failed: {e.stderr or e.stdout}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]✗ Error running email sending script: {e}[/bold red]")

    # 3. Monitor for credentials
    last_known_creds_count = 0
    if credential_log_file.exists(): # Get initial count if file exists
        with open(credential_log_file, "r", encoding='utf-8') as f_init:
            content_init = f_init.read().strip()
            if content_init:
                try:
                    # With our backend changes, this should now be a valid JSON array
                    current_creds_objects_init = json.loads(content_init)
                    if isinstance(current_creds_objects_init, list):
                        last_known_creds_count = len(current_creds_objects_init)
                    else:
                        # Fallback for possibly not-yet-converted files
                        json_records = '[' + content_init.rstrip(',') + ']'
                        current_creds_objects_init = json.loads(json_records)
                        last_known_creds_count = len(current_creds_objects_init)
                    
                    console.print(f"[dim]Found {last_known_creds_count} existing credential entries[/dim]")
                except json.JSONDecodeError as e:
                    # Fallback to basic counting if JSON parsing fails
                    # Fix the Rich markup by ensuring all tags are balanced
                    console.print(f"[yellow dim]Warning: Couldn't parse credentials file as JSON: {str(e)}[/yellow dim]")
                    potential_creds_str_init = [s for s in content_init.split('},') if s.strip()]
                    last_known_creds_count = len(potential_creds_str_init)
                    console.print(f"[dim]Found approximately {last_known_creds_count} existing credential entries[/dim]")

    console.print(f"\n[cyan]Monitoring for credentials in '{credential_log_file}'... Press Ctrl+C to stop.[/cyan]")
    try:
        while True:
            if credential_log_file.exists():
                with open(credential_log_file, "r", encoding='utf-8') as f:
                    content = f.read().strip()
                
                if not content:
                    time.sleep(5)
                    continue

                try:
                    # Parse the content as a proper JSON array
                    current_creds_objects = json.loads(content)
                    
                    # Make sure it's a list
                    if not isinstance(current_creds_objects, list):
                        # Try the old format conversion as fallback
                        json_records = '[' + content.rstrip(',') + ']'
                        current_creds_objects = json.loads(json_records)
                    
                    if len(current_creds_objects) > last_known_creds_count:
                        new_creds_count = len(current_creds_objects) - last_known_creds_count
                        console.print(f"\n[bold green]🎉 {new_creds_count} new credential(s) captured![/bold green]")
                        
                        for cred_obj in current_creds_objects[last_known_creds_count:]:
                            email = cred_obj.get("credentials", {}).get("email", "N/A")
                            # For safety, avoid printing password directly in a real tool or log it carefully
                            # password = cred_obj.get("credentials", {}).get("password", "N/A") 
                            ip = cred_obj.get("userInfo", {}).get("ipAddress", "N/A")
                            ua = cred_obj.get("userInfo", {}).get("userAgent", "N/A")
                            timestamp = cred_obj.get("timestamp", "Unknown time")
                            console.print(f"  - [{timestamp}] Email: {email}, IP: {ip}, UserAgent: {ua}")
                        
                        last_known_creds_count = len(current_creds_objects)
                except json.JSONDecodeError as e:
                    # If JSON parsing fails, try the old method
                    # Fix Rich markup formatting
                    console.print(f"[yellow dim]Warning: JSON parsing error: {str(e)}[/yellow dim]")
                    potential_creds_str = [s for s in content.split('},') if s.strip()]
                    
                    if len(potential_creds_str) > last_known_creds_count:
                        new_creds_count = len(potential_creds_str) - last_known_creds_count
                        console.print(f"\n[bold green]🎉 {new_creds_count} new credential(s) captured! (fallback detection)[/bold green]")
                        last_known_creds_count = len(potential_creds_str)
            
            time.sleep(config.timeout / 60 if config.timeout > 60 else 5) # Check every 5 seconds, or more if timeout is long
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped monitoring credentials.[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Error during credential monitoring: {e}[/bold red]")

    console.print("\n[bold green]Phishing simulation completed.[/bold green]")
    pause()


def cleanup_phishing_simulation() -> None:
    """Cleans up after a phishing simulation."""
    global PHISHING_SERVER_PROCESS
    print_header("Cleanup Phishing Simulation")

    # 1. Stop the Node.js server
    if PHISHING_SERVER_PROCESS and PHISHING_SERVER_PROCESS.poll() is None:
        console.print(f"[italic]Stopping phishing server (PID: {PHISHING_SERVER_PROCESS.pid})...[/italic]")
        try:
            PHISHING_SERVER_PROCESS.terminate() # Send SIGTERM
            PHISHING_SERVER_PROCESS.wait(timeout=10) # Wait for graceful shutdown
            console.print("[green]✓ Phishing server terminated.[/green]")
        except subprocess.TimeoutExpired:
            console.print("[yellow]Phishing server did not terminate gracefully, killing...[/yellow]")
            PHISHING_SERVER_PROCESS.kill() # Force kill
            PHISHING_SERVER_PROCESS.wait()
            console.print("[green]✓ Phishing server killed.[/green]")
        except Exception as e:
            console.print(f"[bold red]✗ Error stopping phishing server: {e}[/bold red]")
        PHISHING_SERVER_PROCESS = None
    else:
        console.print("[yellow]Phishing server is not running or process info unavailable.[/yellow]")

    # 2. Offer to clear log files
    config = get_config()
    if config.phishing_site_path:
        log_dir = Path(config.phishing_site_path) / "logs"
        if log_dir.is_dir():
            if Confirm.ask(f"\nDo you want to clear log files in '{log_dir}'?", default=False):
                try:
                    for item in log_dir.iterdir():
                        if item.is_file():
                            item.unlink()
                            console.print(f"  Deleted: {item.name}")
                    console.print("[green]✓ Log files cleared.[/green]")
                except Exception as e:
                    console.print(f"[bold red]✗ Error clearing log files: {e}[/bold red]")
        else:
            console.print(f"[yellow]Log directory '{log_dir}' not found, cannot clear logs.[/yellow]")
    else:
        console.print("[yellow]Phishing site path not configured, cannot clear logs.[/yellow]")
    
    console.print("\n[bold green]Phishing simulation cleanup process finished.[/bold green]")
    pause()


def clickfix_simulation_menu() -> None:
    """Display the ClickFix simulation menu and execute the simulation."""
    print_header("ClickFix Simulation")
    
    console.print("[bold]ClickFix Simulation Options:[/bold]")
    console.print("1. Run ClickFix Simulation")
    console.print("2. Back to Custom Tests Menu")
    
    choice = IntPrompt.ask("Enter your choice", default=1)
    
    if choice == 1:
        run_clickfix_simulation()
        clickfix_simulation_menu()
    elif choice == 2:
        return
    else:
        console.print("[bold red]Invalid choice.[/bold red]")
        pause()
        clickfix_simulation_menu()


def run_clickfix_simulation() -> None:
    """Executes the ClickFix simulation by running the start_clickfix_flow.py script."""
    print_header("Executing ClickFix Simulation")
    
    # Path to the ClickFix script
    clickfix_script_path = Path("../clickfix_site/start_clickfix_flow.py")
    
    if not clickfix_script_path.exists():
        console.print(f"[bold red]ClickFix script not found at: {clickfix_script_path}[/bold red]")
        console.print("Please ensure the ClickFix site is properly set up.")
        pause()
        return
    
    console.print("[italic]Starting ClickFix simulation...[/italic]")
    console.print("This will start the ClickFix website and send phishing emails.")
    
    if not Confirm.ask("Continue with ClickFix simulation?", default=True):
        console.print("[yellow]ClickFix simulation cancelled.[/yellow]")
        pause()
        return
    
    try:
        # Run the ClickFix script
        result = subprocess.run(
            [sys.executable, str(clickfix_script_path)],
            cwd=clickfix_script_path.parent,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            console.print("[bold green]✓ ClickFix simulation completed successfully![/bold green]")
            if result.stdout:
                console.print(f"\n[dim]Output:[/dim]\n{result.stdout}")
        else:
            console.print(f"[bold red]✗ ClickFix simulation failed with exit code {result.returncode}[/bold red]")
            if result.stderr:
                console.print(f"\n[dim]Error:[/dim]\n{result.stderr}")
                
    except subprocess.TimeoutExpired:
        console.print("[bold red]✗ ClickFix simulation timed out after 5 minutes[/bold red]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped monitoring credentials.[/yellow]")

    except Exception as e:
        console.print(f"[bold red]✗ Error running ClickFix simulation: {e}[/bold red]")
    
    console.print("\n[italic]Note: The ClickFix website should now be running at http://localhost:3001/clickfix[/italic]")
    console.print("[italic]Check the terminal output above for email sending results.[/italic]")
    pause()


if __name__ == "__main__":
    run_interactive_cli()