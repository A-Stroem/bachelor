import os
import sys
from typing import Dict, List, Optional, Callable, Tuple, Any, Set # Added Any, Set
import yaml
from pathlib import Path
import re 

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm 
from rich.panel import Panel
from rich.table import Table
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
    
    # Add rows to the table
    for i, playbook in enumerate(playbooks, 1):
        table.add_row(
            str(i),
            playbook["name"],
            playbook["description"]
        )
    
    # Display the table
    console.print(table)
    
    # Option to view playbook details
    console.print("\n")
    user_input = Prompt.ask(
        "Enter a playbook number or name to view details, or press Enter to return to the main menu",
        default=""
    ).strip()
    
    if user_input:
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
                return
        except ValueError:
            # Not a number, treat as playbook name
            playbook_name = user_input
        
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
        console.print("[bold]Current Configuration:[/bold]")
        console.print(f"1. Atomics Path:    {config.atomics_path or '[italic yellow]Not set[/italic]'}")
        console.print(f"2. PowerShell Path: {config.powershell_path or '[italic yellow]Not set (using default)[/italic]'}")
        console.print(f"3. Command Timeout: {config.timeout} seconds")
        
        # Configuration options
        options = [
            "Set Atomics Path",
            "Set PowerShell Path",
            "Set Command Timeout",
            "Return to Main Menu"
        ]
        
        console.print("\n[bold]Options:[/bold]")
        for i, option in enumerate(options, 1):
            console.print(f"[bold cyan]{i+3}.[/bold cyan] {option}") # Start numbering after current settings
        
        choice = IntPrompt.ask("\nEnter number to modify or return", default=len(options)+3) # Default to return
        
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
        
        elif choice == 4: # Set Atomics Path option
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

        elif choice == 5: # Set PowerShell Path option
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

        elif choice == 6: # Set Command Timeout option
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

        elif choice == 7: # Return to Main Menu option
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