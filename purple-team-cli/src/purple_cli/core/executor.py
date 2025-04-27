"""
Module for executing Atomic Red Team tests.

This module provides functionality to execute Atomic Red Team tests
using the Invoke-AtomicRedTeam PowerShell module.
"""

import subprocess
import sys
import re
from typing import List, Tuple, Optional, Dict, Any, Union
from pathlib import Path

from purple_cli.core.config import get_config


def validate_technique_id(technique_id: str) -> bool:
    """
    Validates that the technique ID follows the expected format (e.g., T1234 or T1234.001).

    Args:
        technique_id: The technique ID to validate.

    Returns:
        True if the technique ID is valid, False otherwise.
    """
    pattern = r"^T\d{4}(\.\d{3})?$"
    return bool(re.match(pattern, technique_id))


def build_command(
    technique_id: str,
    test_numbers: Optional[List[int]] = None,
    check_prereqs: bool = False,
    get_prereqs: bool = False,
    cleanup: bool = False,
    show_details: bool = False,
    show_details_brief: bool = False,
    session: Optional[str] = None,
    any_os: bool = False,
) -> List[str]:
    """
    Builds the PowerShell command to execute an Atomic Red Team test.

    Args:
        technique_id: The technique ID to run.
        test_numbers: Optional list of specific test numbers to run.
        check_prereqs: Whether to check prerequisites only.
        get_prereqs: Whether to install prerequisites.
        cleanup: Whether to run cleanup commands.
        show_details: Whether to show full details of the test.
        show_details_brief: Whether to show brief details of the test.
        session: Optional PowerShell session name to run the test on.
        any_os: Whether to include tests for all platforms.

    Returns:
        A list representing the PowerShell command to execute.
    """
    config = get_config()
    powershell_path = config.powershell_path

    # Base PowerShell command
    command = [powershell_path, "-Command"]

    # Build the Invoke-AtomicTest command
    invoke_cmd = f"Invoke-AtomicTest -AtomicTechnique {technique_id}"

    # Add optional parameters
    if test_numbers:
        test_nums_str = ",".join(str(num) for num in test_numbers)
        invoke_cmd += f" -TestNumbers {test_nums_str}"
    
    if check_prereqs:
        invoke_cmd += " -CheckPrereqs"
    
    if get_prereqs:
        invoke_cmd += " -GetPrereqs"
    
    if cleanup:
        invoke_cmd += " -Cleanup"
    
    if show_details:
        invoke_cmd += " -ShowDetails"
    
    if show_details_brief:
        invoke_cmd += " -ShowDetailsBrief"
    
    if any_os:
        invoke_cmd += " -AnyOS"
    
    if session:
        invoke_cmd += f" -Session ${session}"
    
    command.append(invoke_cmd)
    
    return command


def run_atomic_test(
    technique_id: str,
    test_numbers: Optional[List[int]] = None,
    check_prereqs: bool = False,
    get_prereqs: bool = False,
    cleanup: bool = False,
    session: Optional[str] = None,
    show_details_brief: bool = False,
    any_os: bool = False,
    timeout: Optional[int] = None,
    capture_output: bool = True,  # New parameter to control output capture
) -> Tuple[bool, str]:
    """
    Executes an Atomic Red Team test using Invoke-AtomicTest.

    Args:
        technique_id: The technique ID to run.
        test_numbers: Optional list of specific test numbers to run.
        check_prereqs: Whether to check prerequisites only.
        get_prereqs: Whether to install prerequisites.
        cleanup: Whether to run cleanup commands.
        session: Optional PowerShell session name to run the test on.
        show_details_brief: Whether to show brief details of the test.
        any_os: Whether to include tests for all platforms.
        timeout: Optional timeout in seconds.
        capture_output: Whether to capture and return the command output. If False, 
                       allows interactive programs to display normally.

    Returns:
        A tuple containing (success_flag, output_text).
    """
    config = get_config()
    
    if not validate_technique_id(technique_id):
        return False, f"Error: Invalid technique ID format: {technique_id}. Expected format: T1234 or T1234.001"

    # Use the configured timeout if not specified
    if timeout is None:
        timeout = config.timeout

    # Build the command
    command = build_command(
        technique_id=technique_id,
        test_numbers=test_numbers,
        check_prereqs=check_prereqs,
        get_prereqs=get_prereqs,
        cleanup=cleanup,
        show_details_brief=show_details_brief,
        session=session,
        any_os=any_os,
    )

    # Execute the command
    try:
        if capture_output:
            # Capture output (good for logging, but may prevent GUI apps from displaying)
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return True, result.stdout
        else:
            # Don't capture output - allow GUI applications to display normally
            # For non-interactive tests, this will print output to the console
            print(f"Executing: {' '.join(command)}")
            result = subprocess.run(
                command,
                check=True,
                timeout=timeout
            )
            return True, "Command executed successfully. Output was displayed in console."
    except FileNotFoundError:
        error_msg = f"Error: PowerShell executable not found at '{config.powershell_path}'."
        print(error_msg, file=sys.stderr)
        return False, error_msg
    except subprocess.CalledProcessError as e:
        error_msg = f"Error: Command failed with exit code {e.returncode}.\n"
        if hasattr(e, 'stderr') and e.stderr:
            error_msg += f"Details: {e.stderr}"
        print(error_msg, file=sys.stderr)
        return False, error_msg
    except subprocess.TimeoutExpired:
        error_msg = f"Error: Command timed out after {timeout} seconds."
        print(error_msg, file=sys.stderr)
        return False, error_msg
    except Exception as e:
        error_msg = f"An unexpected error occurred: {str(e)}"
        print(error_msg, file=sys.stderr)
        return False, error_msg


def list_available_tests(
    technique_id: str = "All",
    show_details: bool = False,
    show_details_brief: bool = True,
    any_os: bool = False,
) -> Tuple[bool, Union[List[Dict[str, Any]], str]]:
    """
    Lists available Atomic Red Team tests.

    Args:
        technique_id: The technique ID to list tests for. Use "All" for all techniques.
        show_details: Whether to show full details of the tests.
        show_details_brief: Whether to show brief details of the tests.
        any_os: Whether to include tests for all platforms or just the current one.

    Returns:
        A tuple containing (success_flag, list_of_tests_or_output).
    """
    config = get_config()
    
    # Check if the atomics path is configured
    if not config.atomics_path:
        return False, "Error: Atomics path is not configured. Use 'purpletool config set atomics-path <path>' to set it."
    
    atomics_path = Path(config.atomics_path)
    if not atomics_path.exists() or not atomics_path.is_dir():
        return False, f"Error: Atomics directory not found at '{atomics_path}'."
    
    # Use PowerShell to list available tests
    command = [config.powershell_path, "-Command"]
    
    # Build the command
    if technique_id == "All" and not show_details and not show_details_brief:
        # Command to list just technique IDs and names
        invoke_cmd = "Invoke-AtomicTest -ListTechniques"
    else:
        # Command to list techniques with details
        invoke_cmd = f"Invoke-AtomicTest {technique_id}"
        
        if show_details:
            invoke_cmd += " -ShowDetails"
        elif show_details_brief:
            invoke_cmd += " -ShowDetailsBrief"
        
    if any_os:
        invoke_cmd += " -AnyOS"
    
    command.append(invoke_cmd)
    
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=config.timeout
        )
        
        # If we're just listing technique IDs, parse them into a structured format
        if technique_id == "All" and not show_details and not show_details_brief:
            techniques = []
            for line in result.stdout.splitlines():
                # Look for lines matching pattern like "T1234 - Technique Name"
                match = re.match(r"\s*([T]\d{4}(?:\.\d{3})?)\s*-\s*(.+)", line)
                if match:
                    technique_id, technique_name = match.groups()
                    techniques.append({
                        "id": technique_id,
                        "name": technique_name.strip()
                    })
            return True, techniques
        else:
            # Just return the raw output for detailed listings
            return True, result.stdout
    except Exception as e:
        error_msg = f"Error listing techniques: {str(e)}"
        return False, error_msg


def get_test_details(
    technique_id: str,
    show_details: bool = False,
    any_os: bool = False,
) -> Tuple[bool, str]:
    """
    Get details about specific Atomic Red Team tests.

    Args:
        technique_id: The technique ID to get details for.
        show_details: Whether to show full details (True) or brief details (False).
        any_os: Whether to include tests for all platforms or just the current one.

    Returns:
        A tuple containing (success_flag, output_text).
    """
    config = get_config()
    
    # Build the command
    command = [config.powershell_path, "-Command"]
    
    invoke_cmd = f"Invoke-AtomicTest {technique_id}"
    
    if show_details:
        invoke_cmd += " -ShowDetails"
    else:
        invoke_cmd += " -ShowDetailsBrief"
    
    if any_os:
        invoke_cmd += " -AnyOS"
    
    command.append(invoke_cmd)
    
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=config.timeout
        )
        return True, result.stdout
    except Exception as e:
        error_msg = f"Error getting test details: {str(e)}"
        return False, error_msg