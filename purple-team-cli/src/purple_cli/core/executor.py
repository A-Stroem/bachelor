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
    timeout: Optional[int] = None,
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
        timeout: Optional timeout in seconds.

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
    )

    # Execute the command
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return True, result.stdout
    except FileNotFoundError:
        error_msg = f"Error: PowerShell executable not found at '{config.powershell_path}'."
        print(error_msg, file=sys.stderr)
        return False, error_msg
    except subprocess.CalledProcessError as e:
        error_msg = f"Error: Command '{' '.join(e.cmd)}' failed with exit code {e.returncode}.\n"
        if e.stderr:
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


def list_available_tests() -> Tuple[bool, Union[List[Dict[str, Any]], str]]:
    """
    Lists all available Atomic Red Team tests from the atomic directory.

    Returns:
        A tuple containing (success_flag, list_of_tests_or_error_message).
    """
    config = get_config()
    
    # Check if the atomics path is configured
    if not config.atomics_path:
        return False, "Error: Atomics path is not configured. Use 'purpletool config set atomics-path <path>' to set it."
    
    atomics_path = Path(config.atomics_path)
    if not atomics_path.exists() or not atomics_path.is_dir():
        return False, f"Error: Atomics directory not found at '{atomics_path}'."
    
    # Use PowerShell to list available tests
    command = [
        config.powershell_path,
        "-Command",
        "Invoke-AtomicTest -ListTechniques"
    ]
    
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=config.timeout
        )
        
        # Parse the output to extract technique IDs
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
    except Exception as e:
        error_msg = f"Error listing techniques: {str(e)}"
        return False, error_msg