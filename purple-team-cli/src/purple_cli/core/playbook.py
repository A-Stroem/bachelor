"""
Module for handling predefined playbooks of atomic tests.

This module provides functionality to define and execute sequences
of Atomic Red Team tests as playbooks.
"""

from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass

from purple_cli.core.executor import run_atomic_test


@dataclass(frozen=True)
class PlaybookTest:
    """
    Represents a single test in a playbook.
    
    Attributes:
        technique_id: The MITRE ATT&CK technique ID.
        test_numbers: Optional list of specific test numbers to run.
        description: Description of the test's purpose in the playbook.
    """
    technique_id: str
    test_numbers: Optional[List[int]] = None
    description: str = ""


@dataclass(frozen=True)
class Playbook:
    """
    Represents a predefined sequence of Atomic Red Team tests.
    
    Attributes:
        name: Name of the playbook.
        description: Description of the playbook's purpose and attack chain.
        tests: List of PlaybookTest objects defining the tests to run.
        blue_team_guidance: Notes for blue team on detecting and responding to this attack chain.
    """
    name: str
    description: str
    tests: List[PlaybookTest]
    blue_team_guidance: str = ""


# Predefined playbooks
PLAYBOOKS: Dict[str, Playbook] = {
    "credential-access": Playbook(
        name="credential-access",
        description="Basic credential access and dumping playbook simulating an attacker attempting to harvest credentials",
        tests=[
            PlaybookTest(
                technique_id="T1003",
                test_numbers=[1],
                description="OS Credential Dumping - Dumps cached credentials"
            ),
            PlaybookTest(
                technique_id="T1552.001",
                test_numbers=[1],
                description="Credentials In Files - Access credential files"
            ),
            PlaybookTest(
                technique_id="T1555.003",
                test_numbers=[1],
                description="Credentials from Web Browsers - Extract credentials from browser stores"
            ),
        ],
        blue_team_guidance="""
# Blue Team Guidance - Credential Access Playbook

## Log Sources to Monitor
- Windows Event Log (Security): 4663, 4656, 4624, 4625
- Sysmon: Process creation (Event ID 1), File creation (Event ID 11)
- PowerShell Script Block Logging (Event ID 4104)
- Process and command line auditing

## Key Detection Opportunities
- Monitor for processes accessing credential files (mimikatz, procdump)
- Look for suspicious process creation events creating lsass.exe dumps
- Monitor registry operations related to credential storage
- Watch for unexpected DPAPI usage
- Monitor access to browser data files and directories
- Detect suspicious command-line parameters for built-in utilities like reg.exe

## Basic Response Steps
1. Isolate the affected endpoint immediately
2. Investigate the authentication events following the credential access
3. Force password resets for any potentially compromised accounts
4. Look for persistence mechanisms that may have been established
5. Check for lateral movement using potentially stolen credentials
"""
    ),
    "discovery": Playbook(
        name="discovery",
        description="Host and network discovery playbook simulating an attacker's reconnaissance phase",
        tests=[
            PlaybookTest(
                technique_id="T1087.001",
                test_numbers=[1],
                description="Account Discovery - Local Accounts"
            ),
            PlaybookTest(
                technique_id="T1016",
                test_numbers=[1],
                description="System Network Configuration Discovery"
            ),
            PlaybookTest(
                technique_id="T1018",
                description="Remote System Discovery"
            ),
            PlaybookTest(
                technique_id="T1082",
                description="System Information Discovery"
            ),
        ],
        blue_team_guidance="""
# Blue Team Guidance - Discovery Playbook

## Log Sources to Monitor
- Windows Event Log (Security and System)
- PowerShell Module Logging (Event ID 4103)
- Command-line process auditing (Event ID 4688 with command line)
- Sysmon Process Creation (Event ID 1)
- Network connection logs and NetFlow/zeek data

## Key Detection Opportunities
- Multiple discovery commands executed in short succession
- Use of built-in Windows utilities for system enumeration (net.exe, ipconfig, systeminfo)
- PowerShell cmdlets for system and network discovery
- Host enumeration via Active Directory queries
- Suspicious registry queries related to system configuration

## Basic Response Steps
1. Evaluate context - is this activity expected from the user/system?
2. Look for other suspicious activities that might follow reconnaissance
3. Correlate discovery activities with other potential attack indicators
4. If malicious, investigate how the attacker gained initial access
5. Monitor for subsequent lateral movement or privilege escalation attempts
"""
    ),
    "persistence": Playbook(
        name="persistence",
        description="Persistence mechanism playbook simulating an attacker establishing staying power in the environment",
        tests=[
            PlaybookTest(
                technique_id="T1547.001", 
                description="Boot or Logon Autostart Execution - Registry Run Keys"
            ),
            PlaybookTest(
                technique_id="T1053.005",
                description="Scheduled Task/Job: Scheduled Task"
            ),
            PlaybookTest(
                technique_id="T1136.001",
                description="Create Account: Local Account"
            ),
        ],
        blue_team_guidance="""
# Blue Team Guidance - Persistence Playbook

## Log Sources to Monitor
- Windows Event Log (Security): 4624, 4720, 4732
- System Event Log: 106, 4698, 4699, 4700, 4701 (Task Scheduler)
- Sysmon: Registry modifications (Event ID 12 & 13)
- Process Creation (Event ID 4688 with command line or Sysmon Event ID 1)
- PowerShell logs if used for persistence implementation

## Key Detection Opportunities
- New scheduled tasks created with odd names or suspicious command lines
- Registry modifications to Run/RunOnce keys
- New user account creation outside normal provisioning processes
- Unusual service installations or modifications
- New startup folder items

## Basic Response Steps
1. Identify and analyze the persistence mechanism
2. Identify how it was established (credential access? privileged account?)
3. Verify what commands or payloads execute when the persistence triggers
4. Remove the persistence mechanism after proper investigation
5. Hunt for additional persistence mechanisms (adversaries rarely use just one)
6. Reset credentials for any accounts that were potentially compromised
7. Analyze any payloads/binaries used by the persistence mechanism
"""
    ),
}


def get_available_playbooks() -> List[Dict[str, str]]:
    """
    Get information about all available playbooks.
    
    Returns:
        List of dictionaries with playbook information.
    """
    return [
        {"name": name, "description": playbook.description}
        for name, playbook in PLAYBOOKS.items()
    ]


def get_playbook(name: str) -> Optional[Playbook]:
    """
    Get a specific playbook by name.
    
    Args:
        name: The name of the playbook to retrieve.
        
    Returns:
        The Playbook object if found, None otherwise.
    """
    return PLAYBOOKS.get(name.lower())


def execute_playbook(
    playbook_name: str, 
    check_prereqs: bool = False,
    get_prereqs: bool = False,
    cleanup: bool = False,
    session: Optional[str] = None,
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Execute all tests in a specified playbook.
    
    Args:
        playbook_name: The name of the playbook to execute.
        check_prereqs: Whether to check prerequisites for each test.
        get_prereqs: Whether to install prerequisites for each test.
        cleanup: Whether to run cleanup for each test.
        session: Optional PowerShell session name to run the tests on.
        
    Returns:
        Tuple of (success, results) where success is a boolean indicating if all tests
        were successful, and results is a list of dictionaries with test results.
    """
    playbook = get_playbook(playbook_name)
    if not playbook:
        return False, [{"error": f"Playbook '{playbook_name}' not found"}]
    
    all_successful = True
    results = []
    
    for test in playbook.tests:
        print(f"\nExecuting: {test.technique_id} - {test.description}")
        success, output = run_atomic_test(
            technique_id=test.technique_id,
            test_numbers=test.test_numbers,
            check_prereqs=check_prereqs,
            get_prereqs=get_prereqs,
            cleanup=cleanup,
            session=session,
            show_details_brief=True,
        )
        
        result = {
            "technique_id": test.technique_id,
            "description": test.description,
            "success": success,
            "output": output,
        }
        
        results.append(result)
        if not success:
            all_successful = False
    
    return all_successful, results