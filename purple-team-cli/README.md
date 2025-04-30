# Purple Team CLI

A command-line interface (CLI) tool for executing Atomic Red Team tests to facilitate adversary emulation and purple team exercises.

## Overview

Purple Team CLI is a Python-based orchestrator for executing Atomic Red Team (ART) tests within a controlled lab environment. It allows cybersecurity students and practitioners to easily run atomic tests for learning, training, and basic security control validation.

## Prerequisites

- **Python 3.8+**: Required to run the Purple Team CLI tool.
- **PowerShell**:
  - Windows: PowerShell 5.0+ (pre-installed on Windows 10/11)
  - Linux/macOS: PowerShell Core 6.0+ ([Installation Guide](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell))
- **Invoke-AtomicRedTeam**: PowerShell module for executing Atomic Red Team tests ([Installation Guide](https://github.com/redcanaryco/invoke-atomicredteam))
- **Atomic Red Team Atomics**: A local copy of the atomic tests ([GitHub Repository](https://github.com/redcanaryco/atomic-red-team))

## Installation

### 1. Install Python 3.8+

- Windows: [Python.org](https://www.python.org/downloads/)
- Linux: `sudo apt install python3 python3-pip` (Ubuntu/Debian) or equivalent
- macOS: `brew install python` (with Homebrew)

### 2. Install PowerShell (if not already installed)

#### Windows

PowerShell is pre-installed on Windows 10 and Windows 11.

#### macOS

```bash
# Using Homebrew
brew install --cask powershell
```

#### Linux (Ubuntu/Debian)

```bash
# Download the Microsoft repository GPG keys
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb
# Register the Microsoft repository GPG keys
sudo dpkg -i packages-microsoft-prod.deb
# Update the list of products
sudo apt-get update
# Install PowerShell
sudo apt-get install -y powershell
```

### 3. Install Invoke-AtomicRedTeam and Atomic Red Team

Launch PowerShell and run the following commands:

```powershell
# Install the Invoke-AtomicRedTeam module
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser

IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics

#Test
# List atomic tests that can be run from the current platform (Windows,Linux,macOS)
Invoke-AtomicTest T1003 -ShowDetailsBrief

# List all atomic tests regardless of which platform it can be executed from
Invoke-AtomicTest T1003 -ShowDetailsBrief -anyOS
```


### 4. Install the Purple Team CLI

```bash
# Clone the repository
git clone https://github.com/yourusername/purple-team-cli.git
cd purple-team-cli

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
# venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install the package in editable mode
pip install -e .

# Install pacakges + dev packages
pip install -e ".[dev]"

```

## Configuration

After installation, you need to configure Purple Team CLI to use your local Atomic Red Team resources:

```bash
# Set the path to the atomics directory
purpletool config set-atomics-path "/path/to/atomic-red-team/atomics"

# Set the path to PowerShell (if not in default location)
purpletool config set-powershell-path "/path/to/pwsh"  # or "powershell" on Windows

# Verify your configuration
purpletool config show
```

## Usage

### Execute a Single Test

```bash
# Execute a test by technique ID
purpletool run test T1003

# Execute a specific test number within a technique
purpletool run test T1003 --test-numbers 1

# Check prerequisites for a test
purpletool run test T1003 --check-prereqs

# Install prerequisites for a test
purpletool run test T1003 --get-prereqs

# Run cleanup commands after a test
purpletool run test T1003 --cleanup
```

### Execute a Playbook

```bash
# List available playbooks
purpletool list playbooks

# View details about a specific playbook
purpletool playbook info credential-access

# Execute a playbook
purpletool playbook run credential-access

# View blue team guidance for a playbook
purpletool playbook guidance credential-access
```

### List Available Tests

```bash
# List all available tests
purpletool list tests

# Filter tests by a keyword
purpletool list tests discovery
```

### Remote Execution

To execute tests on remote systems, you first need to establish a PowerShell remoting session:

```powershell
# In PowerShell, create a session to the target machine
$session = New-PSSession -ComputerName target-machine -Credential (Get-Credential)

# Keep note of the session ID/name to use with the CLI
```

Then, use Purple Team CLI with the session parameter:

```bash
# Execute a test on a remote system
purpletool run test T1003 --session $session

# Execute a playbook on a remote system
purpletool playbook run credential-access --session $session
```

## Setting Up a Test Environment

### Minimal Windows Test VM

1. Set up a Windows 10/11 VM (preferably using VirtualBox, VMware, or Hyper-V)
2. Install PowerShell 5.0+ (pre-installed on Windows 10/11)
3. Install the Invoke-AtomicRedTeam module
4. Configure Windows Defender or other security controls for testing
5. Optional: Install Sysmon for enhanced logging

### Minimal Linux Test VM

1. Set up an Ubuntu 20.04+ VM
2. Install PowerShell Core 6.0+
3. Install the Invoke-AtomicRedTeam module
4. Configure any security controls for testing
5. Optional: Enable auditd for enhanced logging

### PowerShell Remoting Setup

#### Windows to Windows

On the target machine (PowerShell as Administrator):

```powershell
# Enable PowerShell Remoting
Enable-PSRemoting -Force

# Configure TrustedHosts on the source machine if not in a domain
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "target-machine-ip" -Force
```

#### Linux/macOS to Windows

On the Windows target machine:

```powershell
# Enable PowerShell Remoting with HTTPS
Enable-PSRemoting -Force
```

On the Linux/macOS source machine:

```bash
# Connect using PowerShell Core
pwsh -Command "$session = New-PSSession -ComputerName target-machine-ip -Authentication Basic -UseSSL -Credential (Get-Credential)"
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
