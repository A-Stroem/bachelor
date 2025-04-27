# Product Requirements Document (PRD) - MVP Purple Team Tool

**Version:** 1.0 (MVP)  
**Date:** April 27, 2025

## 1. Introduction

This document outlines the requirements for the Minimum Viable Product (MVP) of a command-line interface (CLI) based purple team tool. The tool aims to orchestrate Atomic Red Team (ART) tests to facilitate adversary emulation and blue team training within a controlled lab environment (Windows/Linux). The primary execution engine will be Invoke-AtomicRedTeam, orchestrated via a Python CLI application.

## 2. User Roles

- **Red Team Member:** Executes attack simulations to test defenses.
- **Blue Team Member / Trainer:** Uses the tool for training, observing attack effects, and learning detection/response.
- **User:** Installs and sets up the tool and required environment.

## 3. Requirements

| User Story                                                                                                                                                                                                      | Required Functionality                                                                                                                                                                                                                                                                                                                        | MVP Feature Ref.     |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| As a Red Team Member, I want to execute a specific Atomic Red Team test by its Technique ID (TID) so that I can simulate a precise adversary behavior against the test environment.                             | - Provide a CLI command (e.g., purpletool run <TID>) to initiate a test.<br>- The tool must construct and execute the corresponding Invoke-AtomicTest <TID> command via subprocess.<br>- Support specifying individual test numbers within a technique (e.g., --test-numbers 1,3).                                                            | F1                   |
| As a Red Team Member, I want the tool to handle prerequisites for an atomic test so that I don't have to manually install dependencies before running the test.                                                 | - Provide CLI flags (e.g., --check-prereqs, --get-prereqs) that translate to the corresponding Invoke-AtomicTest flags (-CheckPrereqs, -GetPrereqs).                                                                                                                                                                                          | F1                   |
| As a Red Team Member, I want the tool to perform cleanup after executing an atomic test so that the test environment can be reverted to its previous state.                                                     | - Provide a CLI flag (e.g., --cleanup) that translates to the Invoke-AtomicTest -Cleanup flag.                                                                                                                                                                                                                                                | F1                   |
| As a Red Team Member, I want to execute tests on remote machines within my test environment (Windows/Linux) so that I can simulate attacks across the network.                                                  | - Support initiating remote execution by constructing the Invoke-AtomicTest command with the -Session $sess parameter.<br>- MVP requires the user to pre-establish the PowerShell Remoting session ($sess); documentation must guide this setup.                                                                                              | F1                   |
| As a Blue Team Member / Trainer, I want to see the commands executed by an atomic test and its outcome (success/failure) so that I can understand the attack steps and correlate them with defensive tool logs. | - Capture and display relevant stdout and stderr from the Invoke-AtomicTest process.<br>- Clearly indicate success or failure based on return code and output parsing.<br>- Optionally use Invoke-AtomicTest -ShowDetailsBrief or parse output to show executed commands.                                                                     | F2                   |
| As a Blue Team Member / Trainer, I want to see any error messages generated during test execution so that I can troubleshoot failed tests or understand unexpected behavior.                                    | - Capture and display stderr from the Invoke-AtomicTest process when errors occur.<br>- Implement robust error handling for subprocess execution within the Python tool.                                                                                                                                                                      | F2                   |
| As a User, I want clear instructions on how to set up the necessary test environment (Windows/Linux VMs, PowerShell Core, Invoke-AtomicRedTeam, ART atomics) so that I can successfully run the tool.           | - Provide comprehensive setup documentation (e.g., README.md) covering prerequisites and configuration (including basic PowerShell Remoting setup for remote tests).<br>- Optionally include simple setup scripts (Bash/PowerShell) for common dependencies.<br>- Optionally include a basic CLI check command (e.g., purpletool check-deps). | F3                   |
| As a Red Team Member, I want to run predefined sequences of atomic tests (playbooks) so that I can quickly simulate common attack chains.                                                                       | - Implement 2-3 hardcoded playbooks within the Python tool, each executing a specific sequence of Invoke-AtomicTest commands.<br>- Provide a CLI command to run a playbook by name (e.g., purpletool playbook run <playbook_name>).                                                                                                           | F4                   |
| As a Blue Team Member, I want guidance on how to detect and respond to the specific attack sequences simulated by the Red Team playbooks so that I can practice my defensive skills.                            | - For each implemented Red Team playbook, provide corresponding Blue Team guidance either in the tool's output upon playbook completion or in accompanying documentation.<br>- Guidance should include expected log sources, key detection artifacts/indicators, and basic analysis/response steps relevant to the TTPs executed.             | F5                   |
| As a User, I want to easily list the available Atomic Red Team tests that the tool can execute so that I know which TIDs are valid inputs.                                                                      | - Provide a CLI command (e.g., purpletool list tests) to display available tests.<br>- Implementation can parse the local atomics directory structure or invoke Invoke-AtomicTest -ShowDetailsBrief and parse its output.                                                                                                                     | N/A (Supporting)     |
| As a User, I want helpful information when I use the tool incorrectly or need assistance so that I can understand how to use it properly.                                                                       | - Implement a --help flag for the main command and all subcommands, providing descriptions, usage syntax, options, and examples.<br>- Provide clear, human-readable error messages with suggestions for correction when possible.<br>- Use non-zero exit codes to indicate failure.                                                           | N/A (Non-Functional) |

## 4. Out of Scope for MVP

- Graphical User Interface (GUI)
- Fully automated cloud environment provisioning (e.g., Azure VM deployment)
- Deployment via Docker containers
- Dedicated web server/API backend
- Self-contained portable test environment (e.g., USB drive)
- Advanced remote session management (e.g., credential handling, session creation within the tool)
- Custom playbook definition by users
- Advanced reporting features
- Integration with detection tools (e.g., SIEM/EDR API checks)
- Chain Reactor integration

**Sources and related content**
