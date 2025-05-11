# Bachelor Project: Purple Team Tools

This repository contains a collection of cybersecurity tools and projects developed as part of a bachelor's thesis focused on purple team operations. Each project serves a specific purpose within the purple teaming framework, enabling the simulation of both offensive (red team) and defensive (blue team) security activities.

## Repository Structure

This repository is organized into several distinct projects:

### 1. Purple Team CLI

A command-line interface tool for executing Atomic Red Team tests to facilitate adversary emulation and purple team exercises. This tool provides a Python-based orchestrator for running security tests in a controlled lab environment.

**Key features:**

- Execute Atomic Red Team tests by technique ID
- Run playbooks that group related techniques
- Check and install prerequisites for tests
- Supports remote execution

**Location:** `/purple-team-cli/`

### 2. Phishing Simulation Site

A web application that simulates common phishing techniques for educational and security awareness purposes. The site includes multiple phishing templates and captures interaction details.

**Key features:**

- Multiple phishing templates (Microsoft, KEA)
- Credential harvesting simulation
- Detailed logging of user interactions
- Discord webhook integration for notifications

**Location:** `/phishing_site/`

### 3. Phishing Email Module

A Python module for sending simulated phishing emails as part of security awareness training. Supports both standard and spoofed emails.

**Key features:**

- Email template support
- Recipient list management via CSV
- Support for email spoofing (for authorized testing)
- Customizable templates

**Location:** `/phishing-module/`

### 4. Azure Infrastructure as Code

Version-controlled Azure deployment configurations using Bicep and ARM templates. This includes network infrastructure, DevTest Labs, and shared services setups.

**Key features:**

- Core network infrastructure definitions
- DevTest Labs configurations
- Azure Bastion setup
- Pipeline definitions for automated deployment

**Location:** `/azure/`

## Usage Notes

These tools are designed for educational purposes, security research, and authorized security testing only. Proper authorization should be obtained before using any of these tools in a production environment or against systems you do not own.

## Getting Started

Each project folder contains its own README with specific installation and usage instructions. Please refer to those for detailed guidance on working with individual components.

## License

This project is licensed under the MIT License - see the individual project directories for specific licensing information.

## Disclaimer

The tools in this repository are intended for authorized security testing, educational purposes, and security research only. Misuse of these tools against unauthorized targets may be illegal. The author takes no responsibility for any misuse of the provided materials.
