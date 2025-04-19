# Azure Deployment Configuration Repository

This repository serves as version control for Azure deployment setups. It contains Bicep modules, ARM templates, Azure Pipelines definitions, and associated configuration files used to provision and manage Azure resources.

## Purpose

The primary goal of this repository is to maintain a consistent, version-controlled, and modular collection of infrastructure-as-code (IaC) for various Azure environments, focusing on core networking, DevTest Labs, and shared services.

## Structure

- **`/azure/arm`**: Contains original or decompiled ARM templates. These might serve as a reference or for specific use cases not yet migrated to Bicep.
- **`/azure/infra`**: Contains the core Bicep modules organized by function:
  - `core/`: Modules for fundamental networking infrastructure (VNet, Subnets, Bastion).
  - `devtestlabs/`: Modules for deploying and configuring Azure DevTest Labs.
  - `shared/`: Modules for shared resources like Key Vaults or Storage Accounts.
- **`/azure/lab-content`**: Stores content specific to DevTest Labs, such as:
  - `formulas/`: Definitions for reusable VM bases (e.g., `windos-server-2022-base.json`).
- **`/azure/parameters`**: Holds top-level parameter files (e.g., `dev.parameters.json`) for different environments or deployment scenarios.
- **`/azure/pipelines`**: Contains Azure Pipelines YAML definitions for CI/CD automation (e.g., `azure-pipelines.yml`, `deploy-infra.yml`).
- **`/azure/scripts`**: Includes supplementary scripts used during deployment, configuration, or maintenance.

## Bicep Modules

### Core Infrastructure (`/azure/infra/core`)

- **`network.bicep`**: Defines the core Virtual Network (VNet) and its subnets, including the dedicated `AzureBastionSubnet` and a subnet for DevTest Labs.
- **`bastion.bicep`**: Deploys the Azure Bastion host, including its required Public IP address, and configures it to use the `AzureBastionSubnet` from the core network.
- **`main.bicep`**: Orchestrates the deployment of the core networking and bastion modules, taking environment-specific parameters.

### DevTest Labs (`/azure/infra/devtestlabs`)

- **`lab.bicep`**: Deploys an Azure DevTest Lab instance, configures its connection to the core VNet, sets up artifact repositories (public and potentially custom), and defines auto-shutdown schedules.
- **`policies.bicep`**: (Placeholder/Not fully implemented) Intended for defining DevTest Lab policies (e.g., allowed VM sizes, VM count limits).
- **`main.bicep`**: Orchestrates the deployment of the DevTest Lab, passing necessary parameters like the core VNet ID.

### Shared Resources (`/azure/infra/shared`)

- **`keyvault.bicep`**: (Placeholder) Module for deploying Azure Key Vault.
- **`storageaccount.bicep`**: (Placeholder) Module for deploying Azure Storage Accounts.

## Deployment

Deployments are intended to be automated using Azure Pipelines defined in the `/azure/pipelines` directory. Parameter files in `/azure/parameters` and module-specific parameter files (like `/azure/infra/core/dev.parameters.json`) are used to customize deployments for different environments (e.g., 'dev').

## Getting Started

_(Add instructions here on how to configure and run the pipelines or manual deployment steps if applicable)_
