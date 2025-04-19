// Target scope for deployment (Resource Group)
targetScope = 'resourceGroup'

// ==================================
//          PARAMETERS
// ==================================

@description('Required. Specifies the Azure region where the resources will be deployed.')
param location string = resourceGroup().location

@description('Required. Specifies the environment name (e.g., dev, test, prod) used for resource naming.')
@allowed([
  'dev'
  'test'
  'uat'
  'prod'
])
param environmentName string = 'dev'

@description('Optional. Base name for the project or application, used in resource naming.')
param projectName string = 'bachelor'

@description('Optional. Instance number for uniqueness if deploying multiple stacks.')
param instanceNumber int = 1

@description('Required. Name of the *existing* Virtual Network where the Bastion Host will be deployed.')
param virtualNetworkName string

@description('Optional. Name of the Resource Group containing the Virtual Network (if different from the current RG). Defaults to current RG.')
param virtualNetworkResourceGroupName string = resourceGroup().name

@description('Required. The SKU for the Azure Bastion Host.')
@allowed([
  'Basic'
  'Standard'
])
param bastionSkuName string = 'Standard'

@description('Optional. Number of scale units for Standard SKU Bastion Host (min 2).')
param bastionScaleUnits int = 2

@description('Optional. Tags to apply to all resources.')
param resourceTags object = {
  Environment: environmentName
  Project: projectName
  CreationDate: utcNow('yyyy-MM-dd') // Automatically set creation date
  CreatedBy: 'Bicep' // Or specific user/service principal
}

// ==================================
//          VARIABLES
// ==================================

// Consistent naming convention: type-project-environment-region-instance
var bastionPipName = 'pip-bas-${projectName}-${environmentName}-${location}-${padLeft(instanceNumber, 3, '0')}'
var bastionHostName = 'bas-${projectName}-${environmentName}-${location}-${padLeft(instanceNumber, 3, '0')}'
var bastionSubnetName = 'AzureBastionSubnet' // This name is REQUIRED by Azure

// ==================================
//        EXISTING RESOURCES
// ==================================

// Reference the existing VNet in the specified (or current) resource group
@description('Reference to the existing Virtual Network.')
resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-11-01' existing = {
  name: virtualNetworkName
  scope: resourceGroup(virtualNetworkResourceGroupName) // Scope to the VNet's RG
}

// Get the subnet ID dynamically from the existing VNet resource
var bastionSubnetId = '${virtualNetwork.id}/subnets/${bastionSubnetName}'

// ==================================
//          RESOURCES
// ==================================

@description('Public IP Address for Azure Bastion Host.')
resource bastionPip 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: bastionPipName
  location: location
  tags: resourceTags
  sku: {
    // Standard SKU is required for Bastion SKUs other than Basic, and generally recommended.
    name: 'Standard'
  }
  properties: {
    // Static allocation is required for Bastion
    publicIPAllocationMethod: 'Static'
    // Let Azure assign the IP address
  }
}

@description('Azure Bastion Host resource.')
resource bastionHost 'Microsoft.Network/bastionHosts@2023-11-01' = {
  name: bastionHostName
  location: location
  tags: resourceTags
  sku: {
    name: bastionSkuName
  }
  properties: {
    // Let Azure manage the DNS name - removed hardcoded DNS name
    scaleUnits: (bastionSkuName == 'Standard') ? bastionScaleUnits : null // Scale units only apply to Standard SKU
    enableIpConnect: (bastionSkuName == 'Standard') ? true : null // IP Connect requires Standard SKU
    enableShareableLink: (bastionSkuName == 'Standard') ? true : null // Shareable Link requires Standard SKU
    // Keep other features disabled unless needed, can be parameterized
    disableCopyPaste: false
    enableKerberos: false
    enableSessionRecording: false
    enableTunneling: false

    ipConfigurations: [
      {
        name: 'IpConf' // Default configuration name
        properties: {
          // Reference the dynamically retrieved subnet ID
          subnet: {
            id: bastionSubnetId
          }
          // Reference the Public IP resource created above
          publicIPAddress: {
            id: bastionPip.id
          }
          privateIPAllocationMethod: 'Dynamic' // Standard for Bastion IP Config
        }
      }
    ]
  }
  // Ensure Bastion depends on the PIP being available (dependency on VNet is implicit via subnet ID lookup)
  dependsOn: [
    bastionPip
  ]
}

// ==================================
//          OUTPUTS
// ==================================

@description('The resource ID of the deployed Azure Bastion host.')
output bastionHostId string = bastionHost.id

@description('The name of the Azure Bastion host.')
output bastionHostNameOutput string = bastionHost.name

@description('The resource ID of the Public IP Address used by Bastion.')
output bastionPipId string = bastionPip.id
