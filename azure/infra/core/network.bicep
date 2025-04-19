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

@description('Required. The address space for the Virtual Network.')
param vnetAddressPrefix string = '10.1.0.0/16'

@description('Required. The address prefix for the DevTest Labs subnet.')
param devTestSubnetAddressPrefix string = '10.1.1.0/24'

@description('Required. The address prefix for the Azure Bastion subnet. MUST be /26 or larger.')
param bastionSubnetAddressPrefix string = '10.1.255.0/26'

@description('Required. The SKU for the Azure Bastion Host.')
@allowed([
  'Basic'
  'Standard'
])
param bastionSkuName string = 'Standard'

@description('Optional. Number of scale units for Standard SKU Bastion Host.')
param bastionScaleUnits int = 2 // Default for Standard SKU

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
var vnetName = 'vnet-${projectName}-${environmentName}-${location}-${padLeft(instanceNumber, 3, '0')}'
var bastionPipName = 'pip-bas-${projectName}-${environmentName}-${location}-${padLeft(instanceNumber, 3, '0')}'
var bastionHostName = 'bas-${projectName}-${environmentName}-${location}-${padLeft(instanceNumber, 3, '0')}'
var devTestSubnetName = 'snet-devtestlabs-${padLeft(instanceNumber, 3, '0')}'
var bastionSubnetName = 'AzureBastionSubnet' // This name is REQUIRED by Azure

// ==================================
//          RESOURCES
// ==================================

@description('Virtual Network resource.')
resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: vnetName
  location: location
  tags: resourceTags
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetAddressPrefix
      ]
    }
    // Define subnets directly within the VNet resource properties
    subnets: [
      {
        name: devTestSubnetName
        properties: {
          addressPrefix: devTestSubnetAddressPrefix
          // Add NSG association here if needed for this subnet:
          // networkSecurityGroup: {
          //   id: nsgDevTestSubnet.id // Reference an NSG defined elsewhere for this subnet
          // }
        }
      }
      {
        name: bastionSubnetName // MUST be this exact name
        properties: {
          addressPrefix: bastionSubnetAddressPrefix
          // NOTE: Do NOT associate your own NSG with AzureBastionSubnet.
          // Azure manages the required NSG rules for this subnet automatically.
        }
      }
      // Removed the 'default' subnet from original, add back if specifically needed.
      // Removed the redundant top-level subnet definitions.
    ]
    // Default properties like encryption, DDOS, VNetPolicies are often fine unless specific needs exist.
    // privateEndpointNetworkPolicies: 'Disabled' // Uncomment if needed for private endpoints in subnets
    // privateLinkServiceNetworkPolicies: 'Enabled' // Uncomment if needed for private link services in subnets
  }
}

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
    // Let Azure assign the IP address - removed hardcoded IP '132.164.246.111'
    // Removed Availability Zones - uncomment below if specific zone redundancy is required for the PIP
    // zones: [
    //   '1'
    //   '2'
    //   '3'
    // ]
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
          // Reference the subnet using the VNet resource symbolic name and the known subnet name
          subnet: {
            // Use the reference to the subnet resource within the VNet definition
            id: virtualNetwork.properties.subnets[1].id // Assumes bastionSubnet is the second in the array (index 1)
            // More robust: use filter to find subnet by name if order might change
            // id: filter(virtualNetwork.properties.subnets, s => s.name == bastionSubnetName)[0].id
          }
          // Reference the Public IP resource using its symbolic name
          publicIPAddress: {
            id: bastionPip.id
          }
          privateIPAllocationMethod: 'Dynamic' // Standard for Bastion IP Config
        }
      }
    ]
  }
  // Ensure Bastion depends on the VNet and PIP being available
  dependsOn: [
    virtualNetwork
    bastionPip
  ]
}

// Removed the networkSecurityGroups_nsg_bastion_001_name_resource 'Microsoft.Network/networkSecurityGroups@2024-05-01'
// Azure manages the NSG rules needed for the AzureBastionSubnet automatically.
// If an NSG is needed for the snet-devtestlabs-001 subnet, define it separately and associate it above.
// Removed the redundant networkSecurityGroups_nsg_bastion_001_name_AllowSSHRDPOutbound resource. Rules should be defined inline.

// ==================================
//          OUTPUTS
// ==================================

@description('The resource ID of the deployed Virtual Network.')
output vnetId string = virtualNetwork.id

@description('The name of the deployed Virtual Network.') // Added VNet name output
output vnetNameOutput string = virtualNetwork.name

@description('The resource ID of the deployed Azure Bastion host.')
output bastionHostId string = bastionHost.id

@description('The name of the Azure Bastion host.')
output bastionHostNameOutput string = bastionHost.name

@description('The resource ID of the DevTest Labs subnet.')
// Use reference filter for robustness
output devTestSubnetId string = filter(virtualNetwork.properties.subnets, s => s.name == devTestSubnetName)[0].id
