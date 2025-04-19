@description('The Azure region where resources will be deployed.')
param location string = resourceGroup().location

@description('Name for the Network Security Group for Bastion.')
param nsgBastionName string = 'nsg-bastion-001'

@description('Name for the Virtual Network.')
param vnetName string = 'vnet-dev-platform-northeurope-001'

@description('Name for the Bastion Host.')
param bastionHostName string = 'bas-vnetdevplatformnorteurope001-northeurope-001'

@description('Name for the Public IP Address for Bastion.')
param bastionPipName string = 'pip-bas-vnetdevplatformnorteurope001-northeurope-001'

// Define common tags in a variable
var commonTags = {
  CreatedBy: 'Anders'
  CreationDate: '2025-04-19' // Consider using utcNow() or a parameter for dynamic date
  DataClassification: 'Internal'
  Environment: 'Development'
  Project: 'Bachelor'
}

resource nsgBastion 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: nsgBastionName
  location: location
  tags: commonTags
  properties: {
    securityRules: [
      // Define NSG rules inline
      {
        name: 'AllowHttpsInbound' // Added rule for Bastion HTTPS access
        properties: {
          description: 'Allow Bastion Host HTTPS inbound'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowGatewayManagerInbound' // Added rule for Bastion Gateway Manager access
        properties: {
          description: 'Allow Gateway Manager inbound'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: 'GatewayManager'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowAzureLoadBalancerInbound' // Added rule for Bastion Health Probe
        properties: {
          description: 'Allow Azure Load Balancer inbound for health probes'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowBastionHostCommunication' // Added rule for Bastion control plane
        properties: {
          description: 'Allow Bastion Host communication'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRanges: ['8080', '5701']
          access: 'Allow'
          priority: 130
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowSshRdpOutbound'
        properties: {
          description: 'Allow SSH and RDP connections outbound'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRanges: [
            '22'
            '3389'
          ]
          access: 'Allow'
          priority: 100 // Priorities can be reused for different directions
          direction: 'Outbound'
        }
      }
    ]
  }
}

resource bastionPip 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: bastionPipName
  location: location
  tags: commonTags
  sku: {
    name: 'Standard' // Bastion requires Standard SKU
    tier: 'Regional'
  }
  zones: [
    // Optional: Remove if zone redundancy is not required or supported in the region/subscription
    '1'
    '2'
    '3'
  ]
  properties: {
    // ipAddress: '132.164.246.111' // Removed hardcoded IP - Let Azure allocate
    publicIPAddressVersion: 'IPv4'
    publicIPAllocationMethod: 'Static' // Bastion requires Static allocation
    idleTimeoutInMinutes: 4
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: vnetName
  location: location
  tags: commonTags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.1.0.0/16'
      ]
    }
    // encryption property is less common, remove if not specifically needed
    // encryption: {
    //   enabled: false
    //   enforcement: 'AllowUnencrypted'
    // }
    // privateEndpointVNetPolicies is deprecated, use subnet level policies
    // privateEndpointVNetPolicies: 'Disabled'
    subnets: [
      // Define subnets inline
      {
        name: 'default' // Consider a more descriptive name if 'default' isn't used
        properties: {
          addressPrefixes: [
            '10.1.0.0/24'
          ]
          // delegations: [] // Remove empty arrays if not needed
          privateEndpointNetworkPolicies: 'Disabled' // Explicitly set based on need
          privateLinkServiceNetworkPolicies: 'Enabled' // Explicitly set based on need
        }
      }
      {
        name: 'snet-devtestlabs-001'
        properties: {
          addressPrefixes: [
            '10.1.1.0/24'
          ]
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
      {
        // AzureBastionSubnet *must* be named exactly this
        name: 'AzureBastionSubnet'
        properties: {
          addressPrefixes: [
            // Recommended size is /26 or larger
            '10.1.255.0/26'
          ]
          // Associate the NSG with the Bastion subnet
          networkSecurityGroup: {
            id: nsgBastion.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
    ]
    // virtualNetworkPeerings: [] // Remove empty arrays if not needed
    enableDdosProtection: false // Explicitly set based on need
  }
}

// Removed separate subnet resources as they are now inline

// Removed separate NSG rule resource as it's now inline

resource bastionHost 'Microsoft.Network/bastionHosts@2024-05-01' = {
  name: bastionHostName
  location: location
  tags: commonTags
  sku: {
    // Standard SKU is recommended for production workloads and enables more features
    name: 'Standard'
  }
  properties: {
    // dnsName: 'bst-67fc48cd-6e2a-4f67-aad7-0ec6bdc1c563.bastion.azure.com' // Removed hardcoded DNS name - Azure assigns this
    scaleUnits: 2 // Required for Standard SKU, minimum 2
    // Optional features - enable as needed
    enableTunneling: false
    enableIpConnect: true // Often needed
    disableCopyPaste: false
    enableShareableLink: true // Requires Standard SKU
    enableKerberos: false
    enableSessionRecording: false
    enablePrivateOnlyBastion: false // Set to true for private-only deployments
    ipConfigurations: [
      {
        name: 'IpConf' // Default name
        properties: {
          privateIPAllocationMethod: 'Dynamic' // Must be Dynamic
          publicIPAddress: {
            id: bastionPip.id // Reference the Public IP resource
          }
          subnet: {
            // Reference the inline Bastion subnet using its name
            id: vnet.properties.subnets[2].id // Assumes AzureBastionSubnet is the 3rd in the array (index 2)
            // More robust way to reference the subnet:
            // id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'AzureBastionSubnet')
          }
        }
      }
    ]
  }
  // Bicep infers dependency on vnet (via subnet id) and bastionPip (via public ip id)
}

// Add outputs if needed, e.g., the Bastion Host DNS name
output bastionDnsName string = bastionHost.properties.dnsName
