// Module for deploying Azure DevTest Lab and its configurations
// Location: infra/devtestlabs/lab.bicep

targetScope = 'resourceGroup'

// ==================================
//          PARAMETERS
// ==================================
@description('Required. Name of the DevTest Lab.')
param labName string

@description('Required. Azure region for the DevTest Lab.')
param location string = resourceGroup().location

@description('Required. Resource ID of the Virtual Network to connect the Lab to.')
param virtualNetworkId string

@description('Required. Name of the subnet within the VNet to use for Lab VMs.')
param labSubnetName string

@description('Optional. Type of storage used for the Lab (Standard, Premium). Premium required for Gen2 images.')
@allowed([
  'Standard'
  'Premium'
])
param labStorageType string = 'Premium'

@description('Optional. Default permissions for users in lab environments (Reader, Contributor).')
@allowed([
  'Reader'
  'Contributor'
])
param environmentPermission string = 'Reader'

@description('Optional. Time for the daily auto-shutdown schedule (HHMM format, e.g., "1900").')
param shutdownTime string = '1900'

@description('Optional. Timezone ID for the auto-shutdown schedule (e.g., "W. Europe Standard Time", "UTC"). See Get-AzTimeZone cmdlet for list.')
param shutdownTimeZoneId string = 'W. Europe Standard Time' // Example, adjust as needed

@description('Optional. Email address for auto-shutdown notifications.')
param shutdownNotificationEmail string = '' // Provide email if notifications needed

@description('Optional. Minutes before shutdown to send notification (0-60).')
@minValue(0)
@maxValue(60)
param shutdownNotificationMinutes int = 30

@description('Optional. URI of the Git repository for custom artifacts/formulas.')
param customRepoUri string = ''

@description('Optional. Branch reference for the custom repository.')
param customRepoBranch string = 'main'

@description('Optional. Folder path within the custom repository containing artifacts.')
param customArtifactRepoFolderPath string = '/Artifacts' // Default convention

@description('Optional. Folder path within the custom repository containing formulas/environments.')
param customEnvironmentRepoFolderPath string = '/Formulas' // Default convention

@description('Optional. Type of the custom repository (GitHub, VsoGit).')
@allowed([
  '' // Means no custom repo
  'GitHub'
  'VsoGit' // Azure Repos
])
param customRepoType string = ''

@description('Optional. Name of the secret in Key Vault holding the Personal Access Token (PAT) for the custom repo.')
param customRepoPatSecretName string = ''

@description('Optional. Resource ID of the Key Vault containing the PAT secret.')
param customRepoKeyVaultId string = ''

@description('Optional. Tags to apply to the Lab resource.')
param resourceTags object = {}

// ==================================
//          VARIABLES
// ==================================
var enableShutdownNotifications = !empty(shutdownNotificationEmail)
var enableCustomRepo = !empty(customRepoUri) && !empty(customRepoType)

// Construct subnet resource ID from VNet ID and subnet name
var labSubnetId = '${virtualNetworkId}/subnets/${labSubnetName}'

// ==================================
//          RESOURCES
// ==================================
@description('Azure DevTest Lab resource.')
resource lab 'Microsoft.DevTestLab/labs@2022-11-11' = { // Updated API Version
  name: labName
  location: location
  tags: resourceTags
  properties: {
    labStorageType: labStorageType
    premiumDataDisks: 'Disabled' // Parameterize if needed
    environmentPermission: environmentPermission
    // Add other lab settings as parameters if needed (e.g., mandatory artifacts)
    mandatoryArtifactsResourceIdsLinux: []
    mandatoryArtifactsResourceIdsWindows: []
    announcement: { // Parameterize if needed
      enabled: 'Disabled'
    }
    support: { // Parameterize if needed
      enabled: 'Disabled'
    }
  }
}

@description('Connects the Lab to the specified Virtual Network.')
resource labVnetConnection 'Microsoft.DevTestLab/labs/virtualnetworks@2022-11-11' = {
  parent: lab
  name: last(split(virtualNetworkId, '/')) // Use VNet name as connection name
  properties: {
    allowedSubnets: [
      {
        resourceId: labSubnetId
        labSubnetName: labSubnetName
        // Control public IP usage on VMs created in this subnet
        allowPublicIp: 'Deny' // Best practice: Deny public IPs, use Bastion
        // usePublicIpAddressPermission: 'Deny' // Alternative property name in some API versions
      }
    ]
    // externalProviderResourceId: virtualNetworkId // Not needed for newer APIs when using allowedSubnets
    subnetOverrides: [ // Fine-grained control over the subnet usage
      {
        resourceId: labSubnetId
        labSubnetName: labSubnetName
        useInVmCreationPermission: 'Allow' // Allow users to select this subnet
        usePublicIpAddressPermission: 'Deny' // Enforce no public IPs
        // sharedPublicIpAddressConfiguration: null // Configure if using shared IPs
      }
    ]
  }
}

@description('Configures the daily auto-shutdown schedule for Lab VMs.')
resource labShutdownSchedule 'Microsoft.DevTestLab/labs/schedules@2022-11-11' = {
  parent: lab
  name: 'LabVmsShutdown' // Standard name for the shutdown schedule
  location: location // Schedules require location
  properties: {
    status: 'Enabled'
    taskType: 'LabVmsShutdownTask'
    dailyRecurrence: {
      time: shutdownTime
    }
    timeZoneId: shutdownTimeZoneId
    notificationSettings: {
      status: enableShutdownNotifications ? 'Enabled' : 'Disabled'
      timeInMinutes: shutdownNotificationMinutes
      emailRecipient: enableShutdownNotifications ? shutdownNotificationEmail : null
      // webhookUrl: null // Parameterize if webhook needed
    }
  }
}

@description('Optional: Configures the notification channel for auto-shutdown.')
resource labShutdownNotification 'Microsoft.DevTestLab/labs/notificationchannels@2022-11-11' = if (enableShutdownNotifications) {
  parent: lab
  name: 'AutoShutdownNotification' // Standard name
  properties: {
    description: 'Provides notifications prior to scheduled auto-shutdown.'
    events: [ { eventName: 'AutoShutdown' } ]
    emailRecipient: shutdownNotificationEmail // Use the same email as schedule
    // webhookUrl: null // Parameterize if needed
  }
}

// --- Artifact Repository Connections ---

@description('Connects the default Public Artifact Repository.')
resource publicArtifactRepo 'Microsoft.DevTestLab/labs/artifactsources@2022-11-11' = {
  parent: lab
  name: 'Public Artifact Repo' // Standard name
  properties: {
    displayName: 'Public Artifact Repo'
    uri: 'https://github.com/Azure/azure-devtestlab.git'
    sourceType: 'GitHub'
    folderPath: '/Artifacts'
    branchRef: 'master'
    status: 'Enabled'
  }
}

@description('Connects the default Public Environment (Formula) Repository.')
resource publicEnvironmentRepo 'Microsoft.DevTestLab/labs/artifactsources@2022-11-11' = {
  parent: lab
  name: 'Public Environment Repo' // Standard name
  properties: {
    displayName: 'Public Environment Repo'
    uri: 'https://github.com/Azure/azure-devtestlab.git'
    sourceType: 'GitHub'
    armTemplateFolderPath: '/Environments' // Path for environment templates (Formulas)
    branchRef: 'master'
    status: 'Enabled'
  }
}

@description('Optional: Connects a custom Git repository for artifacts and formulas.')
resource customRepo 'Microsoft.DevTestLab/labs/artifactsources@2022-11-11' = if (enableCustomRepo) {
  parent: lab
  name: 'Custom Repo' // Or parameterize name
  properties: {
    displayName: 'Custom Repo' // Or parameterize display name
    uri: customRepoUri
    sourceType: customRepoType
    folderPath: customArtifactRepoFolderPath // Path containing artifactfile.json folders
    armTemplateFolderPath: customEnvironmentRepoFolderPath // Path containing formula/environment JSON files
    branchRef: customRepoBranch
    securityToken: !empty(customRepoPatSecretName) && !empty(customRepoKeyVaultId) ? { // Use secure token if PAT secret name/KV ID provided
        token: customRepoPatSecretName // Name of the secret in KV
        keyVaultId: customRepoKeyVaultId // Resource ID of the KV
        tokenType: 'PersonalAccessToken' // Or 'Oauth'
      } : null
    status: 'Enabled'
  }
}

// Removed Lab User, User Secret, pre-created VM resources - manage via RBAC and Formulas.

// ==================================
//          OUTPUTS
// ==================================
@description('The resource ID of the deployed DevTest Lab.')
output labId string = lab.id

@description('The name of the deployed DevTest Lab.')
output labName string = lab.name

