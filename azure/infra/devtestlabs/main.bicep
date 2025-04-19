// Main Bicep template for deploying the DevTest Lab environment
// Location: infra/devtestlabs/main.bicep

targetScope = 'resourceGroup'

// ==================================
//          PARAMETERS
// ==================================
@description('Required. Specifies the Azure region where the resources will be deployed.')
param location string = resourceGroup().location

@description('Required. Specifies the environment name (e.g., dev, test, prod).')
@allowed([ 'dev', 'test', 'uat', 'prod' ])
param environmentName string = 'dev'

@description('Optional. Base name for the project or application.')
param projectName string = 'bachelor'

@description('Optional. Instance number for uniqueness.')
param instanceNumber int = 1

@description('Required. Resource ID of the core Virtual Network deployed previously.')
param virtualNetworkId string

@description('Required. Name of the subnet within the core VNet to use for Lab VMs.')
param devTestSubnetName string

@description('Optional. Email address for lab auto-shutdown notifications.')
param labShutdownNotificationEmail string = '' // Example: 'your-email@example.com'

@description('Optional. Time for the daily auto-shutdown schedule (HHMM format, e.g., "1900").')
param labShutdownTime string = '1900'

@description('Optional. Timezone ID for the auto-shutdown schedule (e.g., "W. Europe Standard Time").')
param labShutdownTimeZoneId string = 'W. Europe Standard Time'

// --- Parameters for Custom Git Repo (Optional) ---
@description('Optional. URI of the Git repository for custom artifacts/formulas.')
param customRepoUri string = '' // Example: 'https://github.com/yourorg/your-lab-repo.git'

@description('Optional. Branch reference for the custom repository.')
param customRepoBranch string = 'main'

@description('Optional. Folder path for custom artifacts.')
param customArtifactRepoFolderPath string = '/Artifacts'

@description('Optional. Folder path for custom formulas/environments.')
param customEnvironmentRepoFolderPath string = '/Formulas'

@description('Optional. Type of the custom repository (GitHub, VsoGit).')
@allowed([ '', 'GitHub', 'VsoGit' ])
param customRepoType string = ''

@description('Optional. Name of the secret in the Lab Key Vault holding the PAT for the custom repo.')
param customRepoPatSecretName string = '' // Example: 'lab-repo-pat'

// --- General Parameters ---
@description('Optional. Tags to apply to all resources.')
param resourceTags object = {
  Environment: environmentName
  Project: projectName
  CreationDate: utcNow('yyyy-MM-dd')
  CreatedBy: 'Bicep-DTL-Main'
}

// ==================================
//          VARIABLES
// ==================================
var keyVaultName = 'kv-${projectName}-${environmentName}-${location}-${padLeft(instanceNumber, 3, '0')}'
var storageAccountName = 'st${replace(projectName, '-', '')}${environmentName}${location}${padLeft(instanceNumber, 3, '0')}' // Needs to be globally unique, shorter
var labName = 'dtl-${projectName}-${environmentName}-${location}-${padLeft(instanceNumber, 3, '0')}'

// ==================================
//          MODULES
// ==================================

@description('Deploys the Key Vault associated with the DevTest Lab.')
module keyVaultModule '../shared/keyvault.bicep' = { // Reference shared module
  name: 'deploy-lab-keyvault-${environmentName}-${instanceNumber}'
  params: {
    keyVaultName: keyVaultName
    location: location
    skuName: 'standard' // Or parameterize if needed
    enableRbacAuthorization: true // Use RBAC
    enablePurgeProtection: true
    resourceTags: resourceTags
  }
}

@description('Deploys the Storage Account associated with the DevTest Lab.')
module storageAccountModule '../shared/storageaccount.bicep' = { // Reference shared module
  name: 'deploy-lab-storage-${environmentName}-${instanceNumber}'
  params: {
    storageAccountName: storageAccountName
    location: location
    skuName: 'Standard_LRS' // Or parameterize if needed
    kind: 'StorageV2'
    resourceTags: resourceTags
    allowBlobPublicAccess: false // Keep private
  }
}

@description('Deploys the DevTest Lab and its configurations.')
module labModule './lab.bicep' = { // Reference lab module in same folder
  name: 'deploy-lab-${environmentName}-${instanceNumber}'
  params: {
    labName: labName
    location: location
    virtualNetworkId: virtualNetworkId // Pass VNet ID from core deployment
    labSubnetName: devTestSubnetName // Pass Subnet Name from core deployment
    labStorageType: 'Premium' // Or parameterize
    environmentPermission: 'Reader' // Or parameterize
    shutdownTime: labShutdownTime
    shutdownTimeZoneId: labShutdownTimeZoneId
    shutdownNotificationEmail: labShutdownNotificationEmail
    // Pass custom repo details if provided
    customRepoUri: customRepoUri
    customRepoBranch: customRepoBranch
    customArtifactRepoFolderPath: customArtifactRepoFolderPath
    customEnvironmentRepoFolderPath: customEnvironmentRepoFolderPath
    customRepoType: customRepoType
    customRepoPatSecretName: customRepoPatSecretName
    customRepoKeyVaultId: keyVaultModule.outputs.keyVaultId // Pass the deployed KV ID for PAT lookup
    resourceTags: resourceTags
  }
  // Ensure Lab depends on the KV and SA being created
  dependsOn: [
    keyVaultModule
    storageAccountModule
  ]
}

// ==================================
//          OUTPUTS
// ==================================
@description('The resource ID of the deployed DevTest Lab.')
output labId string = labModule.outputs.labId

@description('The name of the deployed DevTest Lab.')
output labName string = labModule.outputs.labName

@description('The resource ID of the Key Vault associated with the Lab.')
output keyVaultId string = keyVaultModule.outputs.keyVaultId

@description('The name of the Key Vault associated with the Lab.')
output keyVaultName string = keyVaultModule.outputs.keyVaultName

@description('The resource ID of the Storage Account associated with the Lab.')
output storageAccountId string = storageAccountModule.outputs.storageAccountId

@description('The name of the Storage Account associated with the Lab.')
output storageAccountName string = storageAccountModule.outputs.storageAccountName

