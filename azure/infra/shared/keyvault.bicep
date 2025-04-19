// Reusable Module for deploying Azure Key Vault
// Location: infra/shared/keyvault.bicep

targetScope = 'resourceGroup'

// ==================================
//          PARAMETERS
// ==================================
@description('Required. Name of the Key Vault.')
param keyVaultName string

@description('Required. Azure region for the Key Vault.')
param location string = resourceGroup().location

@description('Required. SKU name for the Key Vault.')
@allowed([
  'standard'
  'premium'
])
param skuName string = 'standard'

@description('Optional. Specifies whether Azure RBAC is used for authorization instead of access policies.')
param enableRbacAuthorization bool = true // Defaulting to RBAC best practice

@description('Optional. Specifies whether Soft Delete is enabled.')
param enableSoftDelete bool = true

@description('Optional. Number of days to retain soft-deleted secrets (7-90).')
@minValue(7)
@maxValue(90)
param softDeleteRetentionInDays int = 90 // Increased default retention

@description('Optional. Specifies whether Purge Protection is enabled (recommended).')
param enablePurgeProtection bool = true

@description('Optional. Tags to apply to the Key Vault.')
param resourceTags object = {}

// ==================================
//          VARIABLES
// ==================================
var tenantId = tenant().tenantId // Get tenant ID dynamically

// ==================================
//          RESOURCES
// ==================================
@description('Azure Key Vault resource.')
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = { // Updated API Version
  name: keyVaultName
  location: location
  tags: resourceTags
  properties: {
    sku: {
      family: 'A'
      name: skuName
    }
    tenantId: tenantId
    enableRbacAuthorization: enableRbacAuthorization
    enabledForDeployment: true // Usually required
    enabledForTemplateDeployment: true // Usually required
    enabledForDiskEncryption: false // Only enable if needed for ADE
    enableSoftDelete: enableSoftDelete
    softDeleteRetentionInDays: softDeleteRetentionInDays
    enablePurgeProtection: enablePurgeProtection ? enableSoftDelete : null // Purge protection requires soft delete
    publicNetworkAccess: 'Enabled' // Consider 'Disabled' and use Private Endpoints for higher security
  }
}

// NOTE: Role Assignments for RBAC are typically done outside this module,
// potentially in the calling template or via separate RBAC assignments.
// Example (if done here, requires principalId and roleDefinitionId as parameters):
/*
param keyVaultAdminPrincipalId string // e.g., User/Group/SPN Object ID

resource adminRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, keyVaultAdminPrincipalId, 'KeyVaultAdmin') // Unique name for role assignment
  scope: keyVault // Assign role at the Key Vault scope
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '00482a5a-887f-4fb3-b363-3b7fe8e74483') // Key Vault Administrator role ID
    principalId: keyVaultAdminPrincipalId
    principalType: 'User' // Or 'Group', 'ServicePrincipal'
  }
}
*/

// ==================================
//          OUTPUTS
// ==================================
@description('The resource ID of the deployed Key Vault.')
output keyVaultId string = keyVault.id

@description('The name of the deployed Key Vault.')
output keyVaultName string = keyVault.name

@description('The URI of the deployed Key Vault.')
output keyVaultUri string = keyVault.properties.vaultUri

