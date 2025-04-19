// Reusable Module for deploying Azure Storage Account
// Location: infra/shared/storageaccount.bicep

targetScope = 'resourceGroup'

// ==================================
//          PARAMETERS
// ==================================
@description('Required. Name of the Storage Account. Must be globally unique, 3-24 characters, lowercase letters and numbers only.')
@minLength(3)
@maxLength(24)
param storageAccountName string

@description('Required. Azure region for the Storage Account.')
param location string = resourceGroup().location

@description('Required. SKU name for the Storage Account.')
@allowed([
  'Standard_LRS'
  'Standard_GRS'
  'Standard_RAGRS'
  'Standard_ZRS'
  'Premium_LRS'
  'Premium_ZRS'
])
param skuName string = 'Standard_LRS'

@description('Required. Kind of Storage Account.')
@allowed([
  'StorageV2'
  'BlobStorage'
  'FileStorage'
  // Add others if needed, StorageV2 is most common
])
param kind string = 'StorageV2'

@description('Optional. Access tier for Blob storage.')
@allowed([
  'Hot'
  'Cool'
])
param accessTier string = 'Hot'

@description('Optional. Minimum TLS version.')
@allowed([
  'TLS1_0'
  'TLS1_1'
  'TLS1_2'
])
param minimumTlsVersion string = 'TLS1_2'

@description('Optional. Allow public access to blobs.')
param allowBlobPublicAccess bool = false

@description('Optional. Tags to apply to the Storage Account.')
param resourceTags object = {}

// ==================================
//          RESOURCES
// ==================================
@description('Azure Storage Account resource.')
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = { // Updated API Version
  name: storageAccountName
  location: location
  tags: resourceTags
  sku: {
    name: skuName
  }
  kind: kind
  properties: {
    accessTier: (kind == 'StorageV2' || kind == 'BlobStorage') ? accessTier : null // Access tier applies to Blob/StorageV2
    minimumTlsVersion: minimumTlsVersion
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: allowBlobPublicAccess
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow' // Consider 'Deny' and use Private Endpoints or VNet Service Endpoints
    }
    // Removed explicit definitions for blob/file/queue/table services unless specific config needed
  }
}

// ==================================
//          OUTPUTS
// ==================================
@description('The resource ID of the deployed Storage Account.')
output storageAccountId string = storageAccount.id

@description('The name of the deployed Storage Account.')
output storageAccountName string = storageAccount.name

@description('The primary endpoint object for the Storage Account.')
output primaryEndpoints object = storageAccount.properties.primaryEndpoints

