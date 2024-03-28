param workspaceName string

@description('Specifies the location for workspace.')
param location string

@description('Specifies the resource group name.')
param resourceGroupName string

@description('Name of the storage account.')
param storageAccountName string = 'sa${uniqueString(resourceGroup().id,workspaceName)}'

@description('Name of the key vault.')
param keyVaultName string = 'kv${uniqueString(resourceGroup().id,workspaceName)}'

@description('Name of ApplicationInsights.')
param applicationInsightsName string = 'ai${uniqueString(resourceGroup().id,workspaceName)}'

var tenantId = subscription().tenantId
var storageAccountId = resourceId(resourceGroupName, 'Microsoft.Storage/storageAccounts', storageAccountName)
var keyVaultId = resourceId(resourceGroupName, 'Microsoft.KeyVault/vaults', keyVaultName)
var applicationInsightId = resourceId(resourceGroupName, 'Microsoft.Insights/components', applicationInsightsName)

resource storageAccount 'Microsoft.Storage/storageAccounts@2022-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    encryption: {
      services: {
        blob: {
          enabled: true
        }
        file: {
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: {
      name: 'standard'
      family: 'A'
    }
    accessPolicies: []
    enableSoftDelete: true
    enablePurgeProtection: true
  }
}

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: applicationInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
}

resource workspace 'Microsoft.MachineLearningServices/workspaces@2023-10-01' = {
  name: workspaceName
  location: location
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
  kind: 'Default'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    friendlyName: workspaceName
    storageAccount: storageAccountId
    keyVault: keyVaultId
    applicationInsights: applicationInsightId
    hbiWorkspace: false
    managedNetwork: {
      isolationMode: 'Disabled'
    }
    v1LegacyMode: false
    publicNetworkAccess: 'Disabled'  // Azure_MachineLearningWorkspace_NetSec_Dont_Allow_Public_Network_Access
  }
  dependsOn: [
    applicationInsights
    storageAccount
    keyVault
  ]
}

// / Azure_MachineLearningWorkspace_Audit_Enable_Diagnostics_Log
resource diag_workspace 'Microsoft.Insights/diagnosticsettings@2021-05-01-preview' = {
  scope: workspace
  name: 'diag-${workspaceName}'
  properties: {
    storageAccountId: storageAccount.id
    logs: [
      {
        category: null
        categoryGroup: 'allLogs'
        enabled: true
      }
      {
        category: null
        categoryGroup: 'audit'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}
