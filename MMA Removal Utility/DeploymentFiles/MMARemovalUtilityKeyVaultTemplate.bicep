param resourceHash string

@description('Specifies the name of the key vault.')
param keyVaultName string

@description('Specifies the Azure location where the key vault should be created.')
param location string = resourceGroup().location

@description('Specifies the Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. Get it by using Get-AzSubscription cmdlet.')
param tenantId string = subscription().tenantId

@description('Specifies whether the key vault sku is standard or premium.')
@allowed([
  'standard'
  'premium'
])
param skuName string = 'standard'

@description('Specifies the name of the secret that you want to create.')
param secretName string

@description('Specifies the value of the secret that you want to create.')
@secure()
param secretValue string

@description('The workspace data retention in days. -1 means Unlimited retention for the Unlimited Sku.')
param laRetentionInDays int = 365

@description('The workspace daily quota for ingestion. -1 means unlimited.')
param laDailyQuotaGb int = -1

@description('Specifies the sku for log analytics.')
@allowed([
  'pergb2018'
  'Premium'
  'Standalone'
  'Standard'
])
param laSkuName string = 'pergb2018'

var laWorkspaceName = 'MMARemovalUtility-LAWSForAuditing-${resourceHash}'
var diagnosticSettingsName = 'MMARemovalUtility-AuditSetting-${resourceHash}'

resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: keyVaultName
  location: location
  tags: {
    AzTSMMARemovalUtilityIdentifier: resourceHash
  }
  properties: {
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    tenantId: tenantId
    sku: {
      name: skuName
      family: 'A'
    }
    networkAcls: {
      defaultAction: 'Deny'
      ipRules: []
    }
    accessPolicies: []
  }
}

resource keyVaultName_secret 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  parent: keyVault
  name: secretName
  properties: {
    value: secretValue
  }
}

resource laWorkspace 'Microsoft.OperationalInsights/workspaces@2020-03-01-preview' = {
  name: '${laWorkspaceName}-${resourceHash}'
  tags: {
    AzTSMMARemovalUtilityIdentifier: resourceHash
  }
  location: location
  properties: {
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    retentionInDays: laRetentionInDays
    sku: {
      name: laSkuName
    }
    workspaceCapping: {
      dailyQuotaGb: laDailyQuotaGb
    }
  }
  dependsOn: [
    keyVault
  ]
}

resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: keyVault
  name: diagnosticSettingsName
  properties: {
    workspaceId: laWorkspace.id
    logs: [
      {
        category: 'AuditEvent'
        enabled: true
      }
    ]
  }
}

output keyVaultResourceId string = keyVault.id
output secretURI string = keyVaultName_secret.properties.secretUri
output logAnalyticsResourceId string = laWorkspace.id
