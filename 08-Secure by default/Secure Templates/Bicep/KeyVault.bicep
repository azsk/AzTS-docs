@description('Name of the Key Vault')
param keyVaultName string

@description('Tenant Id for the subscription and use assigned access to the vault. Available from the Get-AzSubscription PowerShell cmdlet')
param tenantId string

@description('Access policies object to define access policies')
param accessPolicies array = []

@description('SKU for the vault')
@allowed([
  'Standard'
  'Premium'
])
param vaultSku string = 'Standard'

@description('Specifies if the vault is enabled for VM or Service Fabric deployment')
param enabledForDeployment bool = false

@description('Specifies if the vault is enabled for Disk Encryption')
param enabledForDiskEncryption bool = false

@description('Specifies if the vault is enabled for ARM template deployment')
param enabledForTemplateDeployment bool = false

@description('Specifies if the vault is enabled for volume encryption')
param enableVaultForVolumeEncryption bool = false

@description('Name of the Storage Account in which Diagnostic Logs should be saved.')
param storageAccountNameForDiagnostics string

resource keyVaultName_resource 'Microsoft.KeyVault/vaults@2015-06-01' = {
  name: keyVaultName
  location: resourceGroup().location
  tags: {
    displayName: 'KeyVault'
  }
  properties: {
    enableSoftDelete: true
    enabledForDiskEncryption: enabledForDiskEncryption
    enabledForDeployment: enabledForDeployment
    enabledForTemplateDeployment: enabledForTemplateDeployment
    enabledForVolumeEncryption: enableVaultForVolumeEncryption
    tenantId: tenantId
    accessPolicies: accessPolicies
    publicNetworkAccess: 'Disabled'
    sku: {
      name: vaultSku
      family: 'A'
    }
    networkAcls: {
      defaultAction: 'Deny'
    }
  }
}

resource keyVaultName_Microsoft_Insights_service 'Microsoft.KeyVault/vaults/providers/diagnosticSettings@2015-07-01' = {
  name: '${keyVaultName}/Microsoft.Insights/service'
  properties: {
    storageAccountId: resourceId('Microsoft.Storage/storageAccounts', storageAccountNameForDiagnostics)
    logs: [
      {
        category: 'AuditEvent'
        enabled: true
        retentionPolicy: {
          days: 365
          enabled: true
        }
      }
    ]
    metrics: [
      {
        timeGrain: 'PT1M'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
    ]
  }
  dependsOn: [
    keyVaultName_resource
  ]
}
