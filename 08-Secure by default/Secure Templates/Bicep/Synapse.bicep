@description('Synapse workspace name.')
param synapseWorkspaceName string

@description('Url of the data lake storage account which we need to associate with synapse workspace.')
param dataLakeStorageAccountName string

@description('File system name to associate with data lake storage and synapse workspace.')
param dataLakeStorageFileSystem string

@description('Storage account id to which the diagnostic logs and metrices will be sent.')
param storageAccountId string

resource synapseWorkspace 'Microsoft.Synapse/workspaces@2021-06-01' = {
  name: synapseWorkspaceName
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    defaultDataLakeStorage: {
      accountUrl: 'https://${dataLakeStorageAccountName}.dfs.core.windows.net'
      filesystem: dataLakeStorageFileSystem
    }
    azureADOnlyAuthentication: true
  }
}

resource diag_synapseWorkspace 'Microsoft.Insights/diagnosticsettings@2017-05-01-preview' = {
  scope: synapseWorkspace
  name: 'diag-${synapseWorkspaceName}'
  properties: {
    storageAccountId: resourceId('Microsoft.Storage/storageAccounts', storageAccountId)
    logs: [
      {
        category: 'SynapseRbacOperations'
        categoryGroup: null
        enabled: true
        retentionPolicy: {
          days: 90
          enabled: false
        }
      }
      {
        category: 'GatewayApiRequests'
        categoryGroup: null
        enabled: true
        retentionPolicy: {
          days: 90
          enabled: false
        }
      }
      {
        category: 'BuiltinSqlReqsEnded'
        categoryGroup: null
        enabled: true
        retentionPolicy: {
          days: 90
          enabled: false
        }
      }
      {
        category: 'IntegrationPipelineRuns'
        categoryGroup: null
        enabled: true
        retentionPolicy: {
          days: 90
          enabled: false
        }
      }
      {
        category: 'IntegrationActivityRuns'
        categoryGroup: null
        enabled: true
        retentionPolicy: {
          days: 90
          enabled: false
        }
      }
      {
        category: 'IntegrationTriggerRuns'
        categoryGroup: null
        enabled: true
        retentionPolicy: {
          days: 90
          enabled: false
        }
      }
      {
        category: 'SynapseLinkEvent'
        categoryGroup: null
        enabled: true
        retentionPolicy: {
          days: 90
          enabled: false
        }
      }
      {
        category: 'SQLSecurityAuditEvents'
        categoryGroup: null
        enabled: true
        retentionPolicy: {
          days: 90
          enabled: false
        }
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
