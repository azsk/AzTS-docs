@description('Synapse workspace name')
param synapseWorkspaceName string

@description('url of the data lake storage account which we need to associate with synapse workspace')
param dataLakeStorageAccountUrl string

@description('File system name to associate with data lake storage and synapse workspace')
param dataLakeStorageFileSystem string

@description('sql admin user ')
param sqlAdminUser string

@description('Password for sql admin user.')
param sqlAdminUserPassword string

@description('Storage account id to which the diagnostic logs and metrices will be sent.')
param storageAccountId string

resource synapseWorkspace 'Microsoft.Synapse/workspaces@2019-06-01-preview' = {
  name: synapseWorkspaceName
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    defaultDataLakeStorage: {
      accountUrl: dataLakeStorageAccountUrl
      filesystem: dataLakeStorageFileSystem
    }
    sqlAdministratorLogin: sqlAdminUser
    sqlAdministratorLoginPassword: sqlAdminUserPassword
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
        enabled: true
      }
      {
        category: 'GatewayApiRequests'
        enabled: true
      }
      {
        category: 'BuiltinSqlReqsEnded'
        enabled: true
      }
      {
        category: 'IntegrationPipelineRuns'
        enabled: true
      }
      {
        category: 'IntegrationActivityRuns'
        enabled: true
      }
      {
        category: 'IntegrationTriggerRuns'
        enabled: true
      }
      {
        category: 'SynapseLinkEvent'
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