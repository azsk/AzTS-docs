@description('Namespace of the Event Hub')
param eventHubNamespace string

@description('Name of the Event Hub')
param eventHubName string

@description('Name of existing Storage Acount for Diagnostics purpose')
param storageAccountNameForDiagnostics string
param AuthorizationRules string = 'RootManageSharedAccessKey'

resource eventHubNamespace_resource 'Microsoft.EventHub/namespaces@2022-01-01-preview' = {
  sku: {
    name: 'Standard'
    tier: 'Standard'
    capacity: 1
  }
  name: eventHubNamespace
  properties: {
       minimumTlsVersion: '1.2'
  }
  location: 'Central US'
}

resource eventHubNamespace_Microsoft_Insights_service 'Microsoft.EventHub/namespaces/providers/diagnosticSettings@2015-07-01' = {
  name: '${eventHubNamespace}/Microsoft.Insights/service'
  properties: {
    logs: [
      {
        category: 'ArchiveLogs'
        enabled: true
        retentionPolicy: {
          days: 365
          enabled: true
        }
      }
      {
        category: 'OperationalLogs'
        enabled: true
        retentionPolicy: {
          days: 365
          enabled: true
        }
      }
      {
        category: 'AutoScaleLogs'
        enabled: true
        retentionPolicy: {
          days: 365
          enabled: true
        }
      }
    ]
    metrics: [
      {
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
    ]
    storageAccountId: resourceId('Microsoft.Storage/storageAccounts', storageAccountNameForDiagnostics)
  }
  dependsOn: [
    eventHubNamespace_resource
  ]
}

resource eventHubNamespace_AuthorizationRules 'Microsoft.EventHub/namespaces/AuthorizationRules@2017-04-01' = {
  parent: eventHubNamespace_resource
  name: '${AuthorizationRules}'
  location: 'Central US'
  properties: {
    rights: [
      'Listen'
      'Manage'
      'Send'
    ]
  }
}

resource eventHubNamespace_eventHubName_AuthorizationRules 'Microsoft.EventHub/namespaces/eventhubs/authorizationRules@2017-04-01' = {
  parent: eventHubNamespace_eventHubName
  name: AuthorizationRules
  location: 'Central US'
  properties: {
    rights: [
      'Listen'
    ]
  }
  dependsOn: [
    eventHubNamespace_resource
  ]
}

resource eventHubNamespace_eventHubName 'Microsoft.EventHub/namespaces/eventhubs@2017-04-01' = {
  parent: eventHubNamespace_resource
  location: 'Central US'
  name: '${eventHubName}'
}