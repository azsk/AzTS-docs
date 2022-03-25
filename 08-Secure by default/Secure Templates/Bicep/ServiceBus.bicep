@description('Name of the Service Bus Namespace')
param serviceBusNamespaceName string

@description('Name of the Service Bus Topic')
param serviceBusTopicName string

@description('Name of the Storage account for storing logs')
param storageAccountNameForDiagnostics string

var sbVersion = '2015-08-01'

resource serviceBusNamespaceName_resource 'Microsoft.ServiceBus/namespaces@2015-08-01' = {
  name: serviceBusNamespaceName
  location: resourceGroup().location
  properties: {}
}

resource serviceBusNamespaceName_serviceBusTopicName 'Microsoft.ServiceBus/namespaces/Topics@[variables(\'sbVersion\')]' = {
  name: '${serviceBusNamespaceName}/${serviceBusTopicName}'
  properties: {
    path: serviceBusTopicName
  }
  dependsOn: [
    serviceBusNamespaceName_resource
  ]
}

resource serviceBusNamespaceName_serviceBusTopicName_AccessKey 'Microsoft.ServiceBus/namespaces/Topics/authorizationRules@2017-04-01' = {
  name: '${serviceBusNamespaceName}/${serviceBusTopicName}/AccessKey'
  properties: {
    rights: [
      'Listen'
    ]
  }
  dependsOn: [
    serviceBusNamespaceName_serviceBusTopicName
  ]
}

resource serviceBusNamespaceName_Microsoft_Insights_service 'Microsoft.ServiceBus/namespaces/providers/diagnosticSettings@2015-07-01' = {
  name: '${serviceBusNamespaceName}/Microsoft.Insights/service'
  properties: {
    storageAccountId: resourceId('Microsoft.Storage/storageAccounts', storageAccountNameForDiagnostics)
    logs: [
      {
        category: 'OperationalLogs'
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
    serviceBusNamespaceName_resource
  ]
}