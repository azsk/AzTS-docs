@description('Name of the Service Bus Namespace')
param serviceBusNamespaceName string

@description('Name of the Service Bus Topic')
param serviceBusTopicName string

@description('Name of the Storage account for storing logs')
param storageAccountNameForDiagnostics string


resource serviceBusNamespaceName_resource 'Microsoft.ServiceBus/namespaces@2022-01-01-preview' = {
  name: serviceBusNamespaceName
  location: resourceGroup().location
  properties: {
    minimumTlsVersion: '1.2'
  }
}

resource serviceBusNamespaceName_serviceBusTopicName 'Microsoft.ServiceBus/namespaces/Topics@2015-08-01' = {
  name: '${serviceBusNamespaceName}/${serviceBusTopicName}'
  properties: {
    path: serviceBusTopicName
  }
  dependsOn: [
    serviceBusNamespaceName_resource
  ]
  location: resourceGroup().location
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
