@description('Name of the Name Space')
param namespace_name string

@description('Name of the NotificationHub')
param notificationHub_name string
param location string = 'East US'

resource namespace_name_resource 'Microsoft.NotificationHubs/namespaces@2014-09-01' = {
  sku: {
    name: 'Basic'
  }
  kind: 'NotificationHub'
  name: namespace_name
  location: location
  tags: {}
  scale: null
  properties: {
    namespaceType: 'NotificationHub'
  }
  dependsOn: []
}

resource namespace_name_notificationHub_name 'Microsoft.NotificationHubs/namespaces/notificationHubs@2014-09-01' = {
  parent: namespace_name_resource
  name: '${notificationHub_name}'
  location: location
  scale: null
  properties: {
    authorizationRules: []
  }
}

resource namespace_name_notificationHub_name_DefaultFullSharedAccessSignature 'Microsoft.NotificationHubs/namespaces/notificationHubs/authorizationRules@2016-03-01' = {
  parent: namespace_name_notificationHub_name
  name: 'DefaultFullSharedAccessSignature'
  properties: {
    rights: [
      'Listen'
      'Send'
    ]
  }
}