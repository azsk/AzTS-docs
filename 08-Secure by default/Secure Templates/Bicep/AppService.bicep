@description('Name of the web app')
param appservicename string

@description('Name of the App Service Plan')
param serviceplanname string

@description('Location of AppService')
param location string = 'South Central US'

resource serviceplanname_resource 'Microsoft.Web/serverfarms@2016-09-01' = {
  name: serviceplanname
  location: location
  properties: {}
  sku: {
    name: 'S1'
    tier: 'Standard'
    size: 'S1'
    capacity: 2
  }
}

resource appservicename_resource 'Microsoft.Web/sites@2016-08-01' = {
  name: appservicename
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: serviceplanname_resource.id
    httpsOnly: true
    siteConfig: {
      alwaysOn: true
      use32BitWorkerProcess: false
      requestTracingEnabled: true
      httpLoggingEnabled: true
      detailedErrorLoggingEnabled: true
      remoteDebuggingEnabled: false
      webSocketsEnabled: false
      siteAuthEnabled: true
      netFrameworkVersion: 'v4.7'
      siteAuthSettings: {
        clientId: '***********ClientId*********'
      }
    }
  }
}