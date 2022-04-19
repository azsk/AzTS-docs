@description('Name of the Web App')
param appServiceName string

@description('Name of the App Service Plan')
param servicePlanName string

@description('Is additional deployment slot required?')
param isAdditionalSlotRequired bool = false

@description('The location of App Service resource.')
param location string = resourceGroup().location

resource servicePlanName_resource 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: servicePlanName
  location: location
  sku: {
    name: 'S1'
    tier: 'Standard'
    size: 'S1'
    capacity: 2
  }
}

resource appServiceName_resource 'Microsoft.Web/sites@2016-08-01' = {
  name: appServiceName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: servicePlanName_resource.id
    httpsOnly: true //Azure_AppService_DP_Dont_Allow_HTTP_Access
    siteConfig: {
      remoteDebuggingEnabled: false //Azure_AppService_Config_Disable_Remote_Debugging
      minTlsVersion: '1.2' //Azure_AppService_DP_Use_Secure_TLS_Version
    }
  }
}

resource appServiceName_WebUISlotName 'Microsoft.Web/sites/slots@2015-08-01' = if (isAdditionalSlotRequired) {
  name: '${appServiceName}/AdditionalSlot'
  location: location
  kind: 'app'
  tags: {
    displayName: 'WebAppSlots'
  }
  properties: {
    serverFarmId: servicePlanName_resource.id
    httpsOnly: true //Azure_AppService_DP_Dont_Allow_HTTP_Access
  }
  dependsOn: [
    appServiceName_resource
  ]
}
