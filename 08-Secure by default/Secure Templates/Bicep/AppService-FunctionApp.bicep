@description('Name of the Function App resource.')
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

resource appServiceName_resource 'Microsoft.Web/sites@2018-11-01' = {
  name: appServiceName
  location: location
  kind: 'functionapp'
  properties: {
    httpsOnly: true //Azure_AppService_DP_Dont_Allow_HTTP_Access
    siteConfig: {
      	remoteDebuggingEnabled: false //Azure_AppService_Config_Disable_Remote_Debugging
      	minTlsVersion: '1.2' //Azure_AppService_DP_Use_Secure_TLS_Version
    }
  }
}
resource appServiceName_ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-01-01' = {
  parent: appServiceName_resource
  name: 'ftp'
  location: location
  properties: {
    allow: false //Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth
  }
}
resource appServiceName_scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-01-01' = {
  parent: appServiceName_resource
  name: 'scm'
  location: location
  properties: {
    allow: false //Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth
  }
}
resource appServiceName_WebUISlotName 'Microsoft.Web/sites/slots@2015-08-01' = if (isAdditionalSlotRequired) {
  name: '${appServiceName}/AdditionalSlot'
  location: location
  kind: 'functionapp'
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
resource appServiceName_AdditionalSlot_ftp 'Microsoft.Web/sites/slots/basicPublishingCredentialsPolicies@2023-01-01' = if (isAdditionalSlotRequired) {
  parent: appServiceName_WebUISlotName
  name: 'ftp'
  location: location
  properties: {
    allow: false //Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth
  }
  dependsOn: [

    appServiceName_resource
  ]
}

resource appServiceName_AdditionalSlot_scm 'Microsoft.Web/sites/slots/basicPublishingCredentialsPolicies@2023-01-01' = if (isAdditionalSlotRequired) {
  parent: appServiceName_WebUISlotName
  name: 'scm'
  location: location
  properties: {
    allow: false //Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth
  }
  dependsOn: [

    appServiceName_resource
  ]
}
