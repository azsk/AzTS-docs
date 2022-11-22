@description('The name of Storage account resource.')
param storageAccountName string

@description('The name of Container resource.')
param containerName string

@description('The location of Storage account resource.')
param location string = resourceGroup().location

resource storageaccount 'Microsoft.Storage/storageAccounts@2021-04-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2' //[Azure_Storage_AuthN_Dont_Allow_Anonymous]
  properties: {
    minimumTlsVersion: 'TLS1_2' //Azure_Storage_DP_Use_Secure_TLS_Version_Trial
    supportsHttpsTrafficOnly: true //[Azure_Storage_DP_Encrypt_In_Transit]
    allowBlobPublicAccess: false //[Azure_Storage_AuthN_Dont_Allow_Anonymous]
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2021-04-01'= {
  name: '${storageAccountName}/default/${containerName}'
  properties: {
    publicAccess: 'None' //[Azure_Storage_AuthN_Dont_Allow_Anonymous]
  }
  dependsOn: [
    storageaccount
    ]
}
