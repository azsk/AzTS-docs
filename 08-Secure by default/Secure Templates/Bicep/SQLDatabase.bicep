@description('The name of the new database server to create.')
param serverName string

@description('The location of the database server.')
param serverLocation string

@description('The account name to use for the database server administrator.')
param administratorLogin string

@description('The password to use for the database server administrator.')
@secure()
param administratorLoginPassword string

@description('The name of the new database to create.')
param databaseName string

@description('The database collation for governing the proper use of characters.')
param collation string = 'SQL_Latin1_General_CP1_CI_AS'

@description('The type of database to create. The available options are: Web, Business, Basic, Standard, and Premium.')
param edition string = 'Basic'

@description('The maximum size, in bytes, for the database')
param maxSizeBytes string = '1073741824'

@description('The name corresponding to the performance level for edition. The available options are: Shared, Basic, S0, S1, S2, S3, P1, P2, and P3.')
param requestedServiceObjectiveName string = 'Basic'

@description('The name of the new storage account to create.')
param storageAccountName string

@description('Email address for alerts.')
param emailAddresses string = 'user@contoso.com'
param AAD_Admin_Login string
param AAD_Admin_ObjectID string
param AAD_TenantId string
param storageEndpoint string = 'https://${storageAccountName}.blob.core.windows.net'

@allowed([
  'Standard_LRS'
  'Standard_ZRS'
  'Standard_GRS'
  'Standard_RAGRS'
  'Premium_LRS'
])
param storageType string = 'Standard_GRS'

resource serverName_resource 'Microsoft.Sql/servers@2014-04-01-preview' = {
  name: serverName
  location: serverLocation
  properties: {
    administratorLogin: administratorLogin
    administratorLoginPassword: administratorLoginPassword
    version: '12.0'
  }
}

resource serverName_databaseName 'Microsoft.Sql/servers/databases@2014-04-01-preview' = {
  parent: serverName_resource
  name: '${databaseName}'
  location: serverLocation
  properties: {
    edition: edition
    collation: collation
    maxSizeBytes: maxSizeBytes
    requestedServiceObjectiveName: requestedServiceObjectiveName
  }
}

resource serverName_databaseName_current 'Microsoft.Sql/servers/databases/transparentDataEncryption@2014-04-01-preview' = {
  parent: serverName_databaseName
  name: 'current'
  location: null
  properties: {
    status: 'Enabled'
  }
  dependsOn: [
    serverName_resource
  ]
}

resource serverName_databaseName_Default 'Microsoft.Sql/servers/databases/auditingSettings@2015-05-01-preview' = {
  parent: serverName_databaseName
  name: 'default'
  location: serverLocation
  properties: {
    state: 'Enabled'
    storageEndpoint: storageEndpoint
    storageAccountAccessKey: listKeys(resourceId('Microsoft.Storage/storageAccounts', storageAccountName), providers('Microsoft.Storage', 'storageAccounts').apiVersions[0]).keys[0].value
    retentionDays: 0
    auditActionsAndGroups: [
      'SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP'
      'DATABASE_LOGOUT_GROUP'
      'USER_CHANGE_PASSWORD_GROUP'
    ]
    storageAccountSubscriptionId: subscription().subscriptionId
    isStorageSecondaryKeyInUse: false
  }
  dependsOn: [
    serverName_resource
  ]
}

resource serverName_AllowAllWindowsAzureIps 'Microsoft.Sql/servers/firewallrules@2014-04-01-preview' = {
  parent: serverName_resource
  location: serverLocation
  name: 'AllowAllWindowsAzureIps'
  properties: {
    endIpAddress: '0.0.0.0'
    startIpAddress: '0.0.0.0'
  }
}

resource serverName_Default 'Microsoft.Sql/servers/auditingSettings@2015-05-01-preview' = {
  parent: serverName_resource
  name: 'Default'
  location: serverLocation
  properties: {
    State: 'Enabled'
    storageEndpoint: storageEndpoint
    storageAccountAccessKey: listKeys(resourceId('Microsoft.Storage/storageAccounts', storageAccountName), providers('Microsoft.Storage', 'storageAccounts').apiVersions[0]).keys[0].value
    retentionDays: 0
    auditActionsAndGroups: null
    storageAccountSubscriptionId: subscription().subscriptionId
    isStorageSecondaryKeyInUse: false
  }
}

resource Microsoft_Sql_servers_securityAlertPolicies_serverName_Default 'Microsoft.Sql/servers/securityAlertPolicies@2015-05-01-preview' = {
  parent: serverName_resource
  name: 'Default'
  properties: {
    state: 'Enabled'
    disabledAlerts: ''
    emailAddresses: emailAddresses
    emailAccountAdmins: 'Enabled'
    storageEndpoint: storageEndpoint
    storageAccountAccessKey: listKeys(resourceId('Microsoft.Storage/storageAccounts', storageAccountName), providers('Microsoft.Storage', 'storageAccounts').apiVersions[0]).keys[0].value
    retentionDays: 0
  }
  dependsOn: [
    serverName_databaseName
    serverName_Default
  ]
}

resource serverName_activeDirectory 'Microsoft.Sql/servers/administrators@2014-04-01-preview' = {
  parent: serverName_resource
  name: 'activeDirectory'
  location: serverLocation
  properties: {
    administratorType: 'ActiveDirectory'
    login: AAD_Admin_Login
    sid: AAD_Admin_ObjectID
    tenantId: AAD_TenantId
  }
  dependsOn: [
    serverName_databaseName
    serverName_Default
  ]
}