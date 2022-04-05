@description('''
The name of the new SQL database server to create.
Use only lowercase letters, numbers and hyphens.
The name must not start or end with a hyphen and must be 1 - 63 characters in length.
The name must be unique across Azure.
''')
@minLength(1)
@maxLength(63)
param sqlServerName string = 'sql-server-${uniqueString(resourceGroup().id, utcNow())}'

@description('The Azure region of the database server. The default location is same as the enclosing Resource Group\'s location.')
param sqlServerLocation string = resourceGroup().location

@description('The account name to use for the database server administrator.')
@secure()
param sqlServerAdministratorLogin string

@description('The password to use for the database server administrator.')
@secure()
param sqlServerAdministratorLoginPassword string

@description('Specify the SQL server administrator settings.')
param sqlServerAdministratorSettings object

@description('''
Specify the name of the storage account for storing the SQL server auditing logs.
This storage account must be in the same Resource Group as that of the SQL server being created.
If no storage account is configured, a new storage account will be created with the same name and used for SQL server auditing.
''')
param sqlServerAuditingStorageAccountSettings object = {
  useExistingStorageAccount: false
  storageAccountName: 'sa${toLower(utcNow())}'
  storageAccountKind: 'StorageV2'
  storageAccountSkuName: 'Standard_LRS'
}

@description('Specify the retention period for the SQL server auditing logs in the storage account. Specify \'0\' to retain the logs for ever.')
@minValue(0)
param sqlServerAuditingStorageAccountRetentionPeriodInDays int = 0

@description('Specifies an array of e-mail addresses to which the alert is sent.')
param sqlServerThreatDetectionEmailAddresses array = []

@description('Specifies the list of SQL databases to be created in the SQL database server.')
param sqlDatabases array = []

// Flag to indicate if an existing storage account is to be used to store the SQL server auditing logs.
var useExistingStorageAccountForSqlServerAuditing = sqlServerAuditingStorageAccountSettings.useExistingStorageAccount

resource sqlServer 'Microsoft.Sql/servers@2021-08-01-preview' = {
  name: sqlServerName
  location: sqlServerLocation
  properties: {
    administratorLogin: sqlServerAdministratorLogin
    administratorLoginPassword: sqlServerAdministratorLoginPassword
  }

  // To enable Azure Active Directory (AAD) authentication on the SQL server.
  // Azure_SQLDatabase_AuthZ_Use_AAD_Admin - Enable Azure AD admin for the SQL Database.
  resource sqlAdministrator 'administrators@2021-08-01-preview' = {
    name: 'ActiveDirectory'
    properties: {
      administratorType: 'ActiveDirectory'
      login: sqlServerAdministratorSettings.sqlServerAdministratorLoginName
      sid: sqlServerAdministratorSettings.sqlServerAdministratorSID
      tenantId: tenant().tenantId
    }
  }

  // Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server - To enable auditing on the SQL server.
  resource sqlServerAuditingSettings 'auditingSettings@2021-08-01-preview' = {
    name: 'default'
    properties: {
      isStorageSecondaryKeyInUse: false
      retentionDays: sqlServerAuditingStorageAccountRetentionPeriodInDays
      state: 'Enabled' // Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server - To enable auditing on the SQL server.
      storageAccountAccessKey: listKeys(resourceId('Microsoft.Storage/storageAccounts', sqlServerAuditingStorageAccountSettings.storageAccountName), providers('Microsoft.Storage', 'storageAccounts').apiVersions[0]).keys[0].value
      storageAccountSubscriptionId: subscription().subscriptionId
      storageEndpoint: useExistingStorageAccountForSqlServerAuditing ? existingStorageAccount.properties.primaryEndpoints.blob : newStorageAccount.properties.primaryEndpoints.blob
    }
  }

  // Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server - To configure threat detection on the SQL server.
  resource sqlServerSecurityAlertPolicies 'securityAlertPolicies@2021-08-01-preview' = {
    name: 'Default'
    properties: {
      disabledAlerts: [] // Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server - Ensure no alerts are disabled.
      emailAccountAdmins: true // Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server - Ensure email to administrators on alerts is enabled.
      emailAddresses: sqlServerThreatDetectionEmailAddresses // // Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server - Configure email addresses to receive alerts on the SQL server.
      retentionDays: sqlServerAuditingStorageAccountRetentionPeriodInDays
      state: 'Enabled' // Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server - To configure threat detection on the SQL server.
      storageAccountAccessKey: listKeys(resourceId('Microsoft.Storage/storageAccounts', sqlServerAuditingStorageAccountSettings.storageAccountName), providers('Microsoft.Storage', 'storageAccounts').apiVersions[0]).keys[0].value
      storageEndpoint: useExistingStorageAccountForSqlServerAuditing ? existingStorageAccount.properties.primaryEndpoints.blob : newStorageAccount.properties.primaryEndpoints.blob
    }
  }
}

// Create SQL database(s) in the SQL server.
module sqlDatabaseResource 'SQLDatabase.bicep' = [for sqlDatabase in sqlDatabases: {
  name: sqlDatabase.name
  params: {
    sqlServerName: sqlServer.name
    sqlDatabaseName: sqlDatabase.name
    sqlDatabaseLocation: sqlServer.location
    sqlDatabaseEnableTde: true // Azure_SQLDatabase_DP_Enable_TDE - Enable Transparent Data Encryption (TDE) on the SQL database.
  }
}]

// Fetch an existing storage account for storing the SQL server auditing logs.
resource existingStorageAccount 'Microsoft.Storage/storageAccounts@2021-08-01' existing = if (useExistingStorageAccountForSqlServerAuditing) {
  name: sqlServerAuditingStorageAccountSettings.storageAccountName
}

// Create a new storage account for storing the SQL server auditing logs.
resource newStorageAccount 'Microsoft.Storage/storageAccounts@2021-08-01' = if (!useExistingStorageAccountForSqlServerAuditing) {
  name: sqlServerAuditingStorageAccountSettings.storageAccountName
  kind: sqlServerAuditingStorageAccountSettings.storageAccountKind
  location: sqlServerLocation
  sku: {
    name: sqlServerAuditingStorageAccountSettings.storageAccountSkuName
  }
}
