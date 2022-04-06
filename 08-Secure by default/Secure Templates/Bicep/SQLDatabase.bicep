@description('''
Specify the name of an existing SQL database server in which the database is to be created.
Use only lowercase letters, numbers and hyphens.
The name must not start or end with a hyphen and must be 1 - 63 characters in length.
''')
@minLength(1)
@maxLength(63)
param sqlServerName string

@description('''
Specify the name of the new SQL database to create.
The following characters are not allowed: \'<>*%&:\\/?\' or control characters.
The name must not start or end with a period or space and must be 1 - 128 characters in length.
The name of a database must be unique within the enclosing SQL server.
''')
@minLength(1)
@maxLength(128)
param sqlDatabaseName string = '${sqlServerName}-sql-database-${utcNow()}'

@description('Specify the Azure region where the SQL database is to be created. The default location is same as the enclosing Resource Group\'s location.')
param sqlDatabaseLocation string = resourceGroup().location

@description('Specify the SKU of the SQL database to create.')
param sqlDatabaseSku object = {
  name: 'Basic'
  capacity: 5
  tier: 'Basic'
}

@allowed([
  false
  true
])
@description('Specify whether Transparent Data Encryption (TDE) is to be enabled on the SQL database. Valid values: true, false. The default value is \'true\'.')
param sqlDatabaseEnableTde bool = true

resource sqlServer 'Microsoft.Sql/servers@2021-08-01-preview' existing = {
  name: sqlServerName
}
  
resource sqlDatabase 'Microsoft.Sql/servers/databases@2021-08-01-preview' = {
  name: sqlDatabaseName
  location: sqlDatabaseLocation
  parent: sqlServer
  sku: {
    name: sqlDatabaseSku.name
    capacity: sqlDatabaseSku.capacity
    tier: sqlDatabaseSku.tier
  }

  // Azure_SQLDatabase_DP_Enable_TDE - Enable Transparent Data Encryption (TDE) on the SQL database.
  resource sqlDatabaseTde 'transparentDataEncryption@2021-08-01-preview' = {
    name: 'current'
    properties: {
      state: sqlDatabaseEnableTde ? 'Enabled' : 'Disabled' // Azure_SQLDatabase_DP_Enable_TDE - Enable Transparent Data Encryption (TDE) on the SQL database.
    }
  }
}
