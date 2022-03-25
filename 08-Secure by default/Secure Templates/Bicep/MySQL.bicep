param servers_mysqldbserver_name string = 'mysqldbserver'
param MySQL_Location string = 'Enter MySQL Database location'
param sku_name string = 'Enter sku name'
param sku_tier string = 'Enter sku tier'
param sku_generation string = 'Enter sku generation'
param storageMB int = 'Enter storageMB'
param version int = 'Enter version'
param start_IP string = 'Enter start_IP'
param end_IP string = 'Enter end_IP'

resource servers_mysqldbserver_name_resource 'Microsoft.DBforMySQL/servers@2017-12-01' = {
  name: servers_mysqldbserver_name
  location: MySQL_Location
  sku: {
    name: sku_name
    tier: sku_tier
    family: sku_generation
    capacity: 2
  }
  properties: {
    storageProfile: {
      storageMB: storageMB
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
      storageAutoGrow: 'Disabled'
    }
    version: version
    sslEnforcement: 'Enabled'
  }
}

resource servers_mysqldbserver_name_AllowAll 'Microsoft.DBforMySQL/servers/firewallRules@2017-12-01' = {
  parent: servers_mysqldbserver_name_resource
  name: 'AllowAll'
  properties: {
    startIpAddress: start_IP
    endIpAddress: end_IP
  }
}

resource servers_mysqldbserver_name_AllowAllWindowsAzureIps 'Microsoft.DBforMySQL/servers/firewallRules@2017-12-01' = {
  parent: servers_mysqldbserver_name_resource
  name: 'AllowAllWindowsAzureIps'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}