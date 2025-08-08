# RedisEnterprise

**Resource Type:** Microsoft.Cache/redisEnterprise 

<!-- TOC -->

- [Azure_RedisEnterprise_Audit_Enable_Diagnostic_Settings](#azure_redisenterprise_audit_enable_diagnostic_settings)
- [Azure_RedisEnterprise_BCDR_Configure_Allowed_Redundancy](#azure_redisenterprise_bcdr_configure_allowed_redundancy)
- [Azure_RedisEnterprise_BCDR_Use_RDB_Backup](#azure_redisenterprise_bcdr_use_rdb_backup)
- [Azure_RedisEnterprise_DP_Use_TLS_Encrypted_Connections](#azure_redisenterprise_dp_use_tls_encrypted_connections)

<!-- /TOC -->
<br/>

___ 

## Azure_RedisEnterprise_Audit_Enable_Diagnostic_Settings 

### Display Name 
Enable security logging in Redis Enterprise

### Rationale 
Enabling diagnostic settings Connection Events collects information on client connections to your cache. Logging and analysing this diagnostic setting helps you understand who is connecting to your caches and the timestamp of those connections which could be used to identify the scope of a security breach and for security auditing purposes.

### Control Spec 

> **Passed:** 
> 1. Required diagnostic logs are enabled.
>
>       and
>
> 2. At least one of the below setting configured:
> a. Log Analytics.
> b. Storage account 
> c. Event Hub.
> 
> **Failed:** 
> 1. Diagnostics setting is disabled for resource.
> 
>       or
>
> 2. Diagnostic settings meet the following conditions:
> a. All diagnostic logs are not enabled.
> b. None of the below setting is configured:
> i. Log Analytics.
> ii. Storage account 
> iii. Event Hub.
> 
> **Error:** 
> Required logs are not configured in control settings.
> 
> 
### Recommendation 

- **Azure Portal** 

To enable diagnostic settings, refer https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-monitor-diagnostic-settings?tabs=enterprise-enterprise-flash#enable-connection-logging-using-the-azure-portal
      
### Azure Policies or REST APIs used for evaluation 

- REST API to get resource details of a Redis Enterprise resources: 
/subscriptions/{subscriptionId}/providers/Microsoft.Cache/redisEnterprise?api-version=2024-02-01

- REST API to list diagnostic setting details of Redis Enterprise resources: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cache/redisEnterprise/{redisEnterproseName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** 
name<br />
properties.logs.category<br />
properties.logs.enabled<br />
properties.logs.retentionPolicy.enabled<br />
properties.logs.retentionPolicy.days<br />
properties.workspaceId<br />
properties.storageAccountId<br />
properties.eventHubName<br />
 <br />

<br />

___ 

## Azure_RedisEnterprise_BCDR_Configure_Allowed_Redundancy

### Display Name
Redis Enterprise must configure appropriate redundancy for business continuity

### Rationale
Redis Enterprise requires proper redundancy configuration for high availability and disaster recovery scenarios. Configuring zone or geo redundancy ensures that enterprise workloads can maintain availability during infrastructure failures and meets enterprise-level SLA requirements.

### Control Settings{
    "AllowedRedundancyTypes": ["Zone", "Geo"],
    "RequireActiveReplication": true,
    "MinimumZones": 2,
    "RequireActiveGeoReplication": false
}
### Control Spec

> **Passed:**
> Redis Enterprise cluster is configured with appropriate redundancy (Zone or Geo redundancy) and meets replication requirements.
>
> **Failed:**
> Redis Enterprise cluster does not have appropriate redundancy configured or replication requirements are not met.

### Recommendation

- **Azure Portal**

    Go to Azure Portal ? Redis Enterprise ? Configuration ? High Availability ? Configure zone redundancy across multiple availability zones ? Enable active geo-replication if required for disaster recovery ? Verify minimum zone distribution requirements.

- **PowerShell**
```powershell
# Create Redis Enterprise with zone redundancy
New-AzRedisEnterpriseCache -ResourceGroupName $rgName -Name $clusterName -Location $location -Sku "Enterprise_E10" -Zone @("1", "2", "3")

# Configure active geo-replication
New-AzRedisEnterpriseCacheDatabase -ClusterName $clusterName -ResourceGroupName $rgName -Name "default" -GeoReplication @{
        LinkedDatabases = @($linkedDatabaseId)
    }
```
### Azure Policies or REST APIs used for evaluation

- REST API to get Redis Enterprise cluster details: /subscriptions/{subscriptionId}/providers/Microsoft.Cache/redisEnterprise?api-version=2024-02-01<br />
**Properties:** properties.zones, properties.highAvailability, properties.geoReplication<br />

- REST API to get database configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cache/redisEnterprise/{clusterName}/databases?api-version=2024-02-01<br />
**Properties:** properties.geoReplication, properties.clustering<br />

<br />

___

## Azure_RedisEnterprise_BCDR_Use_RDB_Backup

### Display Name
Redis Enterprise must use RDB backup for data protection

### Rationale
RDB backups provide point-in-time recovery capabilities and ensure data can be restored in case of corruption or accidental deletion. For enterprise workloads, regular backups are essential for meeting recovery time and recovery point objectives, and compliance with data protection regulations.

### Control Settings{
    "RequireRDBBackup": true,
    "MinimumBackupFrequency": "Daily",
    "BackupRetentionDays": 30,
    "RequireAutomatedBackup": true
}
### Control Spec

> **Passed:**
> Redis Enterprise database has RDB backup configured with appropriate frequency and retention settings.
>
> **Failed:**
> Redis Enterprise database does not have RDB backup enabled or backup settings do not meet minimum requirements.

### Recommendation

- **Azure Portal**

    Go to Azure Portal ? Redis Enterprise ? Databases ? Select database ? Data persistence ? Enable RDB backup ? Configure backup frequency (minimum daily) ? Set retention period (minimum 30 days) ? Verify automated backup schedule.

- **PowerShell**
```powershell
# Configure RDB backup for Redis Enterprise database
Update-AzRedisEnterpriseCacheDatabase -ClusterName $clusterName -ResourceGroupName $rgName -Name "default" -Persistence @{
    RdbEnabled = $true
    RdbFrequency = "24h"
    RdbStorageConnectionString = $storageConnectionString
}

# Verify backup configuration
Get-AzRedisEnterpriseCacheDatabase -ClusterName $clusterName -ResourceGroupName $rgName -Name "default"
```
### Azure Policies or REST APIs used for evaluation

- REST API to get database persistence configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cache/redisEnterprise/{clusterName}/databases/{databaseName}?api-version=2024-02-01<br />
**Properties:** properties.persistence.rdbEnabled, properties.persistence.rdbFrequency, properties.persistence.rdbStorageConnectionString<br />

<br />

___ 

## Azure_RedisEnterprise_DP_Use_TLS_Encrypted_Connections 

### Display Name 
Use approved version of TLS and secure client protocol for Redis Enterprise

### Rationale 
Use of TLS encrypted connections ensures secure connection over network and protects data in transit from network layer man-in-the-middle, eavesdropping, session-hijacking attacks.

### Control Spec 

> **Passed:** 
> ClientProtocol is set to 'TLS-encrypted' for all the databases associated with the Redis Enterprise Cluster and minTLSVersion >= 1.2.
> 
> **Failed:** 
> ClientProtocol is set to 'PlainText' for any database associated with the Redis Enterprise Cluster or minTLSVersion < 1.2.
> 
### Recommendation 

- **Azure Portal** 

To set the minimum required version use command: Update-AzRedisEnterpriseCache  -Name <RedisEnterpriseName> -ResourceGroupName <ResourceGroupName> -MinimumTlsVersion '1.2'. To disable Non-TLS access using Azure portal: Select your Azure Redis Enterprise --> select Overview --> Under essentials click  'Plain text' --> Select the checkbox for 'Non-TLS access only' --> Click 'Save'.
  
      
### Azure Policies or REST APIs used for evaluation 

- REST API to get resource details of a Redis Enterprise resources: 
/subscriptions/{subscriptionId}/providers/Microsoft.Cache/redisEnterprise?api-version=2024-02-01

**Properties:** 
properties.minimumTlsVersion
 <br/>

- REST API to list databases associated with Redis Enterprise cluster: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cache/redisEnterprise/{resourceName}/databases?api-version=2024-02-01

<br />

**Properties:** 
properties.clientProtocol

 <br />

<br />

