# SQLDatabase

**Resource Type:** Microsoft.Sql/servers/databases

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_SQLDatabase_BCDR_Configure_Geo_Redundancy](#azure_sqldatabase_bcdr_configure_geo_redundancy)

<!-- /TOC -->
<br/>

___

## Azure_SQLDatabase_BCDR_Configure_Geo_Redundancy

### Display Name
SQL Database must be configured with geo-redundant backup

### Rationale
Geo-redundant backup provides protection against regional disasters by automatically replicating database backups to a paired region, ensuring business continuity and disaster recovery capabilities.

### Control Settings 
```json
{
    "RequiredBackupStorageRedundancy": ["Geo", "GeoZone"],
    "ExcludedDatabaseTypes": ["master", "tempdb", "model", "msdb"]
}
```

### Control Spec

> **Passed:**
> SQL Database is configured with geo-redundant backup storage.
>
> **Failed:**
> SQL Database is not configured with geo-redundant backup storage.
>
> **NotApplicable:**
> Database is a system database or managed instance database.
>

### Recommendation

- **Azure Portal**

    Go to SQL Database ? Configure ? Backup storage redundancy ? Select "Geo-redundant backup storage" or "Geo-zone-redundant backup storage" ? Apply.

### Azure Policies or REST APIs used for evaluation

- REST API to get SQL Database configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}<br />
**Properties:** properties.requestedBackupStorageRedundancy, properties.currentBackupStorageRedundancy<br />

<br />

___