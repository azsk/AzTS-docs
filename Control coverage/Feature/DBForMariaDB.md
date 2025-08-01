# DBForMariaDB

**Resource Type:** Microsoft.DBforMariaDB/servers

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_DBForMariaDB_Enable_Diagnostic_Settings](#azure_dbformariadb_enable_diagnostic_settings)

<!-- /TOC -->
<br/>

___

## Azure_DBForMariaDB_Enable_Diagnostic_Settings

### Display Name
Database for MariaDB must have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for MariaDB provides visibility into database operations, performance metrics, and security events. This is essential for monitoring database health, detecting security threats, and meeting compliance requirements.

### Control Settings 
```json
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "MySqlSlowLogs",
        "MySqlAuditLogs"
    ],
    "DiagnosticMinRetentionPeriod": "365"
}
```

### Control Spec

> **Passed:**
> Required diagnostic logs are enabled with appropriate retention configuration.
>
> **Failed:**
> Diagnostic logs are not enabled or retention period is insufficient.
>

### Recommendation

- **Azure Portal**

    Go to Database for MariaDB ? Monitoring ? Diagnostic settings ? Add diagnostic setting ? Select required log categories ? Configure destination (Log Analytics, Storage Account, or Event Hub) ? Set retention period to 365 days or more.

### Azure Policies or REST APIs used for evaluation

- REST API to list diagnostic setting details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMariaDB/servers/{serverName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** properties.logs.category, properties.logs.enabled, properties.logs.retentionPolicy<br />

<br />

___