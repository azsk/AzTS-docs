# DBForPostgreFlexibleServer

**Resource Type:** Microsoft.DBforPostgreSQL/flexibleservers 

<!-- TOC -->

- [Azure_DBForPostgreSQLFlexibleServer_DP_Use_Secure_TLS_Version](#azure_dbforpostgresqlflexibleserver_dp_use_secure_tls_version)
- [Azure_DBForPostgreSQLFlexibleServer_Enable_Diagnostic_Settings](#azure_dbforpostgresqlflexibleserver_enable_diagnostic_settings)

<!-- /TOC -->
<br/>

___ 

## Azure_DBForPostgreSQLFlexibleServer_DP_Use_Secure_TLS_Version 

### Display Name 
Use approved version of TLS for Azure Database for PostgreSQL Flexible Servers 

### Rationale 
TLS provides confidentiality and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions.

### Control Spec 

> **Passed:** 
> Current TLS version of Azure Database for PostgreSQL is set to either equal or greater than the required minimum TLS version and SSL connection is enforced.
> 
> **Failed:** 
> Current TLS version of Azure Database for PostgreSQL is less than the required minimum TLS version. Or
TLS for Azure Database for PostgreSQL is not configured or SSL is disabled.
> 
### Recommendation 

- **Azure Portal** 

	To remediate control, secure transport for client communication must be enabled and min tls version must be 1.2 or greater. To configure secure transport for client communication, Go to Azure Portal --> Azure Database for PostgreSQL flexible server --> Select server --> Settings --> Server parameters --> search 'require_secure_transport' --> set parameter 'require_secure_transport' as 'ON' --> Click 'Save' and for updating minimum TLS version, under Server parameters --> search 'ssl_min_protocol_version' --> set parameter 'ssl_min_protocol_version' as 'TLSV1.2' or 'TLSV1.3' --> Click 'Save'.
      
### Azure Policies or REST APIs used for evaluation 

- REST API to get resource details of a DBForPostgreSQL flexible server: 
/subscriptions/{subscriptionId}/providers/Microsoft.DBforPostgreSQL/flexibleServers?api-version=2022-12-01

- REST API to get server parameter details of a DBForPostgreSQL flexible server: 
/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.DBforPostgreSQL/flexibleServers/{2}/configurations?api-version=2022-12-01"
<br />
 
**Properties:** properties.name, properties.value
 <br />

<br />

___ 

## Azure_DBForPostgreSQLFlexibleServer_Enable_Diagnostic_Settings

### Display Name
Database for PostgreSQL Flexible Server must have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for PostgreSQL Flexible Server provides visibility into database operations, performance metrics, and security events. This is essential for monitoring database health, detecting security threats, and meeting compliance requirements.

### Control Settings 
```json
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "PostgreSQLLogs"
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

    Go to Database for PostgreSQL Flexible Server ? Monitoring ? Diagnostic settings ? Add diagnostic setting ? Select required log categories ? Configure destination (Log Analytics, Storage Account, or Event Hub) ? Set retention period to 365 days or more.

### Azure Policies or REST APIs used for evaluation

- REST API to list diagnostic setting details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforPostgreSQL/flexibleServers/{serverName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** properties.logs.category, properties.logs.enabled, properties.logs.retentionPolicy<br />

<br />

___ 
