# DBForPostgreFlexibleServer

**Resource Type:** Microsoft.DBforPostgreSQL/flexibleservers 

<!-- TOC -->

- [Azure_DBForPostgreSQLFlexibleServer_DP_Use_Secure_TLS_Version](#azure_dbforpostgresqlflexibleserver_dp_use_secure_tls_version)

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
