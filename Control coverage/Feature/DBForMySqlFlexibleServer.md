# DBForMySQLFlexibleServer

**Resource Type:** Microsoft.DBforMySQL/flexibleServers 

<!-- TOC -->

- [Azure_DBForMySQLFlexibleServer_DP_Enable_SSL](#azure_dbformysqlflexibleserver_dp_enable_ssl)
- [Azure_DBForMySQLFlexibleServer_DP_Use_Secure_TLS_Version](#azure_dbformysqlflexibleServer_dp_use_secure_tls_version)
- [Azure_DBForMySQLFlexibleServer_Enable_Diagnostic_Settings](#azure_dbformysqlflexibleserver_enable_diagnostic_settings)
- [Azure_DBForMySQLFlexibleServer_NetSec_Dont_Allow_Public_Network_Access](#azure_dbformysqlflexibleserver_netsec_dont_allow_public_network_access)

<!-- /TOC -->
<br/>

___ 

## Azure_DBForMySQLFlexibleServer_DP_Enable_SSL

### Display Name 
SSL connection must be enabled for Azure Database for MySQL - Flexible Servers

### Rationale 
Enforcing secure transport between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. 

### Control Settings 
```json
{
    "RequireSecureTransport": "ON"
} 
```

### Control Spec 

> **Passed:** 
>  Server parameter 'require_secure_transport' is set as ON.
> 
> **Failed:** 
>  Server parameter 'require_secure_transport' is set as OFF.
> 
### Recommendation 

- **Azure Portal** 
To configure secure transport for client communication, Go to Azure Portal --> Azure Database for MySQL flexible server --> Select server --> Settings --> Server parameters --> search 'require_secure_transport' --> set parameter 'require_secure_transport' as 'ON' --> Click 'Save'.

- **PowerShell** 

	 ```powershell 
	 Update-AzMySqlFlexibleServerConfiguration -Name "require_secure_transport"  -ResourceGroupName <ResourceGroupName>  -ServerName <ServerName> -Value "ON" 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to get server parameter values for a DBForMySQL Flexible server: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/flexibleServers/{serverName}/configurations/{parameterName}?api-version=2021-05-01<br />
**Properties:** value
 <br />

<br />

___ 

## Azure_DBForMySQLFlexibleServer_DP_Use_Secure_TLS_Version

### Display Name 
Use approved version of TLS for Azure Database for MySQL - Flexible Servers

### Rationale 
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions. 

### Control Settings 
```json
{
    "MinReqTLSVersion": "1.2",
    "CurrentTLSversionPatternInAPIResponse": "TLSV"
}
```
### Control Spec 

> **Passed:** 
> Server parameter 'tls_version' is set as greater than or equal to minimum TLS version required as part of control settings.
> 
> **Failed:** 
> Server parameter 'tls_version' is set as less than minimum TLS version required as part of control settings.
>  
### Recommendation 

- **Azure Portal** 

	To configure secure transport for client communication, Go to Azure Portal --> Azure Database for MySQL flexible server -->Server parameters --> set parameter 'tls_version' as 'TLSV1.2' and unselect other lower versions like TLSV1

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to get server parameter values for a DBForMySQL Flexible server: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/flexibleServers/{serverName}/configurations/{parameterName}?api-version=2021-05-01<br />
**Properties:** value
 <br />

<br />

___ 

## Azure_DBForMySQLFlexibleServer_Enable_Diagnostic_Settings

### Display Name
Database for MySQL Flexible Server must have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for MySQL Flexible Server provides visibility into database operations, performance metrics, and security events. This is essential for monitoring database health, detecting security threats, and meeting compliance requirements.

### Control Settings {
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "MySqlSlowLogs",
        "MySqlAuditLogs"
    ],
    "DiagnosticMinRetentionPeriod": "365"
}
### Control Spec

> **Passed:**
> Required diagnostic logs are enabled with appropriate retention configuration.
>
> **Failed:**
> Diagnostic logs are not enabled or retention period is insufficient.
>

### Recommendation

- **Azure Portal**

    Go to Database for MySQL Flexible Server ? Monitoring ? Diagnostic settings ? Add diagnostic setting ? Select required log categories ? Configure destination (Log Analytics, Storage Account, or Event Hub) ? Set retention period to 365 days or more.

### Azure Policies or REST APIs used for evaluation

- REST API to list diagnostic setting details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/flexibleServers/{serverName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** properties.logs.category, properties.logs.enabled, properties.logs.retentionPolicy<br />

<br />

___

## Azure_DBForMySQLFlexibleServer_NetSec_Dont_Allow_Public_Network_Access

### Display Name
Database for MySQL Flexible Server must not allow public network access

### Rationale
Restricting public network access to MySQL Flexible Server reduces the attack surface and ensures that access is only allowed from authorized networks through private connectivity.

### Control Spec

> **Passed:**
> Public network access is disabled.
>
> **Failed:**
> Public network access is enabled.
>

### Recommendation

- **Azure Portal**

    Go to Database for MySQL Flexible Server ? Networking ? Public network access ? Select "Disabled" ? Configure private endpoints or virtual network integration for secure access.

### Azure Policies or REST APIs used for evaluation

- REST API to check network access configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/flexibleServers/{serverName}<br />
**Properties:** properties.publicNetworkAccess<br />

<br />

___

