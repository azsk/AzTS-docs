# DBForPostgreSql

**Resource Type:** Microsoft.DBforPostgreSQL/servers 

<!-- TOC -->

- [Azure_DBforPostgreSQL_AuthZ_Enable_SSL_Connection](#azure_dbforpostgresql_authz_enable_ssl_connection)
- [Azure_DBforPostgreSQL_NetSec_Dont_Allow_Universal_IP_Range](#azure_dbforpostgresql_netsec_dont_allow_universal_ip_range)
- [Azure_DBforPostgreSQL_AuthZ_Firewall_Deny_AzureServices_Access](#azure_dbforpostgresql_authz_firewall_deny_azureservices_access)
- [Azure_DBforPostgreSQL_Audit_Enable_ATP](#azure_dbforpostgresql_audit_enable_atp)
- [Azure_DBforPostgreSQL_Audit_Enable_Logging_On_Server](#azure_dbforpostgresql_audit_enable_logging_on_server)
- [Azure_DBforPostgreSQL_AuthN_Enable_Connection_Throttling](#azure_dbforpostgresql_authn_enable_connection_throttling)
- [Azure_DBforPostgreSQL_DP_Use_Secure_TLS_Version](#azure_dbforpostgresql_dp_use_secure_tls_version)
- [Azure_DBforPostgreSQL_Audit_Enable_Diagnostics_Log](#azure_dbforpostgresql_audit_enable_diagnostics_log)

<!-- /TOC -->
<br/>

___ 

## Azure_DBforPostgreSQL_AuthZ_Enable_SSL_Connection 

### Display Name 
SSL connection must be enabled for Azure Database for PostgreSQL 

### Rationale 
Enforcing SSL connections between your database server and your client applications helps protect against 'man-in-the-middle' attacks by encrypting the data stream between the server and your application. 

### Control Spec 

> **Passed:** 
> Enforce SSL connection is enabled.
> 
> **Failed:** 
> Enforce SSL connection is disabled.
> 
### Recommendation 

- **Azure Portal** 

	 To enable SSL connection for Azure Database for PostgreSQL server, refer https://docs.microsoft.com/en-us/azure/postgresql/concepts-ssl-connection-security. 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to get resource details of a DBForPostgreSQL server: 
/subscriptions/{subscriptionId}/providers/Microsoft.DBforPostgreSQL/servers?api-version=2017-12-01 
<br />
 
**Properties:** properties.sslEnforcement
 <br />

<br />

___ 

## Azure_DBforPostgreSQL_NetSec_Dont_Allow_Universal_IP_Range 

### Display Name 
Do not use Any-to-Any IP range for Azure Database for PostgreSQL servers 

### Rationale 
Using the firewall feature ensures that access to the data or the service is restricted to a specific set/group of clients. NOTE: While this control does provide an extra layer of access control protection, it may not always be feasible to implement in all scenarios. 

### Control Settings 
```json 
{
    "FirewallRuleName_AllowAzureIps": "AllowAllWindowsAzureIps",
    "IPRangeEndIP": "255.255.255.255",
    "IPRangeStartIP": "0.0.0.0"
}
 ```  

### Control Spec 

> **Passed:** 
> Custom firewall rule with Any-to-Any IP range with Start IP address as 0.0.0.0 and End Ip address as 255.255.255.255 is NOT found.
> 
> **Failed:** 
> Custom firewall rule with Any-to-Any IP range with Start IP address as 0.0.0.0 and End Ip address as 255.255.255.255 is found.
> 
### Recommendation 

- **Azure Portal** 

	 Do not configure 'Any to Any' firewall IP address. Refer: https://docs.microsoft.com/en-us/azure/postgresql/concepts-firewall-rules. 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to fetch the firewall rules for a DBForPostgreSQL server: 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforPostgreSQL/servers/{serverName}/firewallRules?api-version=2017-12-01 
<br />
 
**Properties:** name, properties.startIpAddress, properties.endIpAddress
 <br />

<br />

___ 

## Azure_DBforPostgreSQL_AuthZ_Firewall_Deny_AzureServices_Access 

### Display Name 
Use the 'Allow access to Azure services' flag for DBforPostgreSQL only if required 

### Rationale 
The 'Allow access to Azure services' setting configures a very broad range of IP addresses from Azure as permitted to access the PostgreSQL Server. Please make sure your scenario really requires this setting before enabling it. Turning it ON exposes your PostgreSQL Server to risk of attacks from resources (IPs) owned by others in the Azure region. 

### Control Settings 
```json 
{
    "FirewallRuleName_AllowAzureIps": "AllowAllWindowsAzureIps"
}
 ```  

### Control Spec 

> **Passed:** 
> Allow access to Azure services flag is off.
> 
> **Failed:** 
> Allow access to Azure services flag is on.
> 
> **Error:** 
> AllowAzureServices ControlSettings is not present.
> 
### Recommendation 

- **Azure Portal** 

	 Turn 'OFF' the 'Allow access to Azure services' setting. Refer: https://docs.microsoft.com/en-us/azure/postgresql/concepts-firewall-rules#connecting-from-azure 
<!-- 
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to fetch the firewall rules for a DBForPostgreSQL server: 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforPostgreSQL/servers/{serverName}/firewallRules?api-version=2017-12-01 <br />
**Properties:** name
 <br />

<br />

___ 

## Azure_DBforPostgreSQL_Audit_Enable_ATP 

### Display Name 
Enable Threat detection for PostgreSQL 

### Rationale 
Advanced Threat Protection for Azure Database for PostgreSQL provides a layer of security, which enables customers to detect and respond to potential threats as they occur by providing security alerts on anomalous activities. 

### Control Settings 
```json 
{
    "UnsupportedTier": [
        "Basic"
    ]
}
 ```

### Control Spec 

> **Passed:** 
> ATP is enabled and 'email notifications to admins' are also enabled.
> 
> **Failed:** 
> Either PostgreSQL is of 'basic tier' which does not support ATP or ATP is disabled or ATP is enabled but 'email notifications to admins' are disabled.
> 
### Recommendation 

- **Azure Portal** 

	 Go to your Azure Database for PostgreSQL server --> Enable Advanced Threat Protection on the server --> Tick the checkbox to 'send email notification to admins and subscription owners'. Refer: https://docs.microsoft.com/en-us/azure/postgresql/howto-database-threat-protection-portal 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to get security alert policy of a DBForPostgreSQL server: 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforPostgreSQL/servers/{serverName}/securityAlertPolicies/Default?api-version=2017-12-01  
<br />
 
**Properties:** properties.state, properties.emailAccountAdmins
 <br />

<br />

___ 

## Azure_DBforPostgreSQL_Audit_Enable_Logging_On_Server 

### Display Name 
Enable PostgreSQL server parameters log_connections and log_disconnections 

### Rationale 
PostgreSQL sever logging parameters enable log collection of important system events pertinent to security. Regular monitoring of logs can help to detect any suspicious and malicious activity early and respond in a timely manner. 

### Control Spec 

> **Passed:** 
> Logging for successful connection and session end are enabled for PostgreSQL.
> 
> **Failed:** 
> Logging for successful connection or session end is NOT enabled for PostgreSQL.
> 
### Recommendation 

- **Azure Portal** 

	 To configure logging for your server, go to Server Parameters --> Set following log parameter: a) 'log_connections': 'ON' b) 'log_disconnections': 'ON'. Refer: https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to list configurations for PostgreSQL servers: 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforPostgreSQL/servers/{serverName}/configurations?api-version=2017-12-01 
<br />
 
**Properties:** configurations['log_connections'].properties.value, configurations['log_disconnections'].properties.value
 <br />

<br />

___ 

## Azure_DBforPostgreSQL_AuthN_Enable_Connection_Throttling 

### Display Name 
Ensure server parameter 'connection_throttling' is set to 'ON' 

### Rationale 
Connection throttling protects your server against password guessing and brute force attacks. 

### Control Spec 

> **Passed:** 
> Temporary connection throttling per IP is enabled for PostgreSQL.
> 
> **Failed:** 
> Temporary connection throttling per IP is NOT enabled for PostgreSQL.
>
### Recommendation 

- **Azure Portal** 

	 The 'connection_throttling' server parameter enables temporary connection throttling per IP for too many invalid password login failures. Go to Server parameter --> Turn 'ON' connection_throttling. 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to list configurations for PostgreSQL servers: 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforPostgreSQL/servers/{serverName}/configurations?api-version=2017-12-01 
<br />
 
**Properties:** configurations['connection_throttling'].properties.value
 <br />

<br />

___ 

## Azure_DBforPostgreSQL_DP_Use_Secure_TLS_Version 

### Display Name 
Use approved version of TLS for Azure Database for PostgreSQL 

### Rationale 
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions. 

### Control Settings 
```json 
{
    "MinReqTLSVersion": "1.2"
}
 ```

### Control Spec 

> **Passed:** 
> Current TLS version of Azure Database for PostgreSQL is set to either equal or greater than the required minimum TLS version.
> 
> **Failed:** 
> Current TLS version of Azure Database for PostgreSQL is less than the required minimum TLS version or TLS for Azure Database for PostgreSQL is not configured or SSL is disabled.
> 
> **Error:** 
> Required minimum TLS version is not set properly in control settings.
> 
### Recommendation 

- **Azure Portal** 

	 To Configure 'Minimum TLS Version' setting for 'Azure Database for PostgreSQL' single server, go to Azure Portal --> Your Resource --> Connection Security --> Enable SSL, if Disabled --> Set the Minimum TLS Version to latest version. Refer: https://docs.microsoft.com/en-us/azure/postgresql/concepts-ssl-connection-security#tls-connectivity-in-azure-database-for-postgresql-single-server 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to get resource details of a DBForPostgreSQL server: 
/subscriptions/{subscriptionId}/providers/Microsoft.DBforPostgreSQL/servers?api-version=2017-12-01 
<br />
 
**Properties:** properties.minimalTlsVersion
 <br />

<br />

## Azure_DBforPostgreSQL_Audit_Enable_Diagnostics_Log 

### Display Name 
Diagnostics logs must be enabled for Azure Database for PostgreSQL 

### Rationale 
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well. 

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
> 1. Required diagnostic logs are enabled.
>
>       and
>
> 2. At least one of the below setting configured:
> a. Log Analytics.
> b. Storage account (with min Retention period of 365 or forever(Retention period 0).
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
> ii. Storage account (with min Retention period of 365 or forever(Retention period 0).
> iii. Event Hub.
> 
> **Error:** 
> Required logs are not configured in control settings.
> 

### Recommendation 

- **Azure Portal** 

	 You can change the diagnostic settings from the Azure Portal by following the steps given here: https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to list diagnostic setting details of DBForPostgreSQL server resources: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforPostgreSQL/servers/{serverName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
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

