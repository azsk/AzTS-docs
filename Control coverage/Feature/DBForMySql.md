# DBForMySql

**Resource Type:** Microsoft.DBforMySQL/servers 

<!-- TOC -->

- [Azure_DBforMySQL_AuthZ_Firewall_Deny_AzureServices_Access](#azure_dbformysql_authz_firewall_deny_azureservices_access)
- [Azure_DBforMySQL_NetSec_Dont_Allow_Universal_IP_Range](#azure_dbformysql_netsec_dont_allow_universal_ip_range)
- [Azure_DBforMySQL_Authz_Enable_SSL_Connection](#azure_dbformysql_authz_enable_ssl_connection)
- [Azure_DBforMySQL_Audit_Enable_ATP](#azure_dbformysql_audit_enable_atp)
- [Azure_DBforMySQL_DP_Use_Secure_TLS_Version](#azure_dbformysql_dp_use_secure_tls_version)
- [Azure_DBforMySQL_Audit_Enable_Diagnostics_Log](#azure_dbformysql_audit_enable_diagnostics_log)
- [Azure_DBforMySQL_NetSec_Dont_Allow_Public_Network_Access](#azure_dbformysql_netsec_dont_allow_public_network_access)

<!-- /TOC -->
<br/>

___ 

## Azure_DBforMySQL_AuthZ_Firewall_Deny_AzureServices_Access 

### Display Name 
Use the 'Allow access to Azure services' flag for DBForMySQL only if required 

### Rationale 
The 'Allow access to Azure services' setting configures a very broad range of IP addresses from Azure as permitted to access the MySQL Server. Please make sure your scenario really requires this setting before enabling it. Turning it ON exposes your MySQL Server to risk of attacks from resources (IPs) owned by others in the Azure region. 

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

	 1. Turn 'OFF' the 'Allow access to Azure services' setting. 
	 2. Remove IP range from firewall rules. Refer: https://docs.microsoft.com/en-us/azure/mysql/concepts-firewall-rules#connecting-from-azure 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to get firewall rules of a DBForMySql server: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/servers/{serverName}/firewallRules/{firewallRuleName}?api-version=2017-12-01 <br />
**Properties:** name
 <br />

<br />

___ 

## Azure_DBforMySQL_NetSec_Dont_Allow_Universal_IP_Range 

### Display Name 
Do not use Any-to-Any IP range for Azure Database for MySQL 

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
> No additional firewall rule or custom firewall rules without Any-to-Any IP range.
> 
> **Failed:** 
> Custom firewall rule with Any-to-Any IP range with Start IP address as 0.0.0.0 and End Ip address as 255.255.255.255 is found.
>  
### Recommendation 

- **Azure Portal** 

	 Do not configure 'Any to Any' firewall IP address. Refer: https://docs.microsoft.com/en-us/azure/mysql/concepts-firewall-rules. 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to get firewall rules of a DBForMySql server: 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/servers/{serverName}/firewallRules/{firewallRuleName}?api-version=2017-12-01 
<br />
 
**Properties:** name, properties.startIpAddress, properties.endIpAddress 
 <br />

<br />

___ 

## Azure_DBforMySQL_Authz_Enable_SSL_Connection 

### Display Name 
SSL connection must be enabled for Azure Database for MySQL 

### Rationale 
Enforcing SSL connections between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. 

### Control Spec 

> **Passed:** 
> SSL connection is enabled.
> 
> **Failed:** 
> SSL connection is disabled.
> 
### Recommendation 

- **Azure Portal** 

	 To enable SSL connection for Azure Database for MySQL server, refer https://docs.microsoft.com/en-us/azure/mysql/concepts-ssl-connection-security. 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to get firewall rules of a DBForMySql server: 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/servers/{serverName}/firewallRules/{firewallRuleName}?api-version=2017-12-01 
<br />
 
**Properties:** properties.sslEnforcement
 <br />

<br />

___ 

## Azure_DBforMySQL_Audit_Enable_ATP 

### Display Name 
Enable Threat detection for MySQL database 

### Rationale 
Advanced Threat Protection for Azure Database for MySQL provides a layer of security, which enables customers to detect and respond to potential threats as they occur by providing security alerts on anomalous activities. 

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
> Either MySQL is of 'basic tier' which does not support ATP or ATP is disabled or ATP is enabled but 'Email notifications to admins' is disabled as well as explicit email(s) are not configured or All 'Advanced threat protection types' are not enabled.
>  
### Recommendation 

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/mysql/concepts-data-access-and-security-threat-protection 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to get security alert policy of a DBForMySql server: 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/servers/{serverName}/securityAlertPolicies/Default?api-version=2017-12-01 
<br />
 
**Properties:** properties.state, properties.emailAccountAdmins, properties.emailAddresses, properties.disabledAlerts
 <br />

<br />

___ 

## Azure_DBforMySQL_DP_Use_Secure_TLS_Version 

### Display Name 
Use approved version of TLS for Azure Database for MySQL 

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
> Current TLS version of Azure Database for MySQL is set to either equal or greater than the required minimum TLS version.
> 
> **Failed:** 
> Current TLS version of Azure Database for MySQL is less than the required minimum TLS version or TLS for Azure Database for MySQL is not configured or SSL is disabled condition.
> 
> **Error:** 
> Required minimum TLS version is not set properly in control settings.
> 
### Recommendation 

- **Azure Portal** 

	 To Configure 'Minimum TLS Version' setting for 'Azure Database for MySQL' single server, go to Azure Portal --> Your Resource --> Connection Security --> Enable SSL, if Disabled --> Set the Minimum TLS Version to latest version. Refer: https://docs.microsoft.com/en-us/azure/mysql/concepts-ssl-connection-security#tls-enforcement-in-azure-database-for-mysql 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to get resource details of a DBForMySql server: 
/subscriptions/{subscriptionId}/providers/Microsoft.DBforMySQL/servers?api-version=2017-12-01 
<br />
 
**Properties:** properties.minimalTlsVersion
 <br />

<br />

___ 

## Azure_DBforMySQL_Audit_Enable_Diagnostics_Log 

### Display Name 
Diagnostics logs must be enabled for Azure Database for MySQL 

### Rationale 
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well. 

### Control Settings 
```json
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "MySqlAuditLogs"
    ],
    "DiagnosticMinRetentionPeriod": "365"
}
```
### Control Spec 

> **Passed:** 
> 1. Required diagnostic logs are enabled and 2. At least one of the below setting configured: a. Log Analytics b. Storage account (with min Retention period of 365 or forever(Retention period 0) c. Event Hub. 
>  
> **Failed:** 
> 1. Diagnostics setting is disabled for resource or 2. Diagnostic setting meet the following conditions: a. All diagnostic logs are not enabled b. None of the below setting is configured: i. Log Analytics ii. Storage account (with min Retention period of 365 or forever(Retention period 0) iii. Event Hub. 
> 
> **Error:** 
> Required logs are not configured in control settings.
> 
### Recommendation 

- **Azure Portal** 

	 You can change the diagnostic settings from the Azure Portal by following the steps given here: https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to list diagnostic setting details of Azure Database for MySQL servers: 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/servers/{serverName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview 
<br />
 
**Properties:** name, properties.logs.category, properties.logs.enabled, properties.logs.retentionPolicy.enabled, properties.logs.retentionPolicy.days, properties.workspaceId, properties.storageAccountId, properties.eventHubName
 <br />

<br />

___ 

## Azure_DBforMySQL_NetSec_Dont_Allow_Public_Network_Access

### Display Name
Database for MySQL must not allow public network access

### Rationale
Restricting public network access to MySQL server reduces the attack surface and ensures that access is only allowed from authorized networks through private connectivity.

### Control Spec

> **Passed:**
> Public network access is disabled.
>
> **Failed:**
> Public network access is enabled.
>

### Recommendation

- **Azure Portal**

    Go to Database for MySQL ? Networking ? Public network access ? Select "Disabled" ? Configure private endpoints or virtual network integration for secure access.

### Azure Policies or REST APIs used for evaluation

- REST API to check network access configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/servers/{serverName}<br />
**Properties:** properties.publicNetworkAccess<br />

<br />

___
