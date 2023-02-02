# DBForMySQLFlexibleServer

**Resource Type:** Microsoft.DBforMySQL/flexibleServers 

<!-- TOC -->

- [Azure_DBForMySQLFlexibleServer_DP_Enable_SSL](#azure_dbformysqlflexibleserver_dp_enable_ssl)
- [Azure_DBForMySQLFlexibleServer_DP_Use_Secure_TLS_Version_Trial](#azure_dbformysqlflexibleServer_dp_use_secure_tls_version_trial)

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

### Azure Policy or ARM API used for evaluation 

- ARM API to get server parameter values for a DBForMySQL Flexible server: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/flexibleServers/{serverName}/configurations/{parameterName}?api-version=2021-05-01<br />
**Properties:** value
 <br />

<br />

___ 

## Azure_DBForMySQLFlexibleServer_DP_Use_Secure_TLS_Version_Trial 

### Display Name 
[Trial] Azure Database for MySQL - Flexible Servers Announcing SSL enforcement and minimum TLS version choice

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

### Azure Policy or ARM API used for evaluation 

- ARM API to get server parameter values for a DBForMySQL Flexible server: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforMySQL/flexibleServers/{serverName}/configurations/{parameterName}?api-version=2021-05-01<br />
**Properties:** value
 <br />

<br />

___ 

