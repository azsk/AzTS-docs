# RedisCache

**Resource Type:** Microsoft.Cache/Redis

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_RedisCache_BCDR_Use_RDB_Backup](#azure_rediscache_bcdr_use_rdb_backup)
- [Azure_RedisCache_DP_Use_SSL_Port](#azure_rediscache_dp_use_ssl_port)

<!-- /TOC -->
<br/>

___ 

## Azure_RedisCache_BCDR_Use_RDB_Backup 

### Display Name 
Redis Data Persistence should be enabled to back up Redis Cache data 

### Rationale 
Enabling backup on Redis Cache ensures that there is always a previous snapshot of data that can be leveraged towards recovery scenarios. 

### Control Settings 
```json 
{
    "RDBBackApplicableSku": [
        "premium"
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> rdb-backup-enabled is enabled
> 
> **Failed:** 
> rdb-backup-enabled is not enabled or is not supported for Sku Tier.
> 
> **Error:** 
> Required Sku(s) are not defined in control settings.
> 
### Recommendation 

- **Azure Portal** 

	 Configure data persistence. Refer: https://docs.microsoft.com/en-us/azure/azure-cache-for-redis/cache-how-to-premium-persistence 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to get all Redis caches in the specified subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Cache/Redis?api-version=2018-03-01 <br />
**Properties:** properties.redisConfiguration, properties.Sku

<br />

___ 

## Azure_RedisCache_DP_Use_SSL_Port 

### Display Name 
Non-SSL port must not be enabled for Redis Cache

### Rationale 
Use of HTTPS ensures server/service authentication and protects data in transit from network layer man-in-the-middle, eavesdropping, session-hijacking attacks. 

### Control Spec 

> **Passed:** 
> Non-SSL port is not enabled for Redis Cache
> 
> **Failed:** 
> Non-SSL port is enabled for Redis Cache
> 
### Recommendation 

<!-- - **Azure Portal** 

	 To disable Non-SSL port for Redis Cache, run command: Set-AzRedisCache -ResourceGroupName <String> -Name <String> -EnableNonSslPort `$false 
-->

 - **PowerShell** 

	 To disable Non-SSL port for Redis Cache, run command: 
	 ```powershell 
	 Set-AzRedisCache -ResourceGroupName <String> -Name <String> -EnableNonSslPort $false
	 ```  
<!--
- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
--> 

### Azure Policy or ARM API used for evaluation 

- ARM API to get all Redis caches in the specified subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Cache/Redis?api-version=2018-03-01 <br />
**Properties:** properties.enableNonSslPort
 <br />

<br />

___ 
<!--
## Azure_RedisCache_DP_Use_Secure_TLS_Version 

### Display Name 
Use approved version of TLS for Azure RedisCache 

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
> Passed condition
> 
> **Failed:** 
> Failed condition
> 
> **Verify:** 
> Verify condition
> 
> **NotApplicable:** 
> NotApplicable condition if applicable
> 
### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal -> your Redis Cache instance -> Settings -> Advanced Settings -> Set Minimum TLS version to '1.2' 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

<br />

___ 

-->
