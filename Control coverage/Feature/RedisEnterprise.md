# RedisEnterprise

**Resource Type:** Microsoft.Cache/redisEnterprise 

<!-- TOC -->

- [Azure_RedisEnterprise_Audit_Enable_Diagnostic_Settings](#azure_redisenterprise_audit_enable_diagnostic_settings)
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

