# ServiceBus

**Resource Type:** Microsoft.ServiceBus/namespaces

<!-- TOC -->

- [Azure_ServiceBus_AuthZ_Dont_Use_Policies_At_SB_Namespace](#azure_servicebus_authz_dont_use_policies_at_sb_namespace)
- [Azure_ServiceBus_DP_Use_Secure_TLS_Version](#azure_servicebus_dp_use_secure_tls_version)
- [Azure_ServiceBus_Audit_Enable_Diagnostic_Settings](#azure_servicebus_audit_enable_diagnostic_settings)

<!-- /TOC -->
<br/>

___ 

## Azure_ServiceBus_AuthZ_Dont_Use_Policies_At_SB_Namespace 

### Display Name 
All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace 

### Rationale 
Service Bus clients should not use a namespace level access policy that provides access to all queues and topics in a namespace. To align with the least privilege security model, you should create access policies at the entity level for queues and topics to provide access to only the specific entity. 

### Control Settings 
```json 
{
    "RootManageSharedAccessKeyName": "RootManageSharedAccessKey"
}
 ```  

### Control Spec 

> **Passed:** 
> If no authorization rules other than RootManageSharedAccessKey found at namespace level
> 
> **Failed:** 
> If any other custom authorization rule found at namespace level
> 
### Recommendation 

- **Azure Portal** 

Use the Azure portal to configure shared access policies with appropriate claims at the specific entity (Topic/Queue) scope.     

- **PowerShell** 

Remove all the authorization rules from Service Bus namespace except RootManageSharedAccessKey using 
```powershell
Remove-AzServiceBusAuthorizationRule 
``` 

For more help, Run 
```powershell
Get-Help Remove-AzServiceBusAuthorizationRule -full
``` 

<!--
- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policies or REST APIs used for evaluation 

- REST API to list Authorization Rules for a ServiceBus namespace: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/AuthorizationRules?api-version=2017-04-01<br />
**Properties:** properties.value[*].id, properties.value[*].name<br />

<br />

___ 

## Azure_ServiceBus_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Azure Service Bus Namespace.

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
> (*If Minimum TLS version is set to 1.2 or higher)
> TLS settings are properly configured.
>
> **Failed:**
> (*If Minimum TLS version is set to 1.0 or 1.1)
> Current minimum TLS version is {currentMinTLSVersionString} which is less than required version 1.2
> 
> **Error:** 
> Required minimum TLS version is not set properly in control settings.
>
### Recommendation

- **Azure Portal**

  Refer https://learn.microsoft.com/en-us/azure/service-bus-messaging/transport-layer-security-configure-minimum-version#specify-the-minimum-tls-version-in-the-azure-portal

- **PowerShell**

  Refer https://learn.microsoft.com/en-us/azure/service-bus-messaging/transport-layer-security-configure-minimum-version#use-azure-powershell

- **Enforcement Policy**
	[Azure_ServiceBus_DP_Use_Secure_TLS_Version Policy Definition](../../Policies/ServiceBus/Azure_ServiceBus_DP_Use_Secure_TLS_Version)
	

### ARM API used for evaluation

- REST API to list all service bus namespaces available under the subscription along with properties: https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.ServiceBus/namespaces?api-version=2022-01-01-preview

  Refer [Azure Namespaces List API](https://learn.microsoft.com/en-us/rest/api/servicebus/preview/namespaces/list?tabs=HTTP)
  <br />
  **Properties:** [*].properties.minimumTlsVersion
  <br />
  <br />

___



## Azure_ServiceBus_Audit_Enable_Diagnostic_Settings
 

### Display Name 
Enable Security Logging in Azure Service Bus

### Rationale 
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.

### Control Settings 
```json 
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticMinRetentionPeriod": "90",
    "DiagnosticLogs": [
      "OperationalLogs",
      "VNetAndIPFilteringLogs",
      "RuntimeAuditLogs"
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> Diagnostic settings should meet the following conditions:
>   1. Diagnostic logs are enabled.
>   2. At least one of the below setting configured:
>       a. Log Analytics.
>       b. Storage account with min Retention period of 90 or forever(Retention period 0).
>       c. Event Hub.
> 
> **Failed:** 
> If any of the below conditions are meet:
>   1. Diagnostic settings should meet the following conditions:
>       a. All diagnostic logs are not enabled.
>       b. No logs destination is configured:
>          i. Log Analytics.
>          ii. Storage account with min Retention period of 90 or forever(Retention period 0).
>          iii. Event Hub.
>   2. Diagnostics setting is disabled for resource.

 
### Recommendation 

- **Azure Portal** 
    - You can change the diagnostic settings from the Azure Portal by following the steps given here: https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings.
      

### Azure Policies or REST APIs used for evaluation 

- REST API used to list diagnostic settings and its related properties at Resource level:
/{ResourceId}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview<br />
**Properties:**
properties.metrics.category,properties.metrics.enabled,properties.metrics.retentionPolicy.enabled, properties.metrics.retentionPolicy.days
properties.logs.category, properties.logs.categorygroup,properties.logs.enabled,properties.metrics.logs.enabled, properties.logs.retentionPolicy.days, name, properties.workspaceId,properties.storageAccountId,properties.eventHubName
 <br />

- REST API used to list diagnostic category group mapping and its related properties at Resource level:
/{ResourceId}/providers/Microsoft.Insights/diagnosticSettingsCategories?api-version=2021-05-01-preview <br />
**Properties:**
properties.categoryGroups, name
<br />
___ 


