# ServiceBus

**Resource Type:** Microsoft.ServiceBus/namespaces

<!-- TOC -->

- [Azure_ServiceBus_AuthZ_Dont_Use_Policies_At_SB_Namespace](#azure_servicebus_authz_dont_use_policies_at_sb_namespace)
- [Azure_ServiceBus_DP_Use_Secure_TLS_Version](#azure_servicebus_dp_use_secure_tls_version)

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

- ARM API to list Authorization Rules for a ServiceBus namespace: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/AuthorizationRules?api-version=2017-04-01<br />
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

- ARM API to list all service bus namespaces available under the subscription along with properties: https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.ServiceBus/namespaces?api-version=2022-01-01-preview

  Refer [Azure Namespaces List API](https://learn.microsoft.com/en-us/rest/api/servicebus/preview/namespaces/list?tabs=HTTP)
  <br />
  **Properties:** [*].properties.minimumTlsVersion
  <br />
  <br />

___
