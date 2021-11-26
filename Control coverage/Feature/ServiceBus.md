# ServiceBus

**Resource Type:** Microsoft.ServiceName/subcategory 

___ 

## Azure_ServiceBus_AuthZ_Dont_Use_Policies_At_SB_Namespace 

### DisplayName 
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

### Azure Policy or ARM API used for evaluation 

- ARM API to list Authorization Rules for a ServiceBus namespace: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/AuthorizationRules?api-version=2017-04-01<br />
**Properties:** properties.value[*].id, properties.value[*].name<br />

<br />

___ 

