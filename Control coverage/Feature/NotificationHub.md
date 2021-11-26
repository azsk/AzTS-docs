# NotificationHub

**Resource Type:** Microsoft.NotificationHubs/namespaces/notificationHubs

<!-- TOC -->

- [Azure_NotificationHub_AuthZ_Dont_Use_Manage_Access_Permission](#azure_notificationhub_authz_dont_use_manage_access_permission)

<!-- /TOC -->
<br/>

___ 

## Azure_NotificationHub_AuthZ_Dont_Use_Manage_Access_Permission 

### DisplayName 
Access policies on Notification Hub must not have Manage access permissions 

### Rationale 
Manage security claim has the highest level of access (Create/Update/Read/Delete/Read registrations by tag) on Notification Hub. Using this key for runtime scenarios violates the principle of least privileged access. It is akin to running as 'sa' or 'localsystem'. 

### Control Spec 

> **Passed:** 
> No authorization rule found with manage permission
> 
> **Failed:** 
> Authorization rules found with manage permission
> 
### Recommendation 

- **Azure Portal** 

	 Use 'Send' and 'Listen' manage policies as access permissions for clients and back ends. Refer: https://docs.microsoft.com/en-us/azure/notification-hubs/notification-hubs-push-notification-security 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policy or ARM API used for evaluation 

- ARM API to fetch authorization rules: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NotificationHubs/namespaces/{namespaceName}/notificationHubs/{notificationHubName}/AuthorizationRules?api-version=2016-03-01<br />
**Properties:** properties.rights, name
 <br />

<br />

___ 

