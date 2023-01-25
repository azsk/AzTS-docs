# EventHub

**Resource Type:** Microsoft.EventHub/namespaces

<!-- TOC -->

- [Azure_EventHub_AuthZ_Dont_Use_Policies_At_Event_Hub_Namespace](#azure_eventhub_authz_dont_use_policies_at_event_hub_namespace)
- [Azure_EventHub_AuthZ_Use_Min_Permissions_Access_Policies](#azure_eventhub_authz_use_min_permissions_access_policies)
- [Azure_EventHub_DP_Use_Secure_TLS_Version](#Azure_EventHub_DP_Use_Secure_TLS_Version)

<!-- /TOC -->
<br/>

___ 

## Azure_EventHub_AuthZ_Dont_Use_Policies_At_Event_Hub_Namespace 

### Display Name 
Event Hub clients (event senders or receivers) must not use 'namespace' level access policies 

### Rationale 
A 'namespace' level access policy provides access to all Event Hubs in a namespace. However, using an access policy at an entity (Event Hub) level provides access only to the specific entity. Thus, using the latter is in line with the principle of least privilege. 

### Control Settings 
```json 
{
    "SharedAccessPoliciesToExclude": [
        "RootManageSharedAccessKey"
    ]
}
 ``` 

### Control Spec 

> **Passed:** 
> No namespace level access policies (except RootManageSharedAccessKey) have been configured for the Event Hub.
> 
> **Failed:** 
> One or more namespace level access policies have been configured for the Event Hub.
> 
> **Error:** 
> There was an error fetching Authorization Rules for the Event Hub.
> 
### Recommendation 

- **Azure Portal** 

	 Use the Azure portal to configure shared access policies with appropriate claims at the specific Event Hub scope. 

- **PowerShell** 

	 ```powershell 

     # Remove all the authorization rules from Event Hub namespace except RootManageSharedAccessKey
     Remove-AzEventHubAuthorizationRule

     # For more help run:
	 Get-Help Remove-AzEventHubAuthorizationRule -full
	 ```  

<!-- - **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list all Authorization Rules for an Event Hubs Namespace: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.EventHub/namespaces/{eventHubsNamespaceName}/authorizationRules?api-version=2017-04-01<br />
**Properties:** properties.rights
 <br />

<br />

___ 

## Azure_EventHub_AuthZ_Use_Min_Permissions_Access_Policies 

### Display Name 
Access policies must be defined with minimum required permissions to the Event Hub 

### Rationale 
Granting minimum access ensures that users are granted just enough permissions to perform their tasks. This minimizes the set of operations that can be performed on the resource by an attacker in case of access policy key compromise. 

### Control Spec 

> **Passed:** 
> No Event Hubs Instances are present. All Authorization Rules across all Event Hubs Instances in the Event Hub have just the least required privileges.
> 
> **Failed:** 
> One or more Event Hubs Instances are present without any associated Authorization Rules. One or more Event Hubs Instances are present with more than the least required privileges for one or more Authorization Rules.
> 
> **Error:** 
> There was an error fetching one or more Event Hubs Instances' metadata.
> 
### Recommendation 

- **Azure Portal** 

	 Ensure that client apps use shared access policies with the least required privilege and at the Event Hub scope. For instance, if the client app is only reading events from the event hub (as opposed to sending), then the policy used must only include the 'Listen' claim. Refer: https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-authentication-and-security-model-overview 
<!-- 
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list all Event Hubs Instances in an Event Hubs Namespace: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.EventHub/namespaces/{eventHubsNamespaceName}/eventhubs?api-version=2017-04-01 <br />
**Properties:** properties.name
 <br />

- ARM API to list all Authorization Rules for an Event Hubs Instance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.EventHub/namespaces/{eventHubsNamespaceName}/eventhubs/{eventHubsInstanceName}/authorizationRules?
api-version=2017-04-01<br />
**Properties:** properties.rights
 <br />

<br />

___ 

## Azure_EventHub_DP_Use_Secure_TLS_Version 

### Display Name 
Use approved version of TLS for Event Hub Namespace.

### Rationale 
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions.

### Control Settings 


### Control Spec 

> **Passed:** 
> TLS version of Event Hub Namespace is already defined as per the Security Recommendation.
> 
> **Failed:** 
> Current minimum TLS version is less than required secured version .
> 
> **Error:** 
> There was an error fetching TLS version of Event Hub Namespace.
> 
### Recommendation 

- **Azure Portal** 

	 Use the Azure portal to configure TLS version as per the Security Recommendation.
	 Go to Azure Portal --> your Event Hub Namespace --> Configuration --> Security --> Set the TLS Version.

- **PowerShell** 

	 ```powershell 

     # Set the TLS Version
     Set-MinTLSVersionForEventHubNamespace

     # For more help run:
	 Get-Help Set-MinTLSVersionForEventHubNamespace -full
	 ```  

### Azure Policy or ARM API used for evaluation 

- ARM API to list all Authorization Rules for an Event Hubs Namespace: /subscriptions/{0}/providers/Microsoft.EventHub/namespaces?api-version=2022-01-01-preview<br />
**Properties:** properties.rights
 <br />

<br />

___ 

