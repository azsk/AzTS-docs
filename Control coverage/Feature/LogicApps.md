# LogicApps

**Resource Type:** Microsoft.Logic/workflows

<!-- TOC -->

- [Azure_LogicApps_AuthZ_Provide_Triggers_Access_Control](#Azure_LogicApps_AuthZ_Provide_Triggers_Access_Control)
- [Azure_LogicApps_AuthZ_Provide_Contents_Access_Control](#Azure_LogicApps_AuthZ_Provide_Contents_Access_Control)
- [Azure_LogicApps_AuthN_Connectors_Use_AAD](#Azure_LogicApps_AuthN_Connectors_Use_AAD)
- [Azure_LogicApps_DP_Connectors_Encrypt_Data_In_Transit](#Azure_LogicApps_DP_Connectors_Encrypt_Data_In_Transit)
- [Azure_LogicApps_Audit_Enable_Diagnostic_Settings](#azure_logicapps_audit_enable_diagnostic_settings)

<!-- /TOC -->
<br/>

___

## Azure_LogicApps_AuthZ_Provide_Triggers_Access_Control

### Display Name
Restrict your Logic App to accept trigger requests only from specified IP addresses

### Rationale
Specifying the IP range ensures that the triggers can be invoked only from a restricted set of endpoints.

### Control Spec

> **Passed:**
> If IP ranges are specified and are not of the Any-to-Any type.
>
> **Failed:**
> If any of the following conditions are met:
>   <br />a. If access control is not specified then trigger requests from all IP addresses are accepted.
>   <br />b. If an empty list for access control is specified then any other Logic App can make trigger requests.
>   <br />c. If access control is specified in the form of IP address ranges but contains atleast one IP range of Any-to-Any type.
> 

### Recommendation

- **Azure Portal**

  Provide access control by navigating to Portal --> Logic App --> Workflow settings --> Access Control Configuration and setting the IP addresses/ranges. Do not add Any-to-Any IP range as this means access to all IPs. Note: In case the IP range is indeterminate (for instance, if the client is a PaaS endpoint), you may need to attest this control.

<!--
- **PowerShell**

	```powershell
	Set-AzStorageContainerAcl -Name '<ContainerName>' -Permission 'Off' -Context (New-AzStorageContext -StorageAccountName '<StorageAccountName>' -StorageAccountKey '<StorageAccountKey>')
	```

	For more help:
	```powershell
	Get-Help Set-AzStorageContainerAcl -full
	```
-->

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to list all the logic apps under subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Logic/workflows?api-version=2016-06-01
  <br />
  **Properties:** [\*].properties.accessControl.triggers.allowedCallerIpAddresses.[\*].addressRange
  <br />
  <br />

___

## Azure_LogicApps_AuthZ_Provide_Contents_Access_Control

### Display Name
Access requests to input/output data of Logic App run history must be restricted to specified IP addresses

### Rationale
Using the firewall feature ensures that access to the data or the service is restricted to a specific set/group of clients. While this may not be feasible in all scenarios, when it can be used, it provides an extra layer of access control protection for critical assets.

### Control Spec

> **Passed:**
> If IP ranges are specified and are not of the Any-to-Any type.
>
> **Failed:**
> If any of the following conditions are met:
>   <br />a. If access control is not defined or an empty list is defined then content access requests from any IP address is allowed.
>   <br />b. If access control is specified in the form of IP address ranges but contains atleast one IP range of Any-to-Any type.
> 

### Recommendation

- **Azure Portal**

  Provide access control by navigating to Portal --> Logic App --> Workflow settings --> Access Control Configuration and setting the IP addresses/ranges. Do not add Any-to-Any IP range as this means access to all IPs. Note: In case the IP range is indeterminate (for instance, if the client is a PaaS endpoint), you may need to attest this control.

<!--
- **PowerShell**

	```powershell
	Set-AzStorageContainerAcl -Name '<ContainerName>' -Permission 'Off' -Context (New-AzStorageContext -StorageAccountName '<StorageAccountName>' -StorageAccountKey '<StorageAccountKey>')
	```

	For more help:
	```powershell
	Get-Help Set-AzStorageContainerAcl -full
	```
-->

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to list all the logic apps under subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Logic/workflows?api-version=2016-06-01
  <br />
  **Properties:** [\*].properties.accessControl.contents.allowedCallerIpAddresses.[\*].addressRange
  <br />
  <br />

___

## Azure_LogicApps_AuthN_Connectors_Use_AAD

### Display Name
Logic App connectors must use AAD-based authentication wherever possible

### Rationale
Using the native enterprise directory for authentication ensures that there is a built-in high level of assurance in the user identity established for subsequent access control. All Enterprise subscriptions are automatically associated with their enterprise directory (xxx.onmicrosoft.com) and users in the native directory are trusted for authentication to enterprise subscriptions.

### Control Settings 
```json 
{
    "AllowedAuthTypes": [ "ActiveDirectoryOAuth", "ManagedServiceIdentity" ],
    "ConnectorTypesToEvaluate": [ "HTTP" ],
    "NonCompliantConnectorTypes": [ "FTP" ],
    "CompliantConnectorTypes": [ "Office365" ],
    "NotApplicableConnectorTypes": [ "Request", "Recurrence", "Response", "If", "Switch", "Until", "ForEach" ]
}
 ```  

### Control Spec

> **Passed:**
> If any of the following conditions are met:
>   <br />a. All connectors in Logic App using AAD Auth ( "ActiveDirectoryOAuth", "ManagedServiceIdentity").
>   <br />b. No such connector found in resource which is currently being evaluated by AzTS.
> 
> **Failed:**
> One or more connector in resource is not using AAD Auth.
> 

### Recommendation

- **Azure Portal**

  For HTTP based connectors, Go to Azure Portal --> Logic App --> Logic app designer --> For each non compliant connector --> Update Authentication type to either Managed Identity or Active Directory Oauth. For more details on AAD auth, refer: https://docs.microsoft.com/en-us/azure/connectors/connectors-native-http#azure-active-directory-oauth-authentication. For other connectors you must manually verify that AAD authentication is used for connectors that support it.

<!--
- **PowerShell**

	```powershell
	Set-AzStorageContainerAcl -Name '<ContainerName>' -Permission 'Off' -Context (New-AzStorageContext -StorageAccountName '<StorageAccountName>' -StorageAccountKey '<StorageAccountKey>')
	```

	For more help:
	```powershell
	Get-Help Set-AzStorageContainerAcl -full
	```
-->

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to list Logic apps at subscription level: 
/subscriptions/{subscriptionId}/providers/Microsoft.Logic/workflows?api-version=2016-06-01<br />
**Properties:** [\*].properties.definition.actions[*].type, [\*].properties.definition.actions[*].inputs, [\*].properties.parameters.$connections.value[*].connectionId <br />

- REST API to list API Connections at subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.Web/connections?api-version=2016-06-01<br />
**Properties:** [\*].properties.api.name
<br />
<br />

___

## Azure_LogicApps_DP_Connectors_Encrypt_Data_In_Transit

### Display Name
Data transit across Logic App connectors must use encrypted channel

### Rationale
Use of HTTPS ensures server/service authentication and protects data in transit from network layer man-in-the-middle, eavesdropping, session-hijacking attacks.

### Control Settings 
```json 
{
    "ConnectorTypesToEvaluate": [ "HTTP", "HttpWebhook" ],
    "NonCompliantConnectorTypes": [ "FTP" ],
    "CompliantConnectorTypes": [ "Office365", "Request", "AzureBlob", "Sql", "Response" ],
    "NotApplicableConnectorTypes": [ "Recurrence", "If", "Switch", "Until", "ForEach" ]
}
 ```  

### Control Spec

> **Passed:**
> If any of the following conditions are met:
>   <br />a. All evaluated connector(s) in resource are using HTTPS URI.
>   <br />b. No such connector found in resource which is currently being evaluated by AzTS.
> 
> **Failed:**
> One or more connector(s) in resource not using HTTPS URI.
> 
> **Verify:**
> Not able to validate/parse URI(s) used in one or more connector(s).
> 

### Recommendation

- **Azure Portal**

  For connectors which are HTTP-based, Go to Azure Portal --> Logic App --> Logic app designer --> For each non compliant connector --> Use HTTPS URLs. For other connectors you must manually verify that encrypted connections are used by the connector protocol.

<!--
- **PowerShell**

	```powershell
	Set-AzStorageContainerAcl -Name '<ContainerName>' -Permission 'Off' -Context (New-AzStorageContext -StorageAccountName '<StorageAccountName>' -StorageAccountKey '<StorageAccountKey>')
	```

	For more help:
	```powershell
	Get-Help Set-AzStorageContainerAcl -full
	```
-->

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to list Logic apps at subscription level: 
/subscriptions/{subscriptionId}/providers/Microsoft.Logic/workflows?api-version=2016-06-01<br />
**Properties:** [\*].properties.definition.actions[*].type, [\*].properties.definition.actions[*].inputs, [\*].properties.parameters.$connections.value[*].connectionId <br />

- REST API to list API Connections at subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.Web/connections?api-version=2016-06-01<br />
**Properties:** [\*].properties.api.name
<br />
<br />


___ 

## Azure_LogicApps_Audit_Enable_Diagnostic_Settings
 

### Display Name 
Enable Security Logging in Azure Logic Apps

### Rationale 
Auditing logs and metrics must be enabled as they provide details for investigation in case of a security breach for threats

### Control Settings 
```json 
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticMinRetentionPeriod": "90",
    "DiagnosticLogs": [
  		"WorkflowRuntime"
	],
	"DiagnosticMetrics": [
  		"AllMetrics"
	]
}
 ```  

### Control Spec 

> **Passed:** 
> Diagnostic setting meet the following conditions:
>   1. Diagnostic logs are enabled.
>   2. At least one of the below setting configured:
>       a. Log Analytics.
>       b. Storage account with min Retention period of 90 or forever(Retention period 0).
>       c. Event Hub.
> 
> **Failed:** 
> If any of the below conditions are meet:
>   1. Diagnostic setting meet the following conditions:
>       a. All diagnostic logs are not enabled.
>       b. All below settings are not configured:
>          i. Log Analytics.
>          ii. Storage account (with min Retention period of 90 or forever(Retention period 0).
>          iii. Event Hub.
>   2. Diagnostics setting is disabled for resource.

 
### Recommendation 

- **Azure Portal** 
    - You can change the diagnostic settings from the Azure Portal by following the steps given here: https://learn.microsoft.com/en-us/azure/logic-apps/monitor-workflows-collect-diagnostic-data?source=recommendations&tabs=consumption#add-a-diagnostic-setting and while updating the diagnostic settings 'Workflow runtime diagnostic events'  category of logs and 'AllMetrics' metrics should be selected and minimum required retention period is of 90 days.
      

### Azure Policies or REST APIs used for evaluation 

- REST API used to list diagnostics setting and its related properties at Resource level: <br />
/{ResourceId}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"<br />
**Properties:**
properties.metrics.category,properties.metrics.enabled,properties.metrics.retentionPolicy.enabled, properties.metrics.retentionPolicy.days<br />
properties.logs.category, properties.logs.categorygroup,properties.logs.enabled,properties.metrics.logs.enabled, properties.logs.retentionPolicy.days, name, properties.workspaceId,properties.storageAccountId,properties.eventHubName
 <br />

- REST API used to list diagnostics category group mapping and its related properties at Resource level: <br />
/{ResourceId}/providers/Microsoft.Insights/diagnosticSettingsCategories?api-version=2021-05-01-preview
**Properties:**
properties.categoryGroups, name
___ 


