# LogicApps

**Resource Type:** Microsoft.Logic/workflows

<!-- TOC -->

- [Azure_LogicApps_AuthZ_Provide_Triggers_Access_Control](#Azure_LogicApps_AuthZ_Provide_Triggers_Access_Control)
- [Azure_LogicApps_AuthZ_Provide_Contents_Access_Control](#Azure_LogicApps_AuthZ_Provide_Contents_Access_Control)

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

### Azure Policy or ARM API used for evaluation

- ARM API to list all the logic apps under subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Logic/workflows?api-version=2016-06-01
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

### Azure Policy or ARM API used for evaluation

- ARM API to list all the logic apps under subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Logic/workflows?api-version=2016-06-01
  <br />
  **Properties:** [\*].properties.accessControl.contents.allowedCallerIpAddresses.[\*].addressRange
  <br />
  <br />

___
