# CloudService

**Resource Type:** Microsoft.Compute/cloudServices

___ 

## Azure_CloudService_DP_DontAllow_HTTP_Access_InputEndpoints 

### DisplayName 
Encrypt data in transit for Cloud service role 

### Rationale 
Use of HTTPS ensures server/service authentication and protects data in transit from network layer man-in-the-middle, eavesdropping, session-hijacking attacks. 

### Control Spec 

> **Passed:** 
> No active non SSL enabled input endpoints for all the roles in cloud service.
> 
> **Failed:** 
> Active non SSL enabled input endpoints are present for any of the roles in cloud service.
>  
### Recommendation 

- **Azure Portal** 

	 Get an SSL certificate from a trusted certificate provider. Upload that certificate to cloud service. Update input endpoints by renaming HTTP to HTTPS in .csdef. Refer: https://docs.microsoft.com/en-us/azure/cloud-services/cloud-services-configure-ssl-certificate 

<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policy or ARM API used for evaluation 

- ARM API to get the list of Deployment Slots in a Cloud Service: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/deploymentSlots?api-version=2016-11-01<br />
**Properties:** properties.slotType, properties.name
 <br />

- ARM API to get the list of Cloud Service Roles in a Deployment Slot: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles?api-version=2016-04-01<br />
**Properties:** properties.name
 <br />

- ARM API to get Cloud Service roles details: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles/{roleName}?api-version=2016-04-01<br />
**Properties:** properties.inputEndpoints.protocol
 <br />

<br />

___ 

## Azure_CloudService_SI_Auto_OSUpdate 

### DisplayName 
Set automatic update for Cloud Service OS version 

### Rationale 
Cloud services where automatic updates are disabled are likely to miss important security patches (human error, forgetfulness). This may lead to compromise from various malware/trojan attacks that exploit known vulnerabilities in operating systems and related software. 

### Control Spec 

> **Passed:** 
> Cloud service is enabled with automatic OS updates for all slots with slotType as 'Role'.
> 
> **Failed:** 
> Cloud service is not set up for automatic OS updates for any of the slots with slotType as 'Role'.
> 
### Recommendation 

- **Azure Portal** 

	To enable automatic updates: Go to Azure portal --> your Cloud ervice --> under configure tab --> set operating system version to automatic. 

<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policy or ARM API used for evaluation 

- ARM API to get the list of Deployment Slots in a Cloud Service: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/deploymentSlots?api-version=2016-11-01<br />
**Properties:** properties.slotType, properties.name
<br />

- ARM API to get the list of Deployment Slots in a Cloud Service: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles?api-version=2016-04-01<br />
**Properties:** properties.configuration.osVersion
<br />

<br />

___ 

## Azure_CloudService_SI_Enable_AntiMalware 

### DisplayName 
Antimalware extension must be installed on cloud service roles 

### Rationale 
Antimalware provides real-time protection, scheduled scanning, malware remediation, signature updates, engine updates, samples reporting, exclusion event collection etc. 

### Control Spec 

> **Passed:** 
> Antimalware extension is enabled for all the roles in the Cloud Service.
> 
> **Failed:** 
> Antimalware extension is not enabled for one or more roles in the Cloud Service.
> 
### Recommendation 

- **Azure Portal** 

	 To enable Antimalware: Go to Azure portal --> your cloud service --> Antimalware under Settings section--> select role and enable Antimalware. 

<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policy or ARM API used for evaluation 

- ARM API to get the list of Deployment Slots in a Cloud Service: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/deploymentSlots?api-version=2016-11-01<br />
**Properties:** properties.slotType
 <br />

- ARM API to get the list of Cloud Service Roles in a Deployment Slot: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles?api-version=2016-04-01<br />
**Properties:** [*].name
 <br />

- ARM API to get the list of Extensions in a Cloud Service Role: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles/{roleName}/extensionReferences?api-version=2015-06-01<br />
**Properties:** name: 'PaaSAntimalware-****', [*].properties.name, [*].properties.state
 <br />

<br />

___ 

## Azure_CloudService_SI_Disable_RemoteDesktop_Access 

### DisplayName 
Disable Remote Desktop (RDP) access on cloud service roles 

### Rationale 
Remote desktop access requires inbound ports to be opened. These ports become easy targets for compromise from various internet based attacks. 

### Control Spec 

> **Passed:** 
> Remote Desktop access is not enabled for any Cloud Service Role.
> 
> **Failed:** 
> Remote Desktop access is enabled for Cloud Service Role(s).
> 

### Recommendation 

- **Azure Portal** 

	 From Azure Portal: After logging into subscription, go under Home -> All Resources -> Select the Cloud service resource type -> Remote Desktop. Under "Remote Desktop", make sure to select "Disabled" toggle option. From PowerShell: Refer https://docs.microsoft.com/en-us/azure/cloud-services/cloud-services-role-enable-remote-desktop-powershell to remove Remote Desktop Extension from a Service. Refer https://docs.microsoft.com/en-us/powershell/module/servicemanagement/azure.service/remove-azureserviceremotedesktopextension?view=azuresmps-4.0.0 to know more about Remove-AzureServiceRemoteDesktopExtension command. 

<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policy or ARM API used for evaluation 

- ARM API to get the list of Deployment Slots in a Cloud Service: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/deploymentSlots?api-version=2016-11-01<br />
**Properties:** properties.slotType, properties.configuration
 <br />

- ARM API to get the list of Cloud Service Roles in a Deployment Slot: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles?api-version=2016-04-01<br />
**Properties:** [*].name
 <br />

- ARM API to get the list of Extensions in a Cloud Service Role: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles/{roleName}/extensionReferences?api-version=2015-06-01<br />
**Properties:** [*].properties.name, [*].properties.state
 <br />

<br />

___ 

