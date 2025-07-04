# CloudService

**Resource Type:** Microsoft.Compute/cloudServices


<!-- TOC -->

- [Azure_CloudService_DP_DontAllow_HTTP_Access_InputEndpoints](#azure_cloudservice_dp_dontallow_http_access_inputendpoints)
- [Azure_CloudService_SI_Auto_OSUpdate](#azure_cloudservice_si_auto_osupdate)
- [Azure_CloudService_SI_Enable_AntiMalware](#azure_cloudservice_si_enable_antimalware)
- [Azure_CloudService_SI_Disable_RemoteDesktop_Access](#azure_cloudservice_si_disable_remotedesktop_access)
- [Azure_CloudService_DP_Avoid_Plaintext_Secrets](#azure_cloudservice_dp_avoid_plaintext_secrets)

<!-- /TOC -->
<br/>

___ 

## Azure_CloudService_DP_DontAllow_HTTP_Access_InputEndpoints 

### Display Name 
Encrypt data in transit for Cloud service role 

### Rationale 
Use of HTTPS ensures server/service authentication and protects data in transit from network layer man-in-the-middle, eavesdropping, session-hijacking attacks.

### Control Spec 

> **Passed:** 
> No active non-SSL enabled input endpoints for all the roles in cloud service.
> 
> **Failed:** 
> Active non-SSL enabled input endpoints are present for any of the roles in cloud service.
>  
### Recommendation 

- **Azure Portal** 

	 Get an SSL certificate from a trusted certificate provider. Refer [Configuring TLS for an application in Azure](https://docs.microsoft.com/en-us/azure/cloud-services/cloud-services-configure-ssl-certificate-portal) for more information on how to use this certificate and configure TLS for the Cloud Service endpoints. 

<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policies or REST APIs used for evaluation 

- REST API to get the list of Deployment Slots in a Cloud Service: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/deploymentSlots?api-version=2016-11-01<br />
**Properties:** properties.slotType, properties.name
 <br />

- REST API to get the list of Cloud Service Roles in a Deployment Slot: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles?api-version=2016-04-01<br />
**Properties:** properties.name
 <br />

- REST API to get Cloud Service roles details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles/{roleName}?api-version=2016-04-01<br />
**Properties:** properties.inputEndpoints.protocol
 <br />

<br />

___ 

## Azure_CloudService_SI_Auto_OSUpdate 

### Display Name 
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

	To enable automatic updates: Go to Azure portal --> your 'Cloud Service' --> under 'settings' section select 'Configuration' tab --> set 'OS version' to 'automatic' from drop-down menu --> Select 'Save'.

<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policies or REST APIs used for evaluation 

- REST API to get the list of Deployment Slots in a Cloud Service: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/deploymentSlots?api-version=2016-11-01<br />
**Properties:** properties.slotType, properties.name
<br />

- REST API to get the list of Deployment Slots in a Cloud Service: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles?api-version=2016-04-01<br />
**Properties:** properties.configuration.osVersion
<br />

<br />

___ 

## Azure_CloudService_SI_Enable_AntiMalware 

### Display Name 
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

### Azure Policies or REST APIs used for evaluation 

- REST API to get the list of Deployment Slots in a Cloud Service: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/deploymentSlots?api-version=2016-11-01<br />
**Properties:** properties.slotType
 <br />

- REST API to get the list of Cloud Service Roles in a Deployment Slot: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles?api-version=2016-04-01<br />
**Properties:** [\*].name
 <br />

- REST API to get the list of Extensions in a Cloud Service Role: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles/{roleName}/extensionReferences?api-version=2015-06-01<br />
**Properties:** name: 'PaaSAntimalware-****', [\*].properties.name, [\*].properties.state
 <br />

<br />

___ 

## Azure_CloudService_SI_Disable_RemoteDesktop_Access 

### Display Name 
Disable Remote Desktop (RDP) access on cloud service roles 

### Rationale 
Remote desktop access requires inbound ports to be opened. These ports become easy targets for compromise from various internet-based attacks. 

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

### Azure Policies or REST APIs used for evaluation 

- REST API to get the list of Deployment Slots in a Cloud Service: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/deploymentSlots?api-version=2016-11-01<br />
**Properties:** properties.slotType, properties.configuration
 <br />

- REST API to get the list of Cloud Service Roles in a Deployment Slot: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles?api-version=2016-04-01<br />
**Properties:** [\*].name
 <br />

- REST API to get the list of Extensions in a Cloud Service Role: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}/slots/{slotName}/roles/{roleName}/extensionReferences?api-version=2015-06-01<br />
**Properties:** [\*].properties.name, [\*].properties.state
 <br />

<br />

___ 



___

## Azure_CloudService_DP_Avoid_Plaintext_Secrets

### Display Name
Avoid storing secrets in plaintext in Azure Cloud Service configuration

### Rationale
Storing secrets such as passwords, connection strings, or API keys in plaintext within Azure Cloud Service configuration files poses a significant security risk. Plaintext secrets are vulnerable to accidental exposure, unauthorized access, and compromise, potentially leading to data breaches or unauthorized actions within your environment. Azure recommends using secure mechanisms such as Azure Key Vault to manage and reference secrets, ensuring they are encrypted at rest and in transit, and access is tightly controlled and auditable. This control helps organizations meet compliance requirements for secret management and reduces the risk of credential leakage.

### Control Spec

> **Passed:**
> - No secrets (passwords, connection strings, API keys, tokens, etc.) are stored in plaintext within the Cloud Service configuration files (ServiceConfiguration.cscfg, ServiceDefinition.csdef).
> - All sensitive information is referenced via secure mechanisms such as Azure Key Vault references or environment variables with secure access.
>
> **Failed:**
> - Any secret is found in plaintext within the Cloud Service configuration files.
> - Sensitive information is hardcoded or stored without encryption or secure referencing.

### Recommendation

- **Azure Portal**
    1. Navigate to your Cloud Service (Classic) resource.
    2. Review the configuration settings under the "Configuration" blade.
    3. Identify any settings containing secrets in plaintext.
    4. Remove plaintext secrets and replace them with references to Azure Key Vault or use secure environment variables.
    5. Update and redeploy your Cloud Service with the revised configuration.

- **PowerShell**
    ```powershell
    # Example: Remove or replace plaintext secrets in configuration
    # Export current configuration
    Get-AzureService | Export-AzureServiceProject

    # Edit ServiceConfiguration.cscfg to remove plaintext secrets
    # Replace with Key Vault reference or secure environment variable

    # Redeploy the updated configuration
    Publish-AzureServiceProject -ServiceName <ServiceName> -Location <Location>
    ```

- **Azure CLI**
    ```bash
    # Download current configuration
    az cloud-service role list --service-name <ServiceName> --query "[].{name:name, config:configuration}"

    # Edit configuration file to remove plaintext secrets

    # Update cloud service with new configuration
    az cloud-service update --name <ServiceName> --resource-group <ResourceGroup> --set configuration=@ServiceConfiguration.cscfg
    ```

- **Automation/Remediation**
    - Use Azure Policy to deny deployments containing plaintext secrets in configuration files.
    - Implement CI/CD pipeline checks to scan for plaintext secrets before deployment (e.g., using tools like Microsoft Security DevOps or open-source secret scanners).
    - Use ARM templates with Key Vault references for all sensitive parameters.
    - For bulk remediation, script scanning of all Cloud Service configurations in your subscription for plaintext secrets and replace them with Key Vault references.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ClassicCompute/domainNames/{cloudServiceName}?api-version=2016-04-01`
  <br />
  **Properties:** `properties.configuration`, `properties.serviceDefinition`
- Azure Policy: [Azure Policy definition for denying plaintext secrets in configuration files](https://docs.microsoft.com/azure/governance/policy/samples/deny-plaintext-secrets)

<br/>

___
