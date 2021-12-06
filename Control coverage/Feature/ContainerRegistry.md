# ContainerRegistry

**Resource Type:** Microsoft.ContainerRegistry 

<!-- TOC -->

- [Azure_ContainerRegistry_AuthZ_Disable_Admin_Account](#azure_containerregistry_authz_disable_admin_account)
- [Azure_ContainerRegistry_DP_Enable_Content_Trust](#azure_containerregistry_dp_enable_content_trust)
- [Azure_ContainerRegistry_Config_Enable_Security_Scanning](#azure_containerregistry_config_enable_security_scanning)

<!-- /TOC -->
<br/>

___ 

## Azure_ContainerRegistry_AuthZ_Disable_Admin_Account 

### DisplayName 
The Admin account in Container Registry should be disabled 

### Rationale 
The Admin user account is designed for a single user to access the registry. Multiple users authenticating with the admin account appear as just one user to the registry. This leads to loss of auditability. Using AAD-based identity ensures that there is a built-in high level of assurance in the user identity established for subsequent access control. 

### Control Spec 

> **Passed:** 
> 'Admin User' is disabled for Container registry resource.
> 
> **Failed:** 
> 'Admin User' is enabled for Container registry resource.
> 

### Recommendation 
<!--
- **Azure Portal** 
-->
	 
- **PowerShell**   
	 ```powershell 
	 # Run below command to remediate:
	 Update-AzContainerRegistry -DisableAdminUser -Name '<ContainerRegistryName>' -ResourceGroupName '<RGName>'
	 # Run below command to know more
	 Get-Help Update-AzContainerRegistry -full
	 ```  
	_Note: You can add AAD-based SPNs or user accounts to the appropriate RBAC role instead._

<!--
- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policy or ARM API used for evaluation 

- ARM API to lists all the container registries under the specified subscription: /subscriptions/{subscriptionId}/providers/Microsoft.ContainerRegistry/registries?api-version=2019-05-01<br />
**Properties:** properties.adminUserEnabled
 <br />

<br />

___ 

## Azure_ContainerRegistry_DP_Enable_Content_Trust 

### DisplayName 
Content trust must be enabled for the Container Registry 

### Rationale 
Content trust gives the ability to verify both the integrity and the publisher of all the image content received from a registry over any channel. If a container image is served from an untrusted registry, the image itself may not be trustworthy/stable. Running such a compromised image can lead to loss of sensitive enterprise data. 

### Control Spec 

> **Passed:** 
> Content trust is enabled for Container registry resource.
> 
> **Failed:** 
> Content trust is not enabled for Container registry resource.
> 

### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal --> your Container Registry --> Content Trust --> Enabled. This feature is currently available only in Premium SKU. After enabling Content Trust, push only trusted images in the repositories. Refer: https://aka.ms/acr/content-trust. 

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

- ARM API to lists all the container registries under the specified subscription: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{ResourceName}/listPolicies?api-version=2017-10-01<br />
**Properties:** trustPolicy.status
 <br />

<br />

___ 

## Azure_ContainerRegistry_Config_Enable_Security_Scanning 

### DisplayName 
Security scanner identity must be granted access to Container Registry for image scans

### Rationale 
Images in a container registry need to be regularly scanned for vulnerabilities. The enterprise wide solution deployed for this needs access to read the images from the registry to perform the scans. 

### Control Settings 
```json 
{
    "CentralAccount": []
}
 ```  

### Control Spec 

> **Passed:** 
> 1. No mandatory central account required.
> _Or_
> 2. Mandatory central account found with required role.
> 
> **Failed:** 
> Mandatory central account not found with required role.
> 

### Recommendation 
<!--
- **Azure Portal** 
-->

- **PowerShell** 
  
	 ```powershell 
	 # Run below command to remediate:
	 New-AzRoleAssignment -ObjectId '<ObjectId>' -RoleDefinitionName '<RoleName>' -Scope '<Scope>'
	 # Run below command to know more
	 Get-Help New-AzRoleAssignment -full
	 ```  

<!--
- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policy or ARM API used for evaluation 

- ARM API to list role assignment at scope: /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview<br />
**Properties:** UserName, RoleName, ResourceId
 <br />

<br />

___ 

