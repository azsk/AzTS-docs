# HybridCompute

**Resource Type:** Microsoft.HybridCompute/machines
<!-- TOC depthto:2 depthfrom:2 -->

- [Azure_HybridCompute_DP_Use_Secure_TLS_Version_Trial](#azure_hybridcompute_dp_use_secure_tls_version_trial)

<!-- /TOC -->
<br/>

___ 

## Azure_HybridCompute_DP_Use_Secure_TLS_Version_Trial

### Display Name 
[Trial] Use approved version of TLS for ARC Windows Servers

### Rationale 
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions

### Control Settings 
```json 
{
 "ApplicableOsTypes": [
          "Windows"
  ]
}
 ```  

### Control Spec 

> **Passed:** 
> Azure Policy "Configure secure communication protocols (TLS 1.1 or TLS 1.2)" is set compliant state to “Compliant”.
>
> **Failed:** 
>  Azure Policy "Configure secure communication protocols (TLS 1.1 or TLS 1.2)" is set compliant state to “Non-Compliant”.
> 
> **Verify:** 
> Policy state not available for evaluation.
> 
> **NotApplicable:** 
> VM OS type is other then 'Windows'.
>
 
### Recommendation
<!--
- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/endpoints-in-resource-manager, https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-create-nsg-arm-ps 
-->

-
	Install the guest configuration extention.
	 
	```powershell 
	Set-AzVMExtension -Publisher 'Microsoft.GuestConfiguration' -Type 'ConfigurationforWindows' -Name 'AzurePolicyforWindows' -TypeHandlerVersion 1.0 -ResourceGroupName 'myResourceGroup' -Location 'myLocation' -VMName 'myVM' -EnableAutomaticUpgrade $true 
	 ```

- Assign Policy (Configure secure communication protocols (TLS 1.1 or TLS 1.2) on ARC windows servers. Refer: https://learn.microsoft.com/en-us/azure/governance/policy/assign-policy-portal
<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri//providers/Microsoft.Authorization/policyDefinitions/828ba269-bf7f-4082-83dd-633417bc391d) 
	 "/providers/Microsoft.Authorization/policyDefinitions/af6cd1bd-1635-48cb-bde7-5b15693900b9"


	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policies or REST APIs used for evaluation 

- REST API to list hybrid machines at
subscription level:
[/subscriptions/{subscriptionId}/providers/Microsoft.HybridCompute/machines?api-version=2022-08-11-preview](https://learn.microsoft.com/en-us/rest/api/hybridcompute/machines/list-by-subscription?tabs=HTTP)<br />
**Properties:** properties.osType

- Azure Policy used for evaluation: [/providers/Microsoft.Authorization/policyDefinitions/828ba269-bf7f-4082-83dd-633417bc391d](https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F828ba269-bf7f-4082-83dd-633417bc391d)
<br />
<br />

___