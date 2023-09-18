# KeyVault

**Resource Type:** Microsoft.KeyVault/vaults

<!-- TOC -->

- [Azure_KeyVault_AuthZ_Configure_Advanced_Access_Policies](#azure_keyvault_authz_configure_advanced_access_policies)
- [Azure_KeyVault_SI_Enable_SoftDelete](#azure_keyvault_si_enable_softdelete)
- [Azure_KeyVault_Audit_Enable_Diagnostics_Log](#azure_keyvault_audit_enable_diagnostics_log)
- [Azure_KeyVault_NetSec_Disable_Public_Network_Access](#azure_keyvault_netsec_disable_public_network_access)
- [Azure_KeyVault_BCDR_Enable_SoftDelete_and_PurgeProtection](#Azure_KeyVault_BCDR_Enable_SoftDelete_and_PurgeProtection)

<!-- /TOC -->
<br/>

___ 

## Azure_KeyVault_AuthZ_Configure_Advanced_Access_Policies 

### Display Name 
Advanced access policies must be configured on a need basis 

### Rationale 
Advanced access policy allows Azure services (Azure Resource Manager, Virtual Machine, Disk Encryption etc.) to seamlessly access Key Vault. To avoid unintentional access to Key Vault from Azure services, advanced access policies must be configured only as required. 

### Control Spec 

> **Passed:** 
> All Advanced access policies are not enabled.
> 
> **Failed:** 
> All Advanced access policies are enabled.
> 
### Recommendation 

<!-- - **Azure Portal** 

	 Remove any advanced policies that are not required using the command: Remove-AzKeyVaultAccessPolicy -VaultName '{VaultName}' -ResourceGroupName '{ResourceGroupName}' -EnabledForDeployment -EnabledForTemplateDeployment -EnabledForDiskEncryption. Refer: https://docs.microsoft.com/en-us/powershell/module/az.keyvault/Remove-AzKeyVaultAccessPolicy  -->

- **PowerShell** 

	 ```powershell 
	 # Remove any advanced policies that are not required using the command: 
     
     Remove-AzKeyVaultAccessPolicy -VaultName '{VaultName}' -ResourceGroupName '{ResourceGroupName}' -EnabledForDeployment -EnabledForTemplateDeployment -EnabledForDiskEncryption.

     # Refer: https://docs.microsoft.com/en-us/powershell/module/az.keyvault/Remove-AzKeyVaultAccessPolicy
	 ```  

<!-- - **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list all the KeyVault configurations under the specified subscription: /subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01<br/>
**Properties:** 
properties/enabledForDeployment<br/>
properties/enabledForDiskEncryption<br/>
properties/enabledForTemplateDeployment
 <br />

<br />

___ 

## Azure_KeyVault_SI_Enable_SoftDelete 

### Display Name 
Soft delete must be enabled to allow recovery of deleted Key Vault and any objects (keys, secrets, etc.) contained in it 

### Rationale 
Enabling soft delete feature on Key Vault acts as a safety measure to recover inadvertently or maliciously deleted Key Vault and any objects (keys, secrets, etc.) contained in it. 

### Control Spec 

> **Passed:** 
> Soft delete is enabled for KeyVault.
> 
> **Failed:** 
> Soft delete is disabled for KeyVault.
> 
### Recommendation 

<!-- - **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/key-vault/key-vault-soft-delete-powershell to enable soft delete feature on Key Vault.  -->

- **PowerShell** 

    Refer: https://docs.microsoft.com/en-us/azure/key-vault/key-vault-soft-delete-powershell to enable soft delete feature on Key Vault. 
<!-- 
	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list all the KeyVault configurations under the specified subscription: /subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01<br />
**Properties:** properties.enableSoftDelete
 <br />

<br />

___ 

## Azure_KeyVault_Audit_Enable_Diagnostics_Log 

### Display Name 
Diagnostics logs must be enabled with a retention period of at least 365 days 

### Rationale 
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well. 

### Control Settings 
```json 
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "AuditEvent"
    ],
    "DiagnosticMinRetentionPeriod": "365"
}
 ``` 

### Control Spec 

> **Passed:** 
> 1. Required diagnostic logs are enabled.
>
>       and
>
> 2. At least one of the below setting configured:
> a. Log Analytics.
> b. Storage account (with min Retention period of 365 or forever(Retention period 0).
> c. Event Hub.
> 
> **Failed:** 
> 1. Diagnostics setting is disabled for resource.
> 
>       or
>
> 2. Diagnostic settings meet the following conditions:
> a. All diagnostic logs are not enabled.
> b. None of the below setting is configured:
> i. Log Analytics.
> ii. Storage account (with min Retention period of 365 or forever(Retention period 0).
> iii. Event Hub.
> 
> **Error:** 
> Required logs are not configured in control settings.
> 

### Recommendation 

- **Azure Portal** 

	 You can change the diagnostic settings from the Azure Portal by following the steps given here: https://docs.microsoft.com/en-us/azure/monitoring-and-diagnostics/monitoring-archive-diagnostic-logs#archive-diagnostic-logs-using-the-portal 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to list diagnostic setting details of Key Vault resources: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{serviceName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** 
name<br />
properties.logs.category<br />
properties.logs.enabled<br />
properties.logs.retentionPolicy.enabled<br />
properties.logs.retentionPolicy.days<br />
properties.workspaceId<br />
properties.storageAccountId<br />
properties.eventHubName<br />
 <br />

<br />

___ 

## Azure_KeyVault_NetSec_Disable_Public_Network_Access

### Display Name
Key Vault must have public access disabled.

### Rationale
Key Vault firewall should be enabled so that the key vault is not accessible by default to any public IPs.

### Control Spec

> **Passed:**
> Network ACLs default action set as deny.
>
> **Failed:**
> Network ACLs default action not set or set as allow.
>
### Recommendation

- **Azure Portal**
	1. Go to [Azure Portal](https://portal.azure.com/) and locate your Key Vault resource.
	2. Under **Settings**, find the **Networking** tab.
	3. Under **Firewalls and virtual networks**, set '**Allow access from**' to either of the following:
		* Allow public access from specific virtual networks and IP addresses. (Do not use "0.0.0.0/0" as the IP range as that allows traffic from any address.)
		* Disable public access.

- **PowerShell**

	```powershell
	# Prerequisites: Appropriate context is set up using Connect-AzAccount and Set-AzContext.
	Update-AzKeyVaultNetworkRuleSet -VaultName "<keyvault-name>" -IpAddressRange @('<ip-range-cidr-1>','<ip-range-cidr-2>') -DefaultAction Deny
	```

### Azure Policy or ARM API used for evaluation

- ARM API to list all the KeyVault configurations under the specified subscription: /subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01<br />
**Properties:**
properties.publicNetworkAccess<br />
properties.networkAcls<br />
 <br />

<br />

___

## Azure_KeyVault_BCDR_Enable_SoftDelete_and_PurgeProtection

### Display Name
Key Vaults must have Soft Delete and Purge Protection enabled

### Rationale
Malicious deletion of a key vault can lead to permanent data loss. A malicious insider in your organization can potentially delete and purge key vaults. Purge protection protects you from insider attacks by enforcing a mandatory retention period for soft deleted key vaults. No one inside your organization or Microsoft will be able to purge your key vaults during the soft delete retention period.

### Control Spec

> **Passed:**
> if both Soft Delete and Purge Protections are enabled.
>
> **Failed:**
> if Soft Delete or Purge Protections is disabled.
>
### Recommendation

- **Azure Portal**
	1. Log in to the Azure portal and select your key vault. 
	2. Click on the 'Properties' tab. 
	3. Select the radio button corresponding to Enable purge protection. 
	4. Select Save. Soft delete is a pre-requisite for purge protection, if you have not already enabled this option, please select the radio button corresponding to Enable soft delete first. Please visit https://aka.ms/keyvaultsoftdelete for detailed configuration steps.

### Azure Policy or ARM API used for evaluation

- ARM API to list all the KeyVault configurations under the specified subscription: /subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01<br />
**Properties:**
properties.enablePurgeProtection<br />
properties.enableSoftDelete<br />
 <br />

<br />

___