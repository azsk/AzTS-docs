# Storage

**Resource Type:** Microsoft.Storage/storageAccounts

<!-- TOC -->

- [Azure_Storage_AuthN_Dont_Allow_Anonymous](#azure_storage_authn_dont_allow_anonymous)
- [Azure_Storage_DP_Encrypt_In_Transit](#azure_storage_dp_encrypt_in_transit)
- [Azure_Storage_NetSec_Restrict_Network_Access](#azure_storage_netsec_restrict_network_access)
- [Azure_Storage_DP_Use_Secure_TLS_Version](#azure_storage_dp_use_secure_tls_version)

<!-- /TOC -->
<br/>

___

## Azure_Storage_AuthN_Dont_Allow_Anonymous

### Display Name
Ensure secure access to storage account containers

### Rationale
Data in containers that have anonymous access can be downloaded by anyone on the internet without authentication. This can lead to a compromise of corporate data.

### Control Spec

> **Passed:**
> Storage account does not have any containers with public access.
>
> **Failed:**
> Storage account has one or more containers with public access.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Storage account is of type `FileStorage`. Kind - `FileStorage` does not support containers.
>
### Recommendation

<!--
- **Azure Portal**
-->

- **PowerShell**

	```powershell
	Set-AzStorageContainerAcl -Name '<ContainerName>' -Permission 'Off' -Context (New-AzStorageContext -StorageAccountName '<StorageAccountName>' -StorageAccountKey '<StorageAccountKey>')
	```

	For more help:
	```powershell
	Get-Help Set-AzStorageContainerAcl -full
	```

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policy or ARM API used for evaluation

- ARM API to list all the storage accounts available under the subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01
  <br />
  **Properties:** [*].kind, [*].properties.allowBlobPublicAccess
  <br />
  <br />

___

## Azure_Storage_DP_Encrypt_In_Transit

### Display Name
Enable Secure transfer to storage accounts

### Rationale
Use of HTTPS ensures server/service authentication and protects data in transit from network layer man-in-the-middle, eavesdropping, session-hijacking attacks. When enabling HTTPS, one must remember to simultaneously disable access over plain HTTP else data can still be subject to compromise over clear text connections.

### Control Spec

> **Passed:**
> Azure Security Center (ASC) reports the assessment status for the storage account as `Healthy`.
> (or)
> Storage account supports encryption in transit using HTTPS protocol.
>
> **Failed:**
> Azure Security Center (ASC) reports the assessment status for the storage account as either `Unhealthy`, or `NotApplicable` with `cause` - `OffByPolicy` or `Exempt`.
> (or)
> Storage account does not support encryption in transit using HTTPS protocol.
>
> **Verify:**
> Azure Security Center (ASC) reports the assessment status for the storage account as `Not Applicable` with `cause` other than `OffByPolicy` and `Exempt`.
>
> **NotApplicable:**
> Not Applicable.
>
> **Note:** If no Azure Security Center (ASC) assessment is found for the storage account, response from the ARM API is considered for the evaluation.
>
### Recommendation

- **Azure Portal**

  Refer https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer#require-secure-transfer-for-an-existing-storage-account to enable secure transfer for storage accounts.

- **PowerShell**

	```powershell
	Set-AzStorageAccount -ResourceGroupName <RGName> -Name <StorageAccountName> -EnableHttpsTrafficOnly $true
	```

  For more help:
	```powershell
	Get-Help Set-AzStorageAccount -full
	```

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policy or ARM API used for evaluation

- Azure Policy (built-in):
  [Secure transfer to storage accounts should be enabled](https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F404c3081-a854-4457-ae30-26a93ef643f9)
  <br />

- ARM API to list all the storage accounts available under the subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01
  <br />
  **Properties:** [*].properties.supportsHttpsTrafficOnly
  <br />
  <br />

___

## Azure_Storage_NetSec_Restrict_Network_Access

### Display Name
Ensure that Firewall and Virtual Network access is granted to a minimal set of trusted origins

### Rationale
Restricting access using firewall/virtual network config reduces network exposure of a storage account by limiting access only to expected range/set of clients. Note that this depends on the overall service architecture and may not be possible to implement in all scenarios.

### Control Spec

> **Passed:**
> Firewall and Virtual Network restrictions are defined for the storage account.
>
> **Failed:**
> Firewall and Virtual Network restrictions are not defined for the storage account.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>
### Recommendation

- **Azure Portal**

	Go to Azure Portal --> your Storage service --> Settings --> Firewalls and virtual networks --> Selected Network. Provide the specific IP address and Virtual Network details that should be allowed to access storage account.

<!--
- **PowerShell**

	 ```powershell
	 $variable = 'apple'
	 ```
-->

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policy or ARM API used for evaluation

- ARM API to list all the storage accounts available under the subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01
  <br />
  **Properties:** [*].properties.networkAcls.defaultAction
  <br />
  <br />

___

## Azure_Storage_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for Azure Storage

### Rationale
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions.

### Control Settings

```json
{
    "MinReqTLSVersion": "1.2"
}
```

### Control Spec

> **Passed:**
> Minimum TLS version is set to 1.2 or higher.
>
> **Failed:**
> Any of the following conditions is met.
> * Minimum TLS version is not set (default 1.0).
> * Minimum TLS version is set to 1.0 or 1.1.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>
### Recommendation

- **Azure Portal**

  Refer https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version?tabs=portal#configure-the-minimum-tls-version-for-a-storage-account to configure the minimum TLS version for a storage account.

- **PowerShell**

  Refer https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version?tabs=powershell#configure-the-minimum-tls-version-for-a-storage-account to configure the minimum TLS version for a storage account.

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policy or ARM API used for evaluation

- ARM API to list all the storage accounts available under the subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01
  <br />
  **Properties:** [*].properties.minimumTlsVersion
  <br />
  <br />

___

