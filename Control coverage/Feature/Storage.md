# Storage

**Resource Type:** Microsoft.Storage/storageAccounts

<!-- TOC -->

- [Azure_Storage_AuthN_Dont_Allow_Anonymous](#azure_storage_authn_dont_allow_anonymous)
- [Azure_Storage_DP_Encrypt_In_Transit](#azure_storage_dp_encrypt_in_transit)
- [Azure_Storage_NetSec_Restrict_Network_Access](#azure_storage_netsec_restrict_network_access)
- [Azure_Storage_DP_Use_Secure_TLS_Version](#azure_storage_dp_use_secure_tls_version)
- [Azure_Storage_AuthZ_Set_SAS_Expiry_Interval](#azure_storage_authz_set_sas_expiry_interval)
- [Azure_Storage_DP_Rotate_Access_Keys](#Azure_Storage_DP_Rotate_Access_Keys)
- [Azure_Storage_Audit_Enable_Diagnostic_Settings](#azure_storage_audit_enable_diagnostic_settings)
- [Azure_Storage_AuthN_Disable_Key_Access](#azure_storage_authn_disable_key_access)
- [Azure_Storage_BCDR_Configure_Required_Redundancy](#azure_storage_bcdr_configure_required_redundancy)
- [Azure_Storage_DP_Enable_Infrastructure_Encryption](#azure_storage_dp_enable_infrastructure_encryption)

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
> Storage account has **'Allow Blob public access'** setting as disabled.
>
> **Failed:**
> Storage account has **'Allow Blob public access'** setting as enabled.
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

### Azure Policies or REST APIs used for evaluation

- REST API to list all the storage accounts available under the subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01
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
> Microsoft Defender for Cloud (MDC) reports the assessment status for the storage account as `Healthy`.
> (and) either of below:
> - Storage account supports encryption in transit using HTTPS protocol.
> - Storage account has only NFS based file shares (which does not support encryption in transit).
>
> **Failed:**
> Microsoft Defender for Cloud (MDC) reports the assessment status for the storage account as either `Unhealthy`, or `NotApplicable` with `cause` - `OffByPolicy` or `Exempt`.
> (or) Storage account has both NFS & SMB based file shares (Since the NFS File shares do not support encryption in transit, they will have to be moved into a separate storage account in order to be excluded from evaluation)
>
> **Verify:**
> Microsoft Defender for Cloud (MDC) reports the assessment status for the storage account as `Not Applicable` with `cause` other than `OffByPolicy` and `Exempt`.
>
> **NotApplicable:**
> Not Applicable.
>
> **Note:** If no Microsoft Defender for Cloud (MDC) assessment is found for the storage account, response from the ARM API is considered for the evaluation.
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
**NOTE:** If your Storage account contains NFS and SMB Fileshares, you would need to move your NFS Fileshares to a separate Storage account that only contains NFS Fileshares. Such Storage accounts would be exempted from evaluation of this security control. Any Storage accounts with SMB fileshare are evaluated for secure transfer with this control.

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- Azure Policy (built-in):
  [Secure transfer to storage accounts should be enabled](https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F404c3081-a854-4457-ae30-26a93ef643f9)
  <br />

- REST API to list all the storage accounts available under the subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01
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

### Azure Policies or REST APIs used for evaluation

- REST API to list all the storage accounts available under the subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01
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
> * Minimum TLS version is less than 1.2 (configured min required tls version).
><!--
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>-->
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

### Azure Policies or REST APIs used for evaluation

- REST API to list all the storage accounts available under the subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01
  <br />
  **Properties:** [*].properties.minimumTlsVersion
  <br />
  <br />

___

## Azure_Storage_AuthZ_Set_SAS_Expiry_Interval

### Display Name
Shared Access Signature (SAS) expiry interval must be less than recommended upper limit for Azure Storage

### Rationale
Shared Access Signature (SAS) is used to provide secure delegate access to resources in storage account. Setting SAS expiry interval to less than recommended upper limit mitigates the risk of providing access to resources in storage account for a large amount of time.

### Control Settings
```json
{
    "SASExpirationPeriod": "7.00:00:00"
}
```
### Control Spec

> **Passed:**
> Azure Storage current SAS expiry interval is set to either less than or equal to the recommended SAS expiry interval.
>
> **Failed:**
> Any of the following conditions is met.
> * Azure Storage current SAS expiry interval is greater than recommended SAS expiry interval.
> * Azure Storage SAS expiry interval is null.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>
### Recommendation

- **Azure Portal**

  Refer https://learn.microsoft.com/en-us/azure/storage/common/sas-expiration-policy?tabs=azure-portal#configure-a-sas-expiration-policy to configure SAS expiry interval for a storage account.

- **PowerShell**

  Refer https://learn.microsoft.com/en-us/azure/storage/common/sas-expiration-policy?tabs=azure-powershell#configure-a-sas-expiration-policy to configure SAS expiry interval for a storage account.

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to list all the storage accounts available under the subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01
  <br />
  **Properties:** [*].properties.sasPolicy.sasExpirationPeriod
  <br />
  <br />

___

## Azure_Storage_DP_Rotate_Access_Keys

### Display Name
Azure Storage account access keys must be rotated on periodic basis.

### Rationale
Rotating access keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used.

### Control Settings
```json
{
    "RecommendedKeyRotationPeriodInDays": "90"
}
```
### Control Spec

> **Passed:**
> Azure Storage account access keys are rotated less than or equal to the required key rotation period.
>
> **Failed:**
> Azure Storage account access keys rotated period is greater than recommended key rotation period.
>

### Recommendation


- **Azure Portal**

  To Rotate 'Keys' for Azure Storage, Go to Azure Portal --> Your Storage Account --> Access keys --> choose the key you want to rotate and press Rotate Key. Refer: https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal.

- **PowerShell**

	```powershell
   New-AzStorageAccountKey -ResourceGroupName '<ResourceGroupName>' -Name '<Name>' -KeyName '<KeyName>'

### Azure Policies or REST APIs used for evaluation

- REST API to list all the storage accounts available under the subscription:
/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01
<br />
**Properties:** [*].properties.keyCreationTime
<br />
<br />

___

## Azure_Storage_Audit_Enable_Diagnostic_Settings

### Display Name
Diagnostics logs must be enabled for Storage Account

### Rationale
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.

### Control Settings 
```json
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "StorageRead",
        "StorageWrite",
        "StorageDelete"
    ],
    "DiagnosticMinRetentionPeriod": "365"
}
```
### Control Spec

> **Passed:**
> Required diagnostic logs are enabled with appropriate retention configuration.
>
> **Failed:**
> Diagnostic logs are not enabled or retention period is insufficient.
>

### Recommendation

- **Azure Portal**

    Go to Storage Account ? Monitoring ? Diagnostic settings ? Add diagnostic setting ? Select required log categories ? Configure destination (Log Analytics, Storage Account, or Event Hub) ? Set retention period to 365 days or more.

### Azure Policies or REST APIs used for evaluation

- REST API to list diagnostic setting details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** properties.logs.category, properties.logs.enabled, properties.logs.retentionPolicy<br />

<br />

___

## Azure_Storage_AuthN_Disable_Key_Access

### Display Name
Storage Account must disable key-based authentication

### Rationale
Disabling key-based authentication forces the use of Azure Active Directory authentication, providing better security, audit trails, and centralized identity management.

### Control Spec

> **Passed:**
> Key-based authentication is disabled.
>
> **Failed:**
> Key-based authentication is enabled.
>

### Recommendation

- **Azure Portal**

    Go to Storage Account ? Configuration ? Allow storage account key access ? Disabled ? Save.

### Azure Policies or REST APIs used for evaluation

- REST API to get Storage Account configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}<br />
**Properties:** properties.allowSharedKeyAccess<br />

<br />

___

## Azure_Storage_BCDR_Configure_Required_Redundancy

### Display Name
Storage Account must be configured with required redundancy level

### Rationale
Configuring appropriate redundancy ensures data availability and protection against outages and disasters according to business requirements.

### Control Settings 
```json
{
    "RequiredRedundancyLevels": ["GRS", "RAGRS", "GZRS", "RAGZRS"],
    "MinimumRedundancyLevel": "GRS"
}
```
### Control Spec

> **Passed:**
> Storage Account is configured with required redundancy level.
>
> **Failed:**
> Storage Account redundancy level does not meet requirements.
>

### Recommendation

- **Azure Portal**

    Go to Storage Account ? Data management ? Redundancy ? Select appropriate redundancy level (GRS, RA-GRS, GZRS, or RA-GZRS) ? Save.

### Azure Policies or REST APIs used for evaluation

- REST API to get Storage Account configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}<br />
**Properties:** sku.name<br />

<br />

___

## Azure_Storage_DP_Enable_Infrastructure_Encryption

### Display Name
Storage Account must enable infrastructure encryption

### Rationale
Infrastructure encryption provides an additional layer of encryption at the infrastructure level, enhancing data protection for highly sensitive data.

### Control Spec

> **Passed:**
> Infrastructure encryption is enabled.
>
> **Failed:**
> Infrastructure encryption is not enabled.
>

### Recommendation

- **Azure Portal**

    Infrastructure encryption can only be enabled during storage account creation. Create a new storage account with infrastructure encryption enabled during the creation process.

### Azure Policies or REST APIs used for evaluation

- REST API to get Storage Account encryption configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}<br />
**Properties:** properties.encryption.requireInfrastructureEncryption<br />

<br />

___