# DataLakeStore

**Resource Type:** Microsoft.DataLakeStore/accounts 

<!-- TOC -->

- [Azure_DataLakeStore_DP_Encrypt_At_Rest](#azure_datalakestore_dp_encrypt_at_rest)
- [Azure_DataLakeStore_Audit_Enable_Diagnostic_Settings](#azure_datalakestore_audit_enable_diagnostic_settings)

<!-- /TOC -->
<br/>

___ 

## Azure_DataLakeStore_DP_Encrypt_At_Rest 

### Display Name 
Data Lake Store sensitive data must be encrypted at rest 

### Rationale 
Using this feature ensures that sensitive data is stored encrypted at rest. This minimizes the risk of data loss from physical theft and also helps meet regulatory compliance requirements. 

### Control Spec 

> **Passed:** 
> Encryption is enabled.
> 
> **Failed:** 
> Encryption is disabled.
> 
### Recommendation 

- **Azure Portal** 

	 Ensure that encryption is not disabled when creating a new Data Lake Store. Refer: https://docs.microsoft.com/en-us/azure/data-lake-store/data-lake-store-security-overview#data-protection. Encryption cannot be enabled after the fact for Data Lake Store. 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policies or REST APIs used for evaluation 

- REST API to get the specified Data Lake Store account: 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}?api-version=2016-11-01 
<br />
 
**Properties:** properties.encryptionState
 <br />

<br />

___ 

## Azure_DataLakeStore_Audit_Enable_Diagnostic_Settings

### Display Name
Diagnostics logs must be enabled for Data Lake Store

### Rationale
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.

### Control Settings {
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "Audit",
        "Requests"
    ],
    "DiagnosticMinRetentionPeriod": "365"
}
### Control Spec

> **Passed:**
> Required diagnostic logs are enabled with appropriate retention configuration.
>
> **Failed:**
> Diagnostic logs are not enabled or retention period is insufficient.
>

### Recommendation

- **Azure Portal**

    Go to Data Lake Store ? Monitoring ? Diagnostic settings ? Add diagnostic setting ? Select required log categories ? Configure destination (Log Analytics, Storage Account, or Event Hub) ? Set retention period to 365 days or more.

### Azure Policies or REST APIs used for evaluation

- REST API to list diagnostic setting details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** properties.logs.category, properties.logs.enabled, properties.logs.retentionPolicy<br />

<br />

___ 

