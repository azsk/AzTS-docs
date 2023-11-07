# DataLakeStore

**Resource Type:** Microsoft.DataLakeStore/accounts 

<!-- TOC -->

- [Azure_DataLakeStore_DP_Encrypt_At_Rest](#azure_datalakestore_dp_encrypt_at_rest)

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

