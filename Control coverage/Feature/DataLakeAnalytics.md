# DataLakeAnalytics

**Resource Type:** Microsoft.DataLakeAnalytics/accounts 

___ 

## Azure_DataLakeAnalytics_DP_Encrypt_At_Rest 

### DisplayName 
Data Lake Analytics sensitive data must be encrypted at rest 

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

	 Default Data Lake Store Account must have encryption enabled. Refer: https://docs.microsoft.com/en-us/azure/data-lake-store/data-lake-store-security-overview#data-protection 

<!---- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policy or ARM API used for evaluation 

- ARM API to get the Data Lake Store accounts associated with the Data Lake Analytics account: - 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeAnalytics/accounts/{accountName}?api-version=2016-11-01 
<br />
 
**Properties:** properties.dataLakeStoreAccounts[*].name
 <br />

- ARM API to get encryption state of associated Data Lake Store accounts: - 
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeStore/accounts/{accountName}?api-version=2016-11-01 
<br />
 
**Properties:** properties.encryptionState
 <br />

<br />

___ 

