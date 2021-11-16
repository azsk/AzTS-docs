# CosmosDB

**Resource Type:** Microsoft.DocumentDB/databaseAccounts 

___ 

## Azure_CosmosDB_AuthZ_Enable_Firewall 

### DisplayName 
Cosmos DB firewall should be enabled 

### Rationale 
Using the firewall feature ensures that access to the data or the service is restricted to a specific set/group of clients. While this may not be feasible in all scenarios, when it can be used, it provides an extra layer of access control protection for critical assets. 

### Control Spec 

> **Passed:** 
> Firewall IP range filter is set for CosmosDB.
> 
> **Failed:** 
> Firewall IP range filter is not set for CosmosDB.
> 
### Recommendation 

- **Azure Portal** 

	 Azure Portal --> Resource --> Firewall. Turn 'ON' - 'Selected Networks' and provide required IP addresses and/or ranges in the IP tab and save. Note: In case the IP range is indeterminate (for instance, if the client is a PaaS endpoint), you may need to attest this control. 

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

- ARM API to get CosmosDB resources in a subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2019-08-01<br />
**Properties:** properties.ipRangeFilter
 <br />

<br />

___ 

## Azure_CosmosDB_AuthZ_Verify_IP_Range 

### DisplayName 
Configure only the required IP addresses on Cosmos DB firewall 

### Rationale 
Using the firewall feature ensures that access to the data or the service is restricted to a specific set/group of clients. For effective usage, allow only the required IPs. Allowing larger ranges like 0.0.0.0/0, 0.0.0.0/1, 128.0.0.0/1, etc. will defeat the purpose. 

### Control Settings 
```json 
{
    "IpLimitPerDb": 2048,
    "IpLimitPerRange": 256
}
 ```  
 
### Control Spec 

> **Passed:** 
> Firewall rule is correctly configured for CosmosDB.
> 
> **Failed:** 
> Firewall rule is not correctly configured for CosmosDB.
> 
### Recommendation 

- **Azure Portal** 

	 Do not use high ranges like 0.0.0.0/0, 0.0.0.0/1, 128.0.0.0/1, etc. Maximum IPs in a range should be less that 256 and total IPs including all ranges should be less than 2048. To modify - Azure Portal --> Resource --> Firewall and Virtual networks. Turn 'ON' - 'Enable IP Access Control' and add/or remove IP addresses and/or ranges and save. Note: In case the IP range is indeterminate (for instance, if the client is a PaaS endpoint), you may need to attest this control. 

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

- ARM API to get CosmosDB resources in a subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2019-08-01<br />
**Properties:** properties.ipRangeFilter
 <br />

<br />

___ 

## Azure_CosmosDB_Deploy_Use_Replication 

### DisplayName 
Use global replication 

### Rationale 
Replication ensures continuity and rapid recovery during disasters. 

### Control Spec 

> **Passed:** 
> Secondary read regions are set for CosmosDB.
> 
> **Failed:** 
> No Secondary read location is set for CosmosDB.
> 

### Recommendation 

- **Azure Portal** 

	 Replication ensures the continuity and rapid recovery during disasters. To add - Azure Portal --> Resource -> Replicate data globally. Select a secondary read region and save. Refer: https://docs.microsoft.com/en-in/azure/cosmos-db/distribute-data-globally 

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

- ARM API to get CosmosDB resources in a subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2019-08-01<br />
**Properties:** properties.readLocations
<br />

___ 

## Azure_CosmosDB_Deploy_Use_Automatic_Failover 

### DisplayName 
Use automatic failover 

### Rationale 
Automatic failover ensures continuity and auto recovery during disasters. 

### Control Spec 

> **Passed:** 
> Automatic Failover is enabled for CosmosDB.
> 
> **Failed:** 
> Automatic Failover is not enabled for CosmosDB.
> 

### Recommendation 

- **Azure Portal** 

	 Automatic failover ensures the continuity and auto recovery during disasters. To configure, you must have at least 1 secondary replica enabled. To enabled replica - Azure Portal --> Resource -> Replicate data globally. Select a secondary read region and save. To set automatic failover - Azure Portal --> Resource -> Replicate data globally --> Automatic Failover. Turn 'ON' - 'Enable Automatic Failover', set the priorities and click 'OK'. 

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

- ARM API to get CosmosDB resources in a subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2019-08-01<br />
**Properties:** properties.enableAutomaticFailover
 <br />

<br />

___ 

## Azure_CosmosDB_Enable_Adv_Threat_Protection 

### DisplayName 
Enable Threat detection for CosmosDB database 

### Rationale 
Threat Protection for Azure Cosmos DB provides an additional layer of security intelligence that detects unusual and potentially harmful attempts to access or exploit Azure Cosmos DB accounts. 

### Control Settings 
```json 
{
    "ApplicableApiTypes": [
        "Sql"
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> Advanced Threat Protection is enabled for CosmosDB.
> 
> **Failed:** 
> Advanced Threat Protection is not enabled for CosmosDB.
> 
> **NotApplicable:** 
> Advanced Threat Protection is not available for the enabled API option(s)
> 
### Recommendation 

- **Azure Portal** 

	 From Azure Portal: Refer https://docs.microsoft.com/en-us/azure/cosmos-db/cosmos-db-advanced-threat-protection. 

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

- ARM API to get CosmosDB resources in a subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2019-08-01<br />
**Properties:** properties.EnabledApiTypes
 <br />

- ARM API to get advanced threat protection settings: - /{ResourceId}/providers/Microsoft.Security/advancedThreatProtectionSettings/current?api-version=2017-08-01-preview<br />
**Properties:** properties.isEnabled
 <br />

<br />

___ 

