# CosmosDB

**Resource Type:** Microsoft.DocumentDB/databaseAccounts 

<!-- TOC -->

- [Azure_CosmosDB_AuthZ_Enable_Firewall](#azure_cosmosdb_authz_enable_firewall)
- [Azure_CosmosDB_AuthZ_Verify_IP_Range](#azure_cosmosdb_authz_verify_ip_range)
- [Azure_CosmosDB_Deploy_Use_Replication](#azure_cosmosdb_deploy_use_replication)
- [Azure_CosmosDB_Deploy_Use_Automatic_Failover](#azure_cosmosdb_deploy_use_automatic_failover)
- [Azure_CosmosDB_Enable_Adv_Threat_Protection](#azure_cosmosdb_enable_adv_threat_protection)
- [Azure_CosmosDB_DP_Use_Secure_TLS_Version](#azure_cosmosdb_dp_use_secure_tls_version)
- [Azure_CosmosDB_DP_Rotate_Read_Master_Key](#azure_cosmosdb_dp_rotate_read_master_key)
- [Azure_CosmosDB_NetSec_Restrict_Public_Network_Access](#azure_cosmosdb_netsec_restrict_public_network_access)
- [Azure_CosmosDB_Audit_Enable_Diagnostic_Settings](#azure_cosmosdb_audit_enable_diagnostic_settings)
- [Azure_CosmosDB_AuthZ_Disable_KeyBased_Metadata_Write_Access](#azure_cosmosdb_authz_disable_keybased_metadata_write_access)
- [Azure_CosmosDB_SI_Rotate_Access_Keys](#azure_cosmosdb_si_rotate_access_keys)

<!-- /TOC -->
<br/>

___ 

## Azure_CosmosDB_AuthZ_Enable_Firewall 

### Display Name 
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

### Azure Policies or REST APIs used for evaluation 

- REST API to get CosmosDB resources in a subscription: /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2023-03-15<br />
**Properties:** properties.ipRangeFilter
 <br />

<br />

___ 

## Azure_CosmosDB_AuthZ_Verify_IP_Range 

### Display Name 
Configure only the required IP addresses on Cosmos DB firewall 

### Rationale 
Using the firewall feature ensures that access to the data or the service is restricted to a specific set/group of clients. For effective usage, allow only the required IPs. Allowing larger ranges like 0.0.0.0/0, 0.0.0.0/1, 128.0.0.0/1, etc. will defeat the purpose. 

### Control Settings {
    "IpLimitPerDb": 2048,
    "IpLimitPerRange": 256
} 
 
### Control Spec 

> **Passed:** 
> Firewall rule is correctly configured for CosmosDB.
> 
> **Failed:** 
> Firewall rule is not correctly configured for CosmosDB.
> 
### Recommendation 

- **Azure Portal** 

	 Do not use high ranges like 0.0.0.0/0, 0.0.0.0/1, 128.0.0.0/1, etc. Maximum IPs in a range should be less than 256 and total IPs including all ranges should be less than 2048. To modify - Azure Portal --> Resource --> Firewall and Virtual networks. Turn 'ON' - 'Enable IP Access Control' and add/or remove IP addresses and/or ranges and save. Note: In case the IP range is indeterminate (for instance, if the client is a PaaS endpoint), you may need to attest this control. 

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

- REST API to get CosmosDB resources in a subscription: /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2019-08-01<br />
**Properties:** properties.ipRangeFilter
 <br />

<br />

___ 

## Azure_CosmosDB_Deploy_Use_Replication 

### Display Name 
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

### Azure Policies or REST APIs used for evaluation 

- REST API to get CosmosDB resources in a subscription: /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2023-03-15<br />
**Properties:** properties.readLocations
<br />

___ 

## Azure_CosmosDB_Deploy_Use_Automatic_Failover 

### Display Name 
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

### Azure Policies or REST APIs used for evaluation 

- REST API to get CosmosDB resources in a subscription: /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2023-03-15<br />
**Properties:** properties.enableAutomaticFailover
 <br />

<br />

___ 

## Azure_CosmosDB_Enable_Adv_Threat_Protection 

### Display Name 
Enable Threat detection for CosmosDB database 

### Rationale 
Threat Protection for Azure Cosmos DB provides an additional layer of security intelligence that detects unusual and potentially harmful attempts to access or exploit Azure Cosmos DB accounts. 

### Control Settings {
    "ApplicableApiTypes": [
        "Sql"
    ]
} 

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

### Azure Policies or REST APIs used for evaluation 

- REST API to get CosmosDB resources in a subscription: /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2023-03-15<br />
**Properties:** properties.EnabledApiTypes
 <br />

- REST API to get advanced threat protection settings: /{ResourceId}/providers/Microsoft.Security/advancedThreatProtectionSettings/current?api-version=2017-08-01-preview<br />
**Properties:** properties.isEnabled
 <br />

<br />

___ 

## Azure_CosmosDB_DP_Use_Secure_TLS_Version

### Display Name 
Use approved version of TLS for the Cosmos DB

### Rationale 
TLS provides confidentiality and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions.

### Control Settings {
    "MinReqTLSVersion": "1.2"
} 
### Control Spec 

> **Passed:** 
> Minimum TLS version is set to required or higher for Cosmos DB.
> 
> **Failed:** 
> Any of the following conditions is met.
> * Minimum TLS version is not set (default 1.0).
> * Minimum TLS version is less than required (configured min required TLS version) for Cosmos DB.

### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal --> your Cosmos DB --> Settings --> Networking --> Connectivity --> Minimum Transport layer security protocol dropdown. Select the required TLS version from the dropdown.

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

- REST API to get CosmosDB resources in a subscription: /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2023-03-15<br />
**Properties:** properties.minimalTlsVersion
 <br />

<br />

___ 

## Azure_CosmosDB_DP_Rotate_Read_Master_Key 

### Display Name 
Azure Cosmos DB account read master keys must be rotated on a periodic basis

### Rationale 
Rotating read master keys will reduce risk of unauthorized access and limit the window of opportunity for keys that are associated with a compromised or terminated account.

### Control Settings {
    "RecommendedKeyRotationPeriodInDays": "365"
} 
### Control Spec 

> **Passed:** 
> Recommended number of days have not been passed since the last key rotation.
> 
> **Failed:** 
> Recommended number of days have been passed since the last key rotation.

### Recommendation 

- **Azure Portal** 

	 To Rotate 'Read Master Keys' for Azure CosmosDB, Go to Azure Portal -> Your Cosmos Account -> Settings -> Keys -> Read-only Keys -> Choose the read key you want to rotate and click regenerate.


### Azure Policies or REST APIs used for evaluation 

- REST API to get Cosmos DB resources in a subscription: /subscriptions/{0}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2023-03-15<br />
**Properties:** properties.keysMetadata.primaryReadonlyMasterKey.generationTime, properties.keysMetadata.secondaryReadonlyMasterKey.generationTime

 <br />

<br />



## Azure_CosmosDB_NetSec_Restrict_Public_Network_Access 

### Display Name 
Restrict public network access for Azure Cosmos DB

### Rationale 
Access to Azure Cosmos DB Resource from public network must be restricted. This will prevent unauthorized access on the resource outside of network boundaries.

### Control Settings {
     "PossibleAddressSpaceSize": "3702258432",
 	 "AllowedPercentageCoverage": "2",
 	 "ItemsInAdditionalInformation": "10"
} 
### Control Spec 

> **Passed:** 
> Public network access is configured as disabled or 'Selected Networks' option is enabled with percentage of allowed public addresses within allowed limit.
> 
> **Failed:** 
> Public Network Access is configured as enabled or 'Selected Networks' options is enabled with percentage of allowed public addresses beyond allowed limit or 'Accept connections from within public Azure datacenters' option is checked .

### Recommendation 

- **Azure Portal** 

	 It is recommended that IP firewall (https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-firewall) or Private endpoints (https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-private-endpoints?tabs=arm-bicep) or Virtual Networks (https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-vnet-service-endpoint) be used instead of complete public accessibility enabled.
   


### Azure Policies or REST APIs used for evaluation 

- REST API to get Cosmos DB resources in a subscription: /subscriptions/{0}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2023-03-15<br />
**Properties:** properties.publicNetworkAccess, properties.ipRules

 <br />

<br />

___ 

## Azure_CosmosDB_Audit_Enable_Diagnostic_Settings

### Display Name
Diagnostics logs must be enabled for CosmosDB

### Rationale
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.

### Control Settings {
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "DataPlaneRequests",
        "QueryRuntimeStatistics",
        "PartitionKeyStatistics",
        "PartitionKeyRUConsumption",
        "ControlPlaneRequests",
        "CassandraRequests",
        "MongoRequests",
        "GremlinRequests",
        "TableApiRequests"
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

    Go to CosmosDB ? Monitoring ? Diagnostic settings ? Add diagnostic setting ? Select required log categories ? Configure destination (Log Analytics, Storage Account, or Event Hub) ? Set retention period to 365 days or more.

### Azure Policies or REST APIs used for evaluation

- REST API to list diagnostic setting details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DocumentDB/databaseAccounts/{accountName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** properties.logs.category, properties.logs.enabled, properties.logs.retentionPolicy<br />

<br />

___

## Azure_CosmosDB_AuthZ_Disable_KeyBased_Metadata_Write_Access

### Display Name
CosmosDB must disable key-based metadata write access

### Rationale
Disabling key-based metadata write access helps prevent unauthorized modification of database metadata and enforces the use of Azure Active Directory for authentication and authorization.

### Control Spec

> **Passed:**
> Key-based metadata write access is disabled.
>
> **Failed:**
> Key-based metadata write access is enabled.
>

### Recommendation

- **Azure Portal**

    Go to CosmosDB ? Features ? Disable key-based metadata write access ? Enable this feature to enhance security by requiring Azure AD authentication for metadata operations.

### Azure Policies or REST APIs used for evaluation

- REST API to get CosmosDB configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DocumentDB/databaseAccounts/{accountName}<br />
**Properties:** properties.disableKeyBasedMetadataWriteAccess<br />

<br />

___

## Azure_CosmosDB_SI_Rotate_Access_Keys

### Display Name
CosmosDB access keys must be rotated periodically

### Rationale
Regular rotation of access keys reduces the risk of unauthorized access and limits the exposure window if keys are compromised.

### Control Settings {
    "RecommendedKeyRotationPeriodInDays": "90"
}
### Control Spec

> **Passed:**
> Access keys have been rotated within the recommended period.
>
> **Failed:**
> Access keys have not been rotated within the recommended period.
>

### Recommendation

- **Azure Portal**

    Go to CosmosDB ? Settings ? Keys ? Regenerate primary or secondary keys periodically. Implement a key rotation schedule and consider using managed identities where possible.

### Azure Policies or REST APIs used for evaluation

- REST API to get CosmosDB key metadata: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DocumentDB/databaseAccounts/{accountName}<br />
**Properties:** properties.keysMetadata.primaryMasterKey.generationTime, properties.keysMetadata.secondaryMasterKey.generationTime<br />

<br />

___