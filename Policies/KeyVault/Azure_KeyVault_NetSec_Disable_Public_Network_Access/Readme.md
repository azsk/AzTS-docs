## Azure_KeyVault_NetSec_Disable_Public_Network_Access

### DisplayName 
[Key Vault must have public access disabled](../../../Control%20coverage/Feature/KeyVault.md#azure_keyvault_netsec_disable_public_network_access)

### Required Policies
Control can be covered with the below mentioned Azure policy.

#### Policy Details
Following policy can be used with 'Audit' effect to view the compliance of Key Vaults having `Public Network Access` disabled at the policy assignment scope.

#### Policy Definition
[Security - Key Vault - DisablePublicNetworkAccess](./Security%20-%20Key%20Vault%20-%20DisablePublicNetworkAccess.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| Audit |No |


### Notes
NA