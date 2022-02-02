## Azure_ContainerRegistry_Config_Enable_Security_Scanning

### DisplayName 
[Security scanner identity must be granted access to Container Registry for image scans](../../../Control%20coverage/Feature/ContainerRegistry.md#azure_storage_dp_encrypt_in_transit)

### Required Policies
Control can be covered with the below mentioned Azure policy:

#### Policy Details

Following policy can be used to grant access to security scanner identity to container registry for image scans and non-compliant resources can be remediated by policy remediation task.

#### Policy Definition
[Security - Container Registry - DeploySecuritScannerIdentity](Security%20-%20Container%20Registry%20-%20DeploySecurityScannerIdentity.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| DeployIfNotExists |No |


### Notes
NA