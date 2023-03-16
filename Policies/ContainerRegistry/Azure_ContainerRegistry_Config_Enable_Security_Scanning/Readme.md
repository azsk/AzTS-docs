## Azure_ContainerRegistry_Config_Enable_Security_Scanning

### DisplayName 
[Security scanner identity must be granted access to Container Registry for image scans](../../../Control%20coverage/Feature/ContainerRegistry.md#azure_containerregistry_config_enable_security_scanning)

### Required Policies
Control can be covered with the below mentioned Azure policy:

#### Policy Details

Following policy can be used with 'AuditIfNotExists' effect to detect non-compliant resources and can be used with 'DeployIfNotExists' effect to avoid further non-compliant resource creation (existing non-compliant resources can be remediated by policy remediation task).

#### Policy Definition
[Security - Container Registry - DeploySecurityScannerIdentity](Security%20-%20Container%20Registry%20-%20DeploySecurityScannerIdentity.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| AuditIfNotExists |No |
| PrincipalId | Principal id for security scanning identity | NA |Yes


### Notes
NA