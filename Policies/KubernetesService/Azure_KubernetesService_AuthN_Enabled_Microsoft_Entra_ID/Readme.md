## Azure_KubernetesService_AuthN_Enabled_Microsoft_Entra_ID

### DisplayName 
[AAD should be enabled in Kubernetes Service](../../../Control%20coverage/Feature/KubernetesService.md#Azure_KubernetesService_AuthN_Enabled_Microsoft_Entra_ID)

### Required Policies
Control can be covered with the below mentioned Azure policy:

#### Policy Details

Following policy can be used with 'Audit' effect to detect non-compliant resources.

#### Policy Definition
[Security - Kubernetes Service - EnableAADAuthentication](Security%20-%20Kubernetes%20Service%20-%20EnableAADAuthentication.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| Audit |No |


### Notes
NA