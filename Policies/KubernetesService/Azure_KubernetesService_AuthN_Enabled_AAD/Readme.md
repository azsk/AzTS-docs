## Azure_KubernetesService_AuthN_Enabled_AAD

### DisplayName 
[Remove Azure Active Directory B2C tenant(s) in a subscription](../../../Control%20coverage/Feature/KubernetesService.md#Azure_KubernetesService_AuthN_Enabled_AAD)

### Required Policies
Control can be covered with the below mentioned Azure policy:

#### Policy Details

Following policy can be used with 'Audit' effect to view the details of Kubernetes service, which doesn't have AAD Authentication enabled, at the policy assignment scope.

#### Policy Definition
[Security - Kubernetes Service - EnableAADAuthentication](./Security%20-%20Kubernetes%20Service%20-%20EnableAADAuthentication)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| Audit |No |


### Notes
NA