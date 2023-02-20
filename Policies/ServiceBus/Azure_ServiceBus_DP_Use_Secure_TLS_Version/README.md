## Azure_ServiceBus_DP_Use_Secure_TLS_Version

### DisplayName 
[Enable Secure Minimum TLS Version on Service Bus Namespace](../../../Control%20coverage/Feature/ServiceBus.md#azure_servicebus_dp_use_secure_tls_version)

### Required Policies
Control can be covered with the below mentioned Azure policy.

#### Policy Details
Following policy can be used with 'Modify' effect to avoid further non-compliant resource creation and existing non-compliant resources can be remediated by policy remediation task.

#### Policy Definition
[Security - Service Bus - SetMinimumRequiredTLSVersion](./Security%20-%20Service%20Bus%20-%20SetMinimumRequiredTLSVersion.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| Modify |No |


### Notes
NA