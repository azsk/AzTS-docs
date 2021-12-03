## Azure_Storage_DP_Encrypt_In_Transit

### DisplayName 
[Enable Secure transfer to storage accounts](../../../Control%20coverage/Feature/Storage.md#azure_storage_dp_encrypt_in_transit)

### Required Policies
Control can be covered with the below mentioned Azure policy:

#### Policy Details

Following policy can be used with 'Modify' effect to avoid further non-compliant resource creation and existing non-compliant resources can be remediated by policy remediation task.

#### Policy Definition
[Security - Storage - EnforceEncryptInTransit](Security%20-%20Storage%20-%20EnforceEncryptInTransit.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| Modify |No |


### Notes
NA