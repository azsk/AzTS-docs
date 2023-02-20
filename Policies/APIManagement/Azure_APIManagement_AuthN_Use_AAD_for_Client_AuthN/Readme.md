## Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN 

### DisplayName 
[Enterprise applications using APIM must authenticate developers/applications using Azure Active Directory backed credentials](../../../Control%20coverage/Feature/APIManagement.md#azure_apimanagement_authn_use_aad_for_client_authn)

### Required Policies
Control can be covered with the below mentioned Azure policy:
- Policy to validate if Basic Authentication is enabled for API Management.
- Policy to validate if Identity Provider is enabled other than Azure Active Directory.

#### Policy Details

Following policy can be used to validate if Basic Authentication is enabled.

#### Policy Definition
[Security - APIManagement - Deny APIs with Basic Authentication Enabled](Security%20-%20APIManagement%20-%20Deny%20APIs%20with%20Basic%20Authentication%20Enabled.json)

#### Parameter details
Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| Audit |No |

___ 


#### Policy Details

Following policy can be used to validate if Identity Provider is enabled other than Azure Active Directory.

#### Policy Definition

[Security - APIManagement - Deny APIs with other than AAD Identity Provider Enabled](Security%20-%20APIManagement%20-%20Deny%20APIs%20with%20other%20than%20AAD%20Identity%20Provider%20Enabled.json)

#### Parameter details
Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| Effect | The effect determines what happens when the policy rule is evaluated to match| Audit |No |

### Notes
1. Policy will flag/target individual APIs(Microsoft.ApiManagement/service/apis) in API Management service.








