## Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN 

### DisplayName 
[Enterprise applications using APIM must authenticate developers/applications using Azure Active Directory backed credentials](../../../Control%20coverage/Feature/APIManagement.md#azure_apimanagement_authn_use_aad_for_client_authn)

### Required Policies
Control can be covered with the below mentioned Azure policy:

#### Policy Details

Following policy can be used with 'Deny' effect to disallow users to create non-compliant APIs under API Management service (Greenfield Scenario).

#### Policy Definition
[Security - APIManagement - Deny APIs with Basic Authentication Enabled](Security%20-%20APIManagement%20-%20Deny%20APIs%20with%20Basic%20Authentication%20Enabled.json)

[Security - APIManagement - Deny APIs with other than AAD Identity Provider Enabled](Security%20-%20APIManagement%20-%20Deny%20APIs%20with%20other%20than%20AAD%20Identity%20Provider%20Enabled.json)

#### Parameter details

|Param Name|Description|Default Value|Mandatory?
|----|----|----|----|
| effectType | Enable or disable the execution of the policy | Deny |No |


### Notes
1. Policy will flag/target individual APIs(Microsoft.ApiManagement/service/apis) in API Management service.
2. Policy can't be designed to cover Brownfield scenario (remediate existing non-compliant resources) as required aliases are not modifiable.
3. If Deny policy is assigned, and user tries to create non-compliant API in API Management service from portal, they will receive following error:
    > "You're not authorized to change 'API Name' API."







