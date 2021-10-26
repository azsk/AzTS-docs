# APIManagement

**Resource Type:** Microsoft.ApiManagement/service 

___ 

## Azure_APIManagement_DP_Use_HTTPS_URL_Scheme 

### DisplayName 
Ensure Backend API(s) are only accessible over HTTPS via API Management service 

### Rationale 
Use of HTTPS ensures server/service authentication and protects data in transit from network layer eavesdropping attacks. 

### Control Spec 

> **Passed:** 
> All API(s) are configured to use secure HTTP access to the backend via API Management, or no API(s) found in APIM instance.
> 
> **Failed:** 
> Found API(s) that are configured to use non-secure HTTP access to the backend via API Management.
> 
> **Verify:** 
> Unable to verify the delegation setting since management endpoint 3443 is disabled.
> 

### Recommendation 

- **PowerShell** 

	 ```powershell 
	 Set-AzApiManagementApi -Context {APIContextObject} -Protocols 'Https' -Name {APIName} -ApiId {APIId} -ServiceUrl {ServiceURL}
	 Get-AzApiManagementApi -Context {APIContextObject} # To get the details of existing APIs
	 # Refer https://docs.microsoft.com/en-us/powershell/module/az.apimanagement/set-azapimanagementapi 
	 ```

### Azure Policy or ARM API used for evaluation 

- ARM API to list APIMs and its related property at Subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01<br />
**Properties:** id<br />

- ARM API to list all APIs of the API Management service instance: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis?api-version=2019-01-01
 <br />

**Properties:** properties.protocols
 <br />

<br />

___ 

## Azure_APIManagement_DP_Use_Secure_TLS_Version 

### DisplayName 
Latest TLS version should be used in your APIM 

### Rationale 
TLS 1.2 is the latest and most secure protocol. Using 3DES Ciphers, TLS protocols (1.1 and 1.0) and SSL 3.0 exposes the API to meet-in-the-middle attack, chosen-plaintext or known-plaintext attacks. 

### Control Spec 

> **Passed:** 
> All old versions of protocols and ciphers configurations are disabled.
> 
> **Failed:** 
> Old versions of protocols and ciphers configurations are being used.
> 
> 
### Recommendation 

- **Azure Portal** 

	 Ensure that secure protocol versions are used between the client and the gateway *and* between the gateway and the backend APIs. Go to Azure Portal --> your API management instance --> Settings --> Protocol settings --> Turn OFF 3DES Ciphers, TLS protocols (1.1 and 1.0) and SSL 3.0 Protocols.

### Azure Policy or ARM API used for evaluation 

- ARM API to list APIMs and its related property at Subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01<br />
**Properties:** properties.customProperties<br />

**Custom Properties:** 
  1. Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TripleDes168
  2. Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10
  3. Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11
  4. Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Ssl30
  5. Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10
  6. Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11
  7. Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Ssl30
<br />

___ 

## Azure_APIManagement_DP_Remove_Default_Products 

### DisplayName 
Delete the two sample products 'Starter' and 'Unlimited' to avoid accidental exposure of APIs 

### Rationale 
By default, each API Management instance comes with two sample products: Starter and Unlimited. Unless the access control of these sample products is being strictly regulated, associating APIs to these products stands the chance of exposing APIs to unauthenticated users. 

### Control Spec 

> **Passed:** 
> APIM does not contains sample products: Starter and Unlimited.
> 
> **Failed:** 
> APIM contains sample products: Starter and Unlimited.
> 
> 
### Recommendation 

- **Azure Portal** 

	 To delete sample products go to Azure Portal --> your API management instance --> Products --> Select 'Starter'/'Unlimited' Product --> Delete. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list a collection of products in the specified service instance: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/products?api-version=2019-01-01 
 <br />

**Properties:** name
 <br />

<br />

___ 

## Azure_APIManagement_AuthN_Verify_Delegated_Authentication 

### DisplayName 
Delegated authentication should be implemented securely 

### Rationale 
Delegation allows you to use your existing website for handling developer sign-in/sign-up and subscription to products as opposed to using the built-in functionality in the developer portal. It is the API publisher's responsibility to ensure protection of user data. 

### Control Spec 

> **Passed:** 
> APIM instance is not using Delegated authentication.
> 
> **Failed:** 
> APIM instance is using Delegated authentication, or provisioning state is not equal to succeeded.
> 
> **Verify:** 
> Unable to verify the delegation setting since management endpoint 3443 is disabled.
> 
> **NotApplicable:** 
> This control does not apply to consumption tier APIM.
> 
### Recommendation 

- **Azure Portal** 

	 To disable delegation, go to APIM service --> Developer portal --> Delegation --> Uncheck the two check boxes (a) Delegate sign-in & sign-up (b) Delegate product subscription. Read more about delegation here: https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-setup-delegation

### Azure Policy or ARM API used for evaluation 

- ARM API to list APIMs and its related property at Subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01 
 <br />

**Properties:** sku
 <br />

- ARM API to list a collection of portalsettings defined within a service instance: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/portalsettings?api-version=2018-06-01-preview 
 <br />

**Properties:** properties.subscriptions.enabled, properties.userRegistration.enabled
 <br />

<br />

___ 

## Azure_APIManagement_AuthZ_Validate_JWT 

### DisplayName 
Ensure that JWT validation is enabled if using OAuth 2.0 or OpenID connect 

### Rationale 
If 'validate-jwt' policy is not configured, client can call the API without the OAuth/OpenID connect authorization token. This policy enforces existence and validity of a JWT extracted from either a specified HTTP Header or a specified query parameter. 

### Control Spec 

> **Passed:** 
> JWT Token validation found for OAuth/OpenID connect authorization, or no API(s) found in APIM Management instance.
> 
> **Failed:** 
> JWT Token validation not found for OAuth/OpenID connect authorization.
> 
> 
### Recommendation 

- **Azure Portal** 

	 For steps to add JWT Validate Token policy please refer: <br>https://docs.microsoft.com/en-us/azure/api-management/api-management-access-restriction-policies#ValidateJWT <br>and <br>https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-protect-backend-with-aad#configure-a-jwt-validation-policy-to-pre-authorize-requests 

### Azure Policy or ARM API used for evaluation 

- ARM API to list APIMs and its related property at Subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01
 <br />

**Properties:** sku
 <br />

- ARM API to list all APIs of the API Management service instance: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis?api-version=2019-01-01 
 <br />

**Properties:** id
 <br />

- ARM API to get the details of the API specified by its identifier: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis/{apiId}?api-version=2019-01-01
 <br />

**Properties:** properties.authenticationSettings.oAuth2, properties.authenticationSettings.openid
 <br />

- ARM API to get policy configuration at the API level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis/{apiId}/policies?api-version=2019-01-01
 <br />

**Properties:** properties.value
 <br />

<br />

___ 

## Azure_APIManagement_AuthN_Disable_Management_API 

### DisplayName 
Do not use API Management REST API 

### Rationale 
The credentials used to access API Management REST API provide admin-level access without support for role-based access control and without recording audit logs. For better security it is recommended to make calls through the ARM-based REST API 

### Control Spec 

> **Passed:** 
> 'Enable Management REST API' option is turned OFF.
> 
> **Failed:** 
> 'Enable Management REST API' option is turned ON.
> 
> **Verify:** 
> Management API setting could not be verified as the API Management service is connected to a Virtual Network. As a result, control plane traffic on port 3443 is denied.
> 
> **NotApplicable:** 
> This control does not apply to consumption tier.
> 
### Recommendation 

- **Azure Portal** 

	 To disable API Management REST API, go to APIM service --> Deployment and infrastructure --> Management API --> Enable Management REST API --> No. For better security it is recommended to make calls through the ARM based REST API mentioned here: https://docs.microsoft.com/en-us/rest/api/apimanagement. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list APIMs and its related property at Subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01 
 <br />

**Properties:** sku
 <br />

- ARM API to get tenant access information details without secrets: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/tenant/access?api-version=2019-12-01
 <br />

**Properties:** enabled
 <br />

<br />

___ 

## Azure_APIManagement_AuthZ_Enable_User_Authorization_For_API 

### DisplayName 
Ensure that either OAuth 2.0 or OpenID Connect are used to authorize developer accounts in API Management 

### Rationale 
Enabling OAuth/OpenID connect user authorization ensure that only valid users have access, and they can only access resources to which they are entitled. 

### Control Spec 

> **Passed:** 
> Either OAuth 2.0 or OpenID Connect are used to authorize developer accounts for this APIM instance.
> 
> **Failed:** 
> Neither OAuth 2.0 nor OpenID Connect are used to authorize developer accounts for this APIM instance.
> 
> 
### Recommendation 

- **Azure Portal** 

	 To enable user authorization for an API go to Azure Portal --> your API management instance --> APIs --> Select API --> Settings -> User Authorization -> Enable 'OAuth 2.0' or 'OpenID connect'. Please refer: https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-oauth2. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list APIMs and its related property at Subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01 
 <br />

**Properties:** sku
 <br />

- ARM API to list all APIs of the API Management service instance: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis?api-version=2019-01-01 
 <br />

**Properties:** id
 <br />

- ARM API to get the details of the API specified by its identifier: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis/{apiId}?api-version=2019-01-01
 <br />

**Properties:** properties.authenticationSettings.oAuth2, properties.authenticationSettings.openid
 <br />

<br />

___ 

## Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN 

### DisplayName 
Enterprise applications using APIM must authenticate developers/applications using Azure Active Directory backed credentials 

### Rationale 
Using the native enterprise directory for authentication ensures that there is a built-in high level of assurance in the user identity established for subsequent access control. All Enterprise subscriptions are automatically associated with their enterprise directory (xxx.onmicrosoft.com) and users in the native directory are trusted for authentication to enterprise subscriptions. 

### Control Spec 

> **Passed:** 
> AAD Identity provider is being used for authentication in developer portal or sign-up/sign-in option has been entirely disabled.
> 
> **Failed:** 
> Identity provider other than AAD is being used for authentication in developer portal.
> 
> **Verify:** 
> Sign up option setting could not be verified as the API Management service is connected to a Virtual Network. As a result, control plane traffic on port 3443 is denied.
> 
> **NotApplicable:** 
> This control does not apply to consumption tier.
> 
### Recommendation 

- **Azure Portal** 

	 For steps to use Azure Active Directory (Azure AD) please refer: https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-aad. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list APIMs and its related property at Subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01 
 <br />

**Properties:** sku
 <br />

- ARM API to list collection of portalsettings defined within a service instance: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/portalsettings?api-version=2018-06-01-preview
 <br />

**Properties:** name: "signup", properties.enabled
 <br />

- ARM API to list collection of Identity Provider configured in the specified service instance: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/identityProviders?api-version=2019-12-01
 <br />

**Properties:** properties.type
 <br />

<br />

___ 

## Azure_APIManagement_AuthN_Secure_API_Using_Client_Certificates 

### DisplayName 
Use client certificates for authentication between gateway and backend APIs 

### Rationale 
Use client certificates to secure access to the back-end service of an API and protects data in transit from network layer man-in-the-middle, eavesdropping, session-hijacking attacks. 

### Control Spec 

> **Passed:** 
> Gateway authentication using client certificate is enabled in API(s), or no API(s) found to enable Gateway authentication using client certificate.
> 
> **Failed:** 
> Gateway authentication using client certificate is not enabled in API(s).
> 
> 
### Recommendation 

- **Azure Portal** 

	 To enable client certificate authentication from Azure portal please refer: <br>https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates <br>and <br>https://docs.microsoft.com/en-us/azure/api-management/api-management-authentication-policies. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list APIMs and its related property at Subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01 
 <br />

**Properties:** sku
 <br />

- ARM API to list all APIs of the API Management service instance: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis?api-version=2019-01-01
 <br />

**Properties:** id
 <br />

- ARM API to get policy configuration at the API level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis/{apiId}/policies?api-version=2019-01-01
 <br />

**Properties:** properties.value
 <br />

<br />

___ 

## Azure_APIManagement_AuthZ_Enable_Requires_Subscription 

### DisplayName 
'Requires Subscription' option must be turned on for all products in an API Management instance 

### Rationale 
When publishing APIs through Azure API Management (APIM), the easiest and most common way to secure access to the APIs is by using Subscription Keys. To obtain a Subscription Key for accessing APIs, a Subscription is required. This ensures that a Client applications that need to consume the published APIs must subscribe before making calls to those APIs. 

### Control Spec 

> **Passed:** 
> 'Requires Subscription' option is turned 'ON' for all product(s) with published state in APIM instance, or no product(s) found in APIM instance, or no product(s) found with 'Published' state.
> 
> **Failed:** 
> 'Requires Subscription' option is turned 'OFF' for product(s) in APIM instance.
> 
> 
### Recommendation 

- **Azure Portal** 

	 To enable 'Requires Subscription' go to Azure Portal --> your API management instance --> Products --> Settings --> 'Requires Subscription'. Refer: https://docs.microsoft.com/en-us/azure/api-management/api-management-subscriptions. <br>To create subscription for a user directly from Azure portal refer: https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-create-subscriptions 

### Azure Policy or ARM API used for evaluation 

- ARM API to list a collection of products in the specified service instance: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/products?api-version=2019-01-01
 <br />

**Properties:** properties.subscriptionRequired, properties.state
 <br />

<br />

___ 

## Azure_APIManagement_AuthN_Use_Managed_Service_Identity 

### DisplayName 
Use Managed Service Identity (MSI) for accessing other AAD-protected resources from the API management instance 

### Rationale 
Managed Service Identity (MSI) allows your API Management instance to easily access other AAD-protected resources, such as Azure Key Vault. The identity is managed by the Azure platform and eliminates the need to provision/manage/rotate any secrets thus reducing the overall risk. 

### Control Spec 

> **Passed:** 
> APIM instance is using Managed Service Identity(MSI).
> 
> **Failed:** 
> APIM instance is not using Managed Service Identity(MSI).
> 
> 
### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal --> your API management instance --> Settings --> Managed Service Identity --> Register with AAD --> ON 

### Azure Policy or ARM API used for evaluation 

- ARM API to list APIMs and its related property at Subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01
 <br />
 
**Properties:** sku, identity.type
 <br />

<br />

___ 

