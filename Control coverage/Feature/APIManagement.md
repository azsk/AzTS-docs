# APIManagement

**Resource Type:** Microsoft.ApiManagement/service 

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_APIManagement_DP_Use_HTTPS_URL_Scheme](#azure_apimanagement_dp_use_https_url_scheme)
- [Azure_APIManagement_DP_Use_Secure_TLS_Version](#azure_apimanagement_dp_use_secure_tls_version)
- [Azure_APIManagement_DP_Remove_Default_Products](#azure_apimanagement_dp_remove_default_products)
- [Azure_APIManagement_AuthN_Verify_Delegated_Authentication](#azure_apimanagement_authn_verify_delegated_authentication)
- [Azure_APIManagement_AuthZ_Validate_JWT](#azure_apimanagement_authz_validate_jwt)
- [Azure_APIManagement_AuthN_Disable_Management_API](#azure_apimanagement_authn_disable_management_api)
- [Azure_APIManagement_AuthZ_Enable_User_Authorization_For_API](#azure_apimanagement_authz_enable_user_authorization_for_api)
- [Azure_APIManagement_AuthN_Use_Microsoft_Entra_ID_for_Client_AuthN](#azure_apimanagement_authn_use_microsoft_entra_id_for_client_authn)
- [Azure_APIManagement_AuthN_Secure_API_Using_Client_Certificates](#azure_apimanagement_authn_secure_api_using_client_certificates)
- [Azure_APIManagement_AuthZ_Enable_Requires_Subscription](#azure_apimanagement_authz_enable_requires_subscription)
- [Azure_APIManagement_AuthN_Use_Managed_Service_Identity](#azure_apimanagement_authn_use_managed_service_identity)
- [Azure_APIManagement_Audit_Enable_Alerts](#azure_apimanagement_audit_enable_alerts)
- [Azure_APIManagement_Audit_Enable_Diagnostics_Log](#azure_apimanagement_audit_enable_diagnostics_log)
- [Azure_APIManagement_Audit_Onboard_APIs_To_Defender_For_APIs](#azure_apimanagement_audit_onboard_apis_to_defender_for_apis)
- [Azure_APIManagement_AuthN_Use_AAD_Only](#azure_apimanagement_authn_use_aad_only)
- [Azure_APIManagement_DP_Enable_Validation_Policy](#azure_apimanagement_dp_enable_validation_policy)
- [Azure_APIManagement_DP_Use_HTTPS_URL_Scheme_ServiceUrl_contains_HTTPS](#azure_apimanagement_dp_use_https_url_scheme_serviceurl_contains_https)
- [Azure_APIManagement_NetSec_Enable_Content_Security_Policy](#azure_apimanagement_netsec_enable_content_security_policy)
- [Azure_APIManagement_NetSec_Limit_OpenAI_Token_Usage](#azure_apimanagement_netsec_limit_openai_token_usage)
- [Azure_APIManagement_NetSec_Use_Virtual_Network](#azure_apimanagement_netsec_use_virtual_network)

<!-- /TOC -->
<br/>

___ 

## Azure_APIManagement_DP_Use_HTTPS_URL_Scheme 

### Display Name 
Ensure API Management service is accessible only over HTTPS

### Rationale 
Use of HTTPS ensures server/service authentication and protects data in transit from network layer eavesdropping attacks. 

### Control Spec 

> **Passed:** 
> All APIs are configured to be accessed only over HTTPS via the API Management service, or no APIs are present in the API Management instance.
> 
> **Failed:** 
> One or more APIs are not configured to be accessed only over HTTPS via the API Management service.
> 
> **Verify:** 
> URL Scheme settings could not be verified as the management endpoint over port 3443 is disabled.
> 

### Recommendation

- **PowerShell**
    ```powershell
    $APIContextObject = New-AzApiManagementContext -ResourceGroupName "<resource-group-name>" -ServiceName "<api-management-service-name>"
    Set-AzApiManagementApi -Context {APIContextObject} -Protocols 'Https' -Name {APIName} -ApiId {APIId} -ServiceUrl {ServiceURL}
    Get-AzApiManagementApi -Context {APIContextObject} # To get the details of existing APIs
    # Refer https://docs.microsoft.com/en-us/powershell/module/az.apimanagement/set-azapimanagementapi
    ```
### Azure Policies or REST APIs used for evaluation

- REST API to list APIMs services and its related property at Subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01<br />
**Properties:** id<br />

- REST API to list all APIs of the API Management service instance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis?api-version=2019-01-01<br />
**Properties:** properties.protocols<br />

<br />

___ 

## Azure_APIManagement_DP_Use_Secure_TLS_Version 

### Display Name 
Latest TLS version should be used in your APIM 

### Rationale 
TLS 1.2 is the latest and most secure protocol. Using 3DES Ciphers, TLS protocols (1.1 and 1.0) and SSL 3.0 exposes the API to meet-in-the-middle attack, chosen-plaintext or known-plaintext attacks. 

### Control Settings {
	"UnsecureProtocolsAndCiphersConfiguration": [
		{
			"Key": "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10",
			"DisplayName": "TLS 1.0 (HTTP/1.x only)",
			"Type": "Client protocol"
		},
		{
			"Key": "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11",
			"DisplayName": "TLS 1.1 (HTTP/1.x only)",
			"Type": "Client protocol"
		},
		{
			"Key": "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Ssl30",
			"DisplayName": "SSL 3.0 (HTTP/1.x only)",
			"Type": "Client protocol"
		},
		{
			"Key": "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10",
			"DisplayName": "TLS 1.0",
			"Type": "Backend protocol"
		},
		{
			"Key": "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11",
			"DisplayName": "TLS 1.1",
			"Type": "Backend protocol"
		},
		{
			"Key": "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Ssl30",
			"DisplayName": "SSL 3.0",
			"Type": "Backend protocol"
		},
		{
			"Key": "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TripleDes168",
			"DisplayName": "TripleDes168",
			"Type": "Cipher"
		}
	]
}

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

    Ensure that secure protocol versions are used between the client and the gateway *and* between the gateway and the backend APIs. Navigate to the API Management service instance -> **Security** section -> **Protocols + ciphers** -> **Protocols** tab and ensure only **TLS 1.2** is enabled and all other protocols are disabled for both **Client protocol** and **Backend protocol**. Also, ensure **TripleDes168** is disabled under **Ciphers** tab.

- **PowerShell**

    Refer [How do I remediate failing control Azure_APIManagement_DP_Use_Secure_TLS_Version?](https://github.com/azsk/DevOpsKit-docs/blob/master/00c-Addressing-Control-Failures/Readme.md#how-do-i-remediate-failing-control-azure_apimanagement_dp_use_secure_tls_version) to disable the insecure protocols and ciphers using PowerShell.

### Azure Policies or REST APIs used for evaluation

- REST API to list APIMs services and its related property at Subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01<br />
**Properties:** properties.customProperties<br />
**Custom Properties:** <br />
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

### Display Name 
Delete the two sample products 'Starter' and 'Unlimited' to avoid accidental exposure of APIs 

### Rationale 
By default, each API Management instance comes with two sample products: Starter and Unlimited. Unless the access control of these sample products is being strictly regulated, associating APIs to these products stands the chance of exposing APIs to unauthenticated users. 

### Control Settings {
    "SampleProductId": [ "starter", "unlimited" ]
}

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

	 To delete sample products, go to Azure Portal --> your API management instance --> Products --> Select 'Starter'/'Unlimited' Product --> Delete. 

### Azure Policies or REST APIs used for evaluation

- REST API to list a collection of products in the specified service instance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/products?api-version=2019-01-01 <br />
**Properties:** name<br />

<br />

___ 

## Azure_APIManagement_AuthN_Verify_Delegated_Authentication 

### Display Name 
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

### Azure Policies or REST APIs used for evaluation

- REST API to list APIMs services and its related property at Subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01 <br />
**Properties:** sku<br />

- REST API to list a collection of portalsettings defined within a service instance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/portalsettings?api-version=2018-06-01-preview <br />
**Properties:** properties.subscriptions.enabled, properties.userRegistration.enabled<br />

<br />

___ 

## Azure_APIManagement_AuthZ_Validate_JWT 

### Display Name 
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

### Azure Policies or REST APIs used for evaluation

- REST API to list APIMs services and its related property at Subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01<br />
**Properties:** sku<br />

- REST API to list all APIs of the API Management service instance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis?api-version=2019-01-01 <br />
**Properties:** id<br />

- REST API to get the details of the API specified by its identifier: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis/{apiId}?api-version=2019-01-01<br />
**Properties:** properties.authenticationSettings.oAuth2, properties.authenticationSettings.openid<br />

- REST API to get policy configuration at the API level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis/{apiId}/policies?api-version=2019-01-01<br />
**Properties:** properties.value<br />

<br />

___ 

## Azure_APIManagement_AuthN_Disable_Management_API

### Display Name
Do not use Management REST API in APIM

### Rationale
The credentials used to access API Management REST API provide admin-level access without support for role-based access control and without recording audit logs. For better security it is recommended to make calls through the ARM-based REST API.

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

    To disable API Management REST API, go to APIM service --> Deployment and infrastructure --> Management API --> Under 'Direct management API' tab --> Enable Management REST API --> No. <br> For better security it is recommended to make calls through the ARM based REST API mentioned here: https://docs.microsoft.com/en-us/rest/api/apimanagement.

- **PowerShell**
```
    $ApiManagementContext = New-AzApiManagementContext -ResourceGroupName "<resource-group-name>" -ServiceName "<api-management-service-name>"
    Set-AzApiManagementTenantAccess -Context $ApiManagementContext -Enabled $false
```
### Azure Policies or REST APIs used for evaluation

- REST API to list APIMs services and its related property at Subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01 <br />
**Properties:** sku<br />

- REST API to get tenant access information details without secrets: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/tenant/access?api-version=2019-12-01<br />
**Properties:** enabled<br />

<br />

___ 

## Azure_APIManagement_AuthZ_Enable_User_Authorization_For_API 

### Display Name 
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

	 To enable user authorization for an API, go to Azure Portal --> your API management instance --> APIs --> Select API --> Settings -> User Authorization -> Enable 'OAuth 2.0' or 'OpenID connect'. Please refer: https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-oauth2. 

### Azure Policies or REST APIs used for evaluation

- REST API to list APIMs services and its related property at Subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01 <br />
**Properties:** sku<br />

- REST API to list all APIs of the API Management service instance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis?api-version=2019-01-01 <br />
**Properties:** id<br />

- REST API to get the details of the API specified by its identifier: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis/{apiId}?api-version=2019-01-01<br />
**Properties:** properties.authenticationSettings.oAuth2, properties.authenticationSettings.openid<br />

<br />

___ 

## Azure_APIManagement_AuthN_Use_Microsoft_Entra_ID_for_Client_AuthN 

### Display Name 
Enterprise applications using APIM must authenticate developers/applications using Azure Active Directory backed credentials 

### Rationale 
Using the native enterprise directory for authentication ensures that there is a built-in high level of assurance in the user identity established for subsequent access control. All Enterprise subscriptions are automatically associated with their enterprise directory (xxx.onmicrosoft.com) and users in the native directory are trusted for authentication to enterprise subscriptions. 

### Control Settings {
    "AllowedIdentityProvider": [
		"Aad"
    ]
}

### Control Spec 

> **Passed:** 
> Entra ID (formerly AAD) Identity provider is being used for authentication in developer portal or sign-up/sign-in option has been entirely disabled.
> 
> **Failed:** 
> Identity provider other than Entra ID (formerly AAD) is being used for authentication in developer portal.
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

### Azure Policies or REST APIs used for evaluation

- REST API to list APIMs services and its related property at Subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01 <br />
**Properties:** sku<br />

- REST API to list collection of portalsettings defined within a service instance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/portalsettings?api-version=2018-06-01-preview<br />
**Properties:** name: "signup", properties.enabled<br />

- REST API to list collection of Identity Provider configured in the specified service instance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/identityProviders?api-version=2019-12-01<br />
**Properties:** properties.type<br />

<br />

___ 

## Azure_APIManagement_AuthN_Secure_API_Using_Client_Certificates 

### Display Name 
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

### Azure Policies or REST APIs used for evaluation

- REST API to list APIMs services and its related property at Subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01 <br />
**Properties:** sku<br />

- REST API to list all APIs of the API Management service instance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis?api-version=2019-01-01<br />
**Properties:** id<br />

- REST API to get policy configuration at the API level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis/{apiId}/policies?api-version=2019-01-01<br />
**Properties:** properties.value<br />

<br />

___ 

## Azure_APIManagement_AuthZ_Enable_Requires_Subscription 

### Display Name 
'Requires Subscription' option must be turned on for all products in an API Management instance 

### Rationale 
When publishing APIs through Azure API Management (APIM), the easiest and most common way to secure access to the APIs is by using Subscription Keys. To obtain a Subscription Key for accessing APIs, a Subscription is required. This ensures that client applications that need to consume the published APIs must subscribe before making calls to those APIs. 

### Control Settings {
    "State": "published"
}

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

### Azure Policies or REST APIs used for evaluation

- REST API to list a collection of products in the specified service instance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/products?api-version=2019-01-01<br />
**Properties:** properties.subscriptionRequired, properties.state<br />

<br />

___ 

## Azure_APIManagement_AuthN_Use_Managed_Service_Identity 

### Display Name 
Use Managed Service Identity (MSI) for accessing other AAD-protected resources from the API management instance 

### Rationale 
Managed Service Identity (MSI) allows your API Management instance to easily access other AAD-protected resources, such as Azure Key Vault. The identity is managed by the Azure platform and eliminates the need to provision/manage/rotate any secrets thus reducing the overall risk. 

### Control Settings {
    "RequiredIdentityType": [
        "SystemAssigned",
        "UserAssigned"
    ]
}

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

### Azure Policies or REST APIs used for evaluation

- REST API to list APIMs services and its related property at Subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?api-version=2019-12-01<br />
**Properties:** sku, identity.type<br />

<br />

___

## Azure_APIManagement_Audit_Enable_Alerts

### DisplayName
Metric alert rules must be configured for critical actions on API Management service

### Rationale
Metric alert for occurrence of unauthorized gateway requests help the admin to identify security breach attempts.

### Control Spec

> **Passed:**
> All the required metric alerts have been configured for the resource.
>
> **Failed:**
> No metric alerts are configured in the Subscription.
> (or)
> One or more required metric alerts are either not configured, or, are misconfigured.
>
> **Verify:**
> Metric alerts are disabled from being fetched.
>
> **Error:**
> No metric alerts configured in Control Settings.
>
### Recommendation


- **Azure Portal**

  To setup an alert rule:
  1. Go to API Management instance -> 'Alerts' -> 'New Alert Rule' -> 'Add condition'.
  2. Select Signal type as 'Metrics' -> Select 'Requests' -> In 'Split by dimensions', in 'Dimension name', select 'Gateway Response Code Category'. In 'Dimension values', select 4xx. If this option is not listed in the drop-down, click 'Add custom value' and add '4xx' for 'Gateway Response Code Category'. Configure 'Alert logic' as follows: a. Operator = 'Greater Than' b. Aggregation type = 'Total' c. Threshold value = '0' and d. Aggregation granularity (Period) = '1 hour'.
  3. Select an existing Action Group or create a new one of type 'Email/SMS message/Push/Voice'. Select 'Email' option and specify the email id.

  Refer: [Set up an alert rule](https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-use-azure-monitor#set-up-an-alert-rule-for-unauthorized-request) for instructions to configure this alert.

<!--
- **PowerShell**

	```powershell
	```

- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to list all alert rule definitions in a Subscription:
  /subscriptions/{0}/providers/Microsoft.Insights/metricAlerts?api-version=2018-03-01
  <br />
  **Properties:** [\*].id, [\*].name, [\*].properties.enabled, [\*].properties.scopes, [\*].properties.windowSize, [\*].properties.criteria, [\*].properties.actions
  <br />

- REST API to list all action groups in a Subscription:
  /subscriptions/{0}/providers/microsoft.insights/actionGroups?api-version=2019-06-01
  <br />
  **Properties:** [\*].id, [\*].name, [\*].properties.enabled, [\*].properties.emailReceivers
  <br />
  <br />

## Azure_APIManagement_Audit_Enable_Diagnostics_Log 

### Display Name 
Diagnostics logs must be enabled for API Management service 

### Rationale 
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well. 

### Control Settings {
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "GatewayLogs",
        "WebSocketConnectionLogs"
    ],
    "DiagnosticMinRetentionPeriod": "365"
}

### Control Spec 

> **Passed:** 
> 1. Required diagnostic logs are enabled.
>
>       and
>
> 2. At least one of the below setting configured:
> a. Log Analytics.
> b. Storage account (with min Retention period of 365 or forever(Retention period 0).
> c. Event Hub.
> 
> **Failed:** 
> 1. Diagnostics setting is disabled for resource.
> 
>       or
>
> 2. Diagnostic settings meet the following conditions:
> a. All diagnostic logs are not enabled.
> b. None of the below setting is configured:
> i. Log Analytics.
> ii. Storage account (with min Retention period of 365 or forever(Retention period 0).
> iii. Event Hub.
> 
> **Error:** 
> Required logs are not configured in control settings.
> 

### Recommendation 

- **Azure Portal** 

	 You can change the diagnostic settings from the Azure Portal by following the steps given here: https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation

- REST API to list diagnostic setting details of API Management resources: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** 
name<br />
properties.logs.category<br />
properties.logs.enabled<br />
properties.logs.retentionPolicy.enabled<br />
properties.logs.retentionPolicy.days<br />
properties.workspaceId<br />
properties.storageAccountId<br />
properties.eventHubName<br />
 <br />

<br />
___

## Azure_APIManagement_Audit_Onboard_APIs_To_Defender_For_APIs

### Display Name
API Management services must be onboarded to Microsoft Defender for APIs

### Rationale
Microsoft Defender for APIs provides comprehensive security monitoring, threat detection, and vulnerability assessment for API endpoints. Onboarding API Management services to Defender for APIs enables real-time threat detection, API security posture assessment, and automated response to security incidents.

### Control Spec

> **Passed:**
> API Management service is onboarded to Microsoft Defender for APIs with appropriate plan and monitoring configuration.
>
> **Failed:**
> API Management service is not onboarded to Defender for APIs or monitoring is not properly configured.
>

### Recommendation

- **Azure Portal**

    Navigate to Microsoft Defender for Cloud → Environment settings → Select your subscription → Find "Defender for APIs" in the list of plans → Toggle "Defender for APIs" to "On" → Select "Standard" plan for full features → Configure settings for your requirements → Click "Save" to apply changes.

### Azure Policies or REST APIs used for evaluation

- REST API to get API Management service: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}<br />
**Properties:** properties.defenderForAPIs.enabled<br />

<br />

___

## Azure_APIManagement_AuthN_Use_AAD_Only

### Display Name
API Management must use Azure Active Directory Only authentication

### Rationale
Using Azure Active Directory Only authentication ensures that only properly authenticated users can access the API Management service, eliminating the risk of unauthorized access through other authentication mechanisms.

### Control Spec

> **Passed:**
> API Management service is configured to use Azure Active Directory Only authentication.
>
> **Failed:**
> API Management service allows other authentication methods besides Azure Active Directory.
>

### Recommendation

- **Azure Portal**

    Go to API Management service → Security → Identity providers → Configure Azure Active Directory as the only allowed identity provider → Disable other authentication methods.

### Azure Policies or REST APIs used for evaluation

- REST API to list Identity Provider configured in the specified service instance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/identityProviders?api-version=2019-12-01<br />
**Properties:** properties.type<br />

<br />

___

## Azure_APIManagement_DP_Enable_Validation_Policy

### Display Name
API Management must enable input validation policies

### Rationale
Input validation policies help protect APIs from malicious requests and ensure data integrity by validating request content against defined schemas.

### Control Spec

> **Passed:**
> Input validation policies are configured for APIs in the API Management service.
>
> **Failed:**
> Input validation policies are not configured or are insufficient.
>

### Recommendation

- **Azure Portal**

    Go to API Management service → APIs → Select API → Design → Add policy → Configure validation policies for request content, headers, and query parameters.

### Azure Policies or REST APIs used for evaluation

- REST API to get policy configuration at the API level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis/{apiId}/policies?api-version=2019-01-01<br />
**Properties:** properties.value<br />

<br />

___

## Azure_APIManagement_DP_Use_HTTPS_URL_Scheme_ServiceUrl_contains_HTTPS

### Display Name
API Management service URL must use HTTPS scheme

### Rationale
Using HTTPS scheme for service URLs ensures that all communication with backend services is encrypted in transit, protecting against man-in-the-middle attacks.

### Control Spec

> **Passed:**
> All API service URLs use HTTPS scheme.
>
> **Failed:**
> One or more API service URLs use HTTP instead of HTTPS.
>

### Recommendation

- **Azure Portal**

    Go to API Management service → APIs → Select API → Settings → Update Service URL to use HTTPS scheme.

### Azure Policies or REST APIs used for evaluation

- REST API to get the details of the API specified by its identifier: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis/{apiId}?api-version=2019-01-01<br />
**Properties:** properties.serviceUrl<br />

<br />

___

## Azure_APIManagement_NetSec_Enable_Content_Security_Policy

### Display Name
API Management must enable Content Security Policy

### Rationale
Content Security Policy (CSP) helps prevent cross-site scripting (XSS) attacks and other code injection attacks by controlling which resources can be loaded.

### Control Spec

> **Passed:**
> Content Security Policy is properly configured.
>
> **Failed:**
> Content Security Policy is not configured or is insufficient.
>

### Recommendation

- **Azure Portal**

    Go to API Management service → Developer portal → Configure Content Security Policy headers through custom policies or portal settings.

### Azure Policies or REST APIs used for evaluation

- REST API to get policy configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/policies?api-version=2019-01-01<br />
**Properties:** properties.value<br />

<br />

___

## Azure_APIManagement_NetSec_Limit_OpenAI_Token_Usage

### Display Name
API Management must implement rate limiting for OpenAI token usage

### Rationale
Rate limiting for OpenAI token usage helps prevent abuse, controls costs, and ensures fair usage across different consumers of the API.

### Control Spec

> **Passed:**
> Rate limiting policies are configured for OpenAI token usage.
>
> **Failed:**
> Rate limiting policies are not configured or are insufficient.
>

### Recommendation

- **Azure Portal**

    Go to API Management service → APIs → Select OpenAI API → Policies → Add rate limiting policies to control token usage per consumer.

### Azure Policies or REST APIs used for evaluation

- REST API to get policy configuration at the API level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/apis/{apiId}/policies?api-version=2019-01-01<br />
**Properties:** properties.value<br />

<br />

___

## Azure_APIManagement_NetSec_Use_Virtual_Network

### Display Name
API Management must be deployed in a virtual network


### Rationale
Deploying API Management in a virtual network provides network isolation and allows for more granular control over network traffic and security.

### Control Spec

> **Passed:**
> API Management service is deployed in a virtual network.
>
> **Failed:**
> API Management service is not deployed in a virtual network.
>

### Recommendation

- **Azure Portal**

    Go to API Management service → Network → Virtual network → Configure virtual network integration for enhanced security and network isolation.

### Azure Policies or REST APIs used for evaluation

- REST API to get API Management service configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}?api-version=2019-12-01<br />
**Properties:** properties.virtualNetworkConfiguration<br />

<br />

___

