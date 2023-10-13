# AppService

**Resource Type:** Microsoft.Web/sites 

<!-- TOC -->

- [Azure_AppService_DP_Use_CNAME_With_SSL](#azure_appservice_dp_use_cname_with_ssl)
- [Azure_AppService_Config_Disable_Remote_Debugging](#azure_appservice_config_disable_remote_debugging)
- [Azure_AppService_Config_Disable_Web_Sockets](#azure_appservice_config_disable_web_sockets)
- [Azure_AppService_BCDR_Use_AlwaysOn](#azure_appservice_bcdr_use_alwayson)
- [Azure_AppService_BCDR_Use_Multiple_Instances](#azure_appservice_bcdr_use_multiple_instances)
- [Azure_AppService_Audit_Enable_Logging_and_Monitoring](#azure_appservice_audit_enable_logging_and_monitoring)
- [Azure_AppService_DP_Dont_Allow_HTTP_Access](#azure_appservice_dp_dont_allow_http_access)
- [Azure_AppService_DP_Review_CORS_Request_Credential](#azure_appservice_dp_review_cors_request_credential)
- [Azure_AppService_DP_Restrict_CORS_Access](#azure_appservice_dp_restrict_cors_access)
- [Azure_AppService_DP_Use_Secure_TLS_Version](#azure_appservice_dp_use_secure_tls_version)
- [Azure_AppService_AuthZ_Configure_IP_Restrictions](#azure_appservice_authz_configure_ip_restrictions)
- [Azure_AppService_AuthN_Use_Managed_Service_Identity](#azure_appservice_authn_use_managed_service_identity)
- [Azure_AppService_DP_Use_Secure_FTP_Deployment](#azure_appservice_dp_use_secure_ftp_deployment)
- [Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth](#azure_appservice_authn_ftp_and_scm_access_disable_basic_auth)

<!-- /TOC -->
<br/>

___ 

## Azure_AppService_DP_Use_CNAME_With_SSL 

### Display Name 
Custom domain with SSL binding must be configured for App Service 

### Rationale 
Use of custom domain protects a web application from common attacks such as phishing, session hijacking and other DNS-related attacks. 

### Control Spec 

> **Passed:** 
> SSL configuration for resource is enabled for all custom domains.
> 
> **Failed:** <br/>
>One of the following conditions is met:
>- Custom domains are not configured.
>- SSL configuration for resource is not enabled for all custom domains.

 
### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal --> your App Service --> Settings --> Custom Domains and follow the steps mentioned to configure a custom domain. 

- **PowerShell** 

Run command New-AzWebAppSSLBinding to enable the SSL binding for your custom domain. Run Get-Help New-AzWebAppSSLBinding -full for more help.  


### Azure Policies or REST APIs used for evaluation 

- ARM API to list all App Services in a subscription: <br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?api-version=2018-11-01 <br />
 **Properties:**  properties.hostNames, properties.hostNameSslStates

<br />

___ 

## Azure_AppService_Config_Disable_Remote_Debugging 

### Display Name 
Remote debugging should be turned off for Web Applications 

### Rationale 
Remote debugging requires inbound ports to be opened on App Service. These ports become easy targets for compromise from various internet-based attacks. 

### Control Spec 

> **Passed:** 
> Remote debugging is disabled for all slots in App Service.
> 
> **Failed:** 
> Remote debugging is enabled for any slot in App Service.
>
> 
### Recommendation 

- **Azure Portal** 

	 To disable remote debugging on default 'Production' slot: Go to Azure Portal --> your App Service --> Settings --> Configuration --> General Settings --> Remote Debugging (Under Debugging) --> Click on 'OFF' --> Save. To disable remote debugging on any non-production slot: Go to Azure Portal --> your App Service --> Deployment --> Deployment slots --> Select slot --> Settings --> Configuration --> General Settings --> Remote Debugging (Under Debugging) --> Click on 'OFF' --> Save.

### Azure Policies or REST APIs used for evaluation 

- ARM API to list all App Services in a subscription: <br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?api-version=2018-11-01
 <br />

- ARM API to list all slots of App Service: <br />
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{site}/slots?api-version=2019-08-01
 <br />

 - ARM API to get configuration of App Service: <br />/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/config/web?api-version=2018-11-01 <br />
**Properties:** properties.RemoteDebuggingEnabled
<br />

 - ARM API to get configuration of App Service slot: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/slots/{slotName}/config/web?api-version=2019-08-01 <br />
**Properties:** properties.RemoteDebuggingEnabled
<br />
 <br />

<br />

___ 

## Azure_AppService_Config_Disable_Web_Sockets 

### Display Name 
Web Sockets should be disabled for App Service 

### Rationale 
WebSockets protocol (WS) is vulnerable to different types of security attacks. Usage of Web Sockets within web applications has to be carefully reviewed. 

### Control Spec 

> **Passed:** 
> Web sockets is disabled for all slots in App Service.
> 
> **Failed:** 
> Web sockets is enabled for any slot in App Service.
> 
### Recommendation 
 
- **PowerShell** 
To disable Web Sockets on default 'Production' slot, run command:
 ```powershell 
 Set-AzWebApp -Name <WebAppName> -ResourceGroupName <RGName> -WebSocketsEnabled $false
 ```
Run 'Get-Help Set-AzWebApp -full' for more help. 

To disable Web Sockets on any non-production slot, run command:
```powershell 
Set-AzWebAppSlot -ResourceGroupName <RGName> -Name <WebAppName> -Slot <SlotName> -WebSocketsEnabled $false
```
<br/>
 Refer: https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/HTML5_Security_Cheat_Sheet.md#websockets 

### Azure Policies or REST APIs used for evaluation 

- ARM API to list all App Services in a subscription: <br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?api-version=2018-11-01
 <br />

- ARM API to list all slots of App Service: <br />
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{site}/slots?api-version=2019-08-01
 <br />

 - ARM API to get configuration of App Service: <br />/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/config/web?api-version=2018-11-01 <br />
**Properties:** properties.webSocketsEnabled<br />

 - ARM API to get configuration of App Service slot: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/slots/{slotName}/config/web?api-version=2019-08-01 <br />
**Properties:**  properties.webSocketsEnabled<br />

<br />

___ 

## Azure_AppService_BCDR_Use_AlwaysOn 

### Display Name 
'Always On' should be configured for App Service 

### Rationale 
By default, websites are unloaded if they have been idle for some period of time. However, this may not be ideal for 'high availability' requirements. Configuring 'Always On' can help prevent app services from getting timed out. 

### Control Settings 
```json 
{
    "ApplicableAppServiceKinds": [
        "app"
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> "Always On" configuration is enabled for the App Service.
> 
> **Failed:** 
> "Always On" configuration is not enabled for the App Service.
> 
> **Error:** 
> App Service Kind could not be determined.
> 
> **NotApplicable:** 
> App Service Kind is excluded from the evaluation.
> 
### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal --> your App Service --> Settings --> Configuration --> General Settings --> Always On --> Click on 'ON'. 

### Azure Policies or REST APIs used for evaluation 
- ARM API to list all App Services in a subscription: <br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?api-version=2018-11-01
 <br />

 - ARM API to get configuration of App Service: <br /> /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/config/web?api-version=2018-11-01 <br />
**Properties:**  properties.alwaysOn

<br />

___ 

## Azure_AppService_BCDR_Use_Multiple_Instances 

### Display Name 
App Service must be deployed on a minimum of two instances to ensure availability 

### Rationale 
App Service deployed on multiple instances ensures that the App Service remains available even if an instance is down. 

### Control Settings 
```json 
{
    "ApplicableAppServiceKinds": [
        "app"
    ],
    "MinimumRequiredInstances": 2
}
 ```  

### Control Spec 

> **Passed:** 
> The App Service is deployed across the minimum required instances.
> 
> **Failed:** 
> The App Service is not deployed across the minimum required instances.
> 
> **Error:** 
One of the below conditions is met:
> - App Service Kind could not be determined.
> - App Service Plan details could not be fetched.
> - Minimum required instances count is either misconfigured, or, is invalid.
> 
> **NotApplicable:** 
> App Service Kind is excluded from the evaluation.
> 
### Recommendation 

- **PowerShell** 
	 ```powershell 
	Set-AzAppServicePlan -Name <AppServicePlanName> -ResourceGroupName <RGName> -NumberofWorkers <NumberofInstances>
	 ```  
	Run 'Get-Help Set-AzAppServicePlan -full' for more help. 

### Azure Policies or REST APIs used for evaluation 

- ARM API to list existing App Services at subscription level: <br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?api-version=2018-11-01
 <br />

-  ARM API to list App Service Plans in a subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Web/serverfarms?api-version=2019-08-01&detailed=false <br />
**Properties:** properties.AppServicePlan.SkuDescription.Capacity
 <br />

<br />

___ 

## Azure_AppService_Audit_Enable_Logging_and_Monitoring 

### Display Name 
Monitoring must be enabled for App Service 

### Rationale 
Auditing enables log collection of important system events pertinent to security. Regular monitoring of audit logs can help to detect any suspicious and malicious activity early and respond in a timely manner. 

### Control Spec 

> **Passed:** 
> HTTP Logging, DetailedError Logging and Request Tracing, all three must be enabled for all slots in App Service.
> 
> **Failed:** 
> HTTP Logging, DetailedError Logging and Request Tracing, any one of the three logging is disabled for any slot of App Service.
> 
 
### Recommendation 

- **PowerShell** 

	To enable monitoring on default 'Production' slot, run command:
	```powershell
	Set-AzWebApp -Name <WebAppName> -ResourceGroupName <RGName> -DetailedErrorLoggingEnabled $true -HttpLoggingEnabled $true -RequestTracingEnabled $true
	``` 
	Run 'Get-Help Set-AzWebApp -full' for more help. 
	
	To enable monitoring on any non-production slot, run command: 
	```powershell
	Set-AzWebAppSlot -ResourceGroupName <RGName> -Name <WebAppName> -Slot <SlotName> -DetailedErrorLoggingEnabled $true -HttpLoggingEnabled $true -RequestTracingEnabled $true
	```

### Azure Policies or REST APIs used for evaluation 

- ARM API to list all App Services in a subscription: <br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?api-version=2018-11-01
 <br />

- ARM API to list all slots of App Service: <br />
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{site}/slots?api-version=2019-08-01
 <br />

 - ARM API to get configuration of App Service: <br />/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/config/web?api-version=2018-11-01 <br />
**Properties:**  properties.detailedErrorLoggingEnabled, properties.httpLoggingEnabled, properties.requestTracingEnabled

 - ARM API to get configuration of App Service slot: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/slots/{slotName}/config/web?api-version=2019-08-01 <br />
**Properties:**  properties.detailedErrorLoggingEnabled, properties.httpLoggingEnabled, properties.requestTracingEnabled
<br />

___ 

## Azure_AppService_DP_Dont_Allow_HTTP_Access 

### Display Name 
Use HTTPS for app services 

### Rationale 
Use of HTTPS ensures server/service authentication and protects data in transit from network layer eavesdropping attacks. 

### Control Spec 
>
> **Passed:** 
> HTTPS Only setting is enabled for all slots in App Service.
> 
> **Failed:** 
> HTTPS Only setting is disabled for any slot in App Service.
>

### Recommendation 

- **PowerShell** 

 To enable only https traffic on default 'Production' slot, run command
 
```powershell
Set-AzWebApp -Name <WebAppName> -ResourceGroupName <RGName> -HttpsOnly $true 
```
Run Get-Help Set-AzWebApp -full for more help.

To enable only https traffic on any non-production slot, run command 
	 
```powershell
Set-AzWebAppSlot -ResourceGroupName <RGName> -Name <WebAppName> -Slot <SlotName> -HttpsOnly $true
```  

### Azure Policies or REST APIs used for evaluation 

- ARM API to list existing App Services at subscription level: <br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?api-version=2018-11-01<br />
 **Properties:**  properties.httpsOnly

- ARM API to list properties of all slots of app service: <br />
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{site}/slots?api-version=2019-08-01<br />
**Properties:**  properties.httpsOnly

- ARM API to list all security assessments for a Subscription:
/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** 
[\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData<br />
 **Assessments:** 
 <br/>cb0acdc6-0846-fd48-debe-9905af151b6d - Function App should only be accessible over HTTPS.
 <br/>1b351b29-41ca-6df5-946c-c190a56be5fe - Web Application should only be accessible over HTTPS.
 <br />

<br />

___ 



## Azure_AppService_DP_Review_CORS_Request_Credential 

### Display Name 
Review use of credentials in CORS request for App Service

### Rationale 
CORS enables applications running under one domain to access a resource under another domain. Allowing cross-origin credentials is a security risk. A website at another domain can send a signed-in user's credentials to the app on the user's behalf without the user's knowledge. 

### Control Spec 

> **Passed:** 
> App Service does not allow CORS or "Access-Control-Allow-Credentials" Header is disabled for the App Service.
> 
> **Failed:** 
> App Service allows CORS and "Access-Control-Allow-Credentials" Header is enabled.
> 
### Recommendation 
- **Azure Portal** 

	 Go to Azure Portal --> your App Service --> API --> CORS --> Request Credentials --> Review if you need to enable 'Access-Control-Allow-Credentials'. Note: No action is needed if you are not using CORS for your app.

### Azure Policies or REST APIs used for evaluation 

- ARM API to get configuration of an App Service: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/config/web?api-version=2018-11-01 <br />
**Properties:** properties.cors<br />

- ARM API to list all deployment slots of an App Service: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/slots?api-version=2019-08-01 <br />
**Properties:** name<br />

- ARM API to get configuration of an App Service slot: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/slots/{slotName}/config/web?api-version=2019-08-01 <br />
**Properties:** properties.cors<br />

<br />

___ 

## Azure_AppService_DP_Restrict_CORS_Access 

### Display Name 
Ensure that CORS access is granted to a limited set of trusted origins 

### Rationale 
CORS enables applications running under one domain to access a resource under another domain. Using '*' (allow all) for CORS setting means that an application running under any domain can have access to your application's resources and data. Restricting allowed origins to the specific set that needs access aligns with the principle of least privilege. 

### Control Spec 

> **Passed:** 
> If Allow-All origin wildcard not found in allowed origins.
> 
> **Failed:** 
> If Allow-All origin wildcard found in allowed origins.
> 
### Recommendation 
- **Azure Portal** 

	 Go to Azure Portal --> your App Service --> API --> CORS --> Provide the specific domain names that should be allowed to make cross-origin calls. Note: No action is needed if you are not using CORS for your app.

### Azure Policies or REST APIs used for evaluation 

- ARM API to get configuration of an App Service: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/config/web?api-version=2018-11-01 <br />
**Properties:** properties.cors.allowedOrigins<br />

- ARM API to list all deployment slots of an App Service: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/slots?api-version=2019-08-01 <br />
**Properties:** name<br />

- ARM API to get configuration of an App Service slot: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/slots/{slotName}/config/web?api-version=2019-08-01 <br />
**Properties:** properties.cors.allowedOrigins<br />

<br />

___ 
 

## Azure_AppService_DP_Use_Secure_TLS_Version 

### Display Name 
Use Approved TLS Version in App Service 

### Rationale 
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions. 

### Control Settings 
```json 
{
    "MinReqTLSVersion": "1.2"
}
 ```  

### Control Spec 

> **Passed:** 
> App Service current min TLS version is set to either equal or greater than the required min TLS version for all the slots.
> 
> **Failed:** 
> App Service current min TLS version is less than required min TLS version for any of the slot.
>
> 
### Recommendation 

- **Azure Portal** 

	 To set required TLS version on default 'Production' slot: Go to Azure Portal --> your App Service --> Settings --> TLS/SSL --> Minimum TLS version --> set to org approved version (see status reason). To set required TLS version on any non-production slot: Go to Azure Portal --> your App Service --> Deployment --> Deployment slots --> Select slot --> Settings --> TLS/SSL --> Minimum TLS version --> set to org approved version (see status reason). 

### Azure Policies or REST APIs used for evaluation 

- ARM API to list all App Services in a subscription: <br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?api-version=2018-11-01
 <br />

- ARM API to list all slots of App Service: <br />
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{site}/slots?api-version=2019-08-01
 <br />

 - ARM API to get configuration of App Service: <br />/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/config/web?api-version=2018-11-01 <br />
**Properties:** properties.minTlsVersion<br />

 - ARM API to get configuration of App Service slot: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/slots/{slotName}/config/web?api-version=2019-08-01 <br />
**Properties:**  properties.minTlsVersion

- ARM API to list all security assessments for a Subscription:
/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** 
[\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData<br />
 **Assessments:** 
 <br/>15be5f3c-e0a4-c0fa-fbff-8e50339b4b22 - TLS should be updated to the latest version for function apps.
 <br/>2a54c352-7ca4-4bae-ad46-47ecd9595bd2 - TLS should be updated to the latest version for web apps.
<br />

<br />

___ 

## Azure_AppService_AuthZ_Configure_IP_Restrictions 

### Display Name 
Setup IP-based access restrictions for App Service if feasible 

### Rationale 
Using the IP/VNet subnet rules-based access restriction ensures that access to the data or the service is restricted to a specific set of IPs. NOTE: While this control does provide an extra layer of access control protection, it may not always be feasible to implement in all scenarios. 

### Control Spec 

> **Passed:** 
> If one of the below conditions is met:<br/>
>  - SCM site relies on the App Service's IP Security Restrictions, and, there are IP Security Restrictions configured for the App Service.
   - SCM site does not rely on the App Service's IP Security Restrictions, but, IP Security Restrictions have been configured for the SCM site.
> 
> **Failed:** 
> If one of the below conditions is met:<br/>
> - SCM site relies on the App Service's IP Security Restrictions, but, no IP Security Restrictions have been configured for the App Service.
>  - SCM site does not rely on the App Service's IP Security Restrictions, and, no IP Security Restrictions have been configured for the SCM site.
> 
### Recommendation 

- **Azure Portal** 

	 Consider using IP-based access restrictions for App Service if feasible. Steps: Go to Azure Portal --> your App Service --> Networking --> Access Restrictions --> Configure Access Restrictions --> Add/Verify access restriction rule for app and scm site. For more information, refer: https://docs.microsoft.com/en-us/azure/app-service/app-service-ip-restrictions 


### Azure Policies or REST APIs used for evaluation 

- ARM API to list existing App Services at subscription level: <br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?api-version=2018-11-01
 <br />

- ARM API to list configuration properties for app service:  <br/>
 /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{site}/config/web?api-version=2018-11-01<br />
 **Properties:**  properties.ipSecurityRestrictions, properties.scmIpSecurityRestrictions, properties["scmIpSecurityRestrictionsUseMain

<br />

___ 

## Azure_AppService_AuthN_Use_Managed_Service_Identity 

### Display Name 
Use Managed Service Identity (MSI) for accessing other AAD-protected resources from the app service 

### Rationale 
Managed Service Identity (MSI) allows your app to easily access other AAD-protected resources such as Azure Key Vault. The identity is managed by the Azure platform and eliminates the need to provision/manage/rotate any secrets thus reducing the overall risk. 

### Control Spec 

> **Passed:** 
> App Service is using SystemAssigned or UserAssigned managed identity or a combination of both.
> 
> **Failed:** 
> App Service is not using any managed identity.
> 
### Recommendation 
- **Azure Portal** 

	 Go to Azure Portal --> your App Service --> Settings --> Identity --> System assigned --> ON

### Azure Policies or REST APIs used for evaluation 

- ARM API to list all the App Services in a subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?2018-11-01<br />
**Properties:** properties.identity.type<br />

- ARM API to list all deployment slots of an App Service: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/slots?api-version=2019-08-01 <br />
**Properties:** properties.identity.type<br />

<br />

___ 

## Azure_AppService_DP_Use_Secure_FTP_Deployment

### Display Name 
App Services should use secure FTP deployments

### Rationale 
FTPS is used to enhance security for your Azure Web Application as it adds an extra layer of security to the FTP protocol. Enforcing FTPS-only access for your Azure App Services apps can guarantee that the encrypted traffic between the web apps and servers and the FTP clients cannot be decrypted by malicious actors.

### Control Spec 

 >**Passed :**
 > - FTP State is found to be configured to "FTPS" (secure FTP) or marked as "disabled" for all slots in the App Service.
 >
> **Failed :**
 > - FTP State is found to be configured as "All Allowed" for any of the production / non-production slots in the App Service.
 >
> **Note :** If Microsoft Defender for Cloud (MDC) assessment is not found for the App Service, then response from the ARM API is considered for the control evaluation.
>

### Recommendation 
- **Azure Portal** 

	 To make production slot compliant:
	 Go to Azure Portal --> your App Service --> Settings --> Configuration --> General Settings --> FTP state -->(Choose FTPS Only/Disabled based on the requirement) --> Save.

	 To make non-production slot compliant
	 Go to Azure Portal --> your App Service --> Deployment --> Deployment slots --> Select slot --> Settings --> Configuration --> General Settings --> FTP state --> (Choose FTPS Only/Disabled based on the requirement) --> Save.


### Azure Policies or REST APIs used for evaluation 

- Azure Policy (built-in):
  [Function apps should require FTPS only](https://ms.portal.azure.com/#view/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F399b2637-a50f-4f95-96f8-3a145476eb15)
  <br />
- Azure Policy (built-in):
  [App Service apps should require FTPS only](https://ms.portal.azure.com/#view/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F4d24b6d4-5e53-4a4f-a7f4-618fa573ee4b)
  <br />

- ARM API to get configuration of App Service: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Web/sites/{2}/config/web?api-version=2018-11-01<br />
**Properties:** properties.ftpsState<br />

- ARM API to get configuration of App Service Slot: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Web/sites/{2}/slots/{3}/config/web?api-version=2019-08-01 <br />
**Properties:** properties.ftpsState<br />

<br />

___ 

## Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth

### Display Name 
AppService must not use basic authentication for FTP and SCM access

### Rationale 
Using the native enterprise directory for authentication ensures that there is a built-in high level of assurance in the user identity established for subsequent access control. All enterprise subscriptions are automatically associated with their enterprise directory (xxx.onmicrosoft.com) and users in the native directory are trusted for authentication to enterprise subscriptions.

### Control Spec 

>**Passed :**
> - Basic Authentication is disabled for both FTP and SCM access for production and non-production slots.
>
> **Failed :**
> - Basic Authentication is enabled for either FTP or SCM access (or both) for either production or non-production slots (or both).
>
> **Error :**
> - AppService basic authentication configuration details could not be fetched.

### Recommendation 
- **Azure Portal** 

	 To make production slot compliant:<br />
	 Go to Azure Portal --> your App Service --> Settings --> Configuration --> General Settings --> Basic Authentication --> Off --> Save

	 To make non-production slot compliant:<br />
	 Go to Azure Portal --> your App Service --> Deployment --> Deployment slots --> Select slot --> Settings --> Configuration --> General Settings -->  Basic Authentication --> Off --> Save

### Azure Policies or REST APIs used for evaluation 

- ARM API to get SCM's basic authentication configuration of App Service: [/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{appServiceName}/basicPublishingCredentialsPolicies/scm?api-version=2022-03-01](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get-scm-allowed?tabs=HTTP)<br />
**Properties:** properties.allow<br />

- ARM API to get SCM's basic authentication configuration of an App Service slot: [/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{appServiceName}/slots/{slotName}/basicPublishingCredentialsPolicies/scm?api-version=2022-03-01](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get-scm-allowed-slot?tabs=HTTP)<br />
**Properties:** properties.allow<br />

- ARM API to get FTP's basic authentication configuration of App Service: [/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{appServiceName}/basicPublishingCredentialsPolicies/ftp?api-version=2022-03-01](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get-ftp-allowed?tabs=HTTP)<br />
**Properties:** properties.allow<br />

- ARM API to get FTP's basic authentication configuration of an App Service slot: [/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{appServiceName}/slots/{slotName}/basicPublishingCredentialsPolicies/ftp?api-version=2022-03-01](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get-ftp-allowed-slot?tabs=HTTP)<br />
**Properties:** properties.allow<br />

<br />

___ 