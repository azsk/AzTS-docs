# CDN

**Resource Type:** Microsoft.Cdn/profiles

<!-- TOC -->

- [Azure_CDN_DP_Enable_Https](#azure_cdn_dp_enable_https)
- [Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration](#Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration)
- [Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version_Trial ](#Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version_Trial )
<!-- /TOC -->
<br/>

___ 

## Azure_CDN_DP_Enable_Https 

### Display Name 
CDN endpoints must use HTTPS protocol while providing data to the client browser/machine or while fetching data from the origin server 

### Rationale 
Use of HTTPS ensures server/service authentication and protects data in transit from network layer man-in-the-middle, eavesdropping, session-hijacking attacks. 

### Control Spec 

> **Passed:** 
One of the following conditions is met:
>- CDN endpoints are configured with HTTPS protocol only or HTTP to HTTPs redirection rule.
>- No CDN endpoints are present in the CDN profile.
> 
> **Failed:** 
> CDN endpoints are not configured with HTTPS protocol only or HTTP to HTTPs redirection rule.

> 
### Recommendation 

- **Azure Portal** 
    Enable only HTTPs protocol for endpoints, to enable HTTPS protocol: Go to Azure Portal --> your CDN Profile --> your CDN Endpoint --> Origin --> Select HTTPS --> Save. 
	Note: In the interest of user experience, enable both HTTP and HTTPS protocol along with HTTP to HTTPS redirection rule configured in rules engine for all endpoints. To enable HTTP and HTTPS protocol: Go to Azure Portal --> your CDN Profile --> your CDN Endpoint --> Origin --> Select HTTPS and HTTP --> Save. Refer: https://docs.microsoft.com/en-us/azure/cdn/cdn-standard-rules-engine to configure HTTP to HTTPs redirection rule in rules engine. 

- **PowerShell** 

	 Enable only HTTPs protocol for endpoints using PowerShell: 
	 ```powershell
	$ce= Get-AzCdnEndpoint -EndpointName <EndpointName> -ProfileName <CDNprofile> -ResourceGroupName <RGName>;
	$ce.IsHttpAllowed =$false; 
	Set-AzCdnEndpoint -CdnEndpoint $ce
	```
	 Note: In the interest of user experience, enable both HTTP and HTTPS protocol along with HTTP to HTTPS redirection rule configured in rules engine for all endpoints. To enable HTTP and HTTPS protocol using PowerShell:
	 ```powershell
	$ce= Get-AzCdnEndpoint -EndpointName <EndpointName> -ProfileName <CDNprofile> -ResourceGroupName <RGName>;
	$ce.IsHttpAllowed =$true; 
	$ce.IsHttpsAllowed =$true; 
	Set-AzCdnEndpoint -CdnEndpoint $ce 
	```
	Refer: https://docs.microsoft.com/en-us/azure/cdn/cdn-standard-rules-engine to configure HTTP to HTTPs redirection rule in rules engine. 


### Azure Policy or ARM API used for evaluation 

- ARM API used to list existing CDN endpoints at subscription level: <br />
/subscriptions/{subscriptionId}/resourceGroups/{resourcegroupName}/providers/Microsoft.Cdn/profiles/{profileName}/endpoints?api-version=2019-12-31<br />
**Properties:** 
properties.isHttpAllowed, properties.isHttpsAllowed, properties.deliveryPolicy.rules
 <br />

___ 


## Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration 

### Display Name 
Protect Internet First Applications with Azure FrontDoor and WAF

### Rationale 
Azure Web Application Firewall (WAF) on Azure Front Door provides centralized protection for your web applications. WAF defends your web services against common exploits & vulnerablities. It keeps your service highly available for your users and helps you meet compliance requirements.

 ### Control Spec 

> **Passed:** 
> Web Application Firewall has been configured on Front Door CDN </br>
> and Configured WAF Policy mode must be Prevention only. </br> 
> and Configured WAF Policy mode must be in Enabled State only. </br> 
> 
> **Failed:** 
> WAF is not configured on Front Door CDN. </br> 
> or Configured WAF Policy mode is not Prevention. </br> 
> or Configured WAF Policy mode is not in Enabled State. </br> 
> 
> **Error:** 
> There was an error fetching WAF Configuration details of Front Door CDN.
> 
### Recommendation 
- **Azure Portal** 

	 Use the Azure portal to configure WAF Policy on the Front Door CDN.<br/>

- **Powershell** 	

     Use following Powershell Bulk Remediation scripts to Configure WAF Policy on the Front Door CDN: <br/>
     You can configure WAF Policy on Front Door using below BRS:<br/>
	 [Remediate-ConfigureWAFOnAzureFrontDoorCDN](../../Scripts/RemediationScripts/Remediate-ConfigureWAFOnAzureFrontDoorCDN.ps1) <br/>
	 You can enable State of WAF Policy configured on Front Door using below BRS:  <br/>
	 [Remediate-EnableWAFPolicyStateOfAzFrontDoorCDN](../../Scripts/RemediationScripts/Remediate-EnableWAFPolicyStateOfAzFrontDoorCDN.ps1) <br/>
	 You can enable Prevention Mode on WAF Policy configured on Front Door using below BRS:  <br/>
	 [Remediate-SetWAFPolicyModeToPreventionForAzFrontDoorCDN](../../Scripts/RemediationScripts/Remediate-SetWAFPolicyModeToPreventionForAzFrontDoorCDN.ps1) <br/>

### Azure Policy or ARM API used for evaluation 

- ARM API to get Front Door resources in a subscription: /subscriptions/{0}/
/subscriptions/{0}/providers/Microsoft.Cdn/profiles?api-version=2021-06-01
**Properties:** [*]	
 <br />

- ARM API to get Front Door Endpoints resources in a subscription: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Cdn/profiles/{2}/afdEndpoints?api-version=2021-06-01<br />
**Properties:** [*].properties.hostname, [*].properties.enabledState, 
 <br />

- ARM API to get WAF Policies in a subscription: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies?api-version=2020-11-01<br />
**Properties:** [*].properties.policySettings
 <br />

- ARM API to get Security Policies in a subscription: 
 /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Cdn/profiles/{2}/securityPolicies?api-version=2021-06-01<br />
**Properties:** [*].properties.parameters
<br />

___ 

## Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version_Trial 

### Display Name 
[Trial] Front Door should have Approved Minimum TLS version

### Rationale 
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions. 

### Control Spec 

> **Passed:** 
>- For all custom domain, the Minimun TLS Version is set to TLS 1.2 or greater than that.
>- If there is no custom domain attached to the front door.
>
> **Failed:** 
>- Custom domain Minimum TLS Version is less than TLS 1.2 for any domain. 
>

### Recommendation 

- **Azure Portal** 
    To configure TLS Version, Go to Azure Portal --> Front Door and CDN profiles -> Select Front door with pricing tier as Standard/Premium -> Goto Domains -> Select Certification Type for All the domains listed -> Select Minimum TLS Version as 1.2

- **PowerShell** 

	 
	 ```powershell
	$secret =  Get-AzFrontDoorCdnSecret -ResourceGroupName $resourceGroupName -ProfileName $resourceName
	$secretResoure = New-AzFrontDoorCdnResourceReferenceObject -Id $secret.Id
    $updateTlsSetting = New-AzFrontDoorCdnCustomDomainTlsSettingParametersObject -CertificateType $CertificateType -MinimumTlsVersion 'TLS12' -Secret $secretResoure
    $resource = Update-AzFrontDoorCdnCustomDomain -ResourceGroupName $resourceGroupName -ProfileName $resourceName -CustomDomainName $DomainName -TlsSetting $updateTlsSetting
	```

                    

### Azure Policy or ARM API used for evaluation 

- ARM API used to list existing CDN Domain endpoints at subscription level: <br />
 /subscriptions/{SubscriptionId}/resourceGroups/{ResourceGroupName}/providers/Microsoft.Cdn/profiles/{FrontDoorName}/customDomains?api-version=2021-06-01<br />
 **Properties:**  properties.tlsSettings.minimumTlsVersion, 
 properties.tlsSettings.profileName

- ARM API to get configuration of a particular custom domain: <br />
/subscriptions/{SubscriptionId}/resourceGroups/{ResourceGroupName}/providers/Microsoft.Cdn/profiles/{FrontDoorName}/customDomains/{CustomDomainName}?api-version=2021-06-01"<br />
**Properties:**  properties.certificateType
 <br />

<br />

___