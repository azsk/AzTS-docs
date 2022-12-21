# CDN

**Resource Type:** Microsoft.Cdn/profiles

<!-- TOC -->

- [Azure_CDN_DP_Enable_Https](#azure_cdn_dp_enable_https)
- [Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration](#azure_frontdoor_cdnprofile_netsec_enable_waf_configuration)

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
Front Door should have Web Application Firewall configured

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
	 [Remediate-ConfigureWAFPolicyForFrontDoorCDN](../../Scripts/RemediationScripts/Remediate-ConfigureWAFPolicyForFrontDoorCDN.ps1) <br/>
	 You can enable State of WAF Policy configured on Front Door using below BRS:  <br/>
	 [Remediate-EnableWAFPolicyForFrontDoorCDN](../../Scripts/RemediationScripts/Remediate-EnableWAFPolicyForFrontDoorCDN.ps1) <br/>
	 You can enable Prevention Mode on WAF Policy configured on Front Door using below BRS:  <br/>
	 [Remediate-EnableWAFPolicyPreventionModeForFrontDoorCDN](../../Scripts/RemediationScripts/Remediate-EnableWAFPolicyPreventionModeForFrontDoorCDN.ps1) <br/>

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

