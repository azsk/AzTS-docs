# FrontDoorCDN

**Resource Type:** Microsoft.Cdn/profiles

<!-- TOC -->
 
- [Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration](#azure_frontdoor_cdnprofile_netsec_enable_waf_configuration)


<!-- /TOC -->
<br/>

___ 

## Azure_FrontDoor_NetSec_Enable_WAF_Configuration 

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
**Properties:** [*]
 <br />

- ARM API to get WAF Policies in a subscription: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies?api-version=2020-11-01<br />
**Properties:** [*]
 <br />

- ARM API to get Security Policies in a subscription: 
 /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Cdn/profiles/{2}/securityPolicies?api-version=2021-06-01<br />
**Properties:** [*]
<br />

___ 


