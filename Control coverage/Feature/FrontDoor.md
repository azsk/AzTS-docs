# FrontDoor

**Resource Type:** Microsoft.Network/frontDoor 

<!-- TOC -->
Azure_FrontDoor_NetSec_Enable_WAF_Configuration
- [Azure_FrontDoor_NetSec_Enable_WAF_Configuration](#azure_frontdoor_netsec_enable_waf_configuration)


<!-- /TOC -->
<br/>

___ 

## Azure_FrontDoor_NetSec_Enable_WAF_Configuration 

### Display Name 
WAF Policy should be configured on for Endpoints in Front Door

### Rationale 
Azure Web Application Firewall (WAF) on Azure Front Door provides centralized protection for your web applications. WAF defends your web services against common exploits & vulnerablities. It keeps your service highly available for your users and helps you meet compliance requirements.

 ### Control Spec 

> **Passed:** 
> Web Application Firewall has been configured on Front Door </br>
> and Configured WAF Policy mode must be Prevention only. </br> 
> and Configured WAF Policy mode must be in Enabled State only. </br> 
> 
> **Failed:** 
> WAF is not configured on Front Door. </br> 
> or Configured WAF Policy mode is not Prevention. </br> 
> or Configured WAF Policy mode is not in Enabled State. </br> 
> 
> **Error:** 
> There was an error fetching WAF Configuration details of Front Door.
> 
### Recommendation 
- **Azure Portal** 

	 Use the Azure portal to configure WAF Policy on the Front Door.<br/>
	 or Use following Powershell Bulk Remediation scripts to Configure WAF Policy on the Front Door: <br/>
	 [Remediate-ConfigureWAFPolicyForFrontDoor](../../Scripts/RemediationScripts/Remediate-ConfigureWAFPolicyForFrontDoor.ps1) <br/>
	 You can enable State of WAF Policy configured on Front Door using below BRS:  <br/>
	 [Remediate-EnableWAFPolicyForFrontDoor](../../Scripts/RemediationScripts/Remediate-EnableWAFPolicyForFrontDoor.ps1) <br/>
	 You can enable Prevention Mode on WAF Policy configured on Front Door using below BRS:  <br/>
	 [Remediate-EnableWAFPolicyPreventionModeForFrontDoor](../../Scripts/RemediationScripts/Remediate-EnableWAFPolicyPreventionModeForFrontDoor.ps1) <br/>

### Azure Policy or ARM API used for evaluation 

- ARM API to get Front Door resources in a subscription: /subscriptions/{0}/providers/Microsoft.Network/frontDoors?api-version=2019-05-01<br />
**Properties:** [*]
 <br />

- ARM API to get WAF Policy resources in a subscription: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies?api-version=2020-11-01<br />
**Properties:** [*]
 <br />

<br />

___ 


