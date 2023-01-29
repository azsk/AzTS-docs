# FrontDoor

**Resource Type:** Microsoft.Network/frontDoor 

<!-- TOC -->

- [Azure_FrontDoor_NetSec_Enable_WAF_Configuration](#azure_frontdoor_netsec_enable_waf_configuration)
- [Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial](#Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial)


<!-- /TOC -->
<br/>

___ 

## Azure_FrontDoor_NetSec_Enable_WAF_Configuration 

### Display Name 
Front Door (Classic) should have Web Application Firewall configured

### Rationale 
Azure Web Application Firewall (WAF) on Azure Front Door provides centralized protection for your web applications. WAF defends your web services against common exploits & vulnerablities. It keeps your service highly available for your users and helps you meet compliance requirements.

 ### Control Spec 

> **Passed:** 
> Web Application Firewall has been configured on Front Door. <b>AND</b> </br>
> Configured WAF Policy mode must be Prevention. <b>AND</b> </br> 
> Configured WAF Policy must be in Enabled State. </br> 
> 
> **Failed:** 
> WAF is not configured on Front Door. <b>OR</b>  </br> 
> Configured WAF Policy mode is not Prevention. <b>OR</b> </br> 
> Configured WAF Policy is not in Enabled State. </br> 
> 
> **Error:** 
> There was an error fetching WAF Configuration details of Front Door.
> 
### Recommendation 

- **Azure Portal** 

	 Use the Azure portal to configure WAF Policy on the Front Door.
	 To know more, please visit : https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-create-portal
	 <br/>
	 
- **Powershell** 	

	You can configure WAF Policy on Front Door using below BRS:<br/>
	 [Remediate-ConfigureWAFPolicyForFrontDoor](../../Scripts/RemediationScripts/Remediate-ConfigureWAFPolicyForFrontDoor.ps1) <br/>
	 <b>Disclaimer: Rollback for above remediation is not available, Once WAF Configured on Front Door can only be disabled from Azure Portal. </b><br/>
	 
	 You can enable State of WAF Policy configured on Front Door using below BRS:  <br/>
	 [Remediate-EnableWAFPolicyForFrontDoor](../../Scripts/RemediationScripts/Remediate-EnableWAFPolicyForFrontDoor.ps1) <br/>
	 You can enable Prevention Mode on WAF Policy configured on Front Door using below BRS:  <br/>
	 [Remediate-EnableWAFPolicyPreventionModeForFrontDoor](../../Scripts/RemediationScripts/Remediate-EnableWAFPolicyPreventionModeForFrontDoor.ps1) <br/>

### Azure Policy or ARM API used for evaluation 

- ARM API to get Front Door resources in a subscription: /subscriptions/{0}/providers/Microsoft.Network/frontDoors?api-version=2019-05-01<br />
**Properties:** [*].properties.frontendEndpoints
 <br />

- ARM API to get WAF Policy resources in a subscription: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies?api-version=2020-11-01<br />
**Properties:** [*].properties.frontendEndpointLinks, [\*].properties.policySettings
 <br />

___ 

## Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial

### Display Name 
[Trial] Front Door Classic should have approved minimum TLS version

### Rationale 
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions. 

### Control Spec 

> **Passed:** 
>- All custom domain present in Front Door should have MinumumTLSVersion greater than or equals to 1.2.
>- If there are no custom domains present in Front Door.
> 
> **Failed:** 
> - Any custom domain present in Front Door is not having TLS Version set to 1.2 or greater than 1.2.
>
> 
### Recommendation 

- **Azure Portal** 
    
    To configure TLS Version, Go to Azure Portal --> Front Door and CDN profiles -> Select Front door with pricing tier as Classic -> Goto Front Door Designer -> Select Frontend/domain which is non-compliant -> Select Minimum TLS Version as greater than or equals to 1.2.


- **PowerShell** 
	 ```powershell
     Enable-AzFrontDoorCustomDomainHttps -ResourceGroupName <ResourceGroupName> -FrontDoorName <FrontDoorName> -FrontendEndpointName <FrontendEndpointName>
    -MinimumTlsVersion <MinimumTlsVersion>
    ```

	Refer: https://learn.microsoft.com/en-us/powershell/module/az.frontdoor/enable-azfrontdoorcustomdomainhttps?view=azps-9.1.0 to configure secured MinimumTLSVersion in custom domain. 


### Azure Policy or ARM API used for evaluation 

- ARM API used to list existing Front Door endpoints at subscription level: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/frontDoors/{2}/frontendEndpoints/{3}?api-version=2019-05-01<br />
**Properties:** properties.minimumTlsVersion
 <br />

___


