# FrontDoor

**Resource Type:** Microsoft.Network/frontDoor 

<!-- TOC -->
Azure_FrontDoor_NetSec_Enable_WAF_Configuration
- [Azure_FrontDoor_NetSec_Enable_WAF_Configuration](#azure_frontdoor_netsec_enable_waf_configuration)
- [Azure_DBForMySQLFlexibleServer_DP_Use_Secure_TLS_Version_Trial](#azure_dbformysqlflexibleServer_dp_use_secure_tls_version_trial)

<!-- /TOC -->
<br/>

___ 

## Azure_FrontDoor_NetSec_Enable_WAF_Configuration 

### Display Name 
[Trial] WAF Policy should be configured on for Endpoints in Front Door

### Rationale 
Azure Web Application Firewall (WAF) on Azure Front Door provides centralized protection for your web applications. WAF defends your web services against common exploits & vulnerablities. It keeps your service highly available for your users and helps you meet compliance requirements.

 ### Control Spec 

> **Passed:** 
> Web Application Firewall has been configured on Front Door. 
> Configured WAF Policy mode must be Prevention only. 
> Configured WAF Policy mode must be in Enabled State only. 
> 
> **Failed:** 
> WAF is not configured on Front Door.
> Configured WAF Policy mode is not Prevention.
> Configured WAF Policy mode is not in Enabled State.
> 
> **Error:** 
> There was an error fetching WAF Configuration details of Front Door.
> 
### Recommendation 
- **Azure Portal** 

	 Use the Azure portal to configure WAF on the Front Door.

 
 <br />

<br />

___ 

