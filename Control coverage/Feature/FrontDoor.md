# Front Door

**Resource Type:** Microsoft.Network/FrontDoors

<!-- TOC -->

- [Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial](#Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial)

<!-- /TOC -->
<br/>

___ 

## Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial

### Display Name 
[Trial] Front Door Classic should have Approved Minimum TLS version

### Rationale 
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions. 

### Control Spec 

> **Passed:** 
>- All custom domain present in Front Door should have MinumumTLSVersion greater than or equals to 1.2.
> 
> **Failed:** 
> - Any custom domain present in Front Door is not having TLS Version set to 1.2 or greater than 1.2.
>
> 
### Recommendation 

- **Azure Portal** 
    
    To configure TLS Version, Go to Azure Portal --> Front Door and CDN profiles -> Select Front door with pricing tier as Classic -> Goto Front Door Designer -> Select any of the Custom domains listed -> Select Minimum TLS Version as greater than or equals to 1.2.


- **PowerShell** 
	 ```powershell
     Enable-AzFrontDoorCustomDomainHttps -ResourceGroupName <ResourceGroupName> -FrontDoorName <FrontDoorName> -FrontendEndpointName <FrontendEndpointName>
    -MinimumTlsVersion <MinimumTlsVersion>
    ```

	Refer: https://learn.microsoft.com/en-us/powershell/module/az.frontdoor/enable-azfrontdoorcustomdomainhttps?view=azps-9.1.0 to configure secured MinimumTLSVersion in custom domain. 


### Azure Policy or ARM API used for evaluation 

- ARM API used to list existing Front Door endpoints at subscription level: <br />
/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/frontDoors/{2}/frontendEndpoints/{3}?api-version=2019-05-01
<br />
**Properties:** 
properties.minimumTlsVersion
 <br />

