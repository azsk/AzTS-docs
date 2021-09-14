# API Managment

**Resource Type:** Microsoft.ApiManagement/service
<!-- TOC depthfrom:2 depthto:2 orderedlist:false -->

- [Azure_APIManagement_DP_Use_HTTPS_URL_Scheme](#azure_apimanagement_dp_use_https_url_scheme)
- [Azure_APIManagement_AuthN_Disable_Management_API](#azure_apimanagement_authn_disable_management_api)

<!-- /TOC -->
___

## Azure_APIManagement_DP_Use_HTTPS_URL_Scheme

### DisplayName: 
Ensure Backend API(s) are only accessible over HTTPS via API Management service.

### Rationale
Use of HTTPS ensures server/service authentication and protects data in transit from network layer eavesdropping attacks.

### Control Spec
    
> **Passed:**
> All API(s) are configured to use secure HTTP access to the backend via API Management, OR
No API(s) found in APIM instance.
> 
> **Failed:**
>Found API(s) that are configured to use non-secure HTTP access to the backend via API Management.
> 
> **Verify:**
Unable to verify the delegation setting since management endpoint 3443 is disabled.

<!-- TOC ignore:true -->
### Recommendation

<!-- - #### **Azure Portal** -->
    


- **PowerShell:**
    ```powershell
    Set-AzApiManagementApi -Context {APIContextObject} -Protocols 'Https' -Name '{APIName}' -ApiId '{APIId}' -ServiceUrl '{ServiceURL}'
    Get-AzApiManagementApi -Context '{APIContextObject}' # To get the details of existing APIs. 
    
    # Refer https://docs.microsoft.com/en-us/powershell/module/az.apimanagement/set-azapimanagementapi
    ```


- **Enforcement Policy**

    [![Link to Azure Policy](https://camo.githubusercontent.com/decd8b19034344bb486631a9d3501b663b199bf367c8a9eb2c43ad0df9be10b2/687474703a2f2f617a7572656465706c6f792e6e65742f6465706c6f79627574746f6e2e706e67)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/https://raw.githubusercontent.com/Azure/azure-policy/master/samples/WebApp/web-app-https-traffic-only/azurepolicy.json)


<!-- TOC ignore:true -->
### Azure Policy or ARM API used for evaluation

- ARM API to list APIMs and its related property at Subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?
api-version=2019-12-01<br />
**Properties:**
sku

- ARM API to get tenant access information details without secrets:
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/tenant/access?
api-version=2019-12-01<br />
**Properties:**
enabled
___

## Azure_APIManagement_AuthN_Disable_Management_API

<!-- TOC ignore:true -->
### DisplayName: 
Ensure Backend API(s) are only accessible over HTTPS via API Management service.

<!-- TOC ignore:true -->
### Rationale
Use of HTTPS ensures server/service authentication and protects data in transit from network layer eavesdropping attacks.

<!-- TOC ignore:true -->
### Control Spec
    
> **Passed:**
> All API(s) are configured to use secure HTTP access to the backend via API Management, OR
No API(s) found in APIM instance.
> 
> **Failed:**
>Found API(s) that are configured to use non-secure HTTP access to the backend via API Management.
> 
> **Verify:**
Unable to verify the delegation setting since management endpoint 3443 is disabled.

<!-- TOC ignore:true -->
### Recommendation

- **Azure Portal**
    


- **PowerShell:**
    ```powershell
    Set-AzApiManagementApi -Context {APIContextObject} -Protocols 'Https' -Name '{APIName}' -ApiId '{APIId}' -ServiceUrl '{ServiceURL}'
    Get-AzApiManagementApi -Context '{APIContextObject}' # To get the details of existing APIs. 
    
    # Refer https://docs.microsoft.com/en-us/powershell/module/az.apimanagement/set-azapimanagementapi
    ```


- **Enforcement Policy**

    [![Link to Azure Policy](https://camo.githubusercontent.com/decd8b19034344bb486631a9d3501b663b199bf367c8a9eb2c43ad0df9be10b2/687474703a2f2f617a7572656465706c6f792e6e65742f6465706c6f79627574746f6e2e706e67)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/https://raw.githubusercontent.com/Azure/azure-policy/master/samples/WebApp/web-app-https-traffic-only/azurepolicy.json)


<!-- TOC ignore:true -->
### Azure Policy or ARM API used for evaluation

- ARM API to list APIMs and its related property at Subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service?
api-version=2019-12-01<br />
**Properties:**
sku

- ARM API to get tenant access information details without secrets:
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/tenant/access?
api-version=2019-12-01<br />
**Properties:**
enabled
___
