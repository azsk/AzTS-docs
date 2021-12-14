# AppService

## Resource Type
Microsoft.Web/sites

## Reference
Refer to [this document](https://github.com/azsk/AzTS-docs/blob/main/Control%20coverage/Feature/AppService.md) for meta-data and evaluation logic of the existing controls of AppService service. 

Certain Azure Policy or ARM APIs are used for evaluation. You can find below the mapping between the properties fetched from ARM APIs and the property name that can be used in the control evaluation while modifying/creating methods in FeatureNameEvaluatorExt class in the FeatureNameControlEvaluatorExt.cs. The properties fetched from ARM APIs are stored in JObject under the name CustomFields. There can be multiple CustomFields such as CustomFields1, CustomFields2, etc with different types of properties. The below mapping will guide you to write the control methods while extending the controls.

## Properties

**appService.CustomField1:**

| Property Name | API Property | Type |
|---|---|---|
|HostNames|properties.hostNames|List<string>|
|HostNameSslStates|properties.hostNameSslStates|string|
|AppServicePlan.SkuDescription.Capacity|properties.AppServicePlan.SkuDescription.Capacity|int|
|AppServicePlan.Name|properties.AppServicePlan.Name|string|
|HttpsEnabled|properties.httpsOnly|bool|
|ManagedServiceIdentityType|properties.identity.type|string|

**appService.CustomField2:**

| Property Name | API Property | Type |
|---|---|---|
| RemoteDebuggingEnabled | properties.RemoteDebuggingEnabled | bool |
|WebSocketEnabled |properties.webSocketsEnabled|bool|
|AlwaysOn|properties.alwaysOn|bool|
|HttpLoggingEnabled|properties.httpLoggingEnabled|bool|
|DetailedErrorLoggingEnabled|properties.detailedErrorLoggingEnabled|bool|
|RequestTracingEnabled|properties.requestTracingEnabled|bool|
|Cors|properties.cors|CorsSettings Model|
|MinTLSVersion|properties.minTlsVersion|string|
|IpSecurityRestrictions|properties.ipSecurityRestrictions|List(IpRule) where IpRule is defined model|
|ScmIpSecurityRestrictions|properties.scmIpSecurityRestrictions|List(IpRule) where IpRule is defined mode|
|ScmIpSecurityRestrictionsUseMain|properties.scmIpSecurityRestrictionsUseMain|bool|

**appService.CustomField4:**
AppSvc.CF4 contains all the deployment slots
It can be accessed using the following:
``` CS
List<AppServiceSlot> deploymentSlots = JsonConvert.DeserializeObject<List<AppServiceSlot>>(appService.CustomField4);
```
<!-- 
## Example

``` CS
public ControlResult CheckAutoProvisioningForSecurity(ControlResult cr)
{
    // We first check if CustomField1 is not NULL or empty
    if (!string.IsNullOrWhiteSpace(this.Subscription.CustomField2)) //// CF2 contains security center details
    {
        // Notice how we deserializes the JSON to the specified model i.e. SecurityCenterModel    
        var securityCenterDetails = JsonConvert.DeserializeObject<SecurityCenterModel>(this.Subscription.CustomField2);

        if (!securityCenterDetails.IsProviderRegistered)
        {
            cr.VerificationResult = VerificationResultStatus.Failed;
            cr.StatusReason = "Security center provider not registered.";
            return cr;
        }

        cr.VerificationResult = VerificationResultStatus.Failed;
        cr.StatusReason = $"Auto Provisioning setting is disabled for subscription. Provisioning Status:[{securityCenterDetails.AutoProvision}]";

        if (securityCenterDetails.AutoProvision.Equals("on", StringComparison.OrdinalIgnoreCase))
        {
            cr.VerificationResult = VerificationResultStatus.Passed;
            cr.StatusReason = $"Auto Provisioning setting is enabled for subscription.";
        }
    }

    return cr;
}
    .
    .
    .
}
``` -->
