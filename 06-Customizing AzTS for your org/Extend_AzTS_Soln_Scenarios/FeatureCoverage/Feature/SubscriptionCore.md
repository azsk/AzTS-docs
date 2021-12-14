# Subscription

## Resource Type
SubscriptionCore

## Reference
Refer to [this document](https://github.com/azsk/AzTS-docs/blob/main/Control%20coverage/Feature/SubscriptionCore.md) for meta-data and evaluation logic of the existing controls of Subscription service. 

Certain Azure Policy or ARM APIs are used for evaluation. You can find below the mapping between the properties fetched from ARM APIs and the property name that can be used in the control evaluation while modifying/creating methods in FeatureNameEvaluatorExt class in the FeatureNameControlEvaluatorExt.cs. The properties fetched from ARM APIs are stored in JObject under the name CustomFields. There can be multiple CustomFields such as CustomFields1, CustomFields2, etc with different types of properties. The below mapping will guide you to write the control methods while extending the controls.

## Properties

**Subscription.CustomField2:**

| Property Name | API Property | Type |
|---|---|---|
| autoProvision | properties.autoProvision | string |
|pricingTier|properties.pricingTier|string|

**Subscription.CustomField3:**

| Property Name | API Property | Type |
|---|---|---|


**Subscription.CustomField4:**

| Property Name | API Property | Type |
|---|---|---|


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
```
