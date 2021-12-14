# Storage

## Resource Type
Microsoft.Storage/storageAccounts

## Reference
Refer to [this document](https://github.com/azsk/AzTS-docs/blob/main/Control%20coverage/Feature/Storage.md) for meta-data and evaluation logic of the existing controls of Storage service. 

Certain Azure Policy or ARM APIs are used for evaluation. You can find below the mapping between the properties fetched from ARM APIs and the property name that can be used in the control evaluation while modifying/creating methods in FeatureNameEvaluatorExt class in the FeatureNameControlEvaluatorExt.cs. The properties fetched from ARM APIs are stored in JObject under the name CustomFields. There can be multiple CustomFields such as CustomFields1, CustomFields2, etc with different types of properties. The below mapping will guide you to write the control methods while extending the controls.

## Properties

**Storage.CustomField1:**

| Property Name | API Property | Type |
|---|---|---|
| HttpsEnabled | properties.supportsHttpsTrafficOnly | bool |
| Kind |kind|string|
|ProvisioningState|properties.provisioningState|string|
|AllowBlobPublicAccess|properties.allowBlobPublicAccess|bool|
|NetworkRuleSet|properties.networkAcls.defaultAction|string|

## Example

``` CS
public class StorageControlEvaluator : BaseControlEvaluator
{
    public void CheckStorageNetworkAccess(Resource storage, ControlResult cr)
    {
        // We first check if CustomField1 is not NULL or empty
        if (!string.IsNullOrEmpty(storage.CustomField1))
        {

            cr.VerificationResult = VerificationResultStatus.Failed;

            // CustomField1 has details about which protocol is supported by Storage for traffic
            // Loading the JObject from a string that contains JSON.
            var stgDetails = JObject.Parse(storage.CustomField1);
            // Note how we use the property NetworkRuleSet here from the extracted JObject stgDetails.
            string strNetworkRuleSet = stgDetails["NetworkRuleSet"].Value<string>();

            if (strNetworkRuleSet.Equals("Deny", StringComparison.OrdinalIgnoreCase))
            {
                cr.StatusReason = $"Firewall and Virtual Network restrictions are defined for this storage";
                cr.VerificationResult = VerificationResultStatus.Passed;
            }
            else
            {
                cr.StatusReason = $"No Firewall and Virtual Network restrictions are defined for this storage";
                cr.VerificationResult = VerificationResultStatus.Failed;
            }
        }

        // 'Else' block not required since CustomField1 is never expected to be null
    }
    .
    .
    .
}
```
