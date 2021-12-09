# Customizing specific controls for an existing service

Using Org policy customization, we can make a slightly more involved change in the context of a specific service (Storage).

Imagine that you want to turn off the evaluation of some control altogether (regardless of whether people filter using the Baseline tags or not). Also, for another control, you want people to use a recommendation which leverages an internal tool the security team in your org has developed. Let us do this for the Storage.json file. Specifically, we will:

1. Turn off the evaluation of Azure_Storage_Audit_Issue_Alert_AuthN_Req altogether.
2. Modify severity of Azure_Storage_AuthN_Dont_Allow_Anonymous to Critical for our org (it is High by default).
3. Change the recommendation for people in our org to follow if they need to address an issue with the Azure_Storage_DP_Encrypt_In_Transit control.

Below is a walk-through example of how to do so leveraging the AzTS-Extended solution that you build using the steps mentioned [here](./SettingUpSolution.md).

<br/>Because the first-time org policy setup does not customize anything from this, we will need to follow the following steps to modify the Control Evaluator:

### Steps:
0.  Initially, set up the organization-specific policy customizable AzTS Solution in your local systems by following the steps mentioned [here](./SettingUpSolution.md).
1.  Copy _FeatureNameExt.json_ file and rename it accordingly. For example: StorageExt.json
2.  Fill the parameters according to the feature. For example: 
    ``` JSON
    {
        "FeatureName": "Storage",
        "Reference": "aka.ms/azsktcp/storage", // you can find this from the FeatureName.json as well
        "IsMaintenanceMode": false,
    }
    ```
3.  Add the control json with all parameters given in template. The following meta-data are required for a control to be scanned:
    ``` JSON
    "Controls": [
        {
        // The following parameters can be taken from the FeatureName.json directly as there will no change in them for the scope of this scenario. 
        "ControlID": "Azure_Storage_NetSec_Restrict_Network_Access",
        "Id": "AzureStorage260",
        "Automated": "Yes",
        "MethodName": "CheckStorageNetworkAccess",
        "Enabled": true,
        "DisplayName": "Ensure that Firewall and Virtual Network access is granted to a minimal set of trusted origins"
        }
    ]
    ```

    1. For **Id** above: 
        * Since we are modifying control settings for an existing control here, use the same ID as used previously from the FeatureName.json . 
    2. For **ControlID** above: Initial part of the control ID is pre-populated based on the service/feature and security domain you choose for the control (Azure_FeatureName_SecurityDomain_XXX). Please don't use spaces between words instead use underscore '_' to separate words in control ID. To see some of the examples of existing control IDs please check out this [list](https://github.com/azsk/AzTS-docs/tree/main/Control%20coverage#azure-services-supported-by-azts).
    3. Keep **Enabled** switch to 'Yes' to scan a control.
    4. **DisplayName** is the user friendly name for the control. It does not necessarily needed to be modified.
    5. For **MethodName** above: You can customize the MethodName here. Just make sure to use the same method name in the Control Evaluator in the next steps.

For this example, make changes to the properties of the respective controls so that the final JSON looks like the below:
``` JSON
{
    "Controls": [
        {
            // The following parameters can be taken from the FeatureName.json directly as there will no change in them for the scope of this scenario. 
            "ControlID": "Azure_Storage_AuthN_Dont_Allow_Anonymous",
            "Id": "AzureStorage110",
            "Automated": "Yes",
            "MethodName": "CheckStorageContainerPublicAccessTurnOff",
            "Enabled": true,
            "DisplayName": "Ensure secure access to storage account containers.",

            // Modifying severity to Critical for your org (it is High by default)
            "ControlSeverity": "Critical"
        },
        {
            // The following parameters can be taken from the FeatureName.json directly as there will no change in them for the scope of this scenario. 
            "ControlID": "Azure_Storage_Audit_Issue_Alert_AuthN_Req",
            "Id": "AzureStorage120",
            "Automated": "Yes",
            "MethodName": "CheckStorageMetricAlert",
            "DisplayName": "Alert rules must be configured for tracking anonymous activity",

            // Turning off the evaluation of Azure_Storage_Audit_Issue_Alert_AuthN_Req altogether
            "Enabled": false
        },
        {
            // The following parameters can be taken from the FeatureName.json directly as there will no change in them for the scope of this scenario. 
            "ControlID": "Azure_Storage_DP_Encrypt_In_Transit",
            "Id": "AzureStorage160",
            "Automated": "Yes",
            "MethodName": "CheckStorageEncryptionInTransit",
            "Enabled": true,
            "DisplayName": "Enable Secure transfer to storage accounts",

            // Change the recommendation for people in your org to follow which leverages an internal tool the security team in your org has developed
            "Recommendation": "**Note**: Use our Contoso-IT-EncryptInTransit.ps1 tool for this!"
        }
    ]
}
```

4. Build and Run
   - Click on the AzTS_Extended as shown below to run the project: <br />
      ![Build Step 1](../../Images/06_OrgPolicy_Setup_BuildStep.png)<br/>
<!-- TODO Add the SubscriptionCore file EXT added log -->
   - Output looks like below:<br/>
      ![Run Output](../../Images/06_OrgPolicy_Setup_RunStep1.png)<br />
      ![Run Output](../../Images/06_OrgPolicy_Setup_RunStep2.png)
   Congratulations! Customizing the Specific controls of an existing service scenario is complete with this step.

5. Verify the changes:
 You can verify your changes in the Log Analytics Workspace with the help of this [link](https://github.com/azsk/AzTS-docs/tree/main/01-Setup%20and%20getting%20started#4-log-analytics-visualization).
 <br/> Few simple queries are provided in the above link related to the inventory and Control Scan summary for reference.
