# Update default metadata (display name, recommendation, etc.) for existing controls

Using Org policy customization, we can change some basic default metadata for an existing control. Below is a walk-through example of how to do so leveraging the AzTS-Extended solution that you build using the steps mentioned [here](./SettingUpSolution.md).
<br/>
<br/>A typical setting you may want to modify is the display name of an existing control according to your org's needs. 
<br/>Let us change the display name of the "Azure_Subscription_AuthZ_Remove_Management_Certs" existing control from "Do not use management certificates" to "Management certificates are classic methods for automation on Azure subscription but are risky because the hygiene tends to be laxed and can easily be compromised.". 
This setting resides in a file called FeatureName.json. 
<br/>Because the first-time org policy setup does not customize anything from this, we will need to follow the following steps to modify the ASC assessments settings:
<br>

> Note: To edit policy JSON files, use a friendly JSON editor such as Visual Studio Code. It will save you lot of debugging time by telling you when objects are not well-formed (extra commas, missing curly-braces, etc.)! This is key because in a lot of policy customization tasks, you will be taking existing JSON objects and removing large parts of them (to only keep the things you want to modify).
<br>

## Steps:
0.  Initially, set up the organization-specific policy customizable AzTS Solution in your local systems by following the steps mentioned [here](./SettingUpSolution.md).
1.  Copy _FeatureNameExt.json_ file and rename it accordingly. For example: SubscriptionCoreExt.json
2.  Fill the parameters according to the feature. For example: 
    ``` JSON
    {
        "FeatureName": "SubscriptionCore"
    }
    ```
3.  Add the control json with all parameters given in template. The following meta-data are required for a control to be scanned:
    ``` JSON
    "Controls": [
        {
        // The following parameters can be taken from the FeatureName.json directly as there will no change in them for the scope of this scenario. 
        "ControlID": "Azure_Subscription_AuthZ_Remove_Management_Certs",
        "Id": "SubscriptionCore170",
        "Automated": "Yes",
        // Note that below we update the Display Name value to the one required according to the org's policy.
        "DisplayName": "Management certificates are classic methods for automation on Azure subscription but are risky because the hygiene tends to be laxed and can easily be compromised.",
        "MethodName": "", // This will be empty since the Control is ASC assessment based
        "Enabled": true
        }
    ]
    ```

    1. For **Id** above: 
        * Since we are modifying control settings for an existing control here, use the same ID as used previously from the FeatureName.json . 
    2. For **ControlID** above: Initial part of the control ID is pre-populated based on the service/feature and security domain you choose for the control (Azure_FeatureName_SecurityDomain_XXX). Please don't use spaces between words instead use underscore '_' to separate words in control ID. To see some of the examples of existing control IDs please check out this [list](https://github.com/azsk/AzTS-docs/tree/main/Control%20coverage#azure-services-supported-by-azts).
    3. Keep **Enabled** switch to 'Yes' to scan a control.
    4. **DisplayName** is the user friendly name for the control.
    5. For **MethodName** above: Use the same method name for this scenario as no change in the control logic is required.

    > *Note*:  You can provide additional details/optional settings for the control as listed below.

    |Settings| Description| Examples|
    |-------------|------|---------|
    |Automated| Whether the control is manual or automated| e.g. Yes/No (keep it Yes for policy based controls)|
    |Description| A basic description on what the control is about| e.g. App Service must only be accessible over HTTPS. |
    | Category| Generic security specification of the control.| e.g. Encrypt data in transit |
    |Tags| Labels that denote the control being of a specific type or belonging to a specific domain | For e.g. Baseline, Automated etc.|
    |Control Severity| The severity of the control| e.g. High: Should be remediated as soon as possible. Medium: Should be considered for remediation. Low: Remediation should be prioritized after high and medium.|
    |Control Requirements| Prerequisites for the control.| e.g. Monitoring and auditing must be enabled and correctly configured according to prescribed organizational guidance|
    |Rationale|  Logical intention for the added control | e.g. Auditing enables log collection of important system events pertinent to security. Regular monitoring of audit logs can help to detect any suspicious and malicious activity early and respond in a timely manner.|
    |Recommendations| Steps or guidance on how to remediate non-compliant resources | e.g. Refer https://azure.microsoft.com/en-in/documentation/articles/key-vault-get-started/ for configuring Key Vault and storing secrets |
    |Custom Tags| Tags can be used for filtering and referring controls in the future while reporting| e.g. Production, Phase2 etc. |
    |Control Settings| Settings specific to the control to be provided for the scan | e.g. Required TLS version for all App services in your tenant (Note: For policy based contols this should be empty) |
    |Comments | These comments show up in the changelog for the feature. | e.g. Added new policy based control for App Service |

4. Build and Run
   - Click on the AzTS_Extended as shown below to run the project: <br />
      ![Build Step 1](../../Images/06_OrgPolicy_Setup_BuildStep.png)<br/>
<!-- TODO Add the SubscriptionCore file EXT added log -->
   - Output looks like below:<br/>
      ![Run Output](../../Images/06_OrgPolicy_Setup_RunStep1.png)<br />
      ![Run Output](../../Images/06_OrgPolicy_Setup_RunStep2.png)
   Congratulations! Updating default metadata Scenario is complete with this step.

5. Verify the changes:
 You can verify your changes in the Log Analytics Workspace with the help of this [link](https://github.com/azsk/AzTS-docs/tree/main/01-Setup%20and%20getting%20started#4-log-analytics-visualization).
 <br/> Few simple queries are provided in the above link related to the inventory and Control Scan summary for reference.
