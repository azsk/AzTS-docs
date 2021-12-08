## Add new control based on custom Azure policy
Please follow the below mentioned steps to add new controls based on custom Azure Policy:

**Step 0:** Following prerequisites are required to add new control.
   1. This feature is not enabled by default. If you have not enabled this feature in your AzTS setup yet, please follow steps mentioned [here](Prerequisites.md#prerequisite-azts-configurations-to-add-new-control).

   2. CMET (Control metadata editor tool) is only accessible to privileged users based on AzTS API configurations. Please follow the steps mentioned [here](Prerequisites.md#access-to-cmet-control-metadata-editor-tool) to add yourself as privileged user (This is only required once per user).

**Step 1:** Assign the required policy definition to root management group of your tenant. To assign a policy definition, please follow the steps mentioned [here](https://docs.microsoft.com/en-us/azure/governance/policy/tutorials/create-and-manage#assign-a-policy).

**Step 2:** Get the ID of the policy definition and policy assignment. If you already have ID of policy definition and assignment handy, please go to step #3 directly or follow the below mentioned steps to get these details.

   1. Go to the Azure portal. Search for and select Policy.

      ![Search and select policy](../../Images/06_ExtendingAzTS_Search_Policy.PNG)

   2. Select Assignments on the left side of the Azure Policy page.

      ![Search and select assignment](../../Images/06_ExtendingAzTS_Search_Assignment.PNG)

   3. Change the Scope filter to required management group scope.

   4. Select the required assignment.

      ![Search and select assignment](../../Images/06_ExtendingAzTS_Select_Assignment.PNG)

   5. Copy the Assignment ID.

      ![copy assignment ID](../../Images/06_ExtendingAzTS_Get_AssignmentId.PNG)

   6. Click on View Definition.

      ![View Definition](../../Images/06_ExtendingAzTS_Select_View_Definition.PNG)

   7. Copy the Definition ID.

      ![Copy the Definition ID](../../Images/06_ExtendingAzTS_Get_PolicyDefinitionId.PNG)

**Step 3:** Go to **AzTS UI**. (To get AzTS UI URL, check this [FAQ](https://github.com/azsk/AzTS-docs/blob/main/03-Running%20AzTS%20solution%20from%20UI/README.md#frequently-asked-questions))

**Step 4:** Open **Control editor tool**.

![Open CMET Editor](../../Images/06_ExtendingAzTS_Open_CMET.png)

**Step 5:** Click on **Action** and select **Add new control** option.

![Open new control window](../../Images/06_ExtendingAzTS_Add_New_Control.png)

**Step 6:** Select the **Service/Feature** for which you want to add new control.
> **Note:** Currently addition of new controls is only supported for existing services evaluated by AzTS. 

![Select Feature Name](../../Images/06_ExtendingAzTS_NewControl_Feature.png)

**Step 7:** Select either one of the existing **Security Domain** for the control or if you want to add new Security Domain, type required domain in text field.

![Select Security Domain](../../Images/06_ExtendingAzTS_NewControl_Security_Domain.png)

**Step 8:** Provide the **Control ID**. Initial part of the control ID is pre-populated based on the service/feature and security domain you choose for the control (Azure_FeatureName_SecurityDomain_XXX).

> **Note:** Please don't use spaces between words instead use underscore '_' to separate words in control ID. 
To see some of the examples of existing control IDs please check out this [list](https://github.com/azsk/AzTS-docs/tree/main/Control%20coverage#azure-services-supported-by-azts).

![Provide ControlId](../../Images/06_ExtendingAzTS_NewControl_ControlId.png)

**Step 9:** Set control **Scan Source** to '**Policy**'.

![Set Scan source](../../Images/06_ExtendingAzTS_NewControl_Scan_Source.png)

**Step 10:** Provide **Display Name** which is a user friendly name for the control.

![Provide Display Name](../../Images/06_ExtendingAzTS_NewControl_DisplayName.png)

**Step 11:** Provide **Policy Assignment ID** of the assignment (Check step #2 on how to get policy assignment ID).

![Provide PolicyAssignment Id](../../Images/06_ExtendingAzTS_NewControl_PolicyAssignment_Id.png)

**Step 12:** Provide one or more **Policy Definition IDs** (Check step #2 on how to get policy definition ID).
    
> **Note:** To provide multiple definition IDs, hit enter after each definition ID.

![Provide PolicyDefinition Id](../../Images/06_ExtendingAzTS_NewControl_PolicyDefinition_Id.png)

**Step 13:** Select either one of the existing **Category** (generic security specification of the control) for the control or if none of the existing categories is relevant for the control, enter/type your required category in text field.

![Select Category](../../Images/06_ExtendingAzTS_NewControl_Category.png)

**Step 14:** Keep **Enabled** switch to '**Yes**'.

**Step 15:** Provide **Additional details/Optional settings** for the control:

|Settings| Description| Examples|
|-------------|------|---------|
|Automated| Whether the control is manual or automated| e.g. Yes/No (keep it Yes for policy based controls)|
|Description| A basic description on what the control is about| e.g. App Service must only be accessible over HTTPS. |
|Tags| Labels that denote the control being of a specific type or belonging to a specific domain | For e.g. Baseline, Automated etc.|
|Control Severity| The severity of the control| e.g. High: Should be remediated as soon as possible. Medium: Should be considered for remediation. Low: Remediation should be prioritized after high and medium.|
|Control Requirements| Prerequisites for the control.| e.g. Monitoring and auditing must be enabled and correctly configured according to prescribed organizational guidance|
|Rationale|  Logical intention for the added control | e.g. Auditing enables log collection of important system events pertinent to security. Regular monitoring of audit logs can help to detect any suspicious and malicious activity early and respond in a timely manner.|
|Recommendations| Steps or guidance on how to remediate non-compliant resources | e.g. Refer https://azure.microsoft.com/en-in/documentation/articles/key-vault-get-started/ for configuring Key Vault and storing secrets |
|Custom Tags| Tags can be used for filtering and referring controls in the future while reporting| e.g. Production, Phase2 etc. |
|Control Settings| Settings specific to the control to be provided for the scan | e.g. Required TLS version for all App services in your tenant (Note: For policy based contols this should be empty) |
|Comments | These comments show up in the changelog for the feature. | e.g. Added new policy based control for App Service |

**Step 16:** Click on **Add** button to save new control.

![Save new control](../../Images/06_ExtendingAzTS_NewControl_Save.png)

**Step 17:** Post control addition, you will get success message. Now you are good to **close** 'Add new control' window.

![New control success msg](../../Images/06_ExtendingAzTS_NewControl_Success.png)

**Step 18:** To **validate the control addition**, refresh the control metadata editor tool and search for newly added control. Control should be available now.

![Validate new control](../../Images/06_ExtendingAzTS_NewControl_Validation.png)

**Step 19:** As an **additional validation**, you can also trigger adhoc scan from AzTS UI for one or more subscriptions and check the control scan results for newly added control. To get information on how to trigger adhoc scan, you can refer to this [link](https://github.com/azsk/AzTS-docs/tree/main/03-Running%20AzTS%20solution%20from%20UI#how-to-scan-subscription-manually).

> **Note:** For custom **Policy** based control, please do provide Self-guiding steps in control **Recommendation** field that would be used by users across your organization to fix non-compliant resources.

-----
