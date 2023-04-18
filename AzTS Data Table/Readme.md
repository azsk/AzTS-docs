# AzTS Data Table


## **Overview**

Azure Tenant Security Solution centrally scans subscriptions and gets control scan results, processed RBAC data, resource inventory data, subscription metadata, etc., and pushes all the data into a blob storage of a central storage account.

## **AzTS Data Table details**

|Table Name|Description|
|--|--|
|[RBAC ](Readme.md#rbac)|Role-Based Access Control (RBAC) contains all PIM, permanent, and classic role assignment details.|
|[Baseline controls](Readme.md#baseline-control)|Baseline controls contains a list of all controls (both baseline & non-baseline) supported by Azure Tenant Security (AzTS).|
|[Control result](Readme.md#control-result)|Control result contains evaluated control scan result with appropriate status reason.|
|[Resource Inventory](Readme.md#resource-inventory)|Resource Inventory contains details of all resources present in the subscription. It includes resource name, resource id, resource type, resource group name etc.|
|[Subscription metadata](Readme.md#subscription-metadata)|Subscription metadata contains each subscription details like subscription id, tenant id, state, etc.|
|[Assessment details](Readme.md#assessment-Details)|Assessment details contains the evaluated assessment details with the appropriate status reason.|
|[Policy state](Readme.md#policy-state)|Policy state contains the evaluated Policy State details with the assigned scope and its state.|
|[Role definition](Readme.md#role-definition)|Role definition Details contains both custom and built-in roles information along with the assigned scope.|
|[Secure score control](Readme.md#secure-score-control)|Secure score control contains the secure score evaluated control details with the current score and healthy and unhealthy resource count.|
|[Secure score](Readme.md#secure-score)|Secure score contains the evaluated secure score details current and maximum score.|
___

### **RBAC**

|Field Name|Field Type|Description|Sample Value|
|--|--|--|--|
|JobId|int|Job ID for the scan (YYYYMMDD).|20230414|
|RoleName|string|The role assignment name.|Reader|
|RoleId|string|The role assignment ID.|xx0x0xx0-0xx0-0000-0x00-000x0x00000x|
|AccountType|string|The role assignment account type.|ServicePrincipal|
|UserName|string|The role assignment user name.|xx0000x0-00x0-000x-000x-x0x00x00xxxx|
|UserNameMApped|string|User name mapped to role assignment user name.|xx0000x0-00x0-000x-000x-x0x00x00xxxx|
|PrincipalName|string|The principal name.|user_alias@microsoft.com|
|UserMail|string|The mail of user.|user_alias@microsoft.com|
|DisplayName|string|The role assignment name.|Username|
|Scope|string|The role assignment scope.|/providers/Microsoft.Management/managementGroups/00000xxx-xx00-0x00-x0x0-00xx00000x00|
|NameId|string|The subscription ID of role assignment.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|RBACSource|string|Scope of role assignment.|subscription|
|RoleDefinitionId|string|Role definition ID.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00/providers/Microsoft.Authorization/roleDefinitions/Role_Def_Id|
|IsPIMEligible|bool|Indicates whether role assignment is of type PIM.|false|
|RBACAPISource|string|Indicates source of the RBAC API.|ARMAPI|
|IsInherited|bool|Indicates whether the role assignment is inherited or assigned at the current scope.|false|
|CustomField1|string|This field contains custom data.|This field contains custom data.|
|CustomField2|string|This field contains custom data.|This field contains custom data.|
|CustomField3|string|This field contains custom data.|This field contains custom data.|
|CustomField4|string|This field contains custom data.|This field contains custom data.|
|CustomField5|string|This field contains custom data.|This field contains custom data.|
___

### **Baseline control**

|Field Name|Field Type|Description|Sample Value|
|--|--|--|--|
|OrgTenantId|string|The tenant ID.|null|
|JobId|int|Job ID for the scan (YYYYMMDD).|20230414|
|ControlId|string|The control ID.|Azure_Storage_DP_Encrypt_In_Transit|
|Description|string|A basic description of what the control is about.|HTTPS protocol must be used for accessing Storage Account resources|
|Id|string|The control short ID.|AzureStorage160|
|DisplayName|string|The control name.|Enable Secure transfer to storage accounts|
|Category|string|Generic security specification of the control.|Encrypt data in transit|
|ControlRequirements|string|Pre-requisites of the control.|Data must be encrypted in transit and at rest|
|AssessmentName|string|Assessment name associated with the control.|00x0x00x-x000-0xxx-x0x0-000x000x00x0|
|PolicyDefinitionId|string|Definition id of the policy associated with the control.|/providers/Microsoft.Authorization/policyDefinitions/000x0000-x000-0000-xx00-00x00xx000x0|
|ControlSeverity|string|The severity of the control.|Critical|
|FeatureName|string|Type of feature this control belongs to.|Storage|
|ControlSettings|string|Settings specific to the control to be provided for the scan.|{"ApplicableOsTypes": ["Windows"]}|
|Tags|string|Labels that denote the control to be of a specific type and belongs to a specific domain.|["Baseline", "SDL", "TCP", "Automated"]|
|Enabled|bool|Field to indicate whether the control is enabled or disabled.|true|
|PolicyDefinitionGuid|string|The policy definition guide.|0x0xxx00-x0x0-000x-xx0x-0000x0000000|
|ResourceType|string|The type of resources this control scans.|"Microsoft.Storage/storageAccounts"|
|Remediation|string|Steps to remediate control.|For remediation using PowerShell commands, run the command: 'Set-AzStorageAccount -ResourceGroupName <RGName> -Name <StorageAccountName> -EnableHttpsTrafficOnly $true'. Run 'Get-Help Set-AzStorageAccount -full' for more help.|
|ControlScanSource|string|The control scan source.|Reader|
|AssessmentProperties|string|The assessment properties.|{"AssessmentNames": ["000000xx-0xxx-0x00-0x00-00x00x0000x0"]}|
|CustomPolicyProperties|string|The custom policy properties.|{"PolicyDefinitionIds": ["/providers/Microsoft.Authorization/policyDefinitions/000xx000-xx0x-0000-00dd-000000xx000x"]}|
|Automated|string|Whether the control is manual or automated.|Yes|

___

### **Control result**

|Field Name|Field Type|Description|Sample Value|
|--|--|--|--|
|JobId|int|JobID for scan (YYYYMMDD).|20230414|
|subscriptionid|string|The subscription ID.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|ResourceGroupName|string|The resource group name.|TestRG|
|ResourceName|string|The resource name.|storageaccount|
|ResourceType|string|The resource type.|Microsoft.Storage/storageAccounts|
|ResourceId|string|The resource ID.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00/resourceGroups/sampleresourcegroup/providersMicrosoft.Storage/storageAccounts/resourcename|
|ControlName|string|The control name.|Azure_Storage_DP_Encrypt_In_Transit|
|VerificationResult|string|It indicates control status.|Passed|
|ScannedOn|datetime|Control scanned date and time.|Fr, 14 Apr 2023 08:39:24 GMT|
|StatusReason|string|Reason associated with control status.|Secure transfer is enabled for the storage account.|
|ScannedBy|string|Scanned by.|null|
|ScanSource|string|The scan source of control.|Reader|
|AssessmentName|string|Name of the assessment evaluated by control.|00x0x00x-x000-0xxx-x0x0-000x000x00x0|
|CustomField1|string|This field contains custom data.|This field contains custom data.|
|CustomField2|string|This field contains custom data.|This field contains custom data.|
|CustomField3|string|This field contains custom data.|This field contains custom data.|
|CustomField4|string|This field contains custom data.|This field contains custom data.|
|CustomField5|string|This field contains custom data.|This field contains custom data.|
|ConsiderForCompliance|bool|Indicates whether consider this control for compliance.|true|
|ActualVerificationResult|string|Control status after checking for any exception raised.|Passed|
|Justification|string|The control justification.|Justification message|
|OnException|bool|It indicates whether the control is granted an exception or not.|true|
|FirstScannedOn|datetime|Control first scan date and time.|2020-11-10T15:44:39|
|FirstFailedOn|datetime|Control first Failed date and time.|2020-11-9T15:44:39|
|LastResultTransitionOn|datetime|Control status last changed date and time.|2020-11-9T15:44:39|
|ExceptionDetails|string|Details related to exception if exception is raised.|{"ExceptionExpiryDate":"2023-09-29T00:00:00", "ExceptionGrantedOn":"2022-11-11T04:03:20.5833333", "RequestedById": "xxxxxxx@microsoft.com"}|
|DueDate|datetime|Due date.|2023-05-06T07:57:45.9650292|
|AssignedTo|string|Assigned to.|null|
|UniqueId|string|Unique ID associated with the control scan.|0x0xx0x0xx0x0000x0xx000000000x0|
|AdditionalInformation|string|Additional information associated with the control scan which is helpful in remediation.|{"Stale identities": [{"RoleName": "Reader", "PrincipalName": "identity not found or stale account", "Scope": "/subscriptions/xxx0000x-00x0-00x0-000x-00xxxxx000x0", "UserName": "xxx0000x-00x0-00x0-000x-00xxxxx000x0", "IdentityType": "ServicePrincipal", "AssignmentType": "Permanent"}]}|

___

### **Resource Inventory**

|Field Name|Field Type|Description|Sample Value|
|--|--|--|--|
|JobId|int|Job ID for the scan (YYYYMMDD).|20230414|
|Name|string|The resource name.|test|
|ResourceId|string|The resource ID.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00/resourceGroups/RG_Name/providers/Microsoft.Storage/storageAccounts/Resource_Name|
|ResourceType|string|The resource provider type.|Microsoft.Storage/storageAccounts|
|Location|string|The resource location.|EastUS|
|ResourceGroup|string|The resource group name.|RG name|
|Kind|string|The type of resource.|app|
|ProvisioningState|string|The resource current state.|Succeeded|
|CreatedTime|datetime|Resource creation time.|2023-03-14T09:25:13.8285199Z|
|ChangedTime|datetime|Resouce last changed date and time.|2023-03-14T09:25:13.8285199Z|
|Subscriptionid|string|The subscription ID.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|OrgTenantId|string|The tenant ID.|00x000xx-00x0-00xx-00xx-0x0xx000xx00|
|CustomField1|string|This field contains custom data.|This field contains custom data.|
|CustomField2|string|This field contains custom data.|This field contains custom data.|
|CustomField3|string|This field contains custom data.|This field contains custom data.|
|CustomField4|string|This field contains custom data.|This field contains custom data.|
|CustomField5|string|This field contains custom data.|This field contains custom data.|
|Tags|string|Tags associated with the resource.|{"cognitive": "storage"}|

___

### **Subscription metadata**

|Field Name|Field Type|Description|Sample value|
|--|--|--|--|
|subscriptionid|string|The subscription ID.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|Timestamp|datetime|The subscription metadata fetched time.|Fr, 14 Apr 2023 08:39:24 GMT|
|JobId|int|Job ID for the scan (YYYYMMDD).|20230414|
|SubscriptionName|string|The subscription display name.|Microsoft Azure Test|
|OrgTenantId|string|The subscription tenant ID.|00x000xx-00x0-00xx-00xx-0x0xx000xx00|
|RetryCount|int|Number of retries count to fetch subscription details.|0|
|Tags|string|Tags attached to the subscription.|{"Env": "Prod"}|
|State|string|The subscription state.|Enabled|
|PIMResourceId|string|PIM resource ID of the subscription.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|CreatedDate|datetime|Subscription creatio date and time.|2020-11-11T13:38:39|Subscription creation date.|
|StateUpdatedOn|datetime|Last date and time on which subscription state is updated.|2021-07-15T12:34:47|
|IsBillingInfoAvailable|bool|Indicates whether subscription billing information is available or not.|true|
|MaxBillingDate|datetime|Subscription billing date and time.|2023-04-03T00:00:00|
|SubscriptionOfferType|string|The subscription offer type.|null|
|SubscriptionExpiryDate|datime|Subscription expiry date and time.|2025-04-03T00:00:00|
|CustomField1|string|This field contains custom data.|This field contains custom data.|
|CustomField2|string|This field contains custom data.|This field contains custom data.|
|CustomField3|string|This field contains custom data.|This field contains custom data.|
|CustomField4|string|This field contains custom data.|This field contains custom data.|
|CustomField5|string|This field contains custom data.|This field contains custom data.|
|ResourceId|string|The subscription fully qualified ID.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00|
___

### **Assessment**

|Field Name|Field Type|Description|Sample value|
|--|--|--|--|
|JobId|int|Job ID for the scan (YYYYMMDD).|20230414|
|SubscriptionId|string|The subscription ID.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|AssessmentName|string|The assessment name.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|AssessmentId|string|The assessment ID.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00/providers/Microsoft.Security/assessments/00000xxx-xx00-0x00-x0x0-00xx00000x00|
|AzureResourceId|string|Azure resource Id of the assessed resource.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00|
|RecommendationDisplayName|string|The recommendation display name.|MFA should be enabled on accounts with read permissions on subscriptions|
|StatusCode|string|Programmatic code for the status of the assessment.|Healthy|
|StatusMessage|string|The assessment status message.|{"code": "Healthy"}|
|AdditionalData|string|The assessment additional data.|{"usersWithNoMfaObjectIdList": "[]"}|

___

### **Policy state**

|Field Name|Field Type|Description|Sample value|
|--|--|--|--|
|JobId|int|Job ID for the scan (YYYYMMDD).|20230414|
|PolicyDefinitionAction|string|Policy definition action, i.e. effect.|deployifnotexists|
|PolicyAssignmentScope|string|The policy assignment scope.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00|
|PolicyAssignmentId|string|The policy assignment ID.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00/providers/microsoft.authorization/policyassignments/PolicyAssignmentName|
|PolicyDefinitionId|string|The policy assignment name.|/providers/microsoft.authorization/policydefinitions/00000xxx-xx00-0x00-x0x0-00xx00000x00|
|PolicyDefinitionName|string|The policy definition name.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|PolicySetDefinitionId|string|Policy set definition ID, if the policy assignment is for a policy set.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00/providers/Microsoft.Authorization/policySetDefinitions/00000xxxxx000x00x0x000xx|
|PolicySetDefinitionName|string|Policy set definition name, if the policy assignment is for a policy set.|00000xxxxx000x00x0x000xx|
|ComplianceState|string|Compliance state of the resource.|Compliant|
|OrgTenantId|string|The tenant ID.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|subscriptionid|string|The subscription ID.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|ResourceLocation|string|The resource location.|eastus|
|ResourceGroup|string|The resource group name.|sampleresourcegroup|
|ResourceType|string|The resource type.|Microsoft.Compute/virtualMachines|
|ResourceId|string|The resource ID.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00/resourcegroups/sampleresourcegroup/providers/microsoft.compute/virtualmachines/sampleresource|
|StateWeight|int|The weight of policy state.|200|
|TimeStamp|datetime|Timestamp for the policy state record.|4/10/2023 3:31:14 AM|
|ManagementGroupIds|string|Comma-separated list of management group IDs,  which represent the hierarchy of the management groups the resource is under.|00000xxx-xx00-0x00-x0x0-00xx00000x00, 00000xxx-xx00-0x00-x0x0-00xx00000x00|
|PolicyAssignmentParameters|string|The policy assignment parameters.|null|
|PolicyDefinitionReferenceId|string|Reference ID for the policy definition inside the policy set, if the policy assignment is for a policy set.|null|
|PolicyStateId|string|The policy state ID.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00/resourcegroups/sampleresourcegroup/providers/microsoft.compute/virtualmachines/sampleresource/providers/microsoft.policyinsights/policystates/00000xxxxx000x00x0x000xx00000xxxxx000x00x0x000xx00000xxxxx000x00x0x000xx|


___

### **Role definition**

|Field Name|Field Type|Description|Sample value|
|--|--|--|--|
|JobId|int|Job ID for the scan (YYYYMMDD).|20230414|
|RoleName|string|The role definition name.|reader|
|Type|string|The role definition type.|CustomRole|
|Description|string|A basic description of the role and its permissions.|Lets you view everything, but not make any changes|
|AssignableScopes|string|The role definition assignable scopes.|["/"]|
|Permissions|string|The role definition permissions.|[{"actions": ["*/read"], "notActions": [], "dataActions": [], "notDataActions": []}]|
|CreatedOn|datetime|Date and time of creation.|14/04/2023 23:38:05|
|UpdatedOn|datetime|Date and time of the last update.|14/04/2023 23:38:05|
|CreatedBy|string|ID of the user who created the role definition.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|UpdatedBy|string|ID of the user who updated the role definition.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|Id|string|The role definition ID.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00/providers/Microsoft.Authorization/roleDefinitions/00000xxx-xx00-0x00-x0x0-00xx00000x00|
|RoleDefinitionName|string|The role definition name.|00000xxx-xx00-0x00-x0x0-00xx00000x00|

___

### **Secure score control**

|Field Name|Field Type|Description|Sample value|
|--|--|--|--|
|OrgTenantId|string|The tenant ID.|00x000xx-00x0-00xx-00xx-0x0xx000xx00|
|subscriptionid|string|The subscription ID.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|Id|string|The resource Id.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00/providers/Microsoft.Security/secureScores/ascScore/secureScoreControls/00000xxx-xx00-0x00-x0x0-00xx00000x00|
|Name|string|The resource name.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|DisplayName|string|User friendly display name of the control.|Restrict unauthorized network access|
|Weight|int|Relative weight for this specific control in each of your subscriptions. Used when calculating an aggregated score for this control across all of your subscriptions.|0|
|Type|string|The control type.|microsoft.security/securescores/securescorecontrols|
|CurrentScore|double|The current score.|0.0|
|PercentageScore|double|Ratio of the current score divided by the maximum. Rounded to 4 digits after the decimal point.|0.0|
|MaxScore|string|The maximum score available.|0|
|NotApplicableResourceCount|string|Number of not applicable resources in the control.|3|
|UnhealthyResourceCount|int|Number of unhealthy resources in the control.|0|
|HealthyResourceCount|int|Number of healthy resources in the control.|0|
|SourceType|string|The type of security control.|BuiltIn|
|AssessmentDefinitions|string|Array of assessments metadata IDs that are included in this security control.|["/providers/Microsoft.Security/assessmentMetadata/00000xxx-xx00-0x00-x0x0-00xx00000x00", "/providers/Microsoft.Security/assessmentMetadata/00000xxx-xx00-0x00-x0x0-00xx00000x00"]|
|JobId|int|Job ID for the scan (YYYYMMDD).|20230414|
|TotalResourceCount|int|The total number of resources in the control.|3|

___

### **Secure score**

|Field Name|Field Type|Description|Sample value|
|--|--|--|--|
|OrgTenantId|string|The tenant ID.|00x000xx-00x0-00xx-00xx-0x0xx000xx00|
|subscriptionid|string|The subscription ID.|00000xxx-xx00-0x00-x0x0-00xx00000x00|
|Id|string|The resource ID.|/subscriptions/00000xxx-xx00-0x00-x0x0-00xx00000x00/providers/Microsoft.Security/secureScores/ascScore|
|Name|string|The resource name.|ascScore|
|DisplayName|string|The initiative’s name.|ascScore|
|Weight|int|Relative weight for each subscription. Used when calculating an aggregated secure score for multiple subscriptions.|35|
|Type|string|The resource type.|microsoft.security/securescores/securescorecontrols|
|CurrentScore|double|The current score.|10.0|
|PercentageScore|double|Ratio of the current score divided by the maximum. Rounded to 4 digits after the decimal point.|10.0|
|MaxScore|string|The maximum score available.|10|
|JobId|int|Job ID for the scan (YYYYMMDD).|20230414|

___