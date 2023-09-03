# SubscriptionCore

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_Subscription_AuthZ_Remove_Deprecated_Accounts](#Azure_Subscription_AuthZ_Remove_Deprecated_Accounts)
- [Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities](#Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities)
- [Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities_Privileged_Roles](#Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities_Privileged_Roles)
- [Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count](#Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count)
- [Azure_Subscription_AuthZ_Remove_Management_Certs - <b>DEPRECATED!!!</b>](#Azure_Subscription_AuthZ_Remove_Management_Certs)
- [Azure_Subscription_Audit_Resolve_MDC_Alerts](#azure_subscription_audit_resolve_mdc_alerts)
- [Azure_Subscription_AuthZ_Custom_RBAC_Roles](#Azure_Subscription_AuthZ_Custom_RBAC_Roles)
- [Azure_Subscription_SI_Classic_Resources](#Azure_Subscription_SI_Classic_Resources)
- [Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access](#Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access)
- [Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG](#Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG)
- [Azure_Subscription_Config_Add_Required_Tags](#Azure_Subscription_Config_Add_Required_Tags)
- [Azure_Subscription_Config_MDC_Defender_Plans](#Azure_Subscription_Config_MDC_Defender_Plans)
- [Azure_Subscription_Use_Only_Alt_Credentials](#Azure_Subscription_Use_Only_Alt_Credentials)
- [Azure_Subscription_Config_MDC_Enable_AutoProvisioning](#Azure_Subscription_Config_MDC_Enable_AutoProvisioning)
- [Azure_Subscription_Config_MDC_Setup_SecurityContacts](#Azure_Subscription_Config_MDC_Setup_SecurityContacts)
- [Azure_Subscription_SI_No_Billing_Activity](#Azure_Subscription_SI_No_Billing_Activity)
- [Azure_Subscription_Configure_Conditional_Access_for_PIM](#Azure_Subscription_Configure_Conditional_Access_for_PIM)
- [Azure_Subscription_AuthZ_Limit_Admin_Owner_Count](#Azure_Subscription_AuthZ_Limit_Admin_Owner_Count)
- [Azure_Subscription_SI_Dont_Use_B2C_Tenant](#azure_subscription_si_dont_use_b2c_tenant)
- [Azure_Subscription_Identity_Rotate_SPN_Credentials](#Azure_Subscription_Identity_Rotate_SPN_Credentials)
- [Azure_Subscription_AuthZ_SPN_Owners_Governance](#Azure_Subscription_AuthZ_SPN_Owners_Governance)

<!-- /TOC -->
<br/>

___ 

## Azure_Subscription_AuthZ_Remove_Deprecated_Accounts 

### Display Name 
Remove Orphaned accounts from your subscription(s) 

### Rationale 
Deprecated accounts are ones that were once deployed to your subscription for some trial/pilot initiative (or some other purpose). These are not required any more and are a standing risk if present in any role on the subscription. 

### Control Settings 
```json 
{
    "DeprecatedAccounts": ""
}
 ```  

### Control Spec 

> **Passed:** 
> No deprecated account is found at subscription scope (in both MDC and Reader scan).
> 
> **Failed:** 
> Deprecated account is found at subscription scope (in any one of MDC and Reader scan).
> 
> **Verify:** 
> MDC assessment status is not applicable or policy is missing.

### Recommendation 

- **Azure Portal** 

	 Steps to remove role assignments of deprecated/invalid accounts are:  <br />a. To remove permanent role assignment use command 'Remove-AzRoleAssignment' or refer link, https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-remove#azure-portal <br />b. To remove classic role assignments, refer link: https://docs.microsoft.com/en-us/azure/role-based-access-control/classic-administrators#remove-a-co-administrator <br />c. To remove PIM role assignments, refer link https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-add-role-to-user?tabs=new#update-or-remove-an-existing-role-assignment. <br />For bulk remediation of permanent and classic role assignments using PowerShell, refer https://aka.ms/azts-docs/rscript/Azure_Subscription_AuthZ_Remove_Deprecated_Accounts.

### Azure Policy or ARM API used for evaluation 

- Microsoft Defender for Cloud Recommendation - [Deprecated accounts should be removed from subscriptions](https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade/assessmentKey/00c6d40b-e990-6acf-d4f3-471e747a27c4)

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalId
 <br />

- PIM API to get role assignment: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}') <br />
**Properties:** [\*].subject.id
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** [\*].properties.emailAddress
 <br />

- ARM API to list security assessments at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01<br />
**Properties:** [\*].id, [\*].name, [\*].properties.resourceDetails.Id, [\*].properties.displayName, [\*].properties.status.code, [\*].properties.status, [\*].properties.additionalData
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities 

### Display Name 
Remove external accounts from Azure subscriptions 

### Rationale 
Non-AD accounts (such as xyz@hotmail.com, pqr@outlook.com, etc.) present at any scope within a subscription subject your cloud assets to undue risk. These accounts are not managed to the same standards as enterprise tenant identities. They don't have multi-factor authentication enabled. Etc. 

### Control Spec 

> **Passed:** 
> No external account is found at subscription scope.
> 
> **Failed:** 
> External account is found at subscription scope.
> 
> **Verify:** 
> RBAC result not found (sufficient data is not available for evaluation).
> 

### Recommendation 

- **PowerShell** 

	 ```powershell 
	 Remove-AzRoleAssignment -SignInName '{signInName}' -Scope '{scope}' -RoleDefinitionName '{role definition name}'
     # Run 'Get-Help Remove-AzRoleAssignment -full' for more help.
     # For bulk remediation using PowerShell, refer https://aka.ms/azts-docs/rscript/Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities
	 ```  

### Azure Policy or ARM API used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.id, [\*].subject.type
 <br />

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalId, [\*].properties.principalType
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** [\*].properties.emailAddress
 <br />

- Graph API to fetch additional details: - /beta/directoryObjects/getByIds?$select=id,userPrincipalName,onPremisesExtensionAttributes,userType,creationType,externalUserState<br />
**Properties:** [\*].userType (To identify guest accounts)
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities_Privileged_Roles 

### Display Name 
Remove external accounts with privileged roles at subscription scope 

### Rationale 
Non-AD accounts (such as xyz@hotmail.com, pqr@outlook.com, etc.) present at any scope within a subscription subject your cloud assets to undue risk. These accounts are not managed to the same standards as enterprise tenant identities. They don't have multi-factor authentication enabled. 

### Control Settings 
```json 
{
    "PrivilegedRoles": [
        "User Access Administrator",
        "Owner",
        "Contributor"
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> No external account with privileged roles at Subscription scope found.
> 
> **Failed:** 
> One or more external account(s) found with privileged roles at Subscription scope.
> 
> **Verify:** 
> RBAC details for the Subscription are not available.
> 

### Recommendation 

- **PowerShell** 

	 ```powershell 
	 Remove-AzRoleAssignment -SignInName '{signInName}' -Scope '{scope}' -RoleDefinitionName '{roleDefinitionName}'
     # Run 'Get-Help Remove-AzRoleAssignment -full' for more help. 
	 ```  

### Azure Policy or ARM API used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.type, [\*].roleDefinition.displayName
 <br />

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalType, [\*].properties.roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** [\*].properties.role
 <br />

- Graph API to fetch additional details: - /beta/directoryObjects/getByIds?$select=id,userPrincipalName,onPremisesExtensionAttributes,userType,creationType,externalUserState<br />
**Properties:** [\*].userType (To identify guest accounts)
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count 

### Display Name 
Limit access per subscription to 2 or less classic administrators 

### Rationale 
The v1 (ASM-based) version of Azure resource access model did not have much in terms of RBAC granularity. As a result, everyone who needed any access on a subscription or its resources had to be added to the Co-administrator role. These individuals are referred to as 'classic' administrators. In the v2 (ARM-based) model, this is not required at all and even the count of 2 classic admins currently permitted is for backward compatibility. (Some Azure services are still migrating onto the ARM-based model so creating/operating on them needs 'classic' admin privilege.) 

### Control Settings 
```json 
{
    "NoOfClassicAdminsLimit": 2,
    "EligibleClassicRoles": [
        "CoAdministrator",
        "ServiceAdministrator"
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> The count of classic administrators does not exceed 2.
> 
> **Failed:** 
> More than 2 classic administrators accounts found.
> 
> **Verify:** 
> RBAC result not found (sufficient data is not available for evaluation).
> 

### Recommendation 

- **Azure Portal** 

	 Please follow these steps: <br />(a) Logon to https://portal.azure.com/ <br />(b) Navigate to Subscriptions <br />(c) Select the subscription <br />(d) Go to 'Access Control (IAM)' and select the 'Classic Administrators' tab. <br />(e) Select the co-administrator account that has to be removed and click on the 'Remove' button. <br />(f) Perform this operation for all the co-administrators that need to be removed from the subscription. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** [\*].properties.role
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Remove_Management_Certs 
[<b>Deprecation Notice!!!</b> - As on 23rd Feb. 2022, this Control has been suspended from getting evaluated as a consequence of the [deprecation](https://docs.microsoft.com/en-us/azure/defender-for-cloud/upcoming-changes#deprecating-the-recommendation-to-use-service-principals-to-protect-your-subscriptions) of the underlying Defender for Cloud recommendation used for the evaluation.]

### Display Name 
Do not use management certificates 

### Rationale 
Just like classic admins, management certificates were used in the v1 model for script/tool based automation on Azure subscriptions. These management certificates are risky because the (private) key management hygiene tends to be lax. These certificates have no role to play in the current ARM-based model and should be immediately cleaned up if found on a subscription. (VS-deployment certificates from v1 timeframe are a good example of these.) 

### Control Spec 

> **Passed:** 
> MDC assessment status is healthy.
> 
> **Failed:** 
> MDC assessment status is unhealthy. (or) MDC assessment status is "NotApplicable" with "cause" as either "OffByPolicy" or "Exempt".
> 
> **Verify:** 
> MDC assessment status is not applicable (with "cause" other than "OffByPolicy" and "Exempt"), OR MDC assessment status was not found.
> 

### Recommendation 

- **Azure Portal** 

	 You need to remove any management certificates that are not required. Please follow these steps: <br />(a) Logon to https://portal.azure.com/ <br />(b) Navigate to Subscriptions <br />(c) Select the subscription <br />(d) Go to Settings tab  --> Management Certificates tab --> Delete unwanted management certificates. 

### Azure Policy or ARM API used for evaluation 

- Microsoft Defender for Cloud Recommendation - [Service principals should be used to protect your subscriptions instead of Management Certificates](https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade/assessmentKey/2acd365d-e8b5-4094-bce4-244b7c51d67c)

- ARM API to list security assessments at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** [\*].id, [\*].name, [\*].properties.resourceDetails.Id, [\*].properties.displayName, [\*].properties.status.code, [\*].properties.status, [\*].properties.additionalData
 <br />

<br />

___ 

## Azure_Subscription_Audit_Resolve_MDC_Alerts 

### Display Name 
Resolve active Microsoft Defender for Cloud (MDC) alerts of medium severity or higher

### Rationale 
Based on the policies that are enabled in the subscription, Microsoft Defender for Cloud raises alerts (which are typically indicative of resources that MDC suspects might be under attack or needing immediate attention). It is important that these alerts/actions are resolved promptly in order to eliminate the exposure to attacks. 

### Control Settings 
```json 
{
    "MDCAlertsGraceInDays": {
        "High": 0,
        "Medium": 30
    }
}
 ```  

### Control Spec 

> **Passed:** 
> There are no active MDC Alerts OR there is no active alert which is beyond defined grace.
> 
> **Failed:** 
> There are MDC alerts in the subscription which are active beyond the defined grace. <br />Alert Severity: High, Grace period: 0 <br />Alert Severity: Medium, Grace period: 30
> 

### Recommendation 

- **Azure Portal** 

	 You need to address all active alerts on Microsoft Defender for Cloud. Please follow these steps: (a) Logon to https://portal.azure.com/ <br />(b) Navigate to 'Microsoft Defender for Cloud'. <br />(c) Click on 'Security alerts'. <br />(d) Take appropriate action on all active alerts. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list all the alerts that are associated with the subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/alerts?api-version=2021-01-01 <br />
**Properties:** [\*].properties.status, [\*].properties.severity, [\*].properties.timeGeneratedUtc
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Custom_RBAC_Roles 

### Display Name 
Do not use custom-defined RBAC roles 

### Rationale 
Custom RBAC role definitions are usually tricky to get right. A lot of threat modeling goes in when the product team works on and defines the various 'out-of-box' roles ('Owners', 'Contributors', etc.). As much as possible, teams should use these roles for their RBAC needs. Using custom roles is treated as an exception and requires a rigorous review. 

### Control Spec 

> **Passed:** 
> No custom-defined RBAC role assignments are present on the subscription.
> 
> **Failed:** 
> Custom-defined RBAC role assignments are present on the subscription.
> 
> **Verify:** 
> RBAC result not found (sufficient data is not available for evaluation).
> 

### Recommendation 

- **PowerShell** 

	 ```powershell 
	 Remove-AzRoleDefinition -Id {id}
     # Run 'Get-Help Remove-AzRoleDefinition -full' for more help. 
	 ```  

### Azure Policy or ARM API used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.type, [\*].roleDefinition.displayName
 <br />

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalType, [\*].properties.roleDefinitionId (Role name resolved from roleDefinitionId), [\*].properties.memberType
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** [\*].properties.role
 <br />

- ARM API to get custom role definitions: - /{scope}/providers/Microsoft.Authorization/roleDefinitions?$filter=type eq 'CustomRole'&api-version=2018-01-01-preview<br />
**Properties:** [\*].properties.roleName
 <br />

<br />

___ 

## Azure_Subscription_SI_Classic_Resources 

### Display Name 
Remove classic resources on a subscription 

### Rationale 
You should use new ARM/v2 resources as the ARM model provides several security enhancements such as: stronger access control (RBAC), better auditing, ARM-based deployment/governance, access to managed identities, access to key vault for secrets, AAD-based authentication, support for tags and resource groups for easier security management, etc. 

### Control Settings 
```json 
{
    "ClassicResourceTypes": [
        "Microsoft.ClassicCompute/virtualMachines",
        "Microsoft.ClassicStorage/storageAccounts",
        "Microsoft.ClassicCompute/domainNames",
        "Microsoft.ClassicNetwork/virtualNetworks",
        "Microsoft.ClassicNetwork/reservedIps",
        "Microsoft.ClassicNetwork/networkSecurityGroups",
        "Microsoft.MarketplaceApps/classicDevServices"
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> No Classic resources found.
> 
> **Failed:** 
> One or more Classic resources found.
> 

### Recommendation 

- **Azure Portal** 

	 Migrate each v1/ASM-based resource in your app to a corresponding v2/ARM-based resource. Refer: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/migration-classic-resource-manager-overview 

### Azure Policy or ARM API used for evaluation 

- ARM API to list all resources in a Subscription: - /subscriptions/{subscriptionId}/resources?$expand=provisioningState,createdTime,changedTime&api-version=2018-05-01 <br />
**Properties:** [\*].type <br />The following Classic resource types are in scope for the evaluation: <br />1. Microsoft.ClassicCompute/virtualMachines <br />2. Microsoft.ClassicStorage/storageAccounts <br /> 3. Microsoft.ClassicCompute/domainNames <br />4. Microsoft.ClassicNetwork/virtualNetworks <br />5. Microsoft.ClassicNetwork/reservedIps <br />6. Microsoft.ClassicNetwork/networkSecurityGroups <br />7. Microsoft.MarketplaceApps/classicDevServices
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access 

### Display Name 
Do not grant permanent access for privileged subscription level roles 

### Rationale 
Permanent access increase the risk of a malicious user getting that access and inadvertently impacting a sensitive resource. To minimize this risk ensure that critical resources present in subscription are accessed only by the legitimate users when required. PIM facilitates this by limiting users to only assume higher privileges in a just in time (JIT) manner (or by assigning privileges for a shortened duration after which privileges are revoked automatically). 

### Control Settings 
```json 
{
    "AllowedIdentityDisplayNames": [
        "MS-PIM"
    ],
    "CriticalPIMRoleIds": [
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "b24988ac-6180-42a0-ab88-20f7382dd24c",
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
    ],
    "CriticalPIMRoles": [
        "Owner",
        "Contributor",
        "User Access Administrator"
    ],
    "ExemptedPIMGroupsPattern": "JIT_(.)*_ElevatedAccess"
}
 ```  

### Control Spec 

> **Passed:** 
> No critical permanent role (Owner, Contributor, UAA) assignments present at subscription level OR if no role assignment present in subscription
> 
> **Failed:** 
> Any critical permanent role (Owner, Contributor, UAA) assignments present at subscription level
> 
> **Verify:** 
> RBAC result not found (sufficient data is not available for evaluation).
> 

### Recommendation 

- **PowerShell** 

	 ```powershell 
	 # Use Privileged Identity Management (PIM) to grant access to privileged roles at subscription scope.
     Remove-AzRoleAssignment -SignInName '{signInName}' -Scope '/subscriptions/{subscriptionid}' -RoleDefinitionName {RoleDefinitionName}
     # Refer https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/azure-pim-resource-rbac#assign-roles
	 ```  

### Azure Policy or ARM API used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.type, [\*].roleDefinition.displayName, [\*].assignmentState, [\*].linkedEligibleRoleAssignmentId, [\*].memberType, [\*].subject.displayName
 <br />

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalType, [\*].properties.roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** [\*].properties.role
 <br />

- Graph API to fetch additional details: - /myorganization/getObjectsByObjectIds?api-version=1.6&$select=objectType,objectId,displayName,userPrincipalName<br />
**Properties:** [\*].displayName
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG 

### Display Name 
Do not grant permanent access for privileged roles at resource group level 

### Rationale 
Permanent access increase the risk of a malicious user getting that access and inadvertently impacting a sensitive resource. To minimize this risk ensure that critical resources present in resource group are accessed only by the legitimate users when required. PIM facilitates this by limiting users to only assume higher privileges in a just in time (JIT) manner (or by assigning privileges for a shortened duration after which privileges are revoked automatically). 

### Control Settings 
```json 
{
    "AllowedIdentityDisplayNames": [
        "MS-PIM"
    ],
    "CriticalPIMRoleIds": [
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
    ],
    "CriticalPIMRoles": [
        "Owner",
        "User Access Administrator"
    ],
    "ExemptedPIMGroupsPattern": "JIT_(.)*_ElevatedAccess"
}
 ```  

### Control Spec 

> **Passed:** 
> No critical permanent role (Owner, Contributor, UAA) assignments present at resource group scope or if no role assignment present at resource group scope.
> 
> **Failed:** 
> Any critical permanent role (Owner, Contributor, UAA) assignments present at resource group scope.
> 
> **Verify:** 
> RBAC result not found (sufficient data is not available for evaluation).
> 

### Recommendation 

- **PowerShell** 

	 ```powershell 
	 # Use Privileged Identity Management (PIM) to grant access to privileged roles at resource group scope
     Remove-AzRoleAssignment -SignInName '{signInName}' -Scope '/subscriptions/{subscriptionid}/resourceGroups/{resourceGroupName}' -RoleDefinitionName {RoleDefinitionName}
     # Refer https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/azure-pim-resource-rbac#assign-roles
	 ```  

### Azure Policy or ARM API used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.type, [\*].roleDefinition.displayName, [\*].assignmentState, [\*].linkedEligibleRoleAssignmentId, [\*].memberType, [\*].subject.displayName
 <br />

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalType, [\*].properties.roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** [\*].properties.role
 <br />

- Graph API to fetch additional details: - /myorganization/getObjectsByObjectIds?api-version=1.6&$select=objectType,objectId,displayName,userPrincipalName<br />
**Properties:** [\*].displayName
 <br />

<br />

___ 

## Azure_Subscription_Config_Add_Required_Tags 

### Display Name 
Mandatory tags must be set per your organization policy 

### Rationale 
Certain tags are expected to be present in all resources to support enterprise wide functions (e.g., security visibility based on environment, security scanning, cost optimization, etc.). The script checks for presence of such 'mandatory' and 'scenario-specific' tags.  

### Control Settings 
```json 
{
    "ExcludeResourceGroupsPattern": [
        "ERNetwork-[0-9]",
        "ERvNet.*",
        "ERNetwork.*",
        "defaultresourcegroup-*",
        "NetworkWatcherRG"
    ],
    "MandatoryTags": [
        {
            "IgnorePatternWhitespaceForTagName": true,
            "Name": "Env",
            "Scope": "ResourceGroup",
            "Type": "string",
            "ValidateTagValueType": false,
            "Values": [
                "Production",
                "Pre-Production"
            ]
        },
        {
            "IgnorePatternWhitespaceForTagName": true,
            "Name": "ComponentID",
            "Scope": "ResourceGroup",
            "Type": "Guid",
            "ValidateTagValueType": true,
            "Values": []
        },
        {
            "IgnorePatternWhitespaceForTagName": true,
            "Name": "Env",
            "Scope": "Subscription",
            "Type": "string",
            "ValidateTagValueType": false,
            "Values": [
                "Production",
                "Pre-Production"
            ]
        },
        {
            "IgnorePatternWhitespaceForTagName": true,
            "Name": "ComponentID",
            "Scope": "Subscription",
            "Type": "Guid",
            "ValidateTagValueType": true,
            "Values": []
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> Mandatory tags are present on all the resource group in a subscription and its value is configured correctly, for example Production, Pre-Production etc.
> 
> **Failed:** 
> Mandatory tags are not present on all the resource group in a subscription or its value is not configured correctly, for example Production, Pre-Production etc.
> 

### Recommendation 

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-using-tags#portal 

### Azure Policy or ARM API used for evaluation 

- ARM API to get the entire set of tags on a resource or subscription: - /{scope}/providers/Microsoft.Resources/tags/default?api-version=2019-10-01<br />
**Properties:** properties.tags
 <br />

- ARM API to get resource group tags: - /subscriptions/{subscriptionId}/resourcegroups?api-version=2019-10-01 <br />
**Properties:** [\*].tags
 <br />

<br />

___ 

## Azure_Subscription_Config_MDC_Defender_Plans 

### Display Name 
Enable all Azure Defender plans in Microsoft Defender for Cloud 

### Rationale 
Azure Defender enables advanced threat detection capabilities, which use built-in behavioral analytics and machine learning to identify attacks and zero-day exploits, access and application controls to reduce exposure to network attacks and malware, and more. 

### Control Settings 
```json 
{
    "ReqMDCTier": "Standard",
    "ReqMDCTierResourceTypes": [
        {
            "Type": "VirtualMachines",
            "DisplayName": "Servers"
        },
        {
            "Type": "SqlServers",
            "DisplayName": "Azure SQL Databases"
        },
        {
            "Type": "AppServices",
            "DisplayName": "App Service"
        },
        {
            "Type": "StorageAccounts",
            "DisplayName": "Storage"
        },
        {
            "Type": "KeyVaults",
            "DisplayName": "Key Vault"
        },
        {
            "Type": "SqlServerVirtualMachines",
            "DisplayName": "SQL servers on machines"
        },
        {
            "Type": "Arm",
            "DisplayName": "Resource Manager"
        },
        {
            "Type": "Dns",
            "DisplayName": "DNS"
        },
        {
            "Type": "Containers",
            "DisplayName": "Containers"
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> All required resource types are configured with MDC standard tier.
> 
> **Failed:** 
> Any of resource types is not configured with MDC standard tier or if security center provider is not registered.
> 

### Recommendation 

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-pricing. For bulk remediation using PowerShell, refer https://aka.ms/azts-docs/rscript/Azure_Subscription_Config_MDC_Defender_Plans

### Azure Policy or ARM API used for evaluation 

- ARM API to list Security Center pricing configurations in the subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2018-06-01 <br />
**Properties:** [\*].properties.pricingTier, [\*].name
 <br />

<br />

___ 

## Azure_Subscription_Use_Only_Alt_Credentials 

### Display Name 
Use Smart-Card ALT (SC-ALT) accounts to access subscription 

### Rationale 
The regular / day to day use accounts are subject to a lot of credential theft attacks due to various activities that a user conducts using such accounts (e.g., browsing the web, clicking on email links, etc.). A user account that gets compromised (say via a phishing attack) immediately subjects the entire cloud subscription to risk if it is a member of critical roles in the subscription. Use of smartcard-backed alternate (SC-ALT) accounts instead protects the cloud subscriptions from this risk. Moreover, for complete protection, all sensitive access must be done using a secure admin workstation (SAW) and Azure Privileged Identity Management (PIM). 

### Control Settings 
```json 
{
    "CriticalPIMRoles": {
        "Subscription": [
            "Owner",
            "Contributor",
            "User Access Administrator"
        ],
        "ResourceGroup": [
            "Owner",
            "User Access Administrator"
        ]
    }
}
 ```  

### Control Spec 

> **Passed:** 
> Critical roles are not assigned to Non SC-alt accounts or no assignments for critical roles found at subscription and resource group level.
> 
> **Failed:** 
> Critical roles are assigned to Non SC-alt accounts.
> 
> **Verify:** 
> No RBAC assignments found.
> 

### Recommendation 

- **Azure Portal** 

	 Go to Azure portal -> Privileged Identity Management -> Azure Resources -> Select the scope -> Members-> Eligible roles and verify the non alternate accounts. Ensure that only alternate accounts are used as members of critical roles in the subscription. Do not use day to day user accounts. 

### Azure Policy or ARM API used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.type, [\*].roleDefinition.displayName
 <br />

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalType, [\*].properties.roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** [\*].properties.role
 <br />

- Graph API to fetch additional details: - /beta/directoryObjects/getByIds?$select=id,userPrincipalName,onPremisesExtensionAttributes,userType,creationType,externalUserState<br />
**Properties:** [\*].userType (To identify guest accounts), [\*].onPremisesExtensionAttributes.extensionAttribute2
 <br />

<br />

___ 

## Azure_Subscription_Config_MDC_Enable_AutoProvisioning 

### Display Name 
Turn on Microsoft Monitoring Agent (MMA) to enable Security Monitoring 

### Rationale 
MDC monitors various security parameters on a VM such as missing updates, OS security settings, endpoint protection status, and health and threat detections, etc using a monitoring agent. This agent needs to be provisioned and running on VMs for the monitoring work. When automatic provisioning is ON, MDC provisions the Microsoft Monitoring Agent (MMA) on all supported Azure VMs and any new ones that are created. 

### Control Spec 

> **Passed:** 
> Auto Provisioning is enabled.
> 
> **Failed:** 
> Auto Provisioning is not enabled or if security center provider is not registered.
> 
> **Verify:** 
> Unable to verify Auto Provisioning detail.
> 

### Recommendation 

- **Azure Portal** 

	 For setting AutoProvisioning settings for your subscription, go to azure portal https://portal.azure.com. On the portal go to --> Security center --> Pricing & Settings --> Select your subscription --> Settings --> Data Collection

### Azure Policy or ARM API used for evaluation 

- ARM API to list auto provisioning settings at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/autoProvisioningSettings/default?api-version=2017-08-01-preview <br />
**Properties:** properties.autoProvision
 <br />

<br />

___ 

## Azure_Subscription_Config_MDC_Setup_SecurityContacts 

### Display Name 
Configure security contacts and alerts of medium severity or higher on your subscription 

### Rationale 
Security contact information will be used by Microsoft to contact you if the Microsoft Security Response Center (MSRC) discovers that your customer data has been accessed by an unlawful or unauthorized party. 

### Control Settings 
```json 
{
    "SecurityContacts": {
        "AlertNotificationSeverities": [
            "Medium",
            "Low"
        ],
        "AlertNotificationState": "On",
        "NotificationsRecipientsRoleName": [
            "Owner",
            "ServiceAdmin"
        ],
        "NotificationsRecipientsState": "On"
    }
}
 ```  

### Control Spec 

> **Passed:** 
> MDC security contact setting meet the following conditions:
>   <br />a. 'Owner' and 'Account Admin' should be selected as email recipients.
>   <br />b. At least one email id is specified as email recipients.
>   <br />c. Alert notification should be enabled.
>   <br />d. Alert notification severity should be at least set to 'Medium' such that notification is triggered for both Medium and High severity alert.
> 
> **Failed:** 
> Fail if security center provider is not registered OR if MDC security contact setting does not meet the following conditions:
>   <br />a. 'Owner' and 'Account Admin' should be selected as email recipients.
>   <br />b. At least one email id is specified as email recipients.
>   <br />c. Notify about alerts is enabled.
>   <br />d. Alert notification severity should be at least set to 'Medium' such that notification is triggered for both Medium and High severity alert.
> 

### Recommendation 

- **Azure Portal** 
    Go to Azure Portal -> Microsoft Defender for Cloud -> Environment settings -> Select your subscription -> Go to 'Email notifications' <br /> a. In the 'Email recipients', Select 'Owner' **and** 'Service Admin' as email recipients **and** specify at least one email recipient. <br /> b. In the 'Notification types', Select the check box to notify about alerts and select the alert severity to 'Medium' or 'Low' (**Medium** = Get alerts for _Medium_ + _High_ severity and **Low** = Get alerts for _Low_ + _Medium_ + _High_ severity) -> Save. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list all security contact configurations for the subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview <br />
**Properties:** properties.emails, properties.phone, properties.alertNotifications.state, properties.alertNotifications.minimalSeverity, properties.notificationsByRole.state, properties.notificationsByRole.roles
 <br />

<br />

___ 

## Azure_Subscription_SI_No_Billing_Activity 

> This control is not evaluated using an Azure ARM API but rather a custom data source and will be marked as "Verify" for users outside Microsoft. <br />With the upcoming extensibility updates, users will be able to extend this control by adding their own control logic.

### Display Name 
Subscriptions with no billing activity and resources must be deleted 

### Rationale 
Cleaning up unused subscriptions is suggested as a good hygiene practice. 

### Control Settings 
```json 
{
    "MinReqdBillingPeriodInDays": 90,
    "GracePeriodForDisabledSubsInDays": 0
}
 ```  

### Control Spec 

> **Passed:** 
> Subscription has been billed in the last 90 days or it is an active subscription which has resources.
> 
> **Failed:** 
> No billing activity and resources were found for a subscription in last ninety days.
>
> **Verify:**
> Billing info is not available for processing.
> 

### Recommendation 

- **Azure Portal** 

	 To cancel subscription in the Azure portal, <br />1. Select your subscription from the Subscriptions page in the Azure portal. <br />2. Select the subscription that you want to cancel. <br />3. Select Overview, and then select Cancel subscription. <br />4. Follow prompts and finish cancellation. <br />For detailed instructions, refer: https://docs.microsoft.com/en-us/azure/cost-management-billing/manage/cancel-azure-subscription.

<br />

___ 

## Azure_Subscription_Configure_Conditional_Access_for_PIM 

### Display Name 
Enable policy to require PIM elevation from SAW for admin roles in Azure subscriptions 

### Rationale 
By using Conditional Access policies for privileged roles, you can apply the right access controls to make sure certain requirements are met before the end user gets access to the resource 

### Control Settings 
```json 
{
    "RuleName": "acrsRule",
    "RuleSettings": "{\"acrsRequired\":true,\"acrs\":\"urn:microsoft:req1\"}"
}
 ```  

### Control Spec 

> **Passed:** 
> CA is enabled with correct policy.
> 
> **Failed:** 
> CA is disabled OR CA is configured with incorrect policy.
> 

### Recommendation 

- **Azure Portal** 

     To configure Conditional Access Policy, refer https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-resource-roles-configure-role-settings. 
     <br>
     > _**Note:** Follow the same steps for 'Owner', 'Contributor' and 'User Access Administrator' roles._
     <br>

     To create Policy for your organization, refer https://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa?bc=/azure/active-directory/conditional-access/breadcrumb/toc.json&toc=/azure/active-directory/conditional-access/toc.json#create-a-conditional-access-policy.
	  

### Azure Policy or ARM API used for evaluation 

- PIM API to get Role Settings: - /beta/privilegedAccess/azureResources/roleSettings?$expand=resource,roleDefinition($expand=resource)&$filter=(resource/id+eq+'{uniquePimIdentifier}')+and+((roleDefinition/templateId+eq+'{ownerTemplateId}')+or+(roleDefinition/templateId+eq+'{userAccessAdminTemplateId}')+or+(roleDefinition/templateId+eq+'{contributorTemplateId}')) <br />
**Properties:** [\*].roleDefinitionId, [\*].userMemberSettings, [\*].roleDefinition.displayName
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Limit_Admin_Owner_Count 

### Display Name 
Minimize the number of admins/owners

### Rationale 
Each additional person in the admin/owner role increases the attack surface for the entire subscription. The number of members in these roles should be kept to as low as possible. 

### Control Settings 
```json 
{
    "ExcludeUsers": [],
    "NoOfAdminOrOwnerLimit": 5,
    "EligibleAdminOrOwnerRoles": [
        "CoAdministrator",
        "ServiceAdministrator",
        "owner"
    ]
}
 ```  

### Control Spec 
> **Passed:** 
> The count of admin/owner accounts does not exceed the configured number of admin/owner count.
Note : Approved central team accounts don't count against your limit
> 
> **Failed:** 
> The count of admin/owner accounts exceed the configured number of admin/owner count. 
Note : Approved central team accounts don't count against your limit
> 
> **Verify:** 
> RBAC result not found (sufficient data is not available for evaluation).
> 


### Recommendation 

- **Azure Portal** 
 <br/>Please follow these steps to remove classic role assignments : <br />(a) Logon to https://portal.azure.com/ <br />(b) Navigate to Subscriptions <br />(c) Select the subscription <br />(d) Go to 'Access Control (IAM)' and select the 'Classic Administrators' tab. <br />(e) Select the co-administrator account that has to be removed and click on the 'Remove' button. <br />(f) Perform this operation for all the co-administrators that need to be removed from the subscription. <br/> 
<br/>Please follow these steps to remove owner role assignments : <br />(a) Logon to https://portal.azure.com/ <br />(b) Navigate to Subscriptions <br />(c) Select the subscription <br />(d) Go to 'Access Control (IAM)' and select the 'Role Assignments' tab. <br />(e) Navigate to owner section and select the owner account that has to be removed and click on the 'Remove' button. <br />(f) Perform this operation for all the owner accounts that need to be removed from the subscription. <br/> 


- **PowerShell** 
    <br> To remove owner role assignment.
	 ```powershell 
	 Remove-AzRoleAssignment -SignInName '{signInName}' -Scope '{scope}' -RoleDefinitionName '{role definition name}'
     # Run 'Get-Help Remove-AzRoleAssignment -full' for more help.
     # For bulk remediation using PowerShell, refer https://aka.ms/azts-docs/rscript/Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities
	 `

### Azure Policy or ARM API used for evaluation 

-  ARM API to list role assignment at subscription level: - /subscriptions/{subscriptionId}}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-07-01<br />
**Properties:** [\*].properties.scope , [\*].name
 <br />

<br />


## Azure_Subscription_SI_Dont_Use_B2C_Tenant 

### Display Name 
Remove Azure Active Directory B2C tenant(s) in a subscription

### Rationale 
This Service depends mainly on 3rd party identity provider, and that can cause authenticity attacks. Closing unnecessary or high-risk Azure B2C usage will reduce the attack surface, reduce risk to the enterprise and protect against identity attacks. 

### Control Spec 
> **Passed:** 
> No Azure Active Directory B2C tenant found AND Resource Provider: 'Microsoft.AzureActiveDirectory' is not registered in this subscription
> 
> **Failed:** 
> Azure Active Directory B2C tenant(s) are found OR <br/>Resource provider: 'Microsoft.AzureActiveDirectory' is registered in this subscription. 


### Recommendation 

- **Azure Portal** 
 <br/>Refer: https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/active-directory-b2c/tutorial-delete-tenant.md to delete the Azure B2C tenant and unregister the 'Microsoft.AzureActiveDirectory' resource provider in the subscription.<br/>Refer to https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types for more information on resource providers.


### Azure Policy or ARM API used for evaluation 

-  ARM API to list providers at subscription level: - "/subscriptions/{subscriptionId}/providers?api-version=2020-06-01&$select=namespace,registrationstate<br />
**Properties:** [\*].value.namespace , [\*].value.registrationState
 <br />

 <br />


## Azure_Subscription_Identity_Rotate_SPN_Credentials 

### Display Name 
App Registrations and Service Principals credentials must be regularly rotated.

### Rationale 
SPNs having access to subscription must have secrets within maximum approved expiry time.

### Control Spec 
> **Passed:** 
> The gap between the End date and Start date of a secret is within maximum approved expiry time 
> 
> **Failed:** 
> The gap between the End date and Start date of a secret is not within maximum approved expiry time 


### Recommendation 

- **Azure Portal** 
 <br/>Rotate/Delete expired SPN secrets.

 ### Control Settings 
```json 
{
    "ExpirationPeriodInDays":380,
    "ServicePrincipalTypeFilter":["Application","Legacy"],
    "AllowedObjectIds":[]
}
 ```  
 <br />

 <br />


## Azure_Subscription_AuthZ_SPN_Owners_Governance 

### Display Name 
App Registrations and Service Principals must have at least two FTE Owners (SC-Alt/SAS-Alt only)

### Rationale 
SPNs in a subscription with access at subscription or resource group level should not have access to any External Users.

### Control Spec 
> **Passed:** 
> A SPN have atleast two FTE Owners with (SC-Alt/SAS-Alt only)
> 
> **Failed:** 
> A SPN does not have atleast two FTE Owners with (SC-Alt/SAS-Alt only) <b>OR</b>
> A SPN have FTE Owners without (SC-Alt/SAS-Alt only) <b>OR</b>
> A SPN have Non FTE Owners

### Recommendation 

- **Azure Portal** 
 <br/>Add exactly two FTE owners or remove SPN's subscription/resource group level access.

 ### Control Settings 
```json 
{
    "ServicePrincipalTypeFilter":["Application","Legacy"],
    "AllowedObjectIds":[]
}
 ```  
 <br />

<br />

___ 

