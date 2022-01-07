# SubscriptionCore

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_Subscription_AuthZ_Remove_Deprecated_Accounts](#Azure_Subscription_AuthZ_Remove_Deprecated_Accounts)
- [Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities](#Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities)
- [Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities_Privileged_Roles](#Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities_Privileged_Roles)
- [Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count](#Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count)
- [Azure_Subscription_AuthZ_Remove_Management_Certs](#Azure_Subscription_AuthZ_Remove_Management_Certs)
- [Azure_Subscription_Audit_Resolve_Azure_Security_Center_Alerts](#Azure_Subscription_Audit_Resolve_Azure_Security_Center_Alerts)
- [Azure_Subscription_AuthZ_Custom_RBAC_Roles](#Azure_Subscription_AuthZ_Custom_RBAC_Roles)
- [Azure_Subscription_SI_Classic_Resources](#Azure_Subscription_SI_Classic_Resources)
- [Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access](#Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access)
- [Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG](#Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG)
- [Azure_Subscription_Config_Add_Required_Tags](#Azure_Subscription_Config_Add_Required_Tags)
- [Azure_Subscription_Config_ASC_Defender](#Azure_Subscription_Config_ASC_Defender)
- [Azure_Subscription_Use_Only_Alt_Credentials](#Azure_Subscription_Use_Only_Alt_Credentials)
- [Azure_Subscription_Config_ASC_Enable_AutoProvisioning](#Azure_Subscription_Config_ASC_Enable_AutoProvisioning)
- [Azure_Subscription_Config_ASC_Setup_SecurityContacts](#Azure_Subscription_Config_ASC_Setup_SecurityContacts)
- [Azure_Subscription_SI_No_Billing_Activity_Trial](#Azure_Subscription_SI_No_Billing_Activity_Trial)
- [Azure_Subscription_Configure_Conditional_Access_for_PIM](#Azure_Subscription_Configure_Conditional_Access_for_PIM)

<!-- /TOC -->
<br/>

___ 

## Azure_Subscription_AuthZ_Remove_Deprecated_Accounts 

### DisplayName 
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
> No deprecated account is found at subscription scope (in both ASC and Reader scan).
> 
> **Failed:** 
> Deprecated account is found at subscription scope (in any one of ASC and Reader scan).
> 
> **Verify:** 
> ASC assessment status is not applicable or policy is missing.

### Recommendation 

- **Azure Portal** 

	 Steps to remove role assignments of deprecated/invalid accounts are:  <br />a. To remove permanent role assignment use command 'Remove-AzRoleAssignment' or refer link, https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-remove#azure-portal <br />b. To remove classic role assignments, refer link: https://docs.microsoft.com/en-us/azure/role-based-access-control/classic-administrators#remove-a-co-administrator <br />c. To remove PIM role assignments, refer link https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-add-role-to-user?tabs=new#update-or-remove-an-existing-role-assignment. <br />For bulk remediation of permanent and classic role assignments using PowerShell, refer https://aka.ms/azts-docs/rscript/Azure_Subscription_AuthZ_Remove_Deprecated_Accounts.

### Azure Policy or ARM API used for evaluation 

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** principalId
 <br />

- PIM API to get role assignment: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}') <br />
**Properties:** subject.id
 <br />

- ARM API to list security assessments at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01<br />
**Properties:** id, name, resourceDetails.Id, displayName, status.code, status, additionalData
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities 

### DisplayName 
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
**Properties:** subject.principalName
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** emailAddress
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Use_NonAD_Identities_Privileged_Roles 

### DisplayName 
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
**Properties:** subject.type, roleDefinition.displayName
 <br />

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** principalType, roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** role
 <br />

- Graph API to fetch additional details: - /beta/directoryObjects/getByIds?$select=id,userPrincipalName,onPremisesExtensionAttributes,userType,creationType,externalUserState<br />
**Properties:** userType (To identify guest accounts)
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count 

### DisplayName 
Limit access per subscription to 2 or less classic administrators 

### Rationale 
The v1 (ASM-based) version of Azure resource access model did not have much in terms of RBAC granularity. As a result, everyone who needed any access on a subscription or its resources had to be added to the Co-administrator role. These individuals are referred to as 'classic' administrators. In the v2 (ARM-based) model, this is not required at all and even the count of 2 classic admins currently permitted is for backward compatibility. (Some Azure services are still migrating onto the ARM-based model so creating/operating on them needs 'classic' admin privilege.) 

### Control Settings 
```json 
{
    "NoOfClassicAdminsLimit": 2
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

	 You need to remove any 'Classic Administrators/Co-Administrators' who should not be in the role. Please follow these steps: <br />(a) Logon to https://portal.azure.com/ <br />(b) Navigate to Subscriptions <br />(c) Select the subscription <br />(d) Go to 'Access Control (IAM)' and select the 'Classic Administrators' tab. <br />(e) Select the co-administrator account that has to be removed and click on the 'Remove' button. <br />(f) Perform this operation for all the co-administrators that need to be removed from the subscription. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** properties.role
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Remove_Management_Certs 

### DisplayName 
Do not use management certificates 

### Rationale 
Just like classic admins, management certificates were used in the v1 model for script/tool based automation on Azure subscriptions. These management certificates are risky because the (private) key management hygiene tends to be lax. These certificates have no role to play in the current ARM-based model and should be immediately cleaned up if found on a subscription. (VS-deployment certificates from v1 timeframe are a good example of these.) 

### Control Spec 

> **Passed:** 
> ASC assessment status is healthy.
> 
> **Failed:** 
> ASC assessment status is unhealthy. (or) ASC assessment status is "NotApplicable" with "cause" as either "OffByPolicy" or "Exempt".
> 
> **Verify:** 
> ASC assessment status is not applicable (with "cause" other than "OffByPolicy" and "Exempt"), OR ASC assessment status was not found.
> 

### Recommendation 

- **Azure Portal** 

	 You need to remove any management certificates that are not required. Please follow these steps: <br />(a) Logon to https://portal.azure.com/ <br />(b) Navigate to Subscriptions <br />(c) Select the subscription <br />(d) Go to Settings tab  --> Management Certificates tab --> Delete unwanted management certificates. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list security assessments at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** id, name, resourceDetails.Id, displayName, status.code, status, additionalData
 <br />

<br />

___ 

## Azure_Subscription_Audit_Resolve_Azure_Security_Center_Alerts 

### DisplayName 
Pending Azure Security Center (ASC) alerts must be resolved 

### Rationale 
Based on the policies that are enabled in the subscription, Azure Security Center raises alerts (which are typically indicative of resources that ASC suspects might be under attack or needing immediate attention). It is important that these alerts/actions are resolved promptly in order to eliminate the exposure to attacks. 

### Control Settings 
```json 
{
    "ASCAlertsGraceInDays": {
        "High": 0,
        "Medium": 30
    }
}
 ```  

### Control Spec 

> **Passed:** 
> There are no active ASC Alerts OR there is no active alert which is beyond defined grace.
> 
> **Failed:** 
> There are ASC alerts in the subscription which are active beyond the defined grace. <br />Alert Severity: High, Grace period: 0 <br />Alert Severity: Medium, Grace period: 30
> 

### Recommendation 

- **Azure Portal** 

	 You need to address all active alerts on Azure Security Center. Please follow these steps: <br />(a) Logon to https://portal.azure.com/ <br />(b) Navigate to Security Center. <br />(c) Click on Security Alerts under 'Threat Protection' category. <br />(d) Take appropriate actions on all active alerts. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list all the alerts that are associated with the subscription: - /subscriptions/{subscriptionId}/providers/microsoft.Security/alerts?api-version=2015-06-01-preview <br />
**Properties:** properties.state, properties.reportedSeverity, properties.reportedTimeUtc
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Custom_RBAC_Roles 

### DisplayName 
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
**Properties:** subject.type, roleDefinition.displayName
 <br />

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** principalType, roleDefinitionId (Role name resolved from roleDefinitionId), memberType
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** role
 <br />

- ARM API to get custom role definitions: - /{scope}/providers/Microsoft.Authorization/roleDefinitions?$filter=type eq 'CustomRole'&api-version=2018-01-01-preview<br />
**Properties:** roleName
 <br />

<br />

___ 

## Azure_Subscription_SI_Classic_Resources 

### DisplayName 
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
**Properties:** type <br />The following Classic resource types are in scope for the evaluation: <br />1. Microsoft.ClassicCompute/virtualMachines <br />2. Microsoft.ClassicStorage/storageAccounts <br /> 3. Microsoft.ClassicCompute/domainNames <br />4. Microsoft.ClassicNetwork/virtualNetworks <br />5. Microsoft.ClassicNetwork/reservedIps <br />6. Microsoft.ClassicNetwork/networkSecurityGroups <br />7. Microsoft.MarketplaceApps/classicDevServices
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access 

### DisplayName 
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
**Properties:** subject.type, roleDefinition.displayName, assignmentState, linkedEligibleRoleAssignmentId, memberType, subject.displayName
 <br />

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** principalType, roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** role
 <br />

- Graph API to fetch additional details: - /myorganization/getObjectsByObjectIds?api-version=1.6&$select=objectType,objectId,displayName,userPrincipalName<br />
**Properties:** displayName
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG 

### DisplayName 
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
**Properties:** subject.type, roleDefinition.displayName, assignmentState, linkedEligibleRoleAssignmentId, memberType, subject.displayName
 <br />

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** principalType, roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** role
 <br />

- Graph API to fetch additional details: - /myorganization/getObjectsByObjectIds?api-version=1.6&$select=objectType,objectId,displayName,userPrincipalName<br />
**Properties:** displayName
 <br />

<br />

___ 

## Azure_Subscription_Config_Add_Required_Tags 

### DisplayName 
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
**Properties:** tags
 <br />

<br />

___ 

## Azure_Subscription_Config_ASC_Defender 

### DisplayName 
Enable all Azure Defender plans in Azure Security Center 

### Rationale 
Azure Defender enables advanced threat detection capabilities, which use built-in behavioral analytics and machine learning to identify attacks and zero-day exploits, access and application controls to reduce exposure to network attacks and malware, and more. 

### Control Settings 
```json 
{
    "ReqASCTier": "Standard",
    "ReqASCTierResourceTypes": [
        {
            "DisplayName": "Servers",
            "Type": "VirtualMachines"
        },
        {
            "DisplayName": "Azure SQL Databases",
            "Type": "SqlServers"
        },
        {
            "DisplayName": "App Service",
            "Type": "AppServices"
        },
        {
            "DisplayName": "Storage",
            "Type": "StorageAccounts"
        },
        {
            "DisplayName": "Kubernetes",
            "Type": "KubernetesService"
        },
        {
            "DisplayName": "Container registries",
            "Type": "ContainerRegistry"
        },
        {
            "DisplayName": "Key Vault",
            "Type": "KeyVaults"
        },
        {
            "DisplayName": "SQL servers on machines",
            "Type": "SqlServerVirtualMachines"
        },
        {
            "DisplayName": "Resource Manager",
            "Type": "Arm"
        },
        {
            "DisplayName": "DNS",
            "Type": "Dns"
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> All required resource types are configured with ASC standard tier.
> 
> **Failed:** 
> Any of resource types is not configured with ASC standard tier or if security center provider is not registered.
> 

### Recommendation 

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-pricing. For bulk remediation using PowerShell, refer https://aka.ms/azts-docs/rscript/Azure_Subscription_Config_ASC_Defender 

### Azure Policy or ARM API used for evaluation 

- ARM API to list Security Center pricing configurations in the subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2018-06-01 <br />
**Properties:** pricingTier, name
 <br />

<br />

___ 

## Azure_Subscription_Use_Only_Alt_Credentials 

### DisplayName 
Use Smart-Card ALT (SC-ALT) accounts to access subscription 

### Rationale 
The regular / day to day use accounts are subject to a lot of credential theft attacks due to various activities that a user conducts using such accounts (e.g., browsing the web, clicking on email links, etc.). A user account that gets compromised (say via a phishing attack) immediately subjects the entire cloud subscription to risk if it is a member of critical roles in the subscription. Use of smartcard-backed alternate (SC-ALT) accounts instead protects the cloud subscriptions from this risk. Moreover, for complete protection, all sensitive access must be done using a secure admin workstation (SAW) and Azure Privileged Identity Management (PIM). 

### Control Settings 
```json 
{
    "AlernateAccountRegularExpressionForOrg": "^sc-(.)*@(.)*microsoft.com$",
    "CriticalPIMRoles": {
        "ResourceGroup": [
            "Owner",
            "User Access Administrator"
        ],
        "Subscription": [
            "Owner",
            "Contributor",
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
**Properties:** subject.type, roleDefinition.displayName
 <br />

- ARM API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** principalType, roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- ARM API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** role
 <br />

- Graph API to fetch additional details: - /beta/directoryObjects/getByIds?$select=id,userPrincipalName,onPremisesExtensionAttributes,userType,creationType,externalUserState<br />
**Properties:** userType (To identify guest accounts), onPremisesExtensionAttributes.extensionAttribute2
 <br />

<br />

___ 

## Azure_Subscription_Config_ASC_Enable_AutoProvisioning 

### DisplayName 
Turn on Microsoft Monitoring Agent (MMA) to enable Security Monitoring 

### Rationale 
ASC monitors various security parameters on a VM such as missing updates, OS security settings, endpoint protection status, and health and threat detections, etc using a monitoring agent. This agent needs to be provisioned and running on VMs for the monitoring work. When automatic provisioning is ON, ASC provisions the Microsoft Monitoring Agent (MMA) on all supported Azure VMs and any new ones that are created. 

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

- **PowerShell** 

	 ```powershell 
	 # Run this command for setting up AutoProvisioning settings
     Set-AzSKAzureSecurityCenterPolicies -SubscriptionId '<SubscriptionId>'
	 ```  

### Azure Policy or ARM API used for evaluation 

- ARM API to list auto provisioning settings at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/autoProvisioningSettings/default?api-version=2017-08-01-preview <br />
**Properties:** autoProvision
 <br />

<br />

___ 

## Azure_Subscription_Config_ASC_Setup_SecurityContacts 

### DisplayName 
A security contact and alerts must be configured for your subscription 

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
> ASC security contact setting meet the following conditions:
>   <br />a. 'Owner' and 'Account Admin' should be selected as email recipients.
>   <br />b. At least one email id is specified as email recipients.
>   <br />c. Alert notification should be enabled.
>   <br />d. Alert notification severity should be at least set to 'Medium' such that notification is triggered for both Medium and High severity alert.
> 
> **Failed:** 
> Fail if security center provider is not registered OR if ASC security contact setting does not meet the following conditions:
>   <br />a. 'Owner' and 'Account Admin' should be selected as email recipients.
>   <br />b. At least one email id is specified as email recipients.
>   <br />c. Notify about alerts is enabled.
>   <br />d. Alert notification severity should be at least set to 'Medium' such that notification is triggered for both Medium and High severity alert.
> 

### Recommendation 

- **Azure Portal** 

	 On Azure portal, go to Security Center -> Pricing & settings (select subscription id) -> Email notifications -> <br />a. Select 'Owner' and 'Account Admin' as email recipients or explicitly specify the email recipients <br />b. Select checkbox to notify about alerts <br />c. Alert severity should be set to atleast 'Medium' -> Save. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list all security contact configurations for the subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview <br />
**Properties:** properties.emails, properties.phone, properties.alertNotifications.state, properties.alertNotifications.minimalSeverity, properties.notificationsByRole.state, properties.notificationsByRole.roles
 <br />

<br />

___ 

## Azure_Subscription_Configure_Conditional_Access_for_PIM 

### DisplayName 
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

- **PowerShell** 

	 ```powershell 
	 # Run the below command for Owner, Contributor and User Access Administrator roles for the subscription
     Set-AzSKPIMConfiguration -ConfigureRoleSettings -SubscriptionId `$subid -RoleName `$roleName  -ApplyConditionalAccessPolicyForRoleActivation `$true

     # Run the below command for Owner, UAA at Resource Group level
     Set-AzSKPIMConfiguration -ConfigureRoleSettings -SubscriptionId `$subid -ResourceGroupName `$RGName -RoleName `$roleName -ApplyConditionalAccessPolicyForRoleActivation `$true
	 ```  

### Azure Policy or ARM API used for evaluation 

- PIM API to get Role Settings: - /beta/privilegedAccess/azureResources/roleSettings?$expand=resource,roleDefinition($expand=resource)&$filter=(resource/id+eq+'{0}')+and+((roleDefinition/templateId+eq+'{1}')+or+(roleDefinition/templateId+eq+'{2}')+or+(roleDefinition/templateId+eq+'{3}')) <br />
**Properties:** roleDefinitionId, userMemberSettings, roleDefinition.displayName
 <br />

<br />

___ 

