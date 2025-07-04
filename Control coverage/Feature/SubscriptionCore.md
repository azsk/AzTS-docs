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
- [Azure_Subscription_AuthZ_Configure_Conditional_Access_for_PIM](#azure_subscription_authz_configure_conditional_access_for_pim)
- [Azure_Subscription_AuthZ_Limit_Admin_Owner_Count](#Azure_Subscription_AuthZ_Limit_Admin_Owner_Count)
- [Azure_Subscription_SI_Dont_Use_B2C_Tenant](#azure_subscription_si_dont_use_b2c_tenant)
- [Azure_Subscription_AuthZ_Dont_Use_SPNs_With_Password](#Azure_Subscription_AuthZ_Dont_Use_SPNs_With_Password)
- [Azure_Subscription_AuthZ_Dont_Grant_SPNs_Privileged_Roles](#Azure_Subscription_AuthZ_Dont_Grant_SPNs_Privileged_Roles)
- [Azure_Subscription_AuthZ_Dont_Grant_SPNs_Privileged_Roles_RG](#Azure_Subscription_AuthZ_Dont_Grant_SPNs_Privileged_Roles_RG)
- [Azure_Subscription_Config_Enable_MicrosoftDefender_Servers](#azure_subscription_config_enable_microsoftdefender_servers)
- [Azure_Subscription_Config_Enable_MicrosoftDefender_Container](#azure_subscription_config_enable_microsoftdefender_container)
- [Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault](#azure_subscription_config_enable_microsoftdefender_keyvault)
- [Azure_Subscription_Config_Enable_MicrosoftDefender_Databases](#azure_subscription_config_enable_microsoftdefender_databases)
- [Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager](#azure_subscription_config_enable_microsoftdefender_resourcemanager)
- [Azure_Subscription_Identity_Rotate_SPN_Credentials](#azure_subscription_identity_rotate_spn_credentials)
- [Azure_Subscription_Config_Enable_MicrosoftDefender_AppService](#azure_subscription_config_enable_microsoftdefender_appservice)
- [Azure_Subscription_Config_Enable_MicrosoftDefender_Storage](#azure_subscription_config_enable_microsoftdefender_storage)
- [Azure_Subscription_Config_Enable_MicrosoftDefender_CSPM](#azure_subscription_config_enable_microsoftDefender_cspm)
- [Azure_Subscription_Config_Enable_MicrosoftDefender_API](#Azure_Subscription_Config_Enable_MicrosoftDefender_API)
- [Azure_Subscription_AuthZ_Expired_SPN_Certificates](#Azure_Subscription_AuthZ_Expired_SPN_Certificates)
- [Azure_Subscription_AuthZ_Dont_Grant_NonAllowed_Broad_Groups](#Azure_Subscription_AuthZ_Dont_Grant_NonAllowed_Broad_Groups)
- [Azure_Subscription_AuthZ_Dont_Grant_NonAD_Identities_Privileged_Roles_RG](#Azure_Subscription_AuthZ_Dont_Grant_NonAD_Identities_Privileged_Roles_RG)
- [Azure_Subscription_AuthZ_Configure_ConditionalAccess_For_PIM](#Azure_Subscription_AuthZ_Configure_ConditionalAccess_For_PIM)
- [Azure_Subscription_AuthZ_SPN_Owners_Governance](#azure_subscription_authz_spn_owners_governance)
- [Azure_Subscription_AuthZ_Use_Only_Alt_Credentials](#Azure_Subscription_AuthZ_Use_Only_Alt_Credentials)
- [Azure_Subscription_Config_Enable_MicrosoftDefender_AIServices](#Azure_Subscription_Config_Enable_MicrosoftDefender_AIServices)
- [Azure_Subscription_DP_Avoid_Plaintext_Secrets_Deployments](#azure_subscription_dp_avoid_plaintext_secrets_deployments)
- [Azure_Subscription_DP_Avoid_Plaintext_Secrets_Tags](#azure_subscription_dp_avoid_plaintext_secrets_tags)

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

### Azure Policies or REST APIs used for evaluation 

- Microsoft Defender for Cloud Recommendation - [Deprecated accounts should be removed from subscriptions](https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade/assessmentKey/00c6d40b-e990-6acf-d4f3-471e747a27c4)

- REST API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalId
 <br />

- PIM API to get role assignment: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}') <br />
**Properties:** [\*].subject.id
 <br />

- REST API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** [\*].properties.emailAddress
 <br />

- REST API to list security assessments at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01<br />
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

### Azure Policies or REST APIs used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.id, [\*].subject.type
 <br />

- REST API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalId, [\*].properties.principalType
 <br />

- REST API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
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

### Azure Policies or REST APIs used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.type, [\*].roleDefinition.displayName
 <br />

- REST API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalType, [\*].properties.roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- REST API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
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

### Azure Policies or REST APIs used for evaluation 

- REST API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
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

### Azure Policies or REST APIs used for evaluation 

- Microsoft Defender for Cloud Recommendation - [Service principals should be used to protect your subscriptions instead of Management Certificates](https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade/assessmentKey/2acd365d-e8b5-4094-bce4-244b7c51d67c)

- REST API to list security assessments at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
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

### Azure Policies or REST APIs used for evaluation 

- REST API to list all the alerts that are associated with the subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/alerts?api-version=2021-01-01 <br />
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

### Azure Policies or REST APIs used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.type, [\*].roleDefinition.displayName
 <br />

- REST API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalType, [\*].properties.roleDefinitionId (Role name resolved from roleDefinitionId), [\*].properties.memberType
 <br />

- REST API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** [\*].properties.role
 <br />

- REST API to get custom role definitions: - /{scope}/providers/Microsoft.Authorization/roleDefinitions?$filter=type eq 'CustomRole'&api-version=2018-01-01-preview<br />
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

### Azure Policies or REST APIs used for evaluation 

- REST API to list all resources in a Subscription: - /subscriptions/{subscriptionId}/resources?$expand=provisioningState,createdTime,changedTime&api-version=2018-05-01 <br />
**Properties:** [\*].type <br />The following Classic resource types are in scope for the evaluation: <br />1. Microsoft.ClassicCompute/virtualMachines <br />2. Microsoft.ClassicStorage/storageAccounts <br /> 3. Microsoft.ClassicCompute/domainNames <br />4. Microsoft.ClassicNetwork/virtualNetworks <br />5. Microsoft.ClassicNetwork/reservedIps <br />6. Microsoft.ClassicNetwork/networkSecurityGroups <br />7. Microsoft.MarketplaceApps/classicDevServices
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access 

### Display Name 
Do not grant permanent access for Subscription level roles 

### Rationale 
Permanent access increase the risk of a malicious user getting that access and inadvertently impacting a sensitive resource. To minimize this risk ensure that critical resources present in subscription are accessed only by the legitimate users when required. PIM facilitates this by limiting users to only assume higher privileges in a just in time (JIT) manner (or by assigning privileges for a shortened duration after which privileges are revoked automatically). 

### Control Settings 
```json 
{
    "AllowedPIMRoles": [
        "Azure Front Door Domain Contributor",
        "Azure Front Door Domain Reader",
        "Azure Front Door Profile Reader",
        "Azure Front Door Secret Contributor",
        "Azure Front Door Secret Reader",
        "Defender for Storage Data Scanner",
        "AzureML Compute Operator",
        "Cognitive Services Usages Reader",
        "Key Vault Crypto Service Release User",
        "ServiceAdministrator",
        "CoAdministrator",
        "AccountAdministrator",
        "ServiceAdministrator;AccountAdministrator",
        "ServiceAdministrator;CoAdministrator",
        "CoAdministrator;AccountAdministrator",
        "CoAdministrator;ServiceAdministrator",
        "AccountAdministrator;ServiceAdministrator",
        "AccountAdministrator;CoAdministrator"
    ],
    "AllowedPIMRoleIds": [
        "0ab34830-df19-4f8c-b84e-aa85b8afa6e8",
        "0f99d363-226e-4dca-9920-b807cf8e1a5f",
        "662802e2-50f6-46b0-aed2-e834bacc6d12",
        "3f2eb865-5811-4578-b90a-6fc6fa0df8e5",
        "0db238c4-885e-4c4f-a933-aa2cef684fca",
        "1e7ca9b1-60d1-4db8-a914-f2ca1ff27c40",
        "e503ece1-11d0-4e8e-8e2c-7a6c3bf38815",
        "bba48692-92b0-4667-a9ad-c31c7b334ac2",
        "08bbd89e-9f13-488c-ac41-acfcb10c90ab"
    ],
    "AllowedIdentityDisplayNames": [
        "MS-PIM"
    ],
    "ExemptedPIMGroupsPattern": "JIT_(.)*_ElevatedAccess"
}
 ```  

### Control Spec 

> **Passed:** 
> No permanent role assignments present at subscription level apart from explicitly allowed roles OR if no role assignment present in subscription.
> 
> **Failed:** 
> Any permanent role assignments present at subscription level apart from explicitly allowed roles.
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

### Azure Policies or REST APIs used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.type, [\*].roleDefinition.displayName, [\*].assignmentState, [\*].linkedEligibleRoleAssignmentId, [\*].memberType, [\*].subject.displayName
 <br />

- REST API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalType, [\*].properties.roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- REST API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
**Properties:** [\*].properties.role
 <br />

- Graph API to fetch additional details: - /myorganization/getObjectsByObjectIds?api-version=1.6&$select=objectType,objectId,displayName,userPrincipalName<br />
**Properties:** [\*].displayName
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG 

### Display Name 
Do not grant permanent access at Resource Group level

### Rationale 
Permanent access increase the risk of a malicious user getting that access and inadvertently impacting a sensitive resource. To minimize this risk ensure that critical resources present in resource group are accessed only by the legitimate users when required. PIM facilitates this by limiting users to only assume higher privileges in a just in time (JIT) manner (or by assigning privileges for a shortened duration after which privileges are revoked automatically). 

### Control Settings 
```json 
{
    "AllowedPIMRoles": [
        "Azure Front Door Domain Contributor",
        "Azure Front Door Domain Reader",
        "Azure Front Door Profile Reader",
        "Azure Front Door Secret Contributor",
        "Azure Front Door Secret Reader",
        "Defender for Storage Data Scanner",
        "AzureML Compute Operator",
        "Cognitive Services Usages Reader",
        "Key Vault Crypto Service Release User"
    ],
    "AllowedPIMRoleIds": [
        "0ab34830-df19-4f8c-b84e-aa85b8afa6e8",
        "0f99d363-226e-4dca-9920-b807cf8e1a5f",
        "662802e2-50f6-46b0-aed2-e834bacc6d12",
        "3f2eb865-5811-4578-b90a-6fc6fa0df8e5",
        "0db238c4-885e-4c4f-a933-aa2cef684fca",
        "1e7ca9b1-60d1-4db8-a914-f2ca1ff27c40",
        "e503ece1-11d0-4e8e-8e2c-7a6c3bf38815",
        "bba48692-92b0-4667-a9ad-c31c7b334ac2",
        "08bbd89e-9f13-488c-ac41-acfcb10c90ab"
    ],
    "AllowedIdentityDisplayNames": [
        "MS-PIM"
    ],
    "ExemptedPIMGroupsPattern": "JIT_(.)*_ElevatedAccess"
}
 ```  

### Control Spec 

> **Passed:** 
> If any of the below condition is satisfied:
> - No permanent role assignments present at resource group scope apart from explicitly allowed roles.
> - If no role assignment present at resource group scope.
> 
> **Failed:** 
>  Any permanent role assignments present at resource group scope.
> 
> **Verify:** 
> RBAC result not found (sufficient data is not available for evaluation).


### Recommendation 

- **PowerShell** 

	 ```powershell 
	 # Use Privileged Identity Management (PIM) to grant access to privileged roles at resource group scope
     Remove-AzRoleAssignment -SignInName '{signInName}' -Scope '/subscriptions/{subscriptionid}/resourceGroups/{resourceGroupName}' -RoleDefinitionName {RoleDefinitionName}
     # Refer https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/azure-pim-resource-rbac#assign-roles
	 ```  

### Azure Policies or REST APIs used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.type, [\*].roleDefinition.displayName, [\*].assignmentState, [\*].linkedEligibleRoleAssignmentId, [\*].memberType, [\*].subject.displayName
 <br />

- REST API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalType, [\*].properties.roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- REST API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
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

### Azure Policies or REST APIs used for evaluation 

- REST API to get the entire set of tags on a resource or subscription: - /{scope}/providers/Microsoft.Resources/tags/default?api-version=2019-10-01<br />
**Properties:** properties.tags
 <br />

- REST API to get resource group tags: - /subscriptions/{subscriptionId}/resourcegroups?api-version=2019-10-01 <br />
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

### Azure Policies or REST APIs used for evaluation 

- REST API to list Security Center pricing configurations in the subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2018-06-01 <br />
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

### Azure Policies or REST APIs used for evaluation 

- PIM API to get role assignments: - /beta/privilegedAccess/azureResources/resources/{uniquePIMIdentifier}/roleAssignments?$expand=subject,roleDefinition($expand=resource)&$filter=(memberType ne '{filterCondition}')<br />
**Properties:** [\*].subject.type, [\*].roleDefinition.displayName
 <br />

- REST API to list role assignment at scope: - /{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview <br />
**Properties:** [\*].properties.principalType, [\*].properties.roleDefinitionId (Role name resolved from roleDefinitionId)
 <br />

- REST API to list classic role assignment at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01<br />
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

### Azure Policies or REST APIs used for evaluation 

- REST API to list auto provisioning settings at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/autoProvisioningSettings/default?api-version=2017-08-01-preview <br />
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

### Azure Policies or REST APIs used for evaluation 

- REST API to list all security contact configurations for the subscription: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview <br />
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

## Azure_Subscription_AuthZ_Configure_Conditional_Access_for_PIM 

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
	  

### Azure Policies or REST APIs used for evaluation 

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

### Azure Policies or REST APIs used for evaluation 

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


### Azure Policies or REST APIs used for evaluation 

-  ARM API to list providers at subscription level: - "/subscriptions/{subscriptionId}/providers?api-version=2020-06-01&$select=namespace,registrationstate<br />
**Properties:** [\*].value.namespace , [\*].value.registrationState
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Use_SPNs_With_Password 

### Display Name 
 Do not use SPNs with password credentials to access subscriptions or resource groups in Azure 

### Rationale 
The purpose of the security control is to prevent the creation of Service Principal identities with secrets associated with them at the subscription or resource group level. This is because secrets, which are often simple string values, can be easily compromised and used by threat actors to gain access to the system.  

### Control Spec 

> **Passed:** 
> No Password Credentials/secret has been added to Service Principal having access on Subscription or Resource Group.
> 
> **Failed:** 
> Password Credentials/secret has been added to Service Principal having access on Subscription or Resource Group.
>

### Recommendation 

- **MS Documentation** 
  To read about removing the secret from SPN, Please visit https://learn.microsoft.com/en-us/graph/api/serviceprincipal-removepassword?view=graph-rest-1.0&tabs=http

- **PowerShell** 

	 ```powershell	 
        # Below commands will be useful to Read and Remove Password Credentials from Service Principals
        Connect-AzAccount
        Connect-AzureAD

        #To get the Service Principal/Enterprise Application's Password Credentials List. This list contains the Key Id and other details.
        $passwordCredentials = Get-AzureADServicePrincipalPasswordCredential -ObjectId "Enterprise Application Object Id"
	
        #Provide the Key Id of the Password Credentials which you want to remove.
        $spn = Remove-AzureADServicePrincipalPasswordCredential -ObjectId "Enterprise Application Object Id" -KeyId "Key Id of the credential"	
	 ```  
### Azure Policies or REST APIs used for evaluation 

- Graph API to fetch secret details: - /v1.0/servicePrincipals?$filter=id in ({ServicePrincipalObjectId})<br />
**Properties:** [\*].passwordCredentials
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Grant_SPNs_Privileged_Roles 

### Display Name 
 Service Principals must follow Least privilege principle for role assignments to Subscriptions 

### Rationale 
SPNs have a single credential and most scenarios that use them cannot support multi-factor authentication. Also, SPNs and Managed Identities can't be granted Just-In-Time access. As a result, adding SPNs to a Subscription with privileged roles is risky.  

### Control Spec 

> **Passed:** 
> Critical roles (Owner, Contributor or User Access Administrator) are not assigned to SPNs at subscription level.
> 
> **Failed:** 
> Critical roles (Owner, Contributor or User Access Administrator) are assigned to SPNs at subscription level.
>

### Recommendation 

- If these SPNs need access to your subscription, make sure you add them at the specific permission scope and role required for your scenario. For example, sometimes 'Contributor' access at 'Resource Group' scope might be sufficient. In other scenarios you may need 'Reader' access at 'Subscription' scope. Exact permission will vary based on your use case.

- **PowerShell** 

	 ```powershell	 
        # Below commands will be useful to remove privileged role assignments for SPNs
        Connect-AzAccount
        Connect-AzureAD
        
        #Provide the objectId, scope and role definition name to remove.
        $spn = Remove-AzRoleAssignment -ObjectId '{objectId}' -Scope '{scope}' -RoleDefinitionName '{role definition name}'
        # Run 'Get-Help Remove-AzRoleAssignment -full' for more help. 
	 ```  
### Azure Policies or REST APIs used for evaluation 

-  ARM API to list role assignment at subscription level: - /subscriptions/{subscriptionId}}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-07-01<br />
**Properties:** [\*].properties.scope , [\*].name
 <br />

<br />

___ 

## Azure_Subscription_AuthZ_Dont_Grant_SPNs_Privileged_Roles_RG 

### Display Name 
 Service Principals must follow Least privilege principle for role assignments to Resource Groups

### Rationale 
SPNs have a single credential and most scenarios that use them cannot support multi-factor authentication. Also, SPNs and Managed Identities can't be granted Just-In-Time access. As a result, adding SPNs to a Resource group with privileged roles is risky. 

### Control Spec 

> **Passed:** 
> Critical roles (Owner or User Access Administrator) are not assigned to SPNs at resource group level.
> 
> **Failed:** 
> Critical roles (Owner or User Access Administrator) are assigned to SPNs at resource group level.
>

### Recommendation 

- If these SPNs need access to your subscription, make sure you add them at the specific permission scope and role required for your scenario. For example, sometimes 'Contributor' access at 'Resource Group' scope might be sufficient. In other scenarios you may need 'Reader' access at 'Subscription' scope. Exact permission will vary based on your use case.

- **PowerShell** 

	 ```powershell	 
        # Below commands will be useful to remove privileged role assignments for SPNs
        Connect-AzAccount
        Connect-AzureAD
        
        #Provide the objectId, scope and role definition name to remove.
        $spn = Remove-AzRoleAssignment -ObjectId '{objectId}' -Scope '{scope}' -RoleDefinitionName '{role definition name}'
        # Run 'Get-Help Remove-AzRoleAssignment -full' for more help. 
	 ```  
### Azure Policies or REST APIs used for evaluation 

-  ARM API to list role assignment at subscription level: - /subscriptions/{subscriptionId}}/providers/Microsoft.Authorization/roleAssignments?api-version=2018-07-01<br />
**Properties:** [\*].properties.scope , [\*].name
 <br />

<br />

___ 

## Azure_Subscription_Config_Enable_MicrosoftDefender_Servers

### Display Name 
Microsoft Defender for Servers should be enabled on subscriptions

### Rationale 
Microsoft Defender for servers provides real-time threat protection for your server workloads and generates hardening recommendations as well as alerts about suspicious activities.

### Control Settings 
```json 
{
    "ReqMDCTier": "Standard",
    "ReqMDCTierResourceTypes": [
        {
            "Type": "VirtualMachines",
            "DisplayName": "Servers"
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> All required resource types are configured with MDC standard tier
> 
> **Failed:** 
> Any of the below condition is satisfied:
>   - Any of the required resource types is not configured with MDC standard tier.
>   - MDC Tier is not enabled on the Subscription.
>   - Fail if security center provider is not registered.
>   - The access to the security center settings via REST API is denied (ErrorCode such as DisallowedOperations).


### Recommendation 

- **Azure Portal** 
    
    To enable this plan on all servers in your subscription: From Defender for Cloud's 'Environment settings' page, select the relevant subscription. In the 'Defender plans' page, set 'Servers' to 'On'."


### Azure Policies or REST APIs used for evaluation 

- Rest API to get providers list with registration status for subscription level : - /subscriptions/{subscriptionId}/providers?api-version=2020-06-01&$select=namespace,registrationstate <br />
**Properties:** 
[\*].namespace, [\*].registrationState
<br />

- Rest API to get Security center pricing tier details for subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2023-01-01 <br />
**Properties:** 
[\*].name, [\*].properties.pricingTier, [\*].properties.subPlan
<br />

___ 



## Azure_Subscription_Config_Enable_MicrosoftDefender_Container

### Display Name 
Microsoft Defender for Containers should be enabled on subscriptions

### Rationale 
Microsoft Defender for Containers provides hardening, vulnerability assessment and run-time protections for your Azure, hybrid, and multi-cloud Kubernetes environments. You can use this information to quickly remediate security issues and improve the security of your containers.

### Control Settings 
```json 
{
    "ReqMDCTier": "Standard",
    "ReqMDCTierResourceTypes": [
        {
            "Type": "Containers",
            "DisplayName": "Containers"
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> All required resource types are configured with MDC standard tier
> 
> **Failed:** 
> Any of the below condition is satisfied:
>   - Any of the required resource types is not configured with MDC standard tier.
>   - MDC Tier is not enabled on the Subscription.
>   - Fail if security center provider is not registered.
>   - The access to the security center settings via REST API is denied (ErrorCode such as DisallowedOperations).


### Recommendation 

- **Azure Portal** 

    To enable this plan on all containers in your subscription: From Defender for Cloud's 'Environment settings' page, select the relevant subscription --> In the 'Defender plans' page, set 'Containers' to 'On'


### Azure Policies or REST APIs used for evaluation 

- Rest API to get providers list with registration status for subscription level : - /subscriptions/{subscriptionId}/providers?api-version=2020-06-01&$select=namespace,registrationstate <br />
**Properties:** 
[\*].namespace, [\*].registrationState
<br />

- Rest API to get Security center pricing tier details for subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2023-01-01 <br />
**Properties:** 
[\*].name, [\*].properties.pricingTier, [\*].properties.subPlan
<br />

___ 



## Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault

### Display Name 
Microsoft Defender for Key Vault should be enabled on subscriptions

### Rationale 
Microsoft Defender for Cloud includes Microsoft Defender for Key Vault, providing an additional layer of security intelligence. Microsoft Defender for Key Vault detects unusual and potentially harmful attempts to access or exploit Key Vault accounts.

### Control Settings 
```json 
{
    "ReqMDCTier": "Standard",
    "ReqMDCTierResourceTypes": [
        {
            "Type": "KeyVaults",
            "DisplayName": "Key Vault"
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> All required resource types are configured with MDC standard tier
> 
> **Failed:** 
> Any of the below condition is satisfied:
>   - Any of the required resource types is not configured with MDC standard tier.
>   - MDC Tier is not enabled on the Subscription.
>   - Fail if security center provider is not registered.
>   - The access to the security center settings via REST API is denied (ErrorCode such as DisallowedOperations).


### Recommendation 

- **Azure Portal** 
    
    To enable this plan on all key vaults in your subscription: From Defender for Cloud's 'Environment settings' page, select the relevant subscription --> In the 'Defender plans' page, set 'Key Vault' to 'On'


### Azure Policies or REST APIs used for evaluation 

- Rest API to get providers list with registration status for subscription level : - /subscriptions/{subscriptionId}/providers?api-version=2020-06-01&$select=namespace,registrationstate <br />
**Properties:** 
[\*].namespace, [\*].registrationState
<br />

- Rest API to get Security center pricing tier details for subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2023-01-01 <br />
**Properties:** 
[\*].name, [\*].properties.pricingTier, [\*].properties.subPlan
<br />
<br />

___ 



## Azure_Subscription_Config_Enable_MicrosoftDefender_Databases

### Display Name 
Microsoft Defender for Databases should be enabled on subscriptions

### Rationale 
Microsoft Defender for Databases allows you to protect your entire database estate with attack detection and threat response for the most popular database types in Azure. Defender for Cloud provides protection for the database engines and for data types, according to their attack surface and security risks.

### Control Settings 
```json 
{
    "ReqMDCTier": "Standard",
    "ReqMDCTierResourceTypes": [
        {
            "Type": "SqlServers",
            "DisplayName": "Azure SQL Databases"
        },
        {
            "Type": "SqlServerVirtualMachines",
            "DisplayName": "SQL servers on machines"
        },
        {
            "Type": "OpenSourceRelationalDatabases",
            "DisplayName": "Open-source relational databases"
        },
        {
            "Type": "CosmosDbs",
            "DisplayName": "Azure Cosmos DB"
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> All required resource types are configured with MDC standard tier
> 
> **Failed:** 
> Any of the below condition is satisfied:
>   - Any of the required resource types is not configured with MDC standard tier.
>   - MDC Tier is not enabled on the Subscription.
>   - Fail if security center provider is not registered.
>   - The access to the security center settings via REST API is denied (ErrorCode such as DisallowedOperations).


### Recommendation 

- **Azure Portal** 
    
    To enable this plan on all Databases in your subscription: From Defender for Cloud's 'Environment settings' page, select the relevant subscription --> In the 'Defender plans' page, set 'Databases' to 'On'. This will enable this plan for 'Azure SQL Databases', 'SQL servers on machines', 'Open-source relational databases' and 'Azure Cosmos DB'.


### Azure Policies or REST APIs used for evaluation 

- Rest API to get providers list with registration status for subscription level : - /subscriptions/{subscriptionId}/providers?api-version=2020-06-01&$select=namespace,registrationstate <br />
**Properties:** 
[\*].namespace, [\*].registrationState
<br />

- Rest API to get Security center pricing tier details for subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2023-01-01 <br />
**Properties:** 
[\*].name, [\*].properties.pricingTier, [\*].properties.subPlan
<br />
<br />

___ 



## Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager

### Display Name 
Microsoft Defender for Resource Manager should be enabled on subscriptions

### Rationale 
Microsoft Defender for Resource Manager automatically monitors the resource management operations in your organization. Defender for Cloud detects threats and alerts you about suspicious activity.

### Control Settings 
```json 
{
    "ReqMDCTier": "Standard",
    "ReqMDCTierResourceTypes": [
        {
            "Type": "Arm",
            "DisplayName": "Resource Manager"
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> All required resource types are configured with MDC standard tier
> 
> **Failed:** 
> Any of the below condition is satisfied:
>   - Any of the required resource types is not configured with MDC standard tier.
>   - MDC Tier is not enabled on the Subscription.
>   - Fail if security center provider is not registered.
>   - The access to the security center settings via REST API is denied (ErrorCode such as DisallowedOperations).
  - The access to the security center settings via REST API is denied (ErrorCode such as DisallowedOperations).

### Recommendation 

- **Azure Portal** 
    
    To enable Microsoft Defender for Resource Manager on your subscription: From Defender for Cloud's 'Environment settings' page, select the relevant subscription --> In the 'Defender plans' page, set 'Resource Manager' to 'On'.


### Azure Policies or REST APIs used for evaluation 

- Rest API to get providers list with registration status for subscription level : - /subscriptions/{subscriptionId}/providers?api-version=2020-06-01&$select=namespace,registrationstate <br />
**Properties:** 
[\*].namespace, [\*].registrationState
<br />

- Rest API to get Security center pricing tier details for subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2023-01-01 <br />
**Properties:** 
[\*].name, [\*].properties.pricingTier, [\*].properties.subPlan
<br />
<br />

___ 



## Azure_Subscription_Identity_Rotate_SPN_Credentials

### Display Name 
App Registrations and Service Principals credentials must be regularly rotated.

### Rationale 
SPNs having access to subscription must have secrets within maximum approved expiry time.

### Control Settings 
```json 
{
    "ExpirationPeriodInDays": 380,
    "ServicePrincipalTypeFilter": [ "Application", "Legacy" ]
}
 ```  

### Control Spec 

> **Passed:** 
>  No expired service principal secrets found.
> 
> **Failed:** 
>  At least one expired service principal secret found.


### Recommendation 

- **Azure Portal** 

    To remove credentials from app registration go to Azure Portal --> MicrosoftEntraId --> Under Manage select App registrations --> Under manage select 'Certificates and secrets' --> Select the certificate or secret --> Delete --> select Yes.

- **PowerShell** 

	 ```powershell 
	 #To remove credentials from service principal execute the below command:
        Remove-AzureADServicePrincipalKeyCredential -ObjectId <String> -KeyId <String>
	 ```  

    

### Azure Policies or REST APIs used for evaluation 

- Graph API to get service principal by object ids : - /v1.0/servicePrincipals?$filter={id} in ({objectId})&$expand=owners <br />
**Properties:** 
[\*].ServicePrincipalDetails.passwordCredentials, [\*].objectId
<br />

- Graph API to get object by ids : /v1.0/directoryObjects/getByIds <br/>
**Properties:**
[\*].ServicePrincipalDetails.passwordCredentials, [\*].objectId
<br />

- Graph API to get app registration by app ids: - /v1.0/applications?$filter=appId in ({appIds})&$expand=owners <br />
**Properties:** 
[\*].ServicePrincipalDetails.passwordCredentials, [\*].objectId
<br />

___ 



## Azure_Subscription_Config_Enable_MicrosoftDefender_AppService

### Display Name 
Microsoft Defender for App Service should be enabled on subscriptions

### Rationale 
Microsoft Defender for App Service leverages the scale of the cloud, and the visibility that Azure has as a cloud provider, to monitor for common web app attacks.

### Control Settings 
```json 
{
    "ReqMDCTier": "Standard",
    "ReqMDCTierResourceTypes": [
        {
            "Type": "AppServices",
            "DisplayName": "App Service"
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> All required resource types are configured with MDC standard tier
> 
> **Failed:** 
> Any of the below condition is satisfied:
>   - Any of the required resource types is not configured with MDC standard tier.
>   - MDC Tier is not enabled on the Subscription.
>   - Fail if security center provider is not registered.
>   - The access to the security center settings via REST API is denied (ErrorCode such as DisallowedOperations).


### Recommendation 

- **Azure Portal** 
    
    To enable this plan on all App Services in your subscription: From Defender for Cloud's 'Environment settings' page, select the relevant subscription --> In the 'Defender plans' page, set 'App Service' to 'On'.


### Azure Policies or REST APIs used for evaluation 

- Rest API to get providers list with registration status for subscription level : - /subscriptions/{subscriptionId}/providers?api-version=2020-06-01&$select=namespace,registrationstate <br />
**Properties:** 
[\*].namespace, [\*].registrationState
<br />

- Rest API to get Security center pricing tier details for subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2023-01-01 <br />
**Properties:** 
[\*].name, [\*].properties.pricingTier, [\*].properties.subPlan
<br />

___ 
## Azure_Subscription_Config_Enable_MicrosoftDefender_Storage

### Display Name 
Microsoft Defender for Storage should be enabled on subscriptions

### Rationale 
Microsoft Defender for storage detects unusual and potentially harmful attempts to access or exploit storage accounts.

### Control Settings 
```json 
{
    "ReqMDCTier": "Standard",
    "ReqMDCTierResourceTypes": [
        {
            "Type": "StorageAccounts",
            "DisplayName": "Storage",
            "ReqMDCSubPlan": "DefenderForStorageV2"
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> All required resource types are configured with MDC standard tier
> 
> **Failed:** 
> Any of the below condition is satisfied:
>   - Any of the required resource types is not configured with MDC standard tier.
>   - MDC Tier is not enabled on the Subscription.
>   - Fail if security center provider is not registered.
>   - The access to the security center settings via REST API is denied (ErrorCode such as DisallowedOperations).


### Recommendation 

- **Azure Portal** 

    To enable this plan on all Azure Storage accounts in your subscription:From Defender for Cloud's 'Environment settings' page, select the relevant subscription. In the 'Defender plans' page, set 'Storage' to 'On'.


### Azure Policies or REST APIs used for evaluation 


- Rest API to get providers list with registration status for subscription level : - /subscriptions/{subscriptionId}/providers?api-version=2020-06-01&$select=namespace,registrationstate <br />
**Properties:** 
[\*].namespace, [\*].registrationState
<br />

- Rest API to get Security center pricing tier details for subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2023-01-01 <br />
**Properties:** 
[\*].name, [\*].properties.pricingTier, [\*].properties.subPlan
<br />

___ 

## Azure_Subscription_Config_Enable_MicrosoftDefender_CSPM

### Display Name 
Microsoft Defender CSPM must be enabled on subscriptions

### Rationale 
Microsoft Defender CSPM provides advanced security posture capabilities including agentless vulnerability scanning, data-aware security posture, the cloud security graph, and advanced threat hunting.

### Control Settings 
```json 
{
    "ReqMDCTier": "Standard",
    "ReqMDCTierResourceTypes": [
      {
        "Type": "CloudPosture",
        "DisplayName": "Defender CSPM",
        "ReqMDCExtensions": [
          "SensitiveDataDiscovery",
          "ContainerRegistriesVulnerabilityAssessments",
          "AgentlessDiscoveryForKubernetes",
          "AgentlessVmScanning",
          "EntraPermissionsManagement"
        ]
      }
}
 ```  

### Control Spec 

> **Passed:** 
> All required resource types are configured with MDC standard tier and MDC Extensions
> 
> **Failed:** 
> Any of the below condition is satisfied:
>   - Any of the required resource types is not configured with MDC standard tier.
>   - MDC Tier is not enabled on the Subscription.
    - MDC Extensions is not enabled on the Subscription.
>   - Fail if security center provider is not registered.
>   - The access to the security center settings via REST API is denied (ErrorCode such as DisallowedOperations).


### Recommendation 

- **Azure Portal** 

    To enable Microsoft Defender CSPM on your subscription: From Defender for Cloud's 'Environment settings' page, select the relevant subscription --> In the 'Defender plans' page, set 'Defender CSPM' to 'On'"


### Azure Policies or REST APIs used for evaluation 


- Rest API to get providers list with registration status for subscription level : - /subscriptions/{subscriptionId}/providers?api-version=2020-06-01&$select=namespace,registrationstate <br />
**Properties:** 
[\*].namespace, [\*].registrationState
<br />

- Rest API to get Security center pricing tier details for subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2023-01-01 <br />
**Properties:** 
[\*].name, [\*].properties.pricingTier, [\*].properties.subPlan
<br />

___ 

## Azure_Subscription_Config_Enable_MicrosoftDefender_API

### Display Name
Subscription must enable Microsoft Defender for APIs

### Rationale  
Microsoft Defender for APIs provides comprehensive security monitoring, threat detection, and vulnerability assessment for API endpoints, ensuring protection against API-specific attacks and compliance with security standards.

### Control Settings 
```json
{
  "RequireDefenderForAPIs": true,
  "EnableThreatDetection": true,
  "RequireVulnerabilityAssessment": true,
  "MonitorAPITraffic": true
}
```

### Control Spec  
- **Passed:** Microsoft Defender for APIs is enabled and configured
- **Failed:** Defender for APIs is not enabled

### Recommendation
```powershell
# Enable Microsoft Defender for APIs
Set-AzSecurityPricing -Name "Api" -PricingTier "Standard"
```

### Control Evaluation Details:
- **Method Name:** CheckMicrosoftDefenderAPI
- **Control Severity:** Medium
- **Evaluation Frequency:** Daily

<br />

___

## Azure_Subscription_AuthZ_Expired_SPN_Certificates

### Display Name
Subscription must not have service principals with expired certificates

### Rationale
Expired certificates for service principals can cause service disruptions and security vulnerabilities. Regular monitoring and renewal of certificates ensures continuous service availability and maintains security posture.

### Control Settings 
```json
{
  "MaxCertificateAge": 365,
  "WarningThreshold": 30,
  "RequireAutomaticRenewal": true,
  "AllowSelfSignedCerts": false
}
```

### Control Spec
- **Passed:** No service principals with expired certificates
- **Failed:** Service principals with expired or expiring certificates found

### Recommendation
```powershell
# Find and remediate expired SPN certificates
$expiredSPNs = Get-AzADServicePrincipal | Where-Object {
    $_.PasswordCredentials.Count -eq 0 -and 
    $_.KeyCredentials.EndDateTime -lt (Get-Date)
}

foreach ($spn in $expiredSPNs) {
    Write-Warning "Expired certificate found for SPN: $($spn.DisplayName)"
    # Generate new certificate and update SPN
}
```

### Control Evaluation Details:
- **Method Name:** CheckExpiredSPNCertificates
- **Control Severity:** High
- **Evaluation Frequency:** Daily

<br />

___

## Azure_Subscription_AuthZ_Dont_Grant_NonAllowed_Broad_Groups

### Display Name
Subscription must not grant permissions to overly broad or non-allowed groups

### Rationale
Granting permissions to overly broad groups (like "All Users" or large organizational groups) violates the principle of least privilege and creates unnecessary security risks. Access should be granted to specific, purpose-built groups with appropriate membership.

### Control Settings
```json
{
  "RestrictBroadGroups": true,
  "ProhibitedGroups": ["All Users", "Everyone", "Domain Users"],
  "MaxGroupSize": 100,
  "RequireApprovedGroups": true,
  "AllowedGroupPatterns": ["AZ-*", "Azure-*"]
}
```

### Control Spec
- **Passed:** No overly broad or prohibited groups have subscription access
- **Failed:** Broad or non-allowed groups have subscription permissions

### Recommendation  

### Audit and Remove Broad Groups:
```powershell
# Identify broad groups with subscription access
$broadGroups = @("All Users", "Everyone", "Domain Users", "Authenticated Users")
$subscriptionScope = "/subscriptions/$((Get-AzContext).Subscription.Id)"

$groupAssignments = Get-AzRoleAssignment -Scope $subscriptionScope | Where-Object {
    $_.ObjectType -eq "Group" -and
    ($_.DisplayName -in $broadGroups -or $_.DisplayName -like "*All*" -or $_.DisplayName -like "*Everyone*")
}

# Remove broad group assignments
foreach ($assignment in $groupAssignments) {
    Remove-AzRoleAssignment -ObjectId $assignment.ObjectId -RoleDefinitionName $assignment.RoleDefinitionName -Scope $assignment.Scope
}
```

### Create Purpose-Built Groups:
```powershell
# Create specific Azure groups with proper naming
$azureGroups = @{
    "AZ-Subscription-Readers" = @{ Role = "Reader"; Members = @("user1@contoso.com") }
    "AZ-ResourceGroup-Contributors" = @{ Role = "Contributor"; Members = @("dev-team@contoso.com") }
}

foreach ($groupConfig in $azureGroups.GetEnumerator()) {
    $group = New-AzADGroup -DisplayName $groupConfig.Key -MailEnabled $false -SecurityEnabled $true
    # Add members and assign role (detailed implementation available in full script)
    New-AzRoleAssignment -ObjectId $group.Id -RoleDefinitionName $groupConfig.Value.Role -Scope $subscriptionScope
}
```

### Monitor and Validate:
```kusto
// Monitor large groups
SecurityResources | where type == "microsoft.graph/groups" and toint(properties.memberCount) > 100
```

### Best Practices:
- Use naming convention: AZ-* or Azure-*
- Limit group size to <100 members
- Regular quarterly reviews
- Assign clear group owners

### Remediation Steps:
1. Audit existing group assignments
2. Create specific replacement groups
3. Migrate users to new groups
4. Remove broad group access

### Azure Policies or REST APIs used for evaluation  
- **List role assignments:** `/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments`
- **Get group details:** Microsoft Graph API for group membership analysis

### Control Evaluation Details:
- **Method Name:** CheckBroadGroupAccess
- **Control Severity:** Medium
- **Evaluation Frequency:** Weekly
- **Baseline Control:** Yes

<br />

___

## Azure_Subscription_AuthZ_Dont_Grant_NonAD_Identities_Privileged_Roles_RG

### Display Name
Subscription must not grant privileged roles to non-Azure AD identities at resource group level

### Rationale
Granting privileged roles to non-Azure AD identities (external users, guest accounts) at resource group level increases security risks and reduces visibility into access patterns. Azure AD identities provide better governance, audit trails, and access management capabilities.

### Control Settings
```json
{
  "RestrictNonADIdentities": true,
  "PrivilegedRoles": ["Owner", "Contributor", "User Access Administrator"],
  "AllowedExceptions": [],
  "RequireJustification": true
}
```

### Control Spec
- **Passed:** No privileged roles assigned to non-Azure AD identities at RG level
- **Failed:** Non-Azure AD identities have privileged roles assigned

### Recommendation  

### Audit and Remove Non-AD Assignments:
```powershell
# Find and remove non-Azure AD identities with privileged roles
$privilegedRoles = @("Owner", "Contributor", "User Access Administrator")
$nonADAssignments = @()

foreach ($rg in Get-AzResourceGroup) {
    $assignments = Get-AzRoleAssignment -Scope $rg.ResourceId | Where-Object {
        $_.RoleDefinitionName -in $privilegedRoles -and
        ($_.SignInName -like "*#EXT#*" -or $_.ObjectType -eq "Unknown" -or $_.SignInName -like "*live.com*")
    }
    
    foreach ($assignment in $assignments) {
        # Remove non-AD privileged assignment
        Remove-AzRoleAssignment -ObjectId $assignment.ObjectId -RoleDefinitionName $assignment.RoleDefinitionName -Scope $assignment.Scope
        Write-Warning "Removed $($assignment.DisplayName) from $($assignment.RoleDefinitionName) in $($rg.ResourceGroupName)"
    }
}
```

### Replace with Azure AD Identities:
```powershell
# Replace with Azure AD users/groups
$azureADReplacements = @{
    "external.user@company.com" = "internal.user@contoso.com"
    "guest.account@external.com" = "AzureAD-Group-Name"
}

foreach ($replacement in $azureADReplacements.GetEnumerator()) {
    $target = Get-AzADUser -UserPrincipalName $replacement.Value -ErrorAction SilentlyContinue
    if (-not $target) { $target = Get-AzADGroup -DisplayName $replacement.Value }
    
    if ($target) {
        New-AzRoleAssignment -ObjectId $target.Id -RoleDefinitionName "Contributor" -ResourceGroupName $resourceGroupName
    }
}
```

### Monitor with KQL:
```kusto
// Find non-Azure AD identities with privileged roles
authorizationresources
| where type == "microsoft.authorization/roleassignments"
| where properties.roleDefinitionId has_any ("8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "b24988ac-6180-42a0-ab88-20f7382dd24c")
| where properties.scope startswith "/subscriptions/{subscription-id}/resourceGroups/"
| where properties.principalType == "User"
```

### Best Practices:
- Regular audits of role assignments
- Use Azure AD groups instead of individual assignments
- Implement Just-in-Time access with PIM
- Document and regularly review any exceptions

### Azure Policies or REST APIs used for evaluation  
- **List role assignments:** `/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments`
- **Evaluated Properties:** Principal type, role definition, and scope analysis

### Control Evaluation Details:
- **Method Name:** CheckNonADPrivilegedRoles
- **Control Severity:** High
- **Evaluation Frequency:** Daily
- **Baseline Control:** Yes

___

## Azure_Subscription_AuthZ_Configure_ConditionalAccess_For_PIM

### Display Name
Configure Conditional Access for Privileged Identity Management (PIM)

### Rationale
Conditional Access policies provide an additional layer of security by enforcing access controls on privileged operations. Requiring Conditional Access for Privileged Identity Management (PIM) ensures that only authorized users under specific conditions (such as compliant devices, MFA, or trusted locations) can activate privileged roles. This reduces the risk of unauthorized privilege escalation and supports compliance with standards such as ISO 27001, NIST SP 800-53, and CIS Controls.

### Control Spec

> **Passed:**
> - Conditional Access policies are configured and enforced for all PIM role activations in the Azure AD tenant.
> - Policies require controls such as Multi-Factor Authentication (MFA), compliant device, or trusted network location for PIM role activation.
>
> **Failed:**
> - No Conditional Access policy is assigned to PIM role activation.
> - Conditional Access policies are assigned but do not enforce strong authentication or device compliance for PIM role activation.

### Recommendation

- **Azure Portal**
    1. Sign in to the [Azure Portal](https://portal.azure.com).
    2. Navigate to **Azure Active Directory** > **Security** > **Conditional Access**.
    3. Select **New policy**.
    4. Set **Assignments**:
        - **Users or workload identities**: Select the users or groups eligible for PIM.
        - **Cloud apps or actions**: Select **Azure AD Privileged Identity Management**.
    5. Under **Grant**, require controls such as **Require multi-factor authentication** and/or **Require device to be marked as compliant**.
    6. Enable the policy and click **Create**.

- **PowerShell**
    ```powershell
    # Install the AzureAD module if not already installed
    Install-Module -Name AzureAD

    # Connect to Azure AD
    Connect-AzureAD

    # Example: Create a Conditional Access policy for PIM activation (requires MS Graph API)
    # Note: Detailed policy creation requires Microsoft Graph PowerShell module and advanced scripting.
    ```

- **Azure CLI**
    ```bash
    # Azure CLI does not currently support direct Conditional Access policy management.
    # Use Microsoft Graph API or PowerShell for automation.
    ```

- **Automation/Remediation**
    - Use [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0) to automate Conditional Access policy creation.
    - Azure Policy and ARM templates do not currently support Conditional Access policy deployment.
    - For bulk or tenant-wide remediation, use AzTS (Azure Tenant Security) scripts if available, or automate via Microsoft Graph SDK.

    **Sample Microsoft Graph API request:**
    ```http
    POST https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies
    Content-Type: application/json

    {
      "displayName": "Require MFA for PIM Activation",
      "state": "enabled",
      "conditions": {
        "users": {
          "includeGroups": ["<PIM-eligible-group-object-id>"]
        },
        "applications": {
          "includeApplications": ["0000000c-0000-0000-c000-000000000000"] // Azure AD PIM app ID
        }
      },
      "grantControls": {
        "operator": "AND",
        "builtInControls": ["mfa"]
      }
    }
    ```

### Azure Policies or REST APIs used for evaluation

- REST API: [Microsoft Graph API - Conditional Access Policy](https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies)<br />
**Properties:** `displayName`, `state`, `conditions.users`, `conditions.applications`, `grantControls`

<br/>

___

___

## Azure_Subscription_AuthZ_SPN_Owners_Governance

### Display Name
Restrict Subscription Owner Role Assignments to Service Principals and Non-Human Identities

### Rationale
Limiting the assignment of the Owner role at the subscription level to only authorized service principals and non-human identities is a critical security control. This reduces the risk of privilege escalation, accidental or malicious changes, and helps enforce least privilege access. By ensuring that only approved identities have Owner rights, organizations can maintain better governance, comply with regulatory requirements (such as ISO 27001, NIST, and CIS), and reduce the attack surface for their Azure environment.

### Control Spec

> **Passed:**
> - No human user accounts (e.g., UPNs, guest users) are assigned the Owner role at the subscription scope.
> - Only authorized service principals, managed identities, or break-glass accounts are assigned the Owner role.
>
> **Failed:**
> - One or more human user accounts are assigned the Owner role at the subscription scope.
> - Unapproved or excessive Owner assignments exist, including to guest users or external identities.

### Recommendation

- **Azure Portal**
    1. Navigate to **Subscriptions** in the Azure Portal.
    2. Select the target subscription.
    3. Go to **Access control (IAM)** > **Role assignments**.
    4. Filter by **Owner** role.
    5. Review the list of assigned identities.
    6. Remove the Owner role from any human user accounts or unapproved identities:
        - Click the ellipsis (...) next to the assignment.
        - Select **Remove**.

- **PowerShell**
    ```powershell
    # List all Owner assignments at the subscription scope
    Get-AzRoleAssignment -Scope "/subscriptions/<subscriptionId>" | Where-Object { $_.RoleDefinitionName -eq "Owner" }

    # Remove Owner role from a specific user
    Remove-AzRoleAssignment -ObjectId <userObjectId> -RoleDefinitionName "Owner" -Scope "/subscriptions/<subscriptionId>"
    ```

- **Azure CLI**
    ```bash
    # List all Owner assignments at the subscription scope
    az role assignment list --scope "/subscriptions/<subscriptionId>" --role "Owner"

    # Remove Owner role from a specific user
    az role assignment delete --assignee <userObjectId> --role "Owner" --scope "/subscriptions/<subscriptionId>"
    ```

- **Automation/Remediation**
    - **Azure Policy**: There is no built-in Azure Policy to restrict Owner assignments to only service principals, but you can use Azure Policy to audit role assignments and alert on non-compliant assignments.
    - **Custom Script**: Implement automation using Azure Functions, Logic Apps, or scheduled PowerShell/Azure CLI scripts to regularly audit and remediate Owner assignments.
    - **AzTS (Azure Tenant Security)**: If using AzTS, leverage its built-in controls to detect and remediate unauthorized Owner assignments across subscriptions.
    - **Bulk Remediation**: Use PowerShell or Azure CLI scripts in a loop to process multiple subscriptions for tenant-wide compliance.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01-preview`  
**Properties:**  
- `roleDefinitionId` (should match Owner role definition)
- `principalType` (should be ServicePrincipal, ManagedIdentity, or explicitly approved identities)
- `principalId` (cross-reference with directory to determine user vs. service principal)

<br/>

___

___

## Azure_Subscription_AuthZ_Use_Only_Alt_Credentials

### Display Name
Use Only Alternative Credentials for Authorization

### Rationale
Limiting authorization to only alternative credentials (such as managed identities or service principals) reduces the risk of credential compromise and enforces stronger access control. This control helps ensure that user accounts and shared credentials are not used for automated processes, thereby improving the security posture of your Azure subscription. Adhering to this practice supports compliance with standards such as ISO 27001, NIST SP 800-53, and Azure CIS benchmarks, which require strong identity and access management.

### Control Spec

> **Passed:**
> - All automated processes and applications use only alternative credentials (e.g., managed identities, service principals) for authorization within the subscription.
> - No user accounts or shared credentials are used for automation or programmatic access.
>
> **Failed:**
> - Any automated process or application uses user accounts or shared credentials for authorization.
> - Alternative credentials are not enforced for automation or programmatic access.

### Recommendation

- **Azure Portal**
    1. Navigate to **Azure Active Directory** > **App registrations**.
    2. Register applications and assign appropriate roles using managed identities or service principals.
    3. Review **Access control (IAM)** on your subscription to ensure only alternative credentials are granted access for automation.
    4. Remove any user accounts or shared credentials from role assignments used by automated processes.

- **PowerShell**
    ```powershell
    # List role assignments for the subscription
    Get-AzRoleAssignment -Scope "/subscriptions/<subscriptionId>"

    # Remove user account assignments for automation
    Remove-AzRoleAssignment -ObjectId <UserObjectId> -RoleDefinitionName "<RoleName>" -Scope "/subscriptions/<subscriptionId>"

    # Assign a managed identity or service principal
    New-AzRoleAssignment -ObjectId <ServicePrincipalObjectId> -RoleDefinitionName "<RoleName>" -Scope "/subscriptions/<subscriptionId>"
    ```

- **Azure CLI**
    ```bash
    # List role assignments
    az role assignment list --scope /subscriptions/<subscriptionId>

    # Remove user assignment
    az role assignment delete --assignee <userPrincipalName or objectId> --role "<RoleName>" --scope /subscriptions/<subscriptionId>

    # Assign role to service principal or managed identity
    az role assignment create --assignee <servicePrincipalId> --role "<RoleName>" --scope /subscriptions/<subscriptionId>
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce the use of managed identities for Azure resources:
      ```json
      {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.Compute/virtualMachines"
            },
            {
              "not": {
                "field": "identity.type",
                "equals": "SystemAssigned"
              }
            }
          ]
        },
        "then": {
          "effect": "deny"
        }
      }
      ```
    - Use AzTS (Azure Tenant Security) scripts to audit and remediate role assignments at scale.
    - Implement ARM templates to deploy resources with managed identities by default.

### Azure Policies or REST APIs used for evaluation

- REST API: `https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01`  
**Properties:**  
- `principalType` (should be `ServicePrincipal` or `ManagedIdentity` for automation)
- `principalId`
- `roleDefinitionId`
- `scope`

<br/>

___

___

## Azure_Subscription_Config_Enable_MicrosoftDefender_AIServices

### Display Name
Enable Microsoft Defender for AI Services on subscriptions

### Rationale
Enabling Microsoft Defender for AI Services provides advanced threat protection for Azure AI resources such as Azure Machine Learning, Cognitive Services, and related workloads. This control ensures that AI workloads are continuously monitored for security threats, anomalous activities, and potential misuse, helping organizations meet compliance requirements and reduce the risk of data breaches or abuse of AI resources.

### Control Spec

> **Passed:**
> - Microsoft Defender for AI Services is enabled at the subscription level for all supported AI resources.
>
> **Failed:**
> - Microsoft Defender for AI Services is not enabled at the subscription level, or is only partially enabled for supported AI resources.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure Portal.
    2. Go to **Microsoft Defender for Cloud**.
    3. Select **Environment settings** and choose your subscription.
    4. Under **Defender plans**, ensure **AI Services** is set to **On**.
    5. Click **Save** to apply changes.

- **PowerShell**
    ```powershell
    # Install the Az.Security module if needed
    Install-Module -Name Az.Security

    # Enable Microsoft Defender for AI Services at the subscription level
    $subscriptionId = "<your-subscription-id>"
    Set-AzSecurityPricing -Name "AIServices" -PricingTier "Standard" -SubscriptionId $subscriptionId
    ```

- **Azure CLI**
    ```bash
    # Enable Microsoft Defender for AI Services using Azure CLI
    az security pricing create --name "AIServices" --tier "Standard" --subscription <your-subscription-id>
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce Microsoft Defender for AI Services across all subscriptions:
        ```json
        {
          "if": {
            "field": "Microsoft.Security/pricings.name",
            "equals": "AIServices"
          },
          "then": {
            "effect": "deployIfNotExists",
            "details": {
              "type": "Microsoft.Security/pricings",
              "name": "AIServices",
              "properties": {
                "pricingTier": "Standard"
              }
            }
          }
        }
        ```
    - For bulk or tenant-wide enablement, use Azure Policy Assignments or Azure Blueprints to ensure Defender for AI Services is enabled on all current and future subscriptions.
    - For organizations using AzTS (Azure Tenant Security), refer to AzTS bulk remediation scripts to enable Defender for AI Services across multiple subscriptions.

### Azure Policies or REST APIs used for evaluation

- REST API: `PUT https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings/AIServices?api-version=2020-01-01`<br />
**Properties:** `properties.pricingTier` (should be set to `Standard`)

<br/>

___

___

## Azure_Subscription_DP_Avoid_Plaintext_Secrets_Deployments

### Display Name
Avoid deployment of secrets in plaintext within Azure subscription resources

### Rationale
Storing secrets such as passwords, connection strings, or API keys in plaintext within resource configurations or deployment templates exposes them to unauthorized access, increasing the risk of data breaches and non-compliance with security standards such as ISO 27001, NIST, and PCI DSS. Azure recommends using secure mechanisms like Azure Key Vault to manage and reference secrets, thereby ensuring confidentiality and integrity of sensitive information.

### Control Spec

> **Passed:**
> No secrets (e.g., passwords, connection strings, API keys) are found in plaintext within resource properties, deployment templates, or parameter files. All secrets are referenced securely, such as via Azure Key Vault references.
>
> **Failed:**
> Secrets are detected in plaintext within resource configurations, deployment templates, or parameters. Examples include hardcoded passwords, connection strings, or API keys directly in ARM/Bicep templates or resource properties.

### Recommendation

- **Azure Portal**
    1. Review all deployment templates and resource configurations for hardcoded secrets.
    2. Replace any plaintext secrets with Azure Key Vault references.
    3. For parameters that require secrets, use the "Reference" function to securely fetch values from Key Vault.

- **PowerShell**
    ```powershell
    # Example: Reference a secret from Azure Key Vault in an ARM template deployment
    $keyVaultId = "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>"
    $secretName = "<secret-name>"

    $templateParameter = @{
        "adminPassword" = @{
            "reference" = @{
                "keyVault" = @{
                    "id" = $keyVaultId
                }
                "secretName" = $secretName
            }
        }
    }

    New-AzResourceGroupDeployment -ResourceGroupName <rg> -TemplateFile <template.json> -TemplateParameterObject $templateParameter
    ```

- **Azure CLI**
    ```bash
    # Example: Deploy ARM template using Key Vault secret reference
    az deployment group create \
      --resource-group <rg> \
      --template-file <template.json> \
      --parameters adminPassword="{'reference':{'keyVault':{'id':'/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>'},'secretName':'<secret-name>'}}"
    ```

- **Automation/Remediation**
    - **Azure Policy:** Assign the built-in policy definition `Do not allow hardcoded secrets in resource properties` to audit and deny deployments containing plaintext secrets.
    - **ARM Template Example:** Use `reference` objects for secret parameters instead of string literals.
    - **Bulk Remediation:** Use Azure Policy remediation tasks to identify and remediate resources with hardcoded secrets.
    - **AzTS Remediation:** If using Azure Tenant Security (AzTS), run the bulk remediation script to scan for and replace plaintext secrets with Key Vault references.

### Azure Policies or REST APIs used for evaluation

- REST API: `https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01`
  <br />
  **Properties:** Resource properties and deployment template parameters are scanned for patterns matching secrets (e.g., "password", "connectionString", "apiKey") and checked for plaintext values.

<br/>

___

___

## Azure_Subscription_DP_Avoid_Plaintext_Secrets_Tags

### Display Name
Avoid storing plaintext secrets in resource tags

### Rationale
Storing sensitive information such as passwords, secrets, or connection strings in resource tags exposes them to unauthorized access and increases the risk of data leakage. Tags are not designed for storing confidential data and are accessible to users with read permissions on the resource. This control enforces best practices for data protection and helps organizations comply with security standards such as ISO 27001, NIST, and CIS by ensuring that secrets are not inadvertently exposed through metadata.

### Control Spec

> **Passed:**
> No resource tags at the subscription level or within resources contain values that match common patterns for secrets, passwords, or connection strings (e.g., values containing "password", "secret", "key", "connectionstring", etc.).
>
> **Failed:**
> One or more resource tags contain values that appear to be plaintext secrets, such as passwords, API keys, or connection strings.

### Recommendation

- **Azure Portal**
    1. Navigate to the Azure Portal.
    2. Go to **Subscriptions** and select the relevant subscription.
    3. Review the tags applied at the subscription and resource levels.
    4. Remove or update any tags containing sensitive information (e.g., secrets, passwords, keys, or connection strings).
    5. Save the changes.

- **PowerShell**
    ```powershell
    # List all tags at the subscription level
    Get-AzTag -ResourceId "/subscriptions/<subscriptionId>"

    # List tags for all resources in a subscription
    Get-AzResource | ForEach-Object {
        Write-Output "$($_.Name): $($_.Tags)"
    }

    # Remove a tag containing sensitive information from a resource
    Remove-AzTag -ResourceId "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/<resourceProvider>/<resourceType>/<resourceName>" -TagName "<SensitiveTagName>"
    ```

- **Azure CLI**
    ```bash
    # List all tags at the subscription level
    az tag list --resource-id /subscriptions/<subscriptionId>

    # List tags for all resources in a subscription
    az resource list --query "[].{name:name, tags:tags}"

    # Remove a tag containing sensitive information from a resource
    az tag remove --resource-id /subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/<resourceProvider>/<resourceType>/<resourceName> --tag <SensitiveTagName>
    ```

- **Automation/Remediation**
    - Implement Azure Policy to deny or audit the creation of tags containing sensitive keywords:
        ```json
        {
          "properties": {
            "displayName": "Audit resource tags that may contain secrets",
            "policyType": "Custom",
            "mode": "All",
            "description": "Audit resource tags that contain values matching common secret patterns.",
            "parameters": {},
            "policyRule": {
              "if": {
                "anyOf": [
                  {
                    "field": "tags",
                    "contains": "password"
                  },
                  {
                    "field": "tags",
                    "contains": "secret"
                  },
                  {
                    "field": "tags",
                    "contains": "key"
                  },
                  {
                    "field": "tags",
                    "contains": "connectionstring"
                  }
                ]
              },
              "then": {
                "effect": "audit"
              }
            }
          }
        }
        ```
    - Use Azure Policy assignments at the subscription or management group level to enforce this control.
    - For bulk remediation, use scripts to scan all tags and remove or redact those containing sensitive patterns.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resources?api-version=2021-04-01`
  <br />
  **Properties:** `tags` (key-value pairs for each resource)

<br/>

___
