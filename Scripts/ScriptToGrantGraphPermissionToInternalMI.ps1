<#

    .PREREQUISITE Permission
        The signed-in user must be a member of one of the following administrator roles on Azure AD: Global Administrator, Privileged Role Administrator, Application Administrator or Cloud Application Administrator.


    .PREREQUISITE Dependent PowerShell Module
        Required version: AzureAD >= 2.0.2.130
        Installation command: Install-Module -Name AzureAD -AllowClobber -Scope CurrentUser -repository PSGallery
#>


# Initialize required parameters

# Your tenant ID (in the Azure portal, under Azure Active Directory > Overview).
$TenantID="<tenant-id>"

# Object id of the internal managed identity
$InternalMIObjectId = "<UserAssignedIdentityObjectId>"

# Connect to Azure AD
Connect-AzureAD -TenantId $TenantID

# Get the service principal for Microsoft Graph and Azure AD Graph.
$GraphServicePrincipal = Get-AzureADServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"

# 1. Assign permissions to the internal managed identity service principal.
    # 1.a. Assign permission to Microsoft Graph
    Write-Host  "Assign internal MI [$($InternalMIObjectId)] 'User.Read.All' access to Microsoft Graph" -ForegroundColor Cyan
    $PermissionName = 'User.Read.All'
    $AppRoles = @($GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application" })
    $AppRoles | ForEach-Object {
        
        New-AzureAdServiceAppRoleAssignment -ObjectId $InternalMIObjectId -PrincipalId $InternalMIObjectId -ResourceId $GraphServicePrincipal.ObjectId -Id $_.Id
    }
