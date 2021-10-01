<# ********************* Script execution guidance *******************

    .PREREQUISITE Permission
        The signed-in user must be a member of one of the following administrator roles on Azure AD: Global Administrator or Privileged Role Administrator.

    .PREREQUISITE Install AzureAD module. (Required version: AzureAD >= 2.0.2.130)
        Example command: Install-Module -Name AzureAD -AllowClobber -Scope CurrentUser -repository PSGallery


    .EXECUTION INSTRUCTION

      To run this script,
          1. Clear existing login, if any using below command: Disconnect-AzureAD
          2. Connect to AzureAD using below command: Connect-AzureAD -TenantId $TenantId
          3. Initialize the parameters and press F5 to run the script.

#>


# ************** Start: Initialize required parameters ******************** #

# Your tenant ID (in the Azure portal, under Azure Active Directory > Overview).
$TenantID="<tenant-id>"

# Object id of the internal managed identity
$InternalMIObjectId = "<UserAssignedIdentityObjectId>"

# ************** End: Initialize required parameters ******************** #

# Load helper functions
function LogError
{
    param(
        [System.Management.Automation.ErrorRecord] $ExceptionObject
    )

    if(($ExceptionObject.Exception | GM ErrorContent -ErrorAction SilentlyContinue) -and ($ExceptionObject.Exception.ErrorContent | GM Message -ErrorAction SilentlyContinue))
    {
        Write-Host "ErrorCode [$($ExceptionObject.Exception.ErrorCode)] ErrorMessage [$($ExceptionObject.Exception.ErrorContent.Message.Value)]"  -ForegroundColor Red
    }
    else
    {
        Write-Host $ExceptionObject.Exception.Message -ForegroundColor Red
    }
    
}

# Connect to Azure AD
try
{
    $TenantDetails = Get-AzureADTenantDetail
    Write-Host "`r`nCurrent tenant id: $($TenantDetails.ObjectId)" -ForegroundColor Cyan
}
catch
{
    try
    {
        Write-Host "You are not logged in to Azure AD. $($_.Exception.Message)" -ForegroundColor Yellow  
        Connect-AzureAD -TenantId $TenantID -ErrorAction Stop
    }
    catch
    {
        Write-Host "Login failed. Use command 'Connect-AzureAD -TenantId <TenantId>'" -ForegroundColor Red
        return;   
        
    }
}

# Grant graph access to internal MI

try
{
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
}
catch
{
    LogError -ExceptionObject $_
}
