<# ********************* Script execution guidance *******************

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

# NOTE: You do not require access on this subscription or resource group to execute this command.
#       SubscriptionId and Resource Group Name are required to update the redirection URL of the Azure AD application

# Subscription id in which Azure Tenant Security Solution needs to be installed.
$SubscriptionId = ""

# Resource group name in which Azure Tenant Security Solution needs to be installed.
$ScanHostRGName = ""

# Azure environment in which Azure Tenant Security Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud, AzureChinaCloud
$AzureEnvironmentName = ""

# ************** End: Initialize required parameters ******************** #

# Standard configuration
$AzureEnvironmentAppServiceURI = @{
    "AzureCloud" = "https://{0}.azurewebsites.net";
    "AzureGovernmentCloud" = "https://{0}.azurewebsites.us";
    "AzureChinaCloud" = "https://{0}.chinacloudsites.cn";
}

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

function get-hash([string]$textToHash) {
    $hasher = new-object System.Security.Cryptography.MD5CryptoServiceProvider
    $toHash = [System.Text.Encoding]::UTF8.GetBytes($textToHash)
    $hashByteArray = $hasher.ComputeHash($toHash)
    $result = [string]::Empty;
    foreach($byte in $hashByteArray)
    {
      $result += "{0:X2}" -f $byte
    }
    return $result;
 }

function CreateAzureADApplication
{
    param (
        [string] $displayName
    )

    Write-Host "Checking if Azure AD application [$($displayName)] already exist..." -ForegroundColor Cyan

    if (!(Get-AzureADApplication -SearchString $displayName)) {

        Write-Host "Creating new AD application [$($displayName)]..." -ForegroundColor Cyan
        # create new application
        $app = New-AzureADApplication -DisplayName $displayName

        # create a service principal for your application
        $spForApp = New-AzureADServicePrincipal -AppId $app.AppId 
    }
    else
    {
        Write-Host "AD application [$($displayName)] already exists." -ForegroundColor Cyan
        $app = Get-AzureADApplication -SearchString $displayName
    }
    #endregion
    return $app
}

function GetADPermissionToBeGranted
{
    param
    (
        [string] $targetServicePrincipalAppId,
        $appPermissionsRequired
    )

    $targetSp = Get-AzureADServicePrincipal -Filter "AppId eq '$($targetServicePrincipalAppId)'"

    $RoleAssignments = @()
    Foreach ($AppPermission in $appPermissionsRequired) {
        $RoleAssignment = $targetSp.Oauth2Permissions | Where-Object { $_.Value -eq $AppPermission}
        $RoleAssignments += $RoleAssignment
    }

    $ResourceAccessObjects = New-Object 'System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]'
    foreach ($RoleAssignment in $RoleAssignments) {
        $resourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess"
        $resourceAccess.Id = $RoleAssignment.Id
        $resourceAccess.Type = 'Scope'
        $ResourceAccessObjects.Add($resourceAccess)
    }
    $requiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $requiredResourceAccess.ResourceAppId = $targetSp.AppId
    $requiredResourceAccess.ResourceAccess = $ResourceAccessObjects

    return $requiredResourceAccess
    
}


# ********************* Run command to setup Azure AD application for AzTS setup ************************ #

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

if([string]::IsNullOrWhiteSpace($SubscriptionId) -or [string]::IsNullOrWhiteSpace($ScanHostRGName))
{
    Write-Host "Please enter a valid subscription id and resource group name." -ForegroundColor Red
    return;
}

try
{

    $ResourceId='/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId,$ScanHostRGName;
    $ResourceIdHash = get-hash($ResourceId)
    $ResourceHash = $ResourceIdHash.Substring(0,5).ToString().ToLower()
    
    Write-Host "Starting Azure AD application setup..." -ForegroundColor Cyan
    
    # Creating Azure AD application: Web API
    $WebAPIAzureADAppName = "AzSK-AzTS-WebApi-$ResourceHash";
    $webApi = CreateAzureADApplication -displayName $WebAPIAzureADAppName
    
    # Creating Azure AD application: UI
    $UIAzureADAppName="AzSK-AzTS-UI-$ResourceHash"
    $webUIApp = CreateAzureADApplication -displayName $UIAzureADAppName
    
    
    Write-Host "Updating Azure AD application registration..." -ForegroundColor Cyan
    $identifierUri = 'api://{0}' -f $webUIApp.AppId
    $replyUris = New-Object Collections.Generic.List[string]
    $replyUris.Add(($AzureEnvironmentAppServiceURI.$AzureEnvironmentName -f $UIAzureADAppName));
    $replyUris.Add($([string]::Join("/", $([string]::Format($AzureEnvironmentAppServiceURI.$AzureEnvironmentName, $UIAzureADAppName)), "auth.html")));
    Set-AzureADApplication -ObjectId $webUIApp.ObjectId -ReplyUrls $replyUris -IdentifierUris $identifierUri -Oauth2AllowImplicitFlow $true
    
    $identifierUri = 'api://{0}' -f $webApi.AppId
    Set-AzureADApplication -ObjectId $webApi.ObjectId -IdentifierUris $identifierUri -Oauth2AllowImplicitFlow $true
    
    Write-Host "Updated Azure AD applications redirection URL and OAuth 2.0 implicit grant flow." -ForegroundColor Cyan
    
    try
    {
        Write-Host "Granting 'User.Read' permission to UI AD application..." -ForegroundColor Cyan
    
        # MS Graph ID
        $targetServicePrincipalAppId='00000003-0000-0000-c000-000000000000';        
        # Grant MS Graph permission
        $appPermissionsRequired = @('User.Read')
        $permission = GetADPermissionToBeGranted -targetServicePrincipalAppId $targetServicePrincipalAppId -appPermissionsRequired $appPermissionsRequired
        Set-AzureADApplication -ObjectId $webUIApp.ObjectId -RequiredResourceAccess $permission
        Write-Host "Granted UI AD application 'User.Read' permission." -ForegroundColor Cyan
    }
    catch
    {
        Write-Host "Failed to grant 'User.Read' permission. ExceptionMessage $($_)" -ForegroundColor Red
    }
    
    Write-Host "Completed Azure AD application setup." -ForegroundColor Cyan
 }
 catch
 {
    LogError -ExceptionObject $_
 }