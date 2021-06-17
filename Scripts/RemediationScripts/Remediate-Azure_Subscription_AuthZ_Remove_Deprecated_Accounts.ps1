<##########################################

# Overivew:
    This script is used to remove deprecated/ghost AAD identities role assignments from subscription.

ControlId: 
    Azure_Subscription_AuthZ_Remove_Deprecated_Accounts

# Pre-requesites:
    You will need owner or User Access Administrator role at subscription level.

# Steps performed by the script
    1. Install and validate pre-requesites to run the script for subscription.

    2. Get role assignments for the subscription and filter ghost/deprecated identities.

    3. Taking backup of ghost/deprecated identities that are going to be removed using remediation script.

    4. Clean up deprecated/ghost AAD object identities role assignments from subscription.

# Step to execute script:
    Download and load remediation script in PowerShell session and execute below command.
    To know how to load script in PowerShell session refer link: https://aka.ms/AzTS-docs/RemediationscriptExcSteps.

# Command to execute:
    Examples:
        1. Run below command to remove all deprecated/ghost identities role assignments from subscription

         Remove-AzTSInvalidAADAccounts -SubscriptionId '<Sub_Id>' -PerformPreReqCheck: $true

        2. Run below command, if you have deprecated/ghost identities list with you. You will get deprecated account list from AzTS UI status reason section.

         Remove-AzTSInvalidAADAccounts -SubscriptionId '<Sub_Id>' -ObjectIds @('<Object_Id_1>', '<Object_Id_2>') -PerformPreReqCheck: $true

To know more about parameter execute below command:
    Get-Help Remove-AzTSInvalidAADAccounts -Detailed

########################################
#>

function Pre_requisites
{
    <#
    .SYNOPSIS
    This command would check pre requisities modules.
    .DESCRIPTION
    This command would check pre requisities modules to perform remediation.
	#>

    Write-Host "Required modules are: Az.Resources, AzureAD, Az.Account" -ForegroundColor Cyan
    Write-Host "Checking for required modules..."
    $availableModules = $(Get-Module -ListAvailable Az.Resources, AzureAD, Az.Accounts)
    
    # Checking if 'Az.Accounts' module is available or not.
    if($availableModules.Name -notcontains 'Az.Accounts')
    {
        Write-Host "Installing module Az.Accounts..." -ForegroundColor Yellow
        Install-Module -Name Az.Accounts -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "Az.Accounts module is available." -ForegroundColor Green
    }

    # Checking if 'Az.Resources' module is available or not.
    if($availableModules.Name -notcontains 'Az.Resources')
    {
        Write-Host "Installing module Az.Resources..." -ForegroundColor Yellow
        Install-Module -Name Az.Resources -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "Az.Resources module is available." -ForegroundColor Green
    }

    # Checking if 'AzureAD' module is available or not.
    if($availableModules.Name -notcontains 'AzureAD')
    {
        Write-Host "Installing module AzureAD..." -ForegroundColor Yellow
        Install-Module -Name AzureAD -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "AzureAD module is available." -ForegroundColor Green
    }
}

function Remove-AzTSInvalidAADAccounts
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Subscription_AuthZ_Remove_Deprecated_Accounts' control.
    .DESCRIPTION
    This command would help in remediating 'Azure_Subscription_AuthZ_Remove_Deprecated_Accounts' control.
    .PARAMETER SubscriptionId
        Enter subscription id on which remediation need to perform.
    .PARAMETER ObjectIds
        Enter objectIds of invalid AAD accounts.
    .Parameter Force
        Enter force parameter value to remove non ad identities
    .PARAMETER PerformPreReqCheck
        Perform pre requisities check to ensure all required module to perform remedition operation is available.
    #>

    param (
        [string]
        $SubscriptionId,

        [string[]]
        $ObjectIds,

        [switch]
        $Force,

        [switch]
        $PerformPreReqCheck
    )

    Write-Host "======================================================"
    Write-Host "Starting with removal of invalid AAD object guids from subscriptions..."
    Write-Host "------------------------------------------------------"

    if($PerformPreReqCheck)
    {
        try 
        {
            Write-Host "Checking for pre-requisites..."
            Pre_requisites
            Write-Host "------------------------------------------------------"     
        }
        catch 
        {
            Write-Host "Error occured while checking pre-requisites. ErrorMessage [$($_)]" -ForegroundColor Red    
            break
        }
    }

    # Connect to AzAccount
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet))
    {       
        Write-Host "Connecting to AzAccount..."
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to AzAccount" -ForegroundColor Green
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop

    
    Write-Host "Note: `n 1. Exclude checking PIM assignment for deprecated account due to insufficient privilege. `n 2. Exclude checking role assignments at MG scope. `n 3. Checking only for user type assignments." -ForegroundColor Yellow
    Write-Host "------------------------------------------------------"
    Write-Host "Metadata Details: `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host "------------------------------------------------------"
    Write-Host "Starting with Subscription [$($SubscriptionId)]..."


    Write-Host "Step 1 of 5: Validating whether the current user [$($currentSub.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."

    # Safe Check: Checking whether the current account is of type User and also grant the current user as UAA for the sub to support fallback
    if($currentSub.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor Yellow
        return;
    }

    # Safe Check: Current user need to be either UAA or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $currentSub.Account.Id -Scope "/subscriptions/$($SubscriptionId)";
    
    $requiredRoleDefinitionName = @("Owner", "User Access Administrator")
    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -in $requiredRoleDefinitionName} | Measure-Object).Count -le 0 )
    {
        Write-Host "Warning: This script can only be run by an [$($requiredRoleDefinitionName -join ", ")]." -ForegroundColor Yellow
        return;
    }

    # Safe Check: saving the current login user object id to ensure we dont remove this during the actual removal
    $currentLoginUserObjectIdArray = @()
    $currentLoginUserObjectId = "";
    $currentLoginUserObjectIdArray += $currentLoginRoleAssignments | select ObjectId -Unique
    if(($currentLoginUserObjectIdArray | Measure-Object).Count -gt 0)
    {
        $currentLoginUserObjectId = $currentLoginUserObjectIdArray[0].ObjectId;
    }
        
    Write-Host "Step 2 of 5: Fetching all the role assignments for subscription [$($SubscriptionId)]..."

    $classicAssignments = $null
    $distinctObjectIds = @();

    # adding one valid object guid, so that even if graph call works, it has to get atleast 1. If we dont get any, means Graph API failed.
    $distinctObjectIds += $currentLoginUserObjectId;
    if(($ObjectIds | Measure-Object).Count -eq 0)
    {
        # Getting all classic role assignments.
        $armUri = "https://management.azure.com/subscriptions/$($subscriptionId)/providers/Microsoft.Authorization/classicadministrators?api-version=2015-06-01"
        $method = "Get"
        $classicAssignments = [ClassicRoleAssignments]::new()
        $headers = $classicAssignments.GetAuthHeader()
        $res = $classicAssignments.GetClassicRoleAssignmnets([string] $armUri, [string] $method, [psobject] $headers)
        $classicDistinctRoleAssignmentList = $res.value | Where-Object { ![string]::IsNullOrWhiteSpace($_.properties.emailAddress) }
        
        # Renaming property name
        $classicRoleAssignments = $classicDistinctRoleAssignmentList | select @{N='SignInName'; E={$_.properties.emailAddress}},  @{N='RoleDefinitionName'; E={$_.properties.role}}, @{N='RoleId'; E={$_.name}}, @{N='Type'; E={$_.type }}, @{N='RoleAssignmentId'; E={$_.id }}

    
        # Getting all role assignments of subscription.
        $currentRoleAssignmentList = Get-AzRoleAssignment

        # Excluding MG scoped role assignment
        $currentRoleAssignmentList = $currentRoleAssignmentList | Where-Object { !$_.Scope.Contains("/providers/Microsoft.Management/managementGroups/") }
        
        # Getting all permanent role assignments.
        $currentRoleAssignmentList = $currentRoleAssignmentList | Where-Object {![string]::IsNullOrWhiteSpace($_.ObjectId)};
        $currentRoleAssignmentList | select -Unique -Property 'ObjectId' | ForEach-Object { $distinctObjectIds += $_.ObjectId }
    }
    else
    {
        $currentRoleAssignmentList = @()
        $ObjectIds | Foreach-Object {
          $objectId = $_;
          
          if(![string]::IsNullOrWhiteSpace($objectId))
            {
                $currentRoleAssignmentList += Get-AzRoleAssignment -ObjectId $objectId | Where-Object { !$_.Scope.Contains("/providers/Microsoft.Management/managementGroups/")}
                $distinctObjectIds += $objectId
            }
            else
            {
                Write-Host "Warning: Dont pass empty string array in the ObjectIds param. If you dont want to use the param, just remove while executing the command" -ForegroundColor Yellow
                break;
            }  
        }
    }        
    
    Write-Host "Step 3 of 5: Resolving all the AAD Object guids against Tenant. Number of distinct object guids [$($distinctObjectIds.Count)]..."
    # Connect to Azure Active Directory.
    try
    {
        # Check if Connect-AzureAD session is already active 
        Get-AzureADUser -ObjectId $currentLoginUserObjectId | Out-Null
    }
    catch
    {
        Write-Host "Connecting to Azure AD..."
        Connect-AzureAD -ErrorAction Stop
    }   

    # Batching object ids in count of 900.
    $activeIdentities = @();
    for( $i = 0; $i -lt $distinctObjectIds.Length; $i = $i + 900)
    {
        if($i + 900 -lt $distinctObjectIds.Length)
        {
            $endRange = $i + 900
        }
        else
        {
            $endRange = $distinctObjectIds.Length -1;
        }

        $subRange = $distinctObjectIds[$i..$endRange]

        # Getting active identities from Azure Active Directory.
        $subActiveIdentities = Get-AzureADObjectByObjectId -ObjectIds $subRange
        # Safe Check 
        if(($subActiveIdentities | Measure-Object).Count -le 0)
        {
            # If the active identities count has come as Zero, then API might have failed.  Print Warning and abort the execution
            Write-Host "Warning: Graph API hasnt returned any active account. Current principal dont have access to Graph or Graph API is throwing error. Aborting the operation. Reach out to aztssup@microsoft.com" -ForegroundColor Yellow
            return;
        }

        $activeIdentities += $subActiveIdentities.ObjectId
    }

    $invalidAADObjectIds = $distinctObjectIds | Where-Object { $_ -notin $activeIdentities}

    # Get list of all invalid classic role assignments followed by principal name.
    $invalidClassicRoles = @();
     
    if(($classicRoleAssignments | Measure-Object).count -gt 0)
    {
        $classicRoleAssignments | ForEach-Object { 
            $userDetails = Get-AzureADUser -Filter "userPrincipalName eq '$($_.SignInName)' or Mail eq '$($_.SignInName)'"
            if (($userDetails | Measure-Object).Count -eq 0 ) 
            {
                $invalidClassicRoles += $_ 
            }
        }
    }
    
    # Get list of all invalidAADObject guid assignments followed by object ids.
    $invalidAADObjectRoleAssignments = $currentRoleAssignmentList | Where-Object {  $invalidAADObjectIds -contains $_.ObjectId}

    # Safe Check: Check whether the current user accountId is part of invalid AAD Object guids List 
    if(($invalidAADObjectRoleAssignments | where { $_.ObjectId -eq $currentLoginUserObjectId} | Measure-Object).Count -gt 0)
    {
        Write-Host "Warning: Current User account is found as part of the invalid AAD Object guids collection. This is not expected behaviour. This can happen typically during Graph API failures. Aborting the operation. Reach out to aztssup@microsoft.com" -ForegroundColor Yellow
        return;
    }

    # Getting count of invalid account
    $invalidAADObjectRoleAssignmentsCount = ($invalidAADObjectRoleAssignments | Measure-Object).Count
    $invalidClassicRolesCount = ($invalidClassicRoles | Measure-Object).Count

    if(($invalidAADObjectRoleAssignmentsCount -eq 0) -and ($invalidClassicRolesCount -eq 0))
    {
        Write-Host "No invalid accounts found for the subscription [$($SubscriptionId)]. Exiting the process."
        return;
    }

    if($invalidAADObjectRoleAssignmentsCount -le 0 )
    {
        Write-Host "No invalid accounts found for the subscription [$($SubscriptionId)]. Exiting the process." -ForegroundColor Cyan
    }
    else
    {
        Write-Host "Found [$($invalidAADObjectRoleAssignmentsCount)] invalid role assignments against invalid AAD object guids for the subscription [$($SubscriptionId)]" -ForegroundColor Cyan
    }    

    if($invalidClassicRolesCount -gt 0 )
    {
        Write-Host "Found [$($invalidClassicRolesCount)] invalid classic role assignments for the subscription [$($SubscriptionId)]" -ForegroundColor Cyan
    }
     
    $folderPath = [Environment]::GetFolderPath("MyDocuments") 
    if (Test-Path -Path $folderPath)
    {
        $folderPath += "\AzTS\Remediation\Subscriptions\$($subscriptionid.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\InvalidAADAccounts\"
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }

    Write-Host "Step 4 of 5: Taking backup of current role assignments at [$($folderPath)]..."  
    
    # Safe Check: Taking backup of invalid identities.   
    if ($invalidAADObjectRoleAssignments.length -gt 0)
    {
        $invalidAADObjectRoleAssignments | ConvertTo-json | out-file "$($folderpath)\InvalidRoleAssignments.json"       
    }

    # Safe Check: Taking backup of invalid classic role assignments.    
    if ($invalidClassicRoles.length -gt 0)
    {
        $invalidClassicRoles | ConvertTo-json | out-file "$($folderpath)\InvalidClassicRoleAssignments.json"       
    }

    if(-not $Force)
    {
        Write-Host "Note: Once deprecated role assignments deleted, it can not be restored." -ForegroundColor Yellow
        Write-Host "Do you want to delete the above listed role assignment?" -ForegroundColor Yellow -NoNewline
        $UserInput = Read-Host -Prompt "(Y|N)"

        if($UserInput -ne "Y")
        {
            return;
        }
    }
   
    Write-Host "Step 5 of 5: Clean up invalid object guids for subscription [$($SubscriptionId)]..."
    # Start deletion of all invalid AAD Object g4uids.
    Write-Host "Starting to delete invalid AAD object guid role assignments..." -ForegroundColor Cyan

    $isRemoved = $true
    $invalidAADObjectRoleAssignments | ForEach-Object {
        try 
        {
            Remove-AzRoleAssignment $_ 
            $_ | Select-Object -Property "Scope", "RoleDefinitionName", "ObjectId"    
        }
        catch
        {
            $isRemoved = $false
            Write-Host "Not able to remove invalid role assignment. ErrorMessage [$($_)]" -ForegroundColor Red  
        }
    }

    # Deleting deprecated account having classic role assignment.
    $invalidClassicRoles | ForEach-Object {
        try 
        {
            if($_.RoleDefinitionName -eq "CoAdministrator" -and $_.RoleAssignmentId.contains("/providers/Microsoft.Authorization/classicAdministrators/"))
            {
                $armUri = "https://management.azure.com" + $_.RoleAssignmentId + "?api-version=2015-06-01"
                $method = "Delete"
                $classicAssignments = $null
                $classicAssignments = [ClassicRoleAssignments]::new()
                $headers = $classicAssignments.GetAuthHeader()
                $res = $classicAssignments.DeleteClassicRoleAssignmnets([string] $armUri, [string] $method,[psobject] $headers)

                if(($null -ne $res) -and ($res.StatusCode -eq 202 -or $res.StatusCode -eq 200))
                {
                    $_ | Select-Object -Property "SignInName", "RoleAssignmentId", "RoleDefinitionName"
                }
            } 
        }
        catch
        {
            $isRemoved = $false
            Write-Host "Not able to remove invalid classic role assignment. ErrorMessage [$($_)]" -ForegroundColor Red  
        }
    }

    if($isRemoved)
    {
        Write-Host "Completed deleting invalid AAD Object guids role assignments." -ForegroundColor Green
    }
    else 
    {
        Write-Host "`n"
        Write-Host "Not able to successfully delete invalid AAD Object guids role assignments." -ForegroundColor Red
    }
}

class ClassicRoleAssignments
{
    [PSObject] GetAuthHeader()
    {
        [psobject] $headers = $null
        try 
        {
            $resourceAppIdUri = "https://management.core.windows.net/"
            $rmContext = Get-AzContext
            $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $rmContext.Account,
            $rmContext.Environment,
            $rmContext.Tenant,
            [System.Security.SecureString] $null,
            "Never",
            $null,
            $resourceAppIdUri); 

            $header = "Bearer " + $authResult.AccessToken
            $headers = @{"Authorization"=$header;"Content-Type"="application/json";}
        }
        catch 
        {
            Write-Host "Error occured while fetching auth header. ErrorMessage [$($_)]" -ForegroundColor Red   
        }
        return($headers)
    }

    [PSObject] GetClassicRoleAssignmnets([string] $armUri, [string] $method, [psobject] $headers)
    {
        $content = $null
        try
        {
            $method = [Microsoft.PowerShell.Commands.WebRequestMethod]::$method
            
            # API to get classic role assignments
            $response = Invoke-WebRequest -Method $method -Uri $armUri -Headers $headers -UseBasicParsing
            $content = ConvertFrom-Json $response.Content
        }
        catch
        {
            Write-Host "Error occured while fetching classic role assignment. ErrorMessage [$($_)]" -ForegroundColor Red
        }
        
        return($content)
    }

    [PSObject] DeleteClassicRoleAssignmnets([string] $armUri, [string] $method, [psobject] $headers)
    {
        $content = $null
        try
        {
            $method = [Microsoft.PowerShell.Commands.WebRequestMethod]::$method
            
            # API to get classic role assignments
            $response = Invoke-WebRequest -Method $method -Uri $armUri -Headers $headers -UseBasicParsing
            $content = $response
        }
        catch
        {
            Write-Host "Error occured while deleting classic role assignment. ErrorMessage [$($_)]" -ForegroundColor Red
        }
        
        return($content)
    }
}


# ***************************************************** #
<#
Function calling with parameters.
Remove-AzTSInvalidAADAccounts -SubscriptionId '<Sub_Id>' -ObjectIds @('<Object_Ids>') -Force:$false -PerformPreReqCheck: $true
#>