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
        Connect-AzAccount
        Write-Host "Connected to AzAccount" -ForegroundColor Green
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId

    
    Write-Host "Note: `n Exclude check to remove invalid role assignments at MG scope." -ForegroundColor Yellow
    Write-Host "Metadata Details: `n SubscriptionId: [$($SubscriptionId)] `n AccountName: [$($currentSub.Account.Id)] `n AccountType: [$($currentSub.Account.Type)]"
    Write-Host "------------------------------------------------------"
    Write-Host "Starting with Subscription [$($SubscriptionId)]..."


    Write-Host "Step 1 of 5: Validating whether the current user [$($currentSub.Account.Id)] have the required permissions to run the script for Subscription [$($SubscriptionId)]..."

    # Safe Check: Checking whether the current account is of type User and also grant the current user as UAA for the sub to support fallback
    if($currentSub.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor Yellow
        break;
    }

    # Safe Check: Current user need to be either UAA or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $currentSub.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -eq "Owner"  -or $_.RoleDefinitionName -eq 'CoAdministrator' -or $_.RoleDefinitionName -eq "User Access Administrator" } | Measure-Object).Count -le 0)
    {
        Write-Host "Warning: This script can only be run by an Owner or User Access Administrator" -ForegroundColor Yellow
        break;
    }

    # Safe Check: saving the current login user object id to ensure we dont remove this during the actual removal
    $currentLoginUserObjectIdArray = @()
    $currentLoginUserObjectId = "";
    $currentLoginUserObjectIdArray += $currentLoginRoleAssignments | select ObjectId -Unique
    if(($currentLoginUserObjectIdArray | Measure-Object).Count -gt 0)
    {
        $currentLoginUserObjectId = $currentLoginUserObjectIdArray[0].ObjectId;
    }
        
    Write-Host "Step 2 of 5: Fetching all the role assignments for Subscription [$($SubscriptionId)]..."

    # Getting all role assignments of subscription.
    $currentRoleAssignmentList = Get-AzRoleAssignment -IncludeClassicAdministrators  

    # Excluding MG scoped role assignment
    $currentRoleAssignmentList = $currentRoleAssignmentList | Where-Object { !$_.Scope.Contains("/providers/Microsoft.Management/managementGroups/") }
    
    # Getting all classic role assignments.
    $classicRoleAssignments = $currentRoleAssignmentList | Where-Object {[string]::IsNullOrWhiteSpace($_.ObjectId)};

    # filter-out classic admins
    $currentRoleAssignmentList = $currentRoleAssignmentList | Where-Object {![string]::IsNullOrWhiteSpace($_.ObjectId)};
    $distinctObjectIds = @();

    # adding one valid object guid, so that even if graph call works, it has to get atleast 1. If we dont get any, means Graph API failed.
    $distinctObjectIds += $currentLoginUserObjectId;

    
    if(($ObjectIds | Measure-Object).Count -eq 0)
    {
        $currentRoleAssignmentList | select -Unique -Property 'ObjectId' | ForEach-Object { $distinctObjectIds += $_.ObjectId }
    }
    else
    {
        $ObjectIds | Foreach-Object {
          $objectId = $_;
           if(![string]::IsNullOrWhiteSpace($objectId))
            {
                $distinctObjectIds += $objectId
            }
            else
            {
                Write-Host "Warning: Dont pass empty string array in the ObjectIds param. If you dont want to use the param, just remove while executing the command" -ForegroundColor Yellow
                break;
            }  
        }
    }        
    
    Write-Host "Step 3 of 5: Resolving all the AAD ObjectGuids against Tenant. Number of distinctObjectGuids [$($distinctObjectIds.Count)]..."
    # Connect to Azure Active Directory.
    try
    {
        # Check if Connect-AzureAD session is already active 
        Get-AzureADUser -ObjectId $currentLoginUserObjectId | Out-Null
    }
    catch
    {
        Write-Host "Connecting to Azure AD..."
        Connect-AzureAD
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
            break;
        }

        $activeIdentities += $subActiveIdentities.ObjectId
    } 

    $folderPath = [Environment]::GetFolderPath("MyDocuments") 
    if (Test-Path -Path $folderPath)
    {
        $folderPath += "\AzTS\Remediation\Subscriptions\$($subscriptionid.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\InvalidAADAccounts\"
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }

    Write-Host "Step 4 of 5: Taking backup of current role assignments at [$($folderPath)]..."    

    $invalidAADObjectIds = $distinctObjectIds | Where-Object { $_ -notin $activeIdentities}

    # get list of all invalid classic role assignments followed by principal name.
    $invalidClassicRoles = @();
     
    $classicRoleAssignments | ForEach-Object { 
                $userDetails = Get-AzureADUser -Filter "userPrincipalName eq '$($_.SignInName)' or Mail eq '$($_.SignInName)'"
                if (($userDetails | Measure-Object).Count -eq 0 ) 
                {
                    $invalidClassicRoles += $_ 
                }
            } 

    # Get list of all invalidAADObject guid assignments followed by object ids.
    $invalidAADObjectRoleAssignments = $currentRoleAssignmentList | Where-Object {  $invalidAADObjectIds -contains $_.ObjectId}

    # Safe Check: Check whether the current user accountId is part of Invalid AAD ObjectGuids List 
    if(($invalidAADObjectRoleAssignments | where { $_.ObjectId -eq $currentLoginUserObjectId} | Measure-Object).Count -gt 0)
    {
        Write-Host "Warning: Current User account is found as part of the Invalid AAD ObjectGuids collection. This is not expected behaviour. This can happen typically during Graph API failures. Aborting the operation. Reach out to aztssup@microsoft.com" -ForegroundColor Yellow
        break;
    }


    if(($invalidAADObjectRoleAssignments | Measure-Object).Count -le 0 )
    {
        Write-Host "No invalid accounts found for the subscription [$($SubscriptionId)]. exiting the process." -ForegroundColor Cyan
        break;
    }
    else
    {
        Write-Host "Found [$(($invalidAADObjectRoleAssignments | Measure-Object).Count)] invalid roleassignments against invalid AAD objectGuids for the subscription [$($SubscriptionId)]" -ForegroundColor Cyan
    }    

    if(($invalidClassicRoles | Measure-Object).Count -gt 0 )
    {
        Write-Host "Found [$(($invalidClassicRoles | Measure-Object).Count)] invalid classic roleassignments for the subscription [$($SubscriptionId)]" -ForegroundColor Cyan
    }  

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
        Write-Host "Note: Once deprecated role assignments deleted. It can not be restore." -ForegroundColor Yellow
        Write-Host "Do you want to delete the above listed role assignment?" -ForegroundColor Yellow -NoNewline
        $UserInput = Read-Host -Prompt "(Y|N)"

        if($UserInput -ne "Y")
        {
            break;
        }
    }
   
    Write-Host "Step 5 of 5: Clean up invalid object guids for Subscription [$($SubscriptionId)]..."
    # Start deletion of all Invalid AAD ObjectGuids.
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

    $invalidClassicRoles | ForEach-Object {
        try 
        {
            Remove-AzRoleAssignment $_ 
            $_ | Select-Object -Property "Scope", "RoleDefinitionName"    
        }
        catch
        {
            $isRemoved = $false
            Write-Host "Not able to remove invalid classic role assignment. ErrorMessage [$($_)]" -ForegroundColor Red  
        }
    }

    if($isRemoved)
    {
        Write-Host "Completed deleting Invalid AAD ObjectGuids role assignments." -ForegroundColor Green
    }
    else 
    {
        Write-Host "`n"
        Write-Host "Not able to successfully delete Invalid AAD ObjectGuids role assignments." -ForegroundColor Red
    }
}

# ***************************************************** #
<#
Function calling with parameters.
Remove-AzTSInvalidAADAccounts -SubscriptionId '<Sub_Id>' -ObjectIds @('<Object_Ids>') -Force:$false -PerformPreReqCheck: $true
#>