<###
# Overview:
    This script is used to create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group.

# Control ID:
    Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access , Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG

# Display Name:
Do not grant permanent access for critical subscription level roles , Do not grant permanent access for critical resource group level roles

# Prerequisites:
    Owner and higher privileged role assignment on the Subscription is required and atleast one service adminstrator role assignment must be present on the subscription level.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of critical permanent role assignment(s) in a Subscription or in a resource group.
        3. Back up details of critical permanent role assignment(s) that are to be remediated.
        4. Create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group.
   
    NOTE: Please provide the output of dryrun only as input for remediation.


# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or at resource group level. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the critical Permanent role assignment(s) on a Subscription that will be remediated:
    
           Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To review the critical Permanent role assignment(s) on the resource group that will be remediated:
    
           Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck  -resourcegroup -DryRun

        3. To create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group, from a previously taken snapshot:
          
           Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemoveCriticalPermanentRoleAssignments\CriticalPermanentRoleAssignment.csv

        4. To create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group, from a previously taken snapshot:
          
           Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -resourcegroup -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemoveCriticalPermanentRoleAssignments\CriticalPermanentRoleAssignment.csv


        To know more about the options supported by the remediation command, execute:
        
        Get-Help Create-PIMForPermanentRoleAssignments -Detailed
       
###>


function Setup-Prerequisites
{
    <#
        .SYNOPSIS
        Checks if the prerequisites are met, else, sets them up.

        .DESCRIPTION
        Checks if the prerequisites are met, else, sets them up.
        Includes installing any required Azure modules.

        .INPUTS
        None. You cannot pipe objects to Setup-Prerequisites.

        .OUTPUTS
        None. Setup-Prerequisites does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Setup-Prerequisites

        .LINK
        None
    #>

    # List of required modules
    $requiredModules = @("Az.Accounts", "Az.Resources", "AzureAD")

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."
    # List of available modules
    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    if ($availableModules.Name -contains "Az.Resources")
    {
        $module = get-module "Az.Resources"
        if($module.Version -ge "5.0.0")
        {
            Write-Host " Az.Resources module is present ..." -ForegroundColor $([Constants]::MessageType.Info)        
        }
        else
        {
            Write-Host "Installing $($_) module with required version(5.0.0)..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name "Az.Resources" -MinimumVersion 5.0.0 -RequiredVersion 5.0.0 -Scope CurrentUser -Repository 'PSGallery'  -Force -ErrorAction Stop   
        }
    }
    else
    {
        Write-Host "Installing $($_) module...." -ForegroundColor $([Constants]::MessageType.Update)
        Install-Module -Name "Az.Resources" -MinimumVersion 5.0.0 -RequiredVersion 5.0.0 -Scope CurrentUser -Repository 'PSGallery' -Force -ErrorAction Stop
    }


    if($availableModules.Name -contains "AZ.Accounts")
    {
        $module = get-module "Az.Accounts"
        if($module.Version -ge "2.5.4")
        {
            Write-Host "Az.Accounts module is present ... " -ForegroundColor $([Constants]::MessageType.Info)
        }
        else
        {
             Write-Host "Installing Az.Accounts module with required version(2.5.4)..." -ForegroundColor $([Constants]::MessageType.Info)
             Install-Module -Name "Az.Accounts" -MinimumVersion 2.5.4 -RequiredVersion 2.5.4 -Scope CurrentUser -Repository 'PSGallery' -Force -ErrorAction Stop        
        }    
    }
    else
    {
        Write-Host "Installing Az.Accounts module...." -ForegroundColor $([Constants]::MessageType.Update)
        Install-Module -Name "Az.Accounts" -MinimumVersion 2.5.4 -RequiredVersion 2.5.4 -Scope CurrentUser -Repository 'PSGallery'  -Force -ErrorAction Stop
    }

    if($availableModules.Name -contains "AzureAD")
    {
        Write-Host "AzureAD module is present ..." -ForegroundColor $([Constants]::MessageType.Info)
    }
    else
    {
        Write-Host "Installing AzureAD module...." -ForegroundColor $([Constants]::MessageType.Update)
        Install-Module -Name AzureAD -Scope CurrentUser -Repository "PSGallery" -Force -ErrorAction Stop
    }
}


function Create-PIMForPermanentRoleAssignments
{
    <#
        .SYNOPSIS
        Remediates 'Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access , Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG' Control.

        .DESCRIPTION
        Remediates 'Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access , Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG' Control.
        To create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .INPUTS
        None. You cannot pipe objects to Create-PIMForPermanentRoleAssignments.

        .OUTPUTS
        None. Create-PIMForPermanentRoleAssignments does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -resourcegroup -DryRun

        .EXAMPLE
        PS> Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemoveCriticalPermanentRoleAssignments\CriticalPermanentRoleAssignment.csv

        .EXAMPLE
        PS> Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -resourcegroup -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemoveCriticalPermanentRoleAssignments\CriticalPermanentRoleAssignment.csv
       
        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", HelpMessage="Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies validation of prerequisites for the command")]
        $ResourceGroup,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies a forceful remediation without any prompts")]
        $Force,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", HelpMessage="Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies a dry run of the actual remediation")]
        $DryRun,

        [String]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true , HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Validate and install the modules required to run the script."

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: $($context.Subscription.Name)"
    Write-Host "Subscription ID: $($context.Subscription.SubscriptionId)"
    Write-Host "Account Name: $($context.Account.Id)"
    Write-Host "Account Type: $($context.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if $($context.Account.Id) is allowed to run this script..."

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of $($context.Account.Id) is: $($context.Account.Type)" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "*** To Create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which PIM role assignment(s) is successfully created in the Subscription or in resource group, Owner and higher privileges on the subscription are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    
    # Safe Check: Current user need to be either UAA or Owner for the subscription
    write-Host "Checking if the current user has required role..."
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $currentSub.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    $requiredRoleDefinitionName = @("Owner", "User Access Administrator")
    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -in $requiredRoleDefinitionName} | Measure-Object).Count -le 0 )
    {
        Write-Host "Warning: This script can only be run by an [$($requiredRoleDefinitionName -join ", ")]." -ForegroundColor Yellow
        return;
    }
    else
    {
        Write-Host "Current user [$($currentSub.Account.Id)] has the required permission for subscription [$($SubscriptionId)]." -ForegroundColor Green
    }
    
    #List of role assignment details 
    $roleAssignmentDetails = @()

    Write-Host "checking if subscription contains one or more service adminstrator role assignment(s)"...

    $roleAssignmentDetails = Get-AzRoleAssignmentScheduleInstance -scope /subscriptions/abb5301a-22a4-41f9-9e5f-99badff261f8
    $serviceAdminstrator = $roleAssignmentDetails | Where-Object {$_.Scope -eq "/subscriptions/abb5301a-22a4-41f9-9e5f-99badff261f8" -and $_.RoleDefinitionDisplayName -eq "Service Adminstrator"}
    
    # Checking the count of service adminstrator role assignment in the subscription.
    if(($serviceAdminstrator |Measure-Object).count -lt 1)
    {
        Write-Host "WARNING: This script can only be run when the subscription contains one or more service admin role assignment(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        #return
    }
    else
    {
        Write-Host " Contains $(($roleAssignmentDetails|Measure-Object).count) "   
    }
    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all role assignment(s)..."

    # No file path provided as input to the script. Fetch all role assignment(s) in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all role assignment(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all role assignment(s) in a Subscription
        $scope = "/subscriptions/$($subscriptionId)"
        $roleAssignmentDetails = Get-AzRoleAssignmentScheduleInstance -scope $scope -ErrorAction Stop
    }
    else
    {   
        # If incorrect file path is provided.
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all role assignment(s) from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

        #Fetching permanent role assignment(s) from the file.
        $roleAssignmentCsvDetails = Import-Csv -LiteralPath $FilePath

        $roleAssignmentCsvDetails | ForEach-Object {

            try
            {
                Write-Host "Fetching role assignment: RoleName - $($_.RoleDefinitionDisplayName) , Email - $($_.PrincipalEmail)"
                
                # Checking if permanent role assignment still exists.
                $roleAssignment =  Get-AzRoleAssignmentScheduleInstance -Name $_.Name -Scope $_.Scope 

                if(($roleAssignment|Measure-Object).count -eq 1)
                {    
                    $roleAssignmentDetails += $_
                }
                else
                {
                    Write-Host "Error fetching role assignment: RoleName - $($_.RoleDefinitionDisplayName) , Email - $($_.PrincipalEmail). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this role assignment..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
            catch
            {
                Write-Host "Error fetching role assignment: RoleName - $($_.RoleDefinitionDisplayName) , Email - $($_.PrincipalEmail). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this role assignment..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
    
        $totalRoleAssignments = ($roleAssignmentDetails| Measure-Object).Count

        if ($totalRoleAssignments -eq 0)
        {
            Write-Host "No role assignment(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
  
        Write-Host "Found $($totalRoleAssignments) role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)

        Write-Host "Checking for critical permanent role assignment(s)..." 

        # List for critical permanent role assignment(s).
        $criticalRoleAssignments = @()

        if( -not $ResourceGroup)
        {
            # Storing critical permanent role assignment on the subscription level.
            $criticalRoleAssignments = $roleAssignmentDetails |  Where-Object {$_.Scope -eq "/subscriptions/$($SubscriptionId)" -and ($_.ExpandedPropertiesPrincipalType -eq "User" -or $_.ExpandedPropertiesPrincipalType -eq "Group") -and [system.convert]::ToBoolean($_.LinkedRoleEligibilityScheduleInstanceId) -eq $false  -and ($_.RoleDefinitionDisplayName -eq "User Access Adminstrator" -or $_.RoleDefinitionDisplayName -eq "Contributor" -or $_.RoleDefinitionDisplayName -eq "Owner") -and $_.PrincipalDisplayName -ne "MS-PIM"}
        }
        else
        {
            # Storing critical permanent role assignment on the resource group level.
            $criticalRoleAssignments = $roleAssignmentDetails | Where-Object {  !([string]::IsNullOrWhiteSpace($_.ResourceGroupName)) -and ($_.ExpandedPropertiesPrincipalType -eq "User" -or $_.ExpandedPropertiesPrincipalType -eq "Group") -and [system.convert]::ToBoolean($_.LinkedRoleEligibilityScheduleInstanceId) -eq $false -and ($_.RoleDefinitionDisplayName -eq "User Access Adminstrator" -or $_.RoleDefinitionDisplayName -eq "Owner" -or $_.RoleDefinitionDisplayName -eq "Contributor") -and $_.PrincipalDisplayName -ne "MS-PIM"}
        }

        # Checking for critical permanent role assignment.                                                               
        if(($criticalRoleAssignments| Measure-Object).Count -eq 0)
        {
            Write-Host "No critical permanent role assignment found . Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }

        Write-Host "Found $(($criticalRoleAssignments|Measure-Object).Count) critical permanent role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)

        # Back up snapshots to `%LocalApplicationData%'.
        $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RemoveCriticalPermanentRoleAssignments"

        if (-not (Test-Path -Path $backupFolderPath))
        {
            New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 3 of 4] Backing up permanent role assignment(s) details to $($backupFolderPath)"
    
        # Backing up role assignment(s) details.
        $backupFile = "$($backupFolderPath)\CriticalPermanentRoleAssignment.csv"

        $criticalRoleAssignments | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Permanent role assignment(s) details have been backed up to $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)

        Write-Host $([Constants]::DoubleDashLine)
    }

    if (-not $DryRun)
    {
        Write-Host "Create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group." -ForegroundColor $([Constants]::MessageType.Warning)

        if (-not $Force)
        {
            Write-Host "Do you want to Create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which PIM role assignment(s) is successfully created in the Subscription or in resource group ? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "PIM role assignment(s) with SC-ALt account for critical permanent role assignment(s) will not be created and critical permanent role assignment(s) will not be removed for which PIM role assignment(s) is successfully created in the Subscription or in resource group. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. PIM role assignment(s) for critical permanent role assignment will be created and critical permanent role assignment will be removed for which PIM role assignment(s) in the Subscription or in resource group already exists without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        
        Write-Host "[Step 4 of 4] Create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group..."

        # List of PIM role assignment(s) with SC-ALt account successfully created.
        $PIMcreated = @()

        # List of PIM role assignment(s) in which error occurred while creating.
        $PIMNotCreated = @()
        
        # List of permanent role assignment(s) which are removed successfully.
        $permanentRemoved = @()
        
        # List of permanent role assignment(s) which were not removed successfully.
        $permanentNotRemoved = @()

        # To create PIM role assignment(s) with SC-ALt account for critical permanent role assignment(s).
        $criticalRoleAssignments | ForEach-Object{
            try
            {
                if(!([string]::IsNullOrWhiteSpace($_.ScAltEmail)))
                {
                    # To get the user details
                    $user = Get-AzAdUser -ObjectId $_.ScAltEmail
                    $Scope = "/providers/Microsoft.Subscription" + $($_.Scope)

                    # Create PIM role assignment(s) with SC-ALt account for critical permanent role assignment(s).
                    $PIMAssignment = New-AzRoleEligibilityScheduleRequest -Name $_.Name -RoleDefinitionId $_.RoleDefinitionId -Scope $Scope -PrincipalId $user.Id -ScheduleInfoStartDateTime ((Get-Date).ToUniversalTime()) -ExpirationEndDateTime ((Get-Date).AddDays(30)) -RequestType 'AdminAssign'
                    if(($PIMAssignment|Measure-Object).Count -ge 1)
                    {
                        $PIMCreated += $roleAssignment
                    }
                    else
                    {
                        $PIMNotCreated += $roleAssignment 
                        Write-Host "Error creating PIM role assignment with SC-ALT  for critical permanent role assignment.  Role Name: [$($_.RoleDefinitionDisplayName)] , Email: [$($_.PrincipalEmail)]" -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "Skipping this role assignment. " -ForegroundColor $([Constants]::MessageType.Error)
                    }
                }
                else
                {
                    $PIMNotCreated += $roleAssignment
                    Write-Host "No SC-ALT Email found for permanent priviliged role assignment. Role Name: [$($_.RoleDefinitionDisplayName)] , Email: [$($_.PrincipalEmail)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping thid role assignment."  -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            catch
            {
                $PIMNotCreated += $roleAssignment
                Write-Host "Error creating PIM role assignment with SC-ALT account for critical permanent role assignment. Role Name: [$($_.RoleDefinitionDisplayName)] , Email: [$($_.PrincipalEmail)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this role assignment. " -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
        
        #Remove critical permanent role assignment for which PIM role assignment is successfully created. 
        $PIMcreated | ForEach-Object {
            try
            {
                # Remove critical permanent role assignment(s) for which PIM role assignment is successfully created.             
                Remove-AzRoleAssignment -Scope $_.Scope -RoleDefinitionName $_.RoleDefinitionDisplayName -SignInName $_.PrincipalEmail 

                # Checking if the role assignment is removed or not.
                $roleAssignment = Get-AzRoleAssignmentScheduleInstance -Name $_.Name -Scope $_.Scope

                if(($roleAssignment|Measure-Object).Count -ge 1)
                {
                    $permanentRemoved += $_ 
                }
                else
                {
                    $permanentNotRemoved += $_
                    Write-Host "Error removing critical permanent role assignment for which PIM role assignment is successfully created. Role Name: [$($_.RoleDefinitionDisplayName)] , Email: [$($_.PrincipalEmail)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this role assignment. " -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            catch
            {
                $permanentNotRemoved += $_
                Write-Host "Error removing critical permanent role assignment for which PIM role assignment is successfully created. Role Name: [$($_.RoleDefinitionDisplayName)] , Email: [$($_.PrincipalEmail)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this role assignment. " -ForegroundColor $([Constants]::MessageType.Error)
            }    
        }

        $colsProperty = @()
        $colsProperty = @{Expression={$_.RoleDefinitionDisplayName};Label="Display Name";Width=40;Alignment="left"},
                        @{Expression={$_.PrincipalEmail};Label="Email";Width=20;Alignment="left"},
                        @{Expression={$_.ExpandedPropertiesPrincipalType};Label="PrincipalType";Width=20;Alignment="left"}

        $skippedRoleAssignments = @()
        
        $skippedRoleAssignments += $permanentNotRemoved | Select-Object @{N='PrincipalDisplayName';E={$_.PrincipalDisplayName}},
                                                                              @{N='Scope';E={$_.Scope}},
                                                                              @{N='Name';E={$_.Name}},
                                                                              @{N='RoleDefinitionDisplayName';E={$_.RoleDefinitionDisplayName}},
                                                                              @{N='PrincipalEmail';E={$_.PrincipalEmail}},
                                                                              @{N='ExpandedPropertiesPrincipalType';E={$_.ExpandedPropertiesPrincipalType}}

        $skippedRoleAssignments += $PIMNotCreated | Select-Object @{N='PrincipalDisplayName';E={$_.PrincipalDisplayName}},
                                                                              @{N='Scope';E={$_.Scope}},
                                                                              @{N='Name';E={$_.Name}},
                                                                              @{N='RoleDefinitionDisplayName';E={$_.RoleDefinitionDisplayName}},
                                                                              @{N='PrincipalEmail';E={$_.PrincipalEmail}},
                                                                              @{N='ExpandedPropertiesPrincipalType';E={$_.ExpandedPropertiesPrincipalType}}
                       
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($permanentRemoved | Measure-Object).Count -gt 0)
        {
            Write-Host "PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) are successfully created and critical permanent role assignment(s) are successfully removed for which PIM role assignment(s) is successfully created in the Subscription or in resource group:" -ForegroundColor $([Constants]::MessageType.Update)
            $permanentRemoved | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $roleAssignmentsRemediatedFile = "$($backupFolderPath)\RemediatedRoleAssignments.csv"
            $permanentRemoved | Export-CSV -Path $roleAssignmentsRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to $($roleAssignmentsRemediatedFile) "
        }

        if ($($skippedRoleAssignments | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError while creating PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) or error occurred while removing critical permanent role assignment(s) for which PIM role assignment(s) is successfully created in the Subscription or in resource group:" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedRoleAssignments | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $roleAssignmentsSkippedFile = "$($backupFolderPath)\SkippedRoleAssignments.csv"
            $skippedRoleAssignments | Export-CSV -Path $roleAssignmentsSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($roleAssignmentsSkippedFile)"
        }
    }
    else
    {
        $totalRoleAssignments = ($roleAssignmentDetails| Measure-Object).Count

        if ($totalRoleAssignments -eq 0)
        {
            Write-Host "No role assignment found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
  
        Write-Host "Found $($totalRoleAssignments) role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)

        #List for critical role assignment(s).
        $criticalRoleAssignments = @()

        Write-Host "Checking for critical permanent role assignment(s)..."

        if( -not $ResourceGroup)
        {
            # Storing critical permanent role assignment(s) on the subscription level.
            $criticalRoleAssignments = $roleAssignmentDetails |  Where-Object {$_.Scope -eq "/subscriptions/$($SubscriptionId)" -and ($_.ExpandedPropertiesPrincipalType -eq "User" -or $_.ExpandedPropertiesPrincipalType -eq "Group") -and [string]::IsNullOrEmpty($_.LinkedRoleEligibilityScheduleInstanceId) -and ($_.RoleDefinitionDisplayName -eq "User Access Adminstrator" -or $_.RoleDefinitionDisplayName -eq "Contributor" -or $_.RoleDefinitionDisplayName -eq "Owner") -and $_.PrincipalDisplayName -ne "MS-PIM"}
        }
        else
        {
            # Storing critical permanent role assignment(s) on the resource group level.
            $criticalRoleAssignments = $roleAssignmentDetails | Where-Object {  $_.ScopeType -eq "resourcegroup" -and ($_.ExpandedPropertiesPrincipalType -eq "User" -or $_.ExpandedPropertiesPrincipalType -eq "Group") -and [string]::IsNullOrEmpty($_.LinkedRoleEligibilityScheduleInstanceId) -and ($_.RoleDefinitionDisplayName -eq "User Access Adminstrator" -or $_.RoleDefinitionDisplayName -eq "Owner" ) -and $_.PrincipalDisplayName -ne "MS-PIM"}
        }

        # List for Storing ids of critical permanent role assignment(s).
        $ids = @()

        $criticalRoleAssignments | ForEach-Object{ $ids += "$($_.PrincipalId)"}

        # Creating object of SCALTAccount class.
        $scaltAccount = [SCALTAccount]::new()
        
        # Calling GetSCALTRoleAssignments function to fetch critical permanent role assignment(s).
        $scALTDetails = $scaltAccount.GetSCALTRoleAssignments($ids)
        
        # Dictionary for storing SC-ALT Account related details.
        $scALTMapping = @{}

        $scALTDetails.value | ForEach-Object { 
            if($_.onPremisesExtensionAttributes.extensionAttribute2 -eq "-10")
            {
                $scALTMapping.Add($_.Id , @($true,$_.userPrincipalName))
            }
            else
            {
                $scALTMapping.Add($_.Id , @($false,""))
            }
        }
        
        # Separating required Parameters for remediation.
        $criticalRoleAssignments = $criticalRoleAssignments | Select-Object @{N='PrincipalDisplayName';E={$_.PrincipalDisplayName}},
                                                                              @{N='Scope';E={$_.Scope}},
                                                                              @{N='Name';E={$_.Name}},
                                                                              @{N='ExpandedPropertiesPrincipalType';E={$_.ExpandedPropertiesPrincipalType}},
                                                                              @{N='ResourceGroupName'; E={$_.ScopeDisplayName}},
                                                                              @{N='RoleDefinitionDisplayName';E={$_.RoleDefinitionDisplayName}},
                                                                              @{N='LinkedRoleEligibilityScheduleInstanceId';E={$false}},
                                                                              @{N='PrincipalEmail';E={$_.PrincipalEmail}},
                                                                              @{N='PrincipalId';E={$_.PrincipalId}},
                                                                              @{N='RoleDefinitionId';E={$_.RoleDefinitionId}},
                                                                              @{N='IsScAltAccount';E={($scALTMapping.($_.PrincipalId))[0]}},
                                                                              @{N='ScAltEmail';E={($scALTMapping.($_.PrincipalId))[1]}}
        # Checking the count of critical permanent role assignment(s).                                                                
        if(($criticalRoleAssignments|Measure-Object).count -eq 0)
        {
            Write-Host "No critical permanent role assignment(s) found . Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }

        Write-Host "Found $(($criticalRoleAssignments|Measure-Object).count) critical permanent role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)

        # Back up snapshots to `%LocalApplicationData%'.
        $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RemoveCriticalPermanentRoleAssignments"

        if (-not (Test-Path -Path $backupFolderPath))
        {
            New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
        }
 
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 3 of 4] Backing up permanent role assignment(s) details..."
    
        # Backing up role assignment(s) details.
        $backupFile = "$($backupFolderPath)\CriticalPermanentRoleAssignment.csv"

        $criticalRoleAssignments | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Permanent role assignment(s) details have been backed up to $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Role assignment(s) details have been backed up to $($backupFile)."
        Write-Host  "**** Only those critical permanent role assignment(s) will be remediated for which corresponding SC-ALT account mapping will be provided ****" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Please provide corresponding mapping of critical permanent role assignment(s) to their SC-ALT account if available in the empty cell of ScAltAccountEmail column."
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, To create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group, which are listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
    }
}

# class for getting role assignment(s) details
class SCALTAccount
{   
    # For generating auth token for Authorization.
    [psobject] GetAuthHeader()
    {    
        [psobject] $headers = $null 
        try
        {
            $resourceAppIdUri = "https://graph.microsoft.com"
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
            Write-Host "Error occurred while fetching auth header. ErrorMessage [$($_)]" -ForegroundColor Red
        }
        return($headers)
    }

    [psobject] GetSCALTRoleAssignments([string[]] $ids)
    {
        $content = $null
        try
        {
            $body = @{ids = $ids ; types = @("user" , "group")}
            $method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Post
            $headers = $this.GetAuthHeader()
            $apiUri = "https://graph.microsoft.com/beta/directoryObjects/getByIds" 

            # Api call for fetching role assignment details.
            $response = Invoke-WebRequest -Method $method -Uri $apiUri -Headers $headers -Body ($body| ConvertTo-Json)  -UseBasicParsing
            $content = ConvertFrom-Json $response.Content
        }
        catch
        {
            Write-Host "Error occurred while fetching classic role assignment. ErrorMessage [$($_)]" -ForegroundColor Red
        }     
        return($content)
    }
}
# Defines commonly used constants.
class Constants
{
    # Defines commonly used colour codes, corresponding to the severity of the log.
    static [Hashtable] $MessageType = @{
        Error = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info = [System.ConsoleColor]::Cyan
        Update = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}
