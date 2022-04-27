<###
# Overview:
    This script is used to create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and PIM non SC-ALT role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group.

# Control ID:
    Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access , Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG , Azure_Subscription__Use_Only_Alt_Credentials

# Display Name:
    Do not grant permanent access for critical subscription level roles , Do not grant permanent access for critical resource group level roles , Use Smart-Card ALT (SC-ALT) accounts to access critical roles on subscription and resource groups

# Prerequisites:
    1. please load the latest Az.Accounts module before loading this script. If module is not installed use - 'Install-Module -Name Az.Accounts -Scope CurrentUser -Repository "PSGallery" -Force  -AllowClobber -ErrorAction Stop'. 
    2. Owner and higher privileged role assignment on the Subscription is required and atleast one service adminstrator role assignment must be present on the subscription level.

# Important Points:
    1. First run the script using the -dryrun switch and for migration user needs to pass two files one for all the role assignments he needs to migrate(Mandatory) and other file with their SC-ALT mapping(Not Mandatory) which are provided as output of dryrun.
    2. Script will only migrate the role assignment if corresponding SC-ALT account mapping is provided by the user or already mapped to SC-ALT account, Otherwise the role assignment will be skipped from migration.
    3. The user critical role assignments will not be removed.
    4. The user needs to renew the PIM role assignments because they are created for a specific time interval which is 30 days.
    5. Rollback is not supported in this script.
    6. The Azure_Subscription_Use_Only_Alt_Credentials control will be partially remediated(corresponding PIM SC-ALT role assignment(s) will be created but the PIM non SC-ALT role assignment(s) will not be removed.
    7. User needs to delete the PIM non SC-ALT role assignment and migrate user's critical role assignment to SC-ALT PIM after the script execution.
	
# Steps performed by the script:
    To migrate:
        1. Install the modules required to run the script and validate the user.
        2. Get the list of critical permanent role assignment(s) in a Subscription or in a resource group.
        3. Back up details of critical permanent role assignment(s) that are to be remediated.
        4. Create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and PIM non SC-ALT role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group.
   
    NOTE: Please first run the script using the -dryrun switch and provide the output file of dryrun by adding corresponding SC-ALT account mapping, only as input for migration .
    NOTE: Rollback is not supported.

# Instructions to execute the script:
    To migrate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or at resource group level. Refer `Examples`, below.

# Examples:
    To migrate:
        1. To review the critical role assignment(s) on a Subscription that will be remediated:
    
           Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and PIM non SC-ALT role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group, from a previously taken snapshot:
          
           Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -RoleAssignmentDetailsFilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemoveCriticalPermanentAndPIMRoleAssignments"\CriticalPermanentAndPIMRoleAssignment.csv -SCALTMappingFilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemoveCriticalPermanentAndPIMRoleAssignments"\nonScAltRoleAssignment.csv

        To know more about the options supported by the migration command, execute:
        
        Get-Help Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments -Detailed
       
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
    $requiredModules = @("Az.Accounts","Az.Resources", "AzureAD")

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."
    # List of available modules
    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.    

    if($availableModules.Name -contains "AZ.Accounts")
    {
        $module = Get-Module "Az.Accounts"
        if($module.Version -ge "2.7.6")
        {
            Write-Host "Az.Accounts module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
             Write-Host "Installing Az.Accounts module..." -ForegroundColor $([Constants]::MessageType.Info)
             Install-Module -Name "Az.Accounts" -MinimumVersion 2.7.6 -Scope CurrentUser -Repository 'PSGallery' -Force  -AllowClobber -ErrorAction Stop
             Write-Host "Az.Accounts module is installed." -ForegroundColor $([Constants]::MessageType.Update) 
        }    
    }
    else
    {
        Write-Host "Installing Az.Accounts module...." -ForegroundColor $([Constants]::MessageType.Info)
        Install-Module -Name "Az.Accounts" -MinimumVersion 2.7.6 -Scope CurrentUser -Repository 'PSGallery' -Force -AllowClobber -ErrorAction Stop
        Write-Host "Az.Accounts module is installed." -ForegroundColor $([Constants]::MessageType.Update) 
    }


    if ($availableModules.Name -contains "Az.Resources")
    {
        $module = Get-Module "Az.Resources"
        if($module.Version -ge "5.5.0")
        {
            Write-Host "Az.Resources module is present." -ForegroundColor $([Constants]::MessageType.Update)        
        }
        else
        {
            Write-Host "Installing Az.Resources module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name "Az.Resources" -MinimumVersion 5.6.0 -Scope CurrentUser -Repository 'PSGallery'  -AllowClobber -Force -ErrorAction Stop 
            Write-Host "Az.Resources module is installed." -ForegroundColor $([Constants]::MessageType.Update)  
        }
    }
    else
    {
        Write-Host "Installing Az.Resources module...." -ForegroundColor $([Constants]::MessageType.Info)
        Install-Module -Name "Az.Resources"  -MinimumVersion 5.6.0 -Scope CurrentUser -Repository 'PSGallery' -Force  -AllowClobber -ErrorAction Stop
        Write-Host "Az.Resources module is installed." -ForegroundColor $([Constants]::MessageType.Update)
    }


    if($availableModules.Name -contains "AzureAD")
    {
        Write-Host "AzureAD module is present." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Installing AzureAD module...." -ForegroundColor $([Constants]::MessageType.Info)
        Install-Module -Name AzureAD -Scope CurrentUser -Repository "PSGallery" -Force -AllowClobber -ErrorAction Stop
        Write-Host "AzureAD module is installed." -ForegroundColor $([Constants]::MessageType.Update)
    }
}


function Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments
{
    <#
        .SYNOPSIS
        Remediates 'Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access, Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG', Azure_Subscription__Use_Only_Alt_Credentials Control.

        .DESCRIPTION
        Remediates 'Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access , Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG', Azure_Subscription__Use_Only_Alt_Credentials Control.
        To create PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) and PIM non SC-ALT role assignment(s) and remove critical permanent role assignment(s) for which the PIM role assignment(s) is successfully created in the Subscription or in resource group. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful migration without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual migration.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the migration.

        .INPUTS
        None. You cannot pipe objects to Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments.

        .OUTPUTS
        None. Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Migrate-PermanentAndNonSCALTPrivilegedToSCALTPrivilegedRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -RoleAssignmentDetailsFilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemoveCriticalPermanentAndPIMRoleAssignments"\CriticalPermanentAndPIMRoleAssignment.csv -SCALTMappingFilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemoveCriticalPermanentAndPIMRoleAssignments"\nonScAltRoleAssignment.csv
   
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
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true , HelpMessage="Specifies a dry run of the actual migration")]
        $DryRun,

        [String]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true , HelpMessage="Specifies the path to the file( which contains Permanent role assignment and PIM non SC-ALT role assignments) to be used as input for the migration")]
        $RoleAssignmentDetailsFilePath,

        [String]
        [Parameter(ParameterSetName = "WetRun" , HelpMessage="Specifies the path to the file(which contains non SC-ALT user details and their mapping) to be used as input for the migration")]
        $SCALTMappingFilePath
    )

    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script and validating the user..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }
    else
    {
        Write-Host "[Step 1 of 4] Validating the user... "
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
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    $docLink = "https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-resource-roles-discover-resources#discover-resources"
    $scope = "/subscriptions/$($SubscriptionId)"
    Write-Host "Checking if subscription [$($SubscriptionId)] is onboarded to PIM or not..."
        try
        {    
         $pimEligibleRoleAssignments = Get-AzRoleEligibilityScheduleInstance -Scope $scope -ErrorAction stop
        }
        catch
        {
            Write-Host "$($_)" -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
        if (-not $pimEligibleRoleAssignments)
        {
            Write-Host "Subscription is not onboarded to PIM. Please onboard the subscription to PIM and again run the script." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "*** To onboard the subscription to PIM please follow the steps mentioned here $($docLink). ***" -ForegroundColor $([Constants]::MessageType.Info)
            return
        }
        else
        {
            Write-Host "Subscription [$($context.Subscription.SubscriptionId)] is onboarded to PIM." -ForegroundColor $([Constants]::MessageType.Update)
        } 
        

    Write-Host "Checking if [$($context.Account.Id)] is of account type [user]..."

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by [User] Account Type. Account Type of [$($context.Account.Id)] is: [$($context.Account.Type)]" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
    Write-Host "[$($context.Account.Id)] is of account type [user]." -ForegroundColor $([Constants]::MessageType.Update)
    
    # Safe Check: Current user need to be either UAA or Owner for the subscription
    write-Host "Checking if the current user has required role[Owner, User Access Administrator , ServiceAdministrator]..."
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id  -IncludeClassicAdministrators -ErrorAction SilentlyContinue

    $requiredRoleDefinitionNames = @("Owner", "User Access Administrator" , "ServiceAdministrator")
    if(($currentLoginRoleAssignments | Where { ($_.Scope -like "/providers/Microsoft.Management/managementGroups*" -or $_.Scope -eq "/subscriptions/$($SubscriptionId)") -and ($_.RoleDefinitionName -split";" -contains "Owner" -or $_.RoleDefinitionName -split";" -contains "User Access Contributor" -or $_.RoleDefinitionName -split";" -contains "ServiceAdministrator")} | Measure-Object).Count -eq 0 )
    {
        Write-Host "Warning: This script can only be run by an [$($requiredRoleDefinitionNames -join ", ")]." -ForegroundColor Yellow
        return;
    }
    else
    {
        Write-Host "Current user [$($context.Account.Id)] has the required role on subscription [$($SubscriptionId)]." -ForegroundColor Green
    }
    
    $currentUserId = (Get-AzAdUser -ObjectId $context.Account.Id).Id
    #List of role assignment details 
    $roleAssignmentDetails = @()
    $roleAssignmentsDetails = @()

    Write-Host "Checking if subscription [$($SubscriptionId)] contains ServiceAdministrator role assignment(s)..."

    $roleAssignmentsDetails = Get-AzRoleAssignment -scope "/subscriptions/$($SubscriptionId)" -IncludeClassicAdministrators
    $administratorRoles = $roleAssignmentsDetails | Where-Object {$_.Scope -eq "/subscriptions/$($SubscriptionId)" -and ($_.RoleDefinitionName -split";" -contains "ServiceAdministrator")}
    
    # Checking the count of service adminstrator role assignment in the subscription.
    if(($administratorRoles |Measure-Object).count -eq 0)
    {
        Write-Host "WARNING: This script can only be run when there is a ServiceAdministrator configured for the Subscription." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host " Do you still want to continue to run the script ?"
        $userInput = Read-Host "(y/N)"
        if($userInput -eq "n")
        {
            Write-Host "Exiting..."
            return
        }
    }
    else
    {
        Write-Host "Current subscription [$($SubscriptionId)] contains $(($administratorRoles|Measure-Object).count) ServiceAdministrator role(s)."  -ForegroundColor $([Constants]::MessageType.Update) 
    }
    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all role assignment(s)..."
    Write-Host $([Constants]::SingleDashLine)

    # No file path provided as input to the script. Fetch all role assignment(s) in the Subscription.
    if ([String]::IsNullOrWhiteSpace($RoleAssignmentDetailsFilePath))
    {
        $scope = "/subscriptions/$($subscriptionId)"
        
        Write-Host "Fetching all role assignment(s) in Subscription: [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all Permanent assignment(s) in a Subscription
        
        $roleAssignmentDetails = Get-AzRoleAssignmentScheduleInstance -scope $scope -ErrorAction Stop

        # Get all PIM eligible assignment(s) in a subscription
        $pimEligibleRoleAssignments = Get-AzRoleEligibilityScheduleInstance -Scope $scope
    }
    else
    {   
        # If incorrect file path is provided.
        if (-not(Test-Path -Path $RoleAssignmentDetailsFilePath ))
        {
            Write-Host "ERROR: Input file not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all role assignment(s) from: " -ForegroundColor $([Constants]::MessageType.Info)
        write-Host "$($RoleAssignmentDetailsFilePath)"

        #Fetching permanent role assignment(s) from the file.
        $roleAssignmentCsvDetails = Import-Csv -LiteralPath $RoleAssignmentDetailsFilePath
        
        $roleAssignmentCsvDetails | ForEach-Object {
            $roleAssignment = $_
            try
            {
                Write-Host "Fetching role assignment: RoleName - [$($_.RoleDefinitionDisplayName)] , Email - [$($_.PrincipalEmail)]"
                
                # Checking if permanent role assignment still exists.
                if($_.RoleAssignmentType -eq "permanent")
                {
                    $roleAssignment =  Get-AzRoleAssignmentScheduleInstance -Name $_.Name -Scope $_.Scope 
                }
                else
                {
                    $roleAssignment =  Get-AzRoleEligibilityScheduleInstance -Name $_.Name -Scope $_.Scope 
                }
                    
                if(($roleAssignment|Measure-Object).count -eq 1)
                {  
                    if($_.PrincipalId -eq $currentUserId -and ($_.RoleDefinitionDisplayName -eq "User Access Adminstrator" -or $_.RoleDefinitionDisplayName -eq "Owner")  -and $_.ScopeType -eq "Subscription")
                    {
                        $currentUserRoleAssignment += $_                
                    }  
                    else
                    {
                        $roleAssignmentDetails += $_
                    }
                }
                else
                {
                    Write-Host "Error fetching role assignment: RoleName - [$($_.RoleDefinitionDisplayName)] , Email - [$($_.PrincipalEmail)]." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this role assignment..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
            catch
            {
                Write-Host "Error fetching role assignment: RoleName - [$($roleAssignment.RoleDefinitionDisplayName)] , Email - [$($roleAssignment.PrincipalEmail)]." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this role assignment..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
            
        $colsProperty = @()
        if(($currentUserRoleAssignment|Measure-Object).Count -gt 0)
        {
           Write-Host "`nFound $(($currentUserRoleAssignment|Measure-Object).Count) role assignment of current logged in user. Please migrate these role assignments manually to SC-ALT PIM role assignments after script execution." -ForegroundColor $([Constants]::MessageType.Update)
           $colsProperty = @{Expression={$_.PrincipalEmail};Label="PrincipalName";Width=40;Alignment="left"},
                        @{Expression={$_.RoleDefinitionDisplayName};Label="Role";Width=20;Alignment="left"},
                        @{Expression={$_.ExpandedPropertiesPrincipalType};Label="PrincipalType";Width=30;Alignment="left"},
                        @{Expression={$_.RoleAssignmentType};Label="RoleAssignmentType";Width=35;Alignment="left"},
                        @{Expression={$_.Scope};Label="Scope";Width=60;Alignment="left"}
           $currentUserRoleAssignment | Format-Table -Property $colsProperty -Wrap 
        }
    
        $totalRoleAssignments = ($roleAssignmentDetails| Measure-Object).Count 

        if ($totalRoleAssignments -eq 0 -and $currentUserRoleAssignment -ne 0)
        {
            Write-Host "No role assignment found except for the current user [$($context.Account.Id)].Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
        elseif($totalRoleAssignments -eq 0 -and $currentUserRoleAssignment -eq 0)
        {
            Write-Host "No role assignment found .Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Break
        }
            
        Write-Host "Found $($totalRoleAssignments) role assignment(s) except for the current user [$($context.Account.Id)]." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Checking for critical permanent and non SC-ALT PIM role assignment(s)..." 

        #List for storing critical pim role assignment.
        $criticalPIMRoleAssignments = @()

        #List for critical role assignment(s).
        $criticalRoleAssignments = @()

        # List for storing permanent role assignments.
        $criticalPermanentRoleAssignments = @()

        # List for storing critical Non SC-ALT Account 
        $CriticalPIMNonSCALTRoleAssignments = @()

        # List for storing critical Permanent and PIM role assignment.
        $criticalPIMAndPermanentRoleAssignments = @()

        # Storing critical PIM role assignment on the subscription and resource group level.
        $criticalPIMRoleAssignments += $roleAssignmentDetails | Where-Object { (($_.ScopeType -eq "subscription" -and ($_.RoleDefinitionDisplayName -eq "User Access Administrator" -or $_.RoleDefinitionDisplayName -eq "Contributor" -or $_.RoleDefinitionDisplayName -eq "Owner")) -or ( $_.ScopeType -eq "resourcegroup" -and ($_.RoleDefinitionDisplayName -eq "User Access Administrator" -or $_.RoleDefinitionDisplayName -eq "Owner"))) -and $_.ExpandedPropertiesPrincipalType -eq "user" -and $_.RoleAssignmentType -eq "Privileged Identity Management(PIM)" }

        # Storing critical permanent role assignment on the subscription level.
        $criticalPermanentRoleAssignments += $roleAssignmentDetails |  Where-Object { $_.ScopeType -eq "subscription" -and ($_.ExpandedPropertiesPrincipalType -eq "User" -or $_.ExpandedPropertiesPrincipalType -eq "Group") -and [system.convert]::ToBoolean($_.LinkedRoleEligibilityScheduleInstanceId) -eq $false  -and ($_.RoleDefinitionDisplayName -eq "User Access Adminstrator" -or $_.RoleDefinitionDisplayName -eq "Contributor" -or $_.RoleDefinitionDisplayName -eq "Owner") -and $_.RoleAssignmentType -eq "Permanent"  }

        # Storing critical permanent role assignment on the resource group level.
        $criticalPermanentRoleAssignments += $roleAssignmentDetails | Where-Object { $_.ScopeType -eq "resourcegroup" -and ($_.ExpandedPropertiesPrincipalType -eq "User" -or $_.ExpandedPropertiesPrincipalType -eq "Group") -and [system.convert]::ToBoolean($_.LinkedRoleEligibilityScheduleInstanceId) -eq $false -and ($_.RoleDefinitionDisplayName -eq "User Access Adminstrator" -or $_.RoleDefinitionDisplayName -eq "Owner" ) -and $_.RoleAssignmentType -eq "Permanent"  }
        
        $criticalPIMAndPermanentRoleAssignments += $criticalPIMRoleAssignments
        $criticalPIMAndPermanentRoleAssignments += $criticalPermanentRoleAssignments
        
        # Checking for critical permanent role assignment.                                                               
        if(($criticalPIMAndPermanentRoleAssignments| Measure-Object).Count -eq 0)
        {
            Write-Host "No critical permanent and non SC-ALT PIM role assignment(s) found.Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }

        Write-Host "Found $(($criticalPIMAndPermanentRoleAssignments|Measure-Object).Count) critical permanent and non SC-ALT PIM role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)

        $colsProperty = @{Expression={$_.PrincipalEmail};Label="PrincipalName";Width=40;Alignment="left"},
                        @{Expression={$_.RoleDefinitionDisplayName};Label="Role";Width=20;Alignment="left"},
                        @{Expression={$_.ExpandedPropertiesPrincipalType};Label="PrincipalType";Width=30;Alignment="left"},
                        @{Expression={$_.RoleAssignmentType};Label="RoleAssignmentType";Width=35;Alignment="left"},
                        @{Expression={$_.Scope};Label="Scope";Width=60;Alignment="left"}
        
        # Printing the critical role assignments
        $criticalPIMAndPermanentRoleAssignments | Format-Table -Property $colsProperty -Wrap

        # Back up snapshots to `%LocalApplicationData%'.
        $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Migration\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RemoveCriticalPermanentAndPIMRoleAssignments"

        if (-not (Test-Path -Path $backupFolderPath))
        {
            New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 3 of 4] Backing up critical role assignment(s) details to $($backupFolderPath)"
        Write-Host $([Constants]::SingleDashLine)
    
        # Backing up role assignment(s) details.
        $backupFile = "$($backupFolderPath)\CriticalPermanentAndPIMRoleAssignment.csv"

        $criticalPIMAndPermanentRoleAssignments | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Critical role assignment(s) details have been backed up to:" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "$($backupFile)"

        $nonScAltRoleAssignmentDictionary = @{}
        if (!([String]::IsNullOrWhiteSpace($SCALTMappingFilePath)))
        {
            $nonScAltRoleAssignment = Import-Csv -LiteralPath $SCALTMappingFilePath
            $nonScAltRoleAssignment | ForEach-Object {
            $nonScAltRoleAssignmentDictionary.add($_.PrincipalEmail, $_.ScAltEmail)
            }
        }

        Write-Host $([Constants]::DoubleDashLine)
    }

    if (-not $DryRun)
    { 
        Write-Host "[Step 4 of 4] Migrating all the critical permanent and non SC-ALT PIM role assignments which are listed in [step 2 of 4]...`n"
        Write-Host "Do you want to create:`n 1.PIM role assignment(s) with SC-ALT account for:`n   * Critical permanent role assignment(s) and `n   * Critical PIM non SC-ALT role assignment(s) `n 2.Remove critical permanent role assignment(s) for which PIM role assignment(s) is successfully created in the Subscription or in resource group.`n" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "PIM role assignment(s) with SC-ALt account for critical permanent role assignment(s) and critical PIM non SC-ALT role assignment(s) will not be created and critical permanent role assignment(s) will not be removed for which PIM role assignment(s) is successfully created in the Subscription or in resource group. Exiting..." -ForegroundColor $([Constants]::MessageType.Info)
            break
        }

        # List of PIM role assignment(s) with SC-ALt account successfully created.
        $PIMcreated = @()

        # List of PIM role assignment(s) in which error occurred while creating.
        $PIMNotCreated = @()
        
        # List of permanent role assignment(s) which are removed successfully.
        $permanentRemoved = @()
        
        # List of permanent role assignment(s) which were not removed successfully.
        $permanentNotRemoved = @()

        # Dictionary for storing reason of failure.
        $failureReasons = @{}

        # List to store pim for which pim SC-ALT is created.
        $pimWithNonSCALTAccount = @()

        Write-Host "PIM role assignments will be created for 30 days time interval,they need to renewed after 30 days if the user wish to continue using them." -ForegroundColor $([Constants]::MessageType.Info)

        # To create PIM role assignment(s) with SC-ALt account for critical permanent role assignment(s).
        $criticalPIMAndPermanentRoleAssignments | ForEach-Object{
            $roleAssignment = $_
           
            if(!(!($_.IsScAltAccount -eq $true) -and [string]::IsNullOrWhiteSpace($nonScAltRoleAssignmentDictionary["$($_.PrincipalEmail)"])))
            {
                try
                {
                    # To get the user details
                    if($_.IsScAltEmail -eq $true)
                    {
                        $user = Get-AzAdUser -ObjectId $_.PrincipalEmail
                    }
                    else
                    {                                        
                        $user = Get-AzAdUser -ObjectId $nonScAltRoleAssignmentDictionary["$($_.PrincipalEmail)"]   
                    }
                    $Scope = "/providers/Microsoft.Subscription" + $($_.Scope)
                    # Create PIM role assignment(s) with SC-ALt account for critical permanent role assignment(s).
                    $PIMAssignment = New-AzRoleEligibilityScheduleRequest -Name $_.Name -RoleDefinitionId $_.RoleDefinitionId -Scope $Scope -PrincipalId $user.Id -ScheduleInfoStartDateTime ("$((Get-Date).ToUniversalTime())" +"Z") -ExpirationDuration "PT8H" -ExpirationEndDateTime ("$(((Get-Date).ToUniversalTime()).AddDays(30))"+"Z") -ExpirationType 'AfterDateTime' -RequestType 'AdminAssign'
                    
                    if(($PIMAssignment|Measure-Object).Count -ne 0)
                    {
                        $PIMCreated += $_ |Select-Object @{N='PrincipalDisplayName';E={$_.PrincipalDisplayName}},
                                                                              @{N='Scope';E={$_.Scope}},
                                                                              @{N='Name';E={$_.Name}},
                                                                              @{N='ExpandedPropertiesPrincipalType';E={$_.ExpandedPropertiesPrincipalType}},
                                                                              @{N='ScopeLevel'; E={$_.ScopeLevel}},
                                                                              @{N='RoleDefinitionDisplayName';E={$_.RoleDefinitionDisplayName}},
                                                                              @{N='LinkedRoleEligibilityScheduleInstanceId';E={$_.LinkedRoleEligibilityScheduleInstanceId}},
                                                                              @{N='PrincipalEmail';E={$_.PrincipalEmail}},
                                                                              @{N='PrincipalId';E={$_.PrincipalId}},
                                                                              @{N='RoleDefinitionId';E={$_.RoleDefinitionId}},
                                                                              @{N='RoleAssignmentType';E={$_.RoleAssignmentType}},
                                                                              @{N='IsScAltAccount';E={$_.IsScAltAccount}},
                                                                              @{N='ScAltEmail'; E ={$user.Mail}}
                    }
                    else
                    {
                        $PIMNotCreated += $_
                        $failureReasons.Add($_.Name , "Error occured while creating PIM with SC-ALT account")
                    }
                }
                catch
                {
                    $PIMNotCreated += $_
                    $failureReasons.Add($_.Name , "Error occured while creating PIM with SC-ALt account")
                }
            }
            else
            {
                try
                {
                    if($_.ExpandedPropertiesPrincipalType -eq "Group")
                    {
                        $Scope = "/providers/Microsoft.Subscription" + $($_.Scope)
                        
                        $user = Get-AzAdUser -ObjectId $_.PrincipalEmail
                        # Create PIM role assignment(s) with SC-ALt account for critical permanent role assignment(s).
                        $PIMAssignment = New-AzRoleEligibilityScheduleRequest -Name $_.Name -RoleDefinitionId $_.RoleDefinitionId -Scope $Scope -PrincipalId $user.Id -ScheduleInfoStartDateTime ("$((Get-Date).ToUniversalTime())" +"Z") -ExpirationDuration "PT8H" -ExpirationEndDateTime ("$(((Get-Date).ToUniversalTime()).AddDays(30))"+"Z") -ExpirationType 'AfterDateTime' -RequestType 'AdminAssign'
                    
                        if(($PIMAssignment|Measure-Object).Count -ge 1)
                        {
                            $PIMCreated += $_ 
                        }
                        else
                        {
                            $PIMNotCreated += $_
                            $failureReasons.Add($_.Name , "Error occured while creating PIM with non SC-ALt account")
                        }
                    }
                    else
                    {
                        $PIMNotCreated += $_
                        $failureReasons.Add($_.Name , "No SC-ALt account found")
                    }    
                }
                catch
                {
                    $PIMNotCreated += $_
                    $failureReasons.Add($_.Name , "Error occured while creating PIM with non SC-ALt account")
                }
            }
        }

        if(($PIMcreated|Measure-Object).Count -ne 0) 
        {
            Write-Host "`nPIM Role assignment is successfully created with SC-ALT account for below role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)
            $PIMcreated | Format-Table -Property $colsProperty -Wrap
        }

        if(($PIMNotCreated|Measure-Object).Count -ne 0)
        {
            Write-Host "`nError occured while creating PIM Role assignment with SC-ALT account for below role assignment(s)." -ForegroundColor $([Constants]::MessageType.Error)
            $PIMNotcreated | Format-Table -Property $colsProperty -Wrap
        }

        if(($PIMcreated|Measure-Object).Count -ne 0)
        {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Please inform all the users whose permanent role assignment will be deleted." -ForegroundColor $([Constants]::MessageType.Info)`n
            Write-Host "*** All the critical Permanent role assignment will be deleted for which PIM role assignment(s) with SC-ALT account is created at Subscription level or resource group level.***"
        }
        #Remove critical permanent role assignment for which PIM role assignment is successfully created. 
        $PIMcreated | ForEach-Object {
            if($_.RoleAssignmentType -eq "Permanent")
            {
                try
                {
                    # Remove critical permanent role assignment(s) for which PIM role assignment is successfully created.             
                    Remove-AzRoleAssignment -Scope $_.Scope -RoleDefinitionName $_.RoleDefinitionDisplayName -SignInName $_.PrincipalEmail
                    if($?)
                    {
                        $permanentRemoved += $_ 
                    }
                    else
                    {
                        $permanentNotRemoved += $_
                        $failureReasons.Add($_.Name , "Error occured while removing permanent role assignment")
                    }
                }
                catch
                {
                    $permanentNotRemoved += $_
                    $failureReasons.Add($_.Name , "Error occured while removing permanent role assignment")
                }
            }
            else
            {
                $pimWithNonSCALTAccount  += $_
            }     
        }
        
        if(($permanentRemoved|Measure-Object).count -gt 0)
        {    
            Write-Host "`nPermanent Role assignment(s) is successfully deleted for below role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)
            $permanentRemoved | Format-Table -Property $colsProperty -Wrap
        }
        if(($permanentNotRemoved|Measure-Object).count -gt 0)
        {    

            Write-Host "`nError occured while deleting permanent role assignment(s) for below role assignment(s)." -ForegroundColor $([Constants]::MessageType.Error)
            $permanentNotRemoved | Format-Table -Property $colsProperty -Wrap
        }


        # List for storing skipped role assignments.
        $skippedRoleAssignments = @()
        $permanentDeleted = @()
        
        $skippedRoleAssignments += $permanentNotRemoved 

        $skippedRoleAssignments += $PIMNotCreated
        
        # List for storing deleted role assignments.
        $permanentDeleted = $permanentRemoved

        # List for storing remediated role assignments.
        $permanentRemoved += $pimWithNonSCALTAccount

        $skippedRoleAssignments = $skippedRoleAssignments | Select-Object @{N='PrincipalDisplayName';E={$_.PrincipalDisplayName}},
                                                                              @{N='Scope';E={$_.Scope}},
                                                                              @{N='Name';E={$_.Name}},
                                                                              @{N='ExpandedPropertiesPrincipalType';E={$_.ExpandedPropertiesPrincipalType}},
                                                                              @{N='ScopeLevel'; E={$_.ScopeLevel}},
                                                                              @{N='RoleDefinitionDisplayName';E={$_.RoleDefinitionDisplayName}},
                                                                              @{N='LinkedRoleEligibilityScheduleInstanceId';E={$_.LinkedRoleEligibilityScheduleInstanceId}},
                                                                              @{N='PrincipalEmail';E={$_.PrincipalEmail}},
                                                                              @{N='PrincipalId';E={$_.PrincipalId}},
                                                                              @{N='RoleDefinitionId';E={$_.RoleDefinitionId}},
                                                                              @{N='RoleAssignmentType';E={$_.RoleAssignmentType}},
                                                                              @{N='IsScAltAccount';E={$_.IsScAltAccount}},
                                                                              @{N='ReasonForFailure'; E ={$failureReasons.($_.Name)}}
        # For wrapping the output.
        $colsProperty1 = @()
        $colsProperty2 = @()
        $colsProperty1 = @{Expression={$_.RoleDefinitionDisplayName};Label="DisplayName";Width=20;Alignment="left"},
                        @{Expression={$_.PrincipalEmail};Label="PrincipalName";Width=30;Alignment="left"},
                        @{Expression={$_.ExpandedPropertiesPrincipalType};Label="PrincipalType";Width=20;Alignment="left"},
                        @{Expression={$_.Scope};Label="Scope";Width=60;Alignment="left"}

        $colsProperty2 = @{Expression={$_.RoleDefinitionDisplayName};Label="DisplayName";Width=20;Alignment="left"},
                        @{Expression={$_.PrincipalEmail};Label="PrincipalName";Width=30;Alignment="left"},
                        @{Expression={$_.ExpandedPropertiesPrincipalType};Label="PrincipalType";Width=20;Alignment="left"},
                        @{Expression={$_.Scope};Label="Scope";Width=60;Alignment="left"},
                        @{Expression={$_.ReasonForFailure};Label="Reason For Failure";Width=60;Alignment="left"}
        
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Migration Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

        if ($($permanentRemoved | Measure-Object).Count -gt 0)
        {
            Write-Host "PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) are successfully created and critical permanent role assignment(s) are successfully removed for which PIM role assignment(s) is successfully created in the Subscription or in resource group:`n" -ForegroundColor $([Constants]::MessageType.Update)
            $permanentRemoved | Format-Table -Property $colsProperty1 -Wrap

            # Write this to a file.
            $roleAssignmentsRemediatedFile = "$($backupFolderPath)\RemediatedRoleAssignments.csv"
            $permanentRemoved | Export-CSV -Path $roleAssignmentsRemediatedFile -NoTypeInformation
            Write-Host "These logs has been saved to $($roleAssignmentsRemediatedFile) "
        }

        if ($($skippedRoleAssignments | Measure-Object).Count -gt 0)
        {
            Write-Host "Error occured while creating PIM role assignment(s) with SC-ALT account for critical permanent role assignment(s) or error occurred while removing critical permanent role assignment(s) for which PIM role assignment(s) is successfully created in the Subscription or in resource group:" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedRoleAssignments | Format-Table -Property $colsProperty2 -Wrap
            
            # Write this to a file.
            $roleAssignmentsSkippedFile = "$($backupFolderPath)\SkippedRoleAssignments.csv"
            $skippedRoleAssignments | Export-CSV -Path $roleAssignmentsSkippedFile -NoTypeInformation
            Write-Host "These logs has been saved to $($roleAssignmentsSkippedFile)"
        }

        if ($($permanentDeleted | Measure-Object).Count -gt 0)
        {   
            # Write this to a file.
            $permanentRemovedRoleAssignmentsFile = "$($backupFolderPath)\PermanentRemovedRoleAssignments.csv"
            $permanentDeleted | Export-CSV -Path $permanentRemovedRoleAssignmentsFile -NoTypeInformation
            Write-Host "`n Refer $($permanentRemovedRoleAssignmentsFile) for list of permanent role assignment which is successfully deleted."
        }

        Write-Host "`nNOTES:`n      1. [RemediatedRoleAssignments.csv] file contains list of role assignments which are successfully remediated.`n      2. [SkippedRoleAssignments.csv] file contains list of role assignments which are skipped from migration. `n      3. [PermanentRemovedRoleAssignments.csv] file contains list of permanent role assignments which are deleted successfully.`n      4. [ToBeDeletedPIMRoleAssignments.csv] file contains list of PIM(Non SC-ALT) role assignments which needs to be removed explicitly.`n      5. [ToBeMigratedCurrentUserRoleAssignments.csv] file contains list of current user role assignments which needs to be migrated to SC-ALT PIM explicitly." -ForegroundColor $([Constants]::MessageType.Warning)

        Write-Host "`nNext Steps:" -ForegroundColor $([Constants]::MessageType.Info)
        
        if(($pimWithNonSCALTAccount|measure-object).Count -gt 0)
        {
            # Write this to a file.
            $nonScAltRoleAssignmentsFile = "$($backupFolderPath)\ToBeDeletedPIMRoleAssignments.csv"
            $pimWithNonSCALTAccount | Export-CSV -Path $nonScAltRoleAssignmentsFile  -NoTypeInformation
            Write-Host "*   Refer $($nonScAltRoleAssignmentsFile) to remove PIM (Non SC-ALT) assignments.`n" 
        }
        
        if(($currentUserRoleAssignment|measure-object).Count -gt 0)
        {
            # Write this to a file.
            $currentuserRoleAssignmentFile = "$($backupFolderPath)\ToBeMigratedCurrentUserRoleAssignments.csv"
            $currentUserRoleAssignment | Export-CSV -Path $currentuserRoleAssignmentFile -NoTypeInformation
            write-host "*   Refer $($currentuserRoleAssignmentFile) to migrate these role assignments to SC-ALT PIM role assignments."
        }
    }
    else
    {
        $totalRoleAssignments = ($roleAssignmentDetails| Measure-Object).Count + ($pimEligibleRoleAssignments|Measure-Object).Count

        if ($totalRoleAssignments -eq 0)
        {
            Write-Host "No role assignment found.Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
  
        Write-Host "Found $($totalRoleAssignments) role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)

        #List for storing critical pim role assignment.
        $criticalPIMRoleAssignments = @()

        #List for critical role assignment(s).
        $criticalRoleAssignments = @()

        # List for storing critical permanent role assignment.
        $criticalPermanentRoleAssignments = @()

        # List for storing critical Non SC-ALT Account 
        $CriticalPIMNonSCALTRoleAssignments = @()

        # List for storing critical Permanent and PIM role assignment
        $criticalPIMAndPermanentRoleAssignments = @()

        Write-Host "Checking for critical permanent and PIM non SC-ALT role assignment(s)..."

        $criticalPIMRoleAssignments = $pimEligibleRoleAssignments | Where-Object { (($_.ScopeType -eq "subscription" -and ($_.RoleDefinitionDisplayName -eq "User Access Administrator" -or $_.RoleDefinitionDisplayName -eq "Contributor" -or $_.RoleDefinitionDisplayName -eq "Owner")) -or ( $_.ScopeType -eq "resourcegroup" -and ($_.RoleDefinitionDisplayName -eq "User Access Administrator" -or $_.RoleDefinitionDisplayName -eq "Owner"))) -and $_.ExpandedPropertiesPrincipalType -eq "User" } 

         # List for Storing ids of critical permanent role assignment(s).
        $ids = @()

        $criticalPIMRoleAssignments | ForEach-Object{ $ids += "$($_.PrincipalId)"}
        $ids = $ids | select-Object -Unique
        # Creating object of SCALTAccount class.
        $scaltAccount = [SCALTAccount]::new()
        
        # Calling GetSCALTRoleAssignments function to fetch critical permanent role assignment(s).
        $scALTDetails = $scaltAccount.GetSCALTRoleAssignments($ids)
        
        # Dictionary for storing SC-ALT Account related details.
        $scALTMapping = @{}

        # Checking if the user is SC-ALT or not.
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
        
        $criticalPIMRoleAssignments | forEach-Object {
            if ($scALTMapping.($_.PrincipalId)[0] -eq $false)
            {
                $CriticalPIMNonSCALTRoleAssignments += $_
            }
        }

        $CriticalPIMNonSCALTRoleAssignments = $CriticalPIMNonSCALTRoleAssignments | Select-Object @{N='PrincipalDisplayName';E={$_.PrincipalDisplayName}},
                                                                              @{N='Scope';E={$_.Scope}},
                                                                              @{N='Name';E={$_.Name}},
                                                                              @{N='ExpandedPropertiesPrincipalType';E={$_.ExpandedPropertiesPrincipalType}},
                                                                              @{N='ScopeLevel'; E={$_.ScopeDisplayName}},
                                                                              @{N='RoleDefinitionDisplayName';E={$_.RoleDefinitionDisplayName}},
                                                                              @{N='LinkedRoleEligibilityScheduleInstanceId';E={$false}},
                                                                              @{N='PrincipalEmail';E={$_.PrincipalEmail}},
                                                                              @{N='PrincipalId';E={$_.PrincipalId}},
                                                                              @{N='RoleDefinitionId';E={$_.RoleDefinitionId}},
                                                                              @{N='RoleAssignmentType';E={"Privileged Identity Management(PIM)"}},
                                                                              @{N='ScopeType';E={$_.ScopeType}},
                                                                              @{N='IsScAltAccount';E={$false}}

        # Storing critical permanent role assignment(s) on the subscription level.
        $criticalPermanentRoleAssignments += $roleAssignmentDetails |  Where-Object {$_.ScopeType -eq "subscription" -and ($_.ExpandedPropertiesPrincipalType -eq "User" -or $_.ExpandedPropertiesPrincipalType -eq "Group") -and [string]::IsNullOrEmpty($_.LinkedRoleEligibilityScheduleInstanceId) -and ($_.RoleDefinitionDisplayName -eq "User Access Administrator" -or $_.RoleDefinitionDisplayName -eq "Contributor" -or $_.RoleDefinitionDisplayName -eq "Owner") -and $_.PrincipalDisplayName -ne "MS-PIM"}
      
        # Storing critical permanent role assignment(s) on the resource group level.
        $criticalPermanentRoleAssignments += $roleAssignmentDetails | Where-Object {$_.ScopeType -eq "resourcegroup" -and ($_.ExpandedPropertiesPrincipalType -eq "User" -or $_.ExpandedPropertiesPrincipalType -eq "Group") -and [string]::IsNullOrEmpty($_.LinkedRoleEligibilityScheduleInstanceId) -and ($_.RoleDefinitionDisplayName -eq "User Access Administrator" -or $_.RoleDefinitionDisplayName -eq "Owner" ) -and $_.PrincipalDisplayName -ne "MS-PIM"}

        # List for Storing ids of critical permanent role assignment(s).
        $ids = @()

        $criticalPermanentRoleAssignments | ForEach-Object{ $ids += "$($_.PrincipalId)"}
        $ids = $ids | select-Object -Unique

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

        # Separating required Parameters for migration.
        $criticalPermanentRoleAssignments = $criticalPermanentRoleAssignments | Select-Object @{N='PrincipalDisplayName';E={$_.PrincipalDisplayName}},
                                                                              @{N='Scope';E={$_.Scope}},
                                                                              @{N='Name';E={$_.Name}},
                                                                              @{N='ExpandedPropertiesPrincipalType';E={$_.ExpandedPropertiesPrincipalType}},
                                                                              @{N='ScopeLevel'; E={$_.ScopeDisplayName}},
                                                                              @{N='RoleDefinitionDisplayName';E={$_.RoleDefinitionDisplayName}},
                                                                              @{N='LinkedRoleEligibilityScheduleInstanceId';E={$false}},
                                                                              @{N='PrincipalEmail';E={$_.PrincipalEmail}},
                                                                              @{N='PrincipalId';E={$_.PrincipalId}},
                                                                              @{N='RoleDefinitionId';E={$_.RoleDefinitionId}},
                                                                              @{N='RoleAssignmentType';E={"Permanent"}},
                                                                              @{N='ScopeType';E={$_.ScopeType}},
                                                                              @{N='IsScAltAccount';E={($scALTMapping.($_.PrincipalId))[0]}}

        $criticalPIMAndPermanentRoleAssignments += $criticalPermanentRoleAssignments
        $criticalPIMAndPermanentRoleAssignments += $CriticalPIMNonSCALTRoleAssignments

        # Checking the count of critical permanent role assignment(s).                                                                
        if(($criticalPIMAndPermanentRoleAssignments|Measure-Object).count -eq 0)
        {
            Write-Host "No critical permanent or PIM non SC-ALT role assignment(s) found.Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }

        Write-Host "Found $(($criticalPIMAndPermanentRoleAssignments|Measure-Object).count) critical permanent and PIM non SC-ALT role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)

        $colsProperty = @()
        $colsProperty = @{Expression={$_.PrincipalEmail};Label="PrincipalName";Width=30;Alignment="left"},
                        @{Expression={$_.RoleDefinitionDisplayName};Label="Role";Width=20;Alignment="left"},
                        @{Expression={$_.ExpandedPropertiesPrincipalType};Label="PrincipalType";Width=20;Alignment="left"},
                        @{Expression={$_.RoleAssignmentType};Label="RoleAssignmentType";Width=40;Alignment="left"},
                        @{Expression={$_.Scope};Label="Scope";Width=60;Alignment="left"}
        
        # Printing the critical role assignments
        $criticalPIMAndPermanentRoleAssignments | Format-Table -Property $colsProperty -Wrap

        $nonScAltRoleAssignment = $criticalPIMAndPermanentRoleAssignments| Where-Object { $_.ExpandedPropertiesPrincipalType -eq "User" -and $_.IsScAltAccount -eq $false}
 
        $nonScAltRoleAssignment = $nonScAltRoleAssignment | Sort-Object -Property PrincipalEmail | Select-Object PrincipalEmail , ScAltEmail | Get-Unique -AsString

        # Back up snapshots to `%LocalApplicationData%'.
        $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Migration\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RemoveCriticalPermanentAndPIMRoleAssignments"

        if (-not (Test-Path -Path $backupFolderPath))
        {
            New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
        }
 
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 3 of 4] Backing up permanent and PIM non SC-ALT role assignment(s) details..."
        Write-Host $([Constants]::SingleDashLine)
    
        # Backing up role assignment(s) details.
        $backupFile1 = "$($backupFolderPath)\CriticalPermanentAndPIMRoleAssignment.csv"

        $criticalPIMAndPermanentRoleAssignments | Export-CSV -Path $backupFile1 -NoTypeInformation
        Write-Host "Permanent and PIM non SC-ALT role assignment(s) details have been backed up to:" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "$($backupFile1)"

        if(($nonScAltRoleAssignment | Measure-Object).Count -ne 0)
        {
            $backupFile2 = "$($backupFolderPath)\NonSCALTRoleAssignment.csv"
            $nonScAltRoleAssignment | Export-CSV -Path $backupFile2 -NoTypeInformation
            Write-Host "Non SC-ALT user details have been backed up to:" -ForegroundColor $([Constants]::MessageType.Update)
            write-Host "$($backupFile2)"
        }
        
        Write-Host $([Constants]::DoubleDashLine)
        write-Host "[step 4 of 4] Migrating all the critical permanent and non SC-ALT PIM role assignments which are listed in [step 2 of 4]..."
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host  "NOTE: Only those critical permanent role assignment(s) and PIM non SC-ALT role assignment(s) will be remediated for which corresponding SC-ALT account mapping will be provided or which are already mapped to SC-ALT account." -ForegroundColor $([Constants]::MessageType.Warning)
        if(($nonScAltRoleAssignment | Measure-Object).Count -ne 0)
        {
            Write-Host "`nNext steps:" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host "*    Please provide corresponding mapping of critical permanent role assignment(s) and PIM non SC-ALT role assignment(s) to their SC-ALT account(if available) in the 'ScAltEmail' column in the file $($backupFile2).`n" 
            Write-Host "*    Run the same command with -RoleAssignmentDetailsFilePath $($backupFile1) and -SCALTMappingFilePath $($backupFile2) without -DryRun." 
        }
        else
        {
            Write-Host "`nNext steps:" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host "*    Run the same command with -RoleAssignmentDetailsFilePath $($backupFile1) without -DryRun." 
        }  
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
            Write-Host "Error occurred while fetching role assignment. ErrorMessage [$($_)]" -ForegroundColor Red
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
