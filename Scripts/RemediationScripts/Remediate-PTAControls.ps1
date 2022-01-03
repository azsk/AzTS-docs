<###
# Overview:
    This script is used to enable HTTPS for Role Assignments in a Subscription.

# Control ID:
    Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access , Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG

# Display Name:
Do not grant permanent access for privileged subscription level roles , Do not grant permanent access for privileged resource group level roles

# Prerequisites:
    Contributor and higher privileges on the Role Assignments in a Subscription.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of permanent privileged Role Assignments in a Subscription or in a resource group.
        3. Back up details of Role Assignments that are to be remediated.
        4. Create PIM role assignments for permanent privileged role Assignment and remove permanent privileged role Assignment for which PIM Role Assignments in the Subscription or in resource group already exists.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Role Assignments in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable HTTPS on the production slot and all non-production slots in all Role Assignments in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remove permanent privileged Role Assignments in the Subscription or at resource group level. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable HTTPS on the production slot and all non-production slots in all Role Assignments in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Role Assignments in a Subscription that will be remediated:
    
           Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To create PIM role assignments for permanent privileged role Assignment and remove permanent privileged role Assignment for which PIM Role Assignments in the Subscription or in resource group:
       
           Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To create PIM role assignments for permanent privileged role Assignment and remove permanent privileged role Assignment for which PIM Role Assignments in the Subscription or in resource group , from a previously taken snapshot:
           Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemovePermanentPrivilegedRoleAssignments\PermanentPrivilegedRoleAssignment.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Create-PIMForPermanentRoleAssignments -Detailed

    To roll back:
        1. To disable HTTPS on the production slot and all non-production slots of all Role Assignments in a Subscription, from a previously taken snapshot:
           Disable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSForAppServices\RemediatedAppServices.csv
        
        2. To disable HTTPS on the production slot and all non-production slots of all Role Assignments in a Subscription, from a previously taken snapshot:
           Disable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -ExcludeNonProductionSlots -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSForAppServices\RemediatedAppServices.csv

        To know more about the options supported by the roll back command, execute:
        
        Get-Help Disable-HttpsForAppServices -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Resources")

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."

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
            Write-Host "Installing $($_) module with correct version(5.0.0)..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name "Az.Resources" -MinimumVersion 5.0.0 -Scope CurrentUser -Repository 'PSGallery'  -Force -ErrorAction Stop   
        }
    }
    else
    {
        Write-Host "Installing $($_) module...." -ForegroundColor $([Constants]::MessageType.Update)
        Install-Module -Name "Az.Resources" -MinimumVersion 5.0.0 -Scope CurrentUser -Repository 'PSGallery' -Force -ErrorAction Stop
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
             Write-Host "Installing $($_) module with correct version(2.5.4)..." -ForegroundColor $([Constants]::MessageType.Info)
             Install-Module -Name "Az.Accounts" -MinimumVersion 2.5.4 -Scope CurrentUser -Repository 'PSGallery' -Force -ErrorAction Stop         }
        }
    }
    else
    {
        Write-Host "Installing $($_) module...." -ForegroundColor $([Constants]::MessageType.Update)
        Install-Module -Name "Az.Accounts" -MinimumVersion 2.5.4 -Scope CurrentUser -Repository 'PSGallery'  -Force -ErrorAction Stop
    }
}


function Create-PIMForPermanentRoleAssignments
{
    <#
        .SYNOPSIS
        Remediates ' Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access , Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG' Control.

        .DESCRIPTION
        Remediates ' Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access , Azure_Subscription_AuthZ_Dont_Grant_Persistent_Access_RG' Control.
        To create PIM role assignments for permanent privileged role Assignment and remove permanent privileged role Assignment for which PIM Role Assignments in the Subscription or in resource group . 
        
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
        PS> Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Create-PIMForPermanentRoleAssignments -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemovePermanentPrivilegedRoleAssignments\PermanentPrivilegedRoleAssignment.csv

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
        $ResourceGroupName,

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
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation")]
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

    Write-Host "*** To Create PIM role assignments for permanent privileged role Assignment and remove permanent privileged role Assignment for which PIM Role Assignments in the Subscription or in resource group, Contributor and higher privileges on the subscription are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Role Assignments..."

    $rbacDetails = @()

    # No file path provided as input to the script. Fetch all Role Assignments in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Role Assignments in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all Role Assignments in a Subscription
        $rbacDetails = Get-AzRoleAssignmentScheduleInstance -scope "/subscription/$($subscriptionId)" -ErrorAction Stop
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all Role Assignments from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

        $roleAssignmentDetails = Import-Csv -LiteralPath $FilePath
        
        $roleAssignmentDetails | ForEach-Object {

            try
            {
                Write-Host "Fetching Role Assignment: RoleName - $($_.RoleDefinitionDisplayName) , Email - $($_.PrincipalEmail)"
                $roleAssignment =  Get-AzRoleAssignmentScheduleInstance -Name $_.Name -Scope $_.Scope
                $rbacDetails += $roleAssignment
            }
            catch
            {
                Write-Host "Error fetching Role Assignment: RoleName - $($_.RoleDefinitionDisplayName) , Email - $($_.PrincipalEmail). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this Role Assignment..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
    }

    
    $totalRoleAssignments = ($rbacDetails| Measure-Object).Count

    if ($totalRoleAssignments -eq 0)
    {
        Write-Host "No Role Assignments found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }
  
    Write-Host "Found $($totalRoleAssignments)Role Assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)

    #seperating critical role assignments.
    $criticalRoleAssignments = @()

    if([string]::IsNullOrWhiteSpace($ResourceGroupName))
    {
        $criticalRoleAssignments = $rbacDetails |  Where-Object {$_.Scope -eq "/subscriptions/$($SubscriptionId)" -and ($_.ExpandedPropertiesPrincipalType -eq "User" -or $_.ExpandedPropertiesPrincipalType -eq "Group") -and [string]::IsNullOrEmpty($_.LinkedRoleEligibilityScheduleInstanceId) -and ($_.RoleDefinitionDisplayName -eq "User Access Adminstrator" -or $_.RoleDefinitionDisplayName -eq "Contributor" -or $_.RoleDefinitionDisplayName -eq "Owner") -and $_.PrincipalDisplayName -ne "MS-PIM"}
    }
    else
    {
        $criticalRoleAssignments = $rbacDetails | Where-Object {$_.Scope -eq "/subscriptions/$($SubscriptionId)/resourcegroup/$($ResourceGroupName)" -and ($_.ExpandedPropertiesPrincipalType -eq "User" -or $_.ExpandedPropertiesPrincipalType -eq "Group") -and [string]::IsNullOrEmpty($_.LinkedRoleEligibilityScheduleInstanceId) -and ($_.RoleDefinitionDisplayName -eq "User Access Adminstrator" -or $_.RoleDefinitionDisplayName -eq "Contributor" -or $_.RoleDefinitionDisplayName -eq "Owner") -and $_.PrincipalDisplayName -ne "MS-PIM"}
    }
    $criticalRoleAssignmentsDryRun = $criticalRoleAssignments | Select-Object @{N='PrincipalDisplayName';E={$_.PrincipalDisplayName}},
                                                                              @{N='Scope';E={$_.Scope}},
                                                                              @{N='Name';E={$_.Name}},
                                                                              @{N='RoleDefinitionDisplayName';E={$_.RoleDefinitionDisplayName}},
                                                                              @{N='PrincipalEmail';E={$_.PrincipalEmail}},
                                                                              @{N='IsPermanent';E={$true}}
                                                                              
    if ($criticalRoleAssignments -eq 0)
    {
        Write-Host "No permanent privileged Role Assignments found . Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalRoleAssignmentsWithoutHttpsEnabled) permanent privileged Role Assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RemovePermanentPrivilegedRoleAssignments"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up permanent Role Assignments details to $($backupFolderPath)"
    
    # Backing up Role Assignments details.
    $backupFile = "$($backupFolderPath)\PermanentPrivilegedRoleAssignment.csv"

    $criticalRoleAssignmentsDryRun | Export-CSV -Path $backupFile -NoTypeInformation

    if (-not $DryRun)
    {
        Write-Host "Permanent Role Assignments details have been backed up to $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "Create PIM role assignments for permanent privileged role Assignment and remove permanent privileged role Assignment for which PIM Role Assignments in the Subscription or in resource group already exists." -ForegroundColor $([Constants]::MessageType.Warning)

        if (-not $Force)
        {
            Write-Host "Do you want to Create PIM role assignments for permanent privileged role Assignment and remove permanent privileged role Assignment for which PIM Role Assignments in the Subscription or in resource group  already exists? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "PIM role assignments for permanent privileged role Assignment will not be created and  permanent privileged role Assignment will not be removed for which PIM Role Assignments in the Subscription or in resource group  already exists. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. PIM role assignments for permanent privileged role Assignment will be created and permanent privileged role Assignment will be removed for which PIM Role Assignments in the Subscription or in resource group already exists without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Create PIM role assignments for permanent privileged role Assignment and remove permanent privileged role Assignment for which PIM Role Assignments in the Subscription or in resource group already exists..." -ForegroundColor $([Constants]::MessageType.Warning)

        #list of PIM Role Assignment successfully created.
        $pimcreated = @()

        #list of PIM Role Assignment in which error occurred while creating.
        $pimNotCreated = @()
        
        #list of permanent Role Assignments which are removed successfully.
        $permanentRemoved = @()
        
        #list of permanent Role Assignments which were not removed successfully.
        $permanentNotRemoved = @()

        #to create PIM role Assignment for permanent privileged role Assignment.
        $criticalRoleAssignments | ForEach-Object {
            try
            {
                $roleAssignment = $_
                $name = $_.Name
                $roledefinitionId = $_.RoleDefinitionId
                $scope = $_.Scope
                $principalId = $_.PrincipalId

                $pimAssignment = New-AzRoleEligibilityScheduleRequest -Name $_.Name -RoleDefinitionId $_.RoleDefinitionId -Scope "/providers/Microsoft.Subscription/$($_.Scope)" -PrincipalId $_.PrincipalId  -RequestType 'AdminAssign' 
                if([string]::IsNullOrWhiteSpace($pimAssignment))
                {
                    $pimNotCreated += $roleAssignment
                }
                else
                {
                    $pimcreated += $roleAssignment 
                    Write-Host "Error creating PIM Role Assignment for permanent privileged Role Assignment." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Role Assignment. " -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            catch
            {
                $pimNotCreated += $roleAssignment
                Write-Host "Error creating PIM Role Assignment for permanent privileged Role Assignment." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this Role Assignment. " -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
        
        #Remove permanent privileged Role Assignment for which PIM Role Assignment already exists. 
        $pimcreated | ForEach-Object {
            try
            {
                $pimAssignment = $_
                $objectId = $_.ObjectId
                $scope = $_.scope
                $roledefinitionName = $_.RoleDefinitionName
             
                Remove-AzRoleAssignment -Scope $_.Scope -RoleDefinitionName $_.RoleDefinitionDisplayName -SignInName $_.PrincipalEmail 

                $permanentRemoved += $pimAssignment | Select-Object @{N='PrincipalDisplayName';E={$_.PrincipalDisplayName}},
                                                                              @{N='Scope';E={$_.Scope}},
                                                                              @{N='Name';E={$_.Name}},
                                                                              @{N='RoleDefinitionDisplayName';E={$_.RoleDefinitionDisplayName}},
                                                                              @{N='PrincipalEmail';E={$_.PrincipalEmail}},
                                                                              @{N='ExpandedPropertiesPrincipalType';E={$_.ExpandedPropertiesPrincipalType}}
            }
            catch
            {
                $permanentNotRemoved += $pimAssignment
                Write-Host "Error removing permanent privileged Role Assignment for which PIM Role Assignment already exists." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this Role Assignment. " -ForegroundColor $([Constants]::MessageType.Error)
            }    
        }


        $colsProperty = @{Expression={$_.RoleDefinitionDisplayName};Label="Display Name";Width=40;Alignment="left"},
                        @{Expression={$_.PrincipalEmail};Label="Email";Width=20;Alignment="left"},
                        @{Expression={$_.ExpandedPropertiesPrincipalType};Label="PrincipalType";Width=20;Alignment="left"},

        $skippedRoleAssignments = @()
        
        $skippedRoleAssignments += $permanentNotRemoved | Select-Object @{N='PrincipalDisplayName';E={$_.PrincipalDisplayName}},
                                                                              @{N='Scope';E={$_.Scope}},
                                                                              @{N='Name';E={$_.Name}},
                                                                              @{N='RoleDefinitionDisplayName';E={$_.RoleDefinitionDisplayName}},
                                                                              @{N='PrincipalEmail';E={$_.PrincipalEmail}},
                                                                              @{N='ExpandedPropertiesPrincipalType';E={$_.ExpandedPropertiesPrincipalType}}

        $skippedRoleAssignments += $pimNotCreated | Select-Object @{N='PrincipalDisplayName';E={$_.PrincipalDisplayName}},
                                                                              @{N='Scope';E={$_.Scope}},
                                                                              @{N='Name';E={$_.Name}},
                                                                              @{N='RoleDefinitionDisplayName';E={$_.RoleDefinitionDisplayName}},
                                                                              @{N='PrincipalEmail';E={$_.PrincipalEmail}},
                                                                              @{N='ExpandedPropertiesPrincipalType';E={$_.ExpandedPropertiesPrincipalType}}
                       
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($permanentRemoved | Measure-Object).Count -gt 0)
        {
            Write-Host "PIM role assignments for permanent privileged role Assignment are successfully created and permanent privileged role Assignment are Successfully removed for which PIM Role Assignments in the Subscription or in resource group already exists:" -ForegroundColor $([Constants]::MessageType.Update)
            $permanentRemoved | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $roleAssignmentsRemediatedFile = "$($backupFolderPath)\RemediatedRoleAssignments.csv"
            $permanentRemoved | Export-CSV -Path $roleAssignmentsRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to $($roleAssignmentsRemediatedFile)"
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($skippedRoleAssignments | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError while creating PIM role assignments for permanent privileged role Assignment or error occurred while removing permanent privileged role Assignment for which PIM Role Assignments in the Subscription or in resource group already exists:" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedRoleAssignments | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $roleAssignmentsSkippedFile = "$($backupFolderPath)\SkippedRoleAssignments.csv"
            $skippedRoleAssignments | Export-CSV -Path $roleAssignmentsSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($roleAssignmentsSkippedFile)"
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Role Assignments details have been backed up to $($backupFile). Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to Create PIM role assignments for permanent privileged role Assignment and remove permanent privileged role Assignment for which PIM Role Assignments in the Subscription or in resource group already exists which are listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
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
