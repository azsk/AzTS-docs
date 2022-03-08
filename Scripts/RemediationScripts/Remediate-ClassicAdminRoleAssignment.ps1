<###
# Overview:
    This script is used to remove classic administrators (CoAdministrator, ServiceAdministrator) in a Subscription.

# Control ID:
    Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count

# Display Name:
    Limit access per subscription to 2 or less classic administrators.

# Prerequisites:
    'Owner' or 'User Access Administrator' role is required at Subscription level.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of all classic role assignments in a Subscription.
        3. Back up details of classic role assignments that are to be remediated.
        4. Remove classic role assignments from given CSV in the Subscription.

    To rollback:
        1. Validate and install the modules required to run the script.
        2. Get the list of all remediated classic role assignments in a Subscription from given CSV.
        3. Restore classic role assignments from given CSV in the Subscription.
           **Note: Service Administrator role assignment cannot be restore via script.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remove classic role assignments in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        Step 1. To fetch classic role assignments from a Subscription that will be remediated:
                Remove-ClassicAdminAccounts -SubscriptionId '00000000-xxxx-0000-xxxx-000000000000' -PerformPreReqCheck -DryRun

        Step 2. In the exported CSV file, set value to the column 'ToBeRemoved' to 'Yes' to remove classic role assignments.

        Step 3. To remove all classic role assignments available in given CSV from a Subscription:
                Remove-ClassicAdminAccounts -SubscriptionId '00000000-xxxx-0000-xxxx-000000000000' -FilePath 'C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202202201059\ClassicRoleAssignments\ClassicRoleAssignments.csv'

        To know more about the options supported by the remediation command, execute:
        Get-Help Remove-ClassicAdminAccounts -Detailed
        
    To rollback:
        1. Restore remediated 'Co-admin' role assignments in a subscription:
           Restore-ClassicAdminAccounts -SubscriptionId '00000000-xxxx-0000-xxxx-000000000000' -FilePath 'C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202202201059\ClassicRoleAssignments\RemediationSummary.csv'    
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

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
        }
        else
        {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }

    Write-Host $([Constants]::DoubleDashLine)
}


function Remove-ClassicAdminAccounts
{
    <#
        .SYNOPSIS
        Remediates 'Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count' Control.

        .DESCRIPTION
        Remediates 'Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count' Control.
        Remove classic admin role assignments in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the actual remediation.

        .INPUTS
        None. You cannot pipe objects to Remove-ClassicAdminAccounts.

        .OUTPUTS
        None. Remove-ClassicAdminAccounts does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Remove-ClassicAdminAccounts -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Remove-ClassicAdminAccounts -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ClassicAdminRoleAssignments\ClassicAdminRoleAssignments.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

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
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath
    )

    Write-Host "[Step 1 of 4] Preparing to remove classic role assignments in Subscription [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

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
            return
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
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop

    # Safe Check: Checking whether the current account is of type 'User'.
    if($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by 'User' account type." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    Write-Host "`n[Step 2 of 4] Validating whether the current user [$($context.Account.Id)] has required permissions to run the script for subscription [$($SubscriptionId)]..."
    Write-Host $([Constants]::SingleDashLine)

    # Safe Check: Current user need to be either UAA or Owner for the subscription.
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    Write-Host "*** To remove classic role assignments in a Subscription, user must have [Owner/User Access Administrator] role at subscription. ***" -ForegroundColor $([Constants]::MessageType.Info)

    Write-Host "**Metadata Details:**"
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"

    $requiredRoleDefinitionName = @("Owner", "User Access Administrator")
    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -in $requiredRoleDefinitionName} | Measure-Object).Count -le 0 )
    {
        Write-Host "WARNING: This script can only be run by an [$($requiredRoleDefinitionName -join ", ")]. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }
    else
    {
        Write-Host "Current user [$($context.Account.Id)] has the required permission for subscription [$($SubscriptionId)].`n" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
    }
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ClassicRoleAssignments"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    # Backing up classic role assignment details.
    $backupFile = "$($backupFolderPath)\ClassicRoleAssignments.csv"

    if ($DryRun)
    {
        Write-Host "`n[Step 3 of 4] Preparing to fetch classic role assignments in subscription [$($SubscriptionId)]... `n"
        Write-Host $([Constants]::SingleDashLine)

        # Getting all classic role assignments.
        $classicAssignments = [ClassicRoleAssignments]::new()
        $res = $classicAssignments.GetClassicRoleAssignments($subscriptionId)
        $classicDistinctRoleAssignmentList = $res.value | Where-Object { ![string]::IsNullOrWhiteSpace($_.properties.emailAddress) }

        # Rename property name
        $classicRoleAssignments = $classicDistinctRoleAssignmentList | select @{N='SignInName'; E={$_.properties.emailAddress}},  
                                                                              @{N='RoleDefinitionName'; E={$_.properties.role}}, 
                                                                              @{N='RoleId'; E={$_.name}}, @{N='Type'; E={$_.type }}, 
                                                                              @{N='RoleAssignmentId'; E={$_.id }},
                                                                              @{N='ToBeRemoved';E={""}}

        if(($classicRoleAssignments | Measure-Object).Count -gt 0)
        {
            # Excluding 'AccountAdministrator' classic role from the collection as 'AccounAdministrator' assignment can't be removed using script.
            $classicRoleAssignments = $classicRoleAssignments | Where-Object { $_.RoleDefinitionName -notlike "AccountAdministrator"}
        }

        # Getting count of classic role assignments.
        $classicRoleAssignmentCount = ($classicRoleAssignments | Measure-Object).Count

        if($classicRoleAssignmentCount -gt 0 )
        {
            Write-Host "Found [$($classicRoleAssignmentCount)] classic role assignments in the subscription [$($SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
        }
        else
        {
            Write-Host "No classic role assignment found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            return;
        }

        Write-Host "`n[Step 4 of 4] Backing up classic role assignment details... `n"
        Write-Host $([Constants]::SingleDashLine)

        $classicRoleAssignments | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Classic role assignments details have been backed up to [$($backupFile)]." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "`n**Next Steps:"
        Write-Host "***Please set value in column 'ToBeRemoved' to 'Yes' in order to remove role assignments in file [$($backupFile)]***`n" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`nRun the same command with -FilePath $($backupFile) and without -DryRun, to remove classic role assignments listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`nThere MUST be at most 2 classic admins [Co-admin/Service Admin] in a subscription to pass the control.`n" -ForegroundColor $([Constants]::MessageType.Warning)
    }
    elseif (![string]::IsNullOrEmpty($FilePath))
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            return
        }

        Write-Host "`n[Step 3 of 4] Fetching all classic role assignments from [$($FilePath)]... `n"
        Write-Host $([Constants]::SingleDashLine)

        $classicRoleAssignmentDetails = Import-Csv -LiteralPath $FilePath

        # Excluding 'AccountAdministrator' classic role from the collection as 'AccounAdministrator' assignment can't be removed using script.
        $classicRoleAssignmentDetails = $classicRoleAssignmentDetails | Where-Object { $_.RoleDefinitionName -notlike "AccountAdministrator" -and $_.ToBeRemoved -eq "Yes" }

        $totalClassicRoleAssignments = $($classicRoleAssignmentDetails | Measure-Object).Count

        if ($totalClassicRoleAssignments -eq 0)
        {
            Write-Host "No classic role assignment found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            return;
        }

        Write-Host "Found [$($totalClassicRoleAssignments)] classic role assignments to be removed from subscription." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "`n*** Below listed classic role assignments from the given CSV will be removed from subscription. ***" -ForegroundColor $([Constants]::MessageType.Warning)

        $classicRoleAssignmentDetails | Select-Object -Property SignInName, RoleDefinitionName, RoleAssignmentId | ft

        Write-Host $([Constants]::DoubleDashLine)

        if (-not $Force)
        {
            Write-Host "Do you want to remove all classic role assignments from the given CSV? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Classic role assignments will not be removed from subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                return
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Classic role assignments will be removed from subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host "`n[Step 4 of 4] Removing above listed classic role assignments..."
        Write-Host $([Constants]::SingleDashLine)

        # Deleting classic role assignments.
        if ($totalClassicRoleAssignments -gt 0)
        {
            $removedAssignments = @()
            $skippedRoleAssignments = @()
            $classicRoleAssignmentDetails | ForEach-Object {
                try 
                {
                    $currentRoleAssignment = $_
                    
                    $eligibleClassicRoles = $currentRoleAssignment.RoleDefinitionName -split ';'
                    $eligibleClassicRoles | ForEach-Object {
                        $currentRole = $_
                        if($currentRole -in ("CoAdministrator", "ServiceAdministrator") -and $currentRoleAssignment.RoleAssignmentId.contains("/providers/Microsoft.Authorization/classicAdministrators/"))
                        {
                            $isServiceAdminAccount = $false
                            if($currentRole -eq "ServiceAdministrator")
                            {
                                $isServiceAdminAccount = $true;
                            }

                            $classicAssignments = [ClassicRoleAssignments]::new()
                            $res = $classicAssignments.DeleteClassicRoleAssignment($currentRoleAssignment.RoleAssignmentId, $isServiceAdminAccount)

                            if(($null -ne $res) -and ($res.StatusCode -eq 202 -or $res.StatusCode -eq 200))
                            {
                                $removedAssignments += $currentRoleAssignment | Select-Object @{N='SignInName';E={$currentRoleAssignment.SignInName}},
                                                                                              @{N='RoleDefinitionName';E={$currentRole}},
                                                                                              @{N='RoleAssignmentId';E={$currentRoleAssignment.RoleAssignmentId}}
                            }
                            else
                            {
                                $skippedRoleAssignments += $currentRoleAssignment | Select-Object @{N='SignInName';E={$currentRoleAssignment.SignInName}},
                                                                                                  @{N='RoleDefinitionName';E={$currentRole}},
                                                                                                  @{N='RoleAssignmentId';E={$currentRoleAssignment.RoleAssignmentId}}
                            }
                        }
                        elseif ($_ -eq "AccountAdministrator")
                        {
                            Write-Host "Account Administrator role cannot be removed." -ForegroundColor $([Constants]::MessageType.Warning)
                        }
                    }
                }
                catch
                {
                    Write-Host "`nError occurred while removing classic role assignment. ErrorMessage [$($_)]`n" -ForegroundColor $([Constants]::MessageType.Error)  
                }
            }

            if(($removedAssignments | Measure-Object).Count -ne 0)
            {
                Write-Host "Successfully removed following classic role assignment(s):" -ForegroundColor $([Constants]::MessageType.Update)
                $removedAssignments |Select-Object -Property SignInName , RoleDefinitionName , RoleAssignmentId | ft
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "`nBacking up remediation summary...`n"
                $remediationSummaryFilePath = "$($backupFolderPath)\RemediationSummary.csv"
                $removedAssignments | Export-CSV -Path $remediationSummaryFilePath -NoTypeInformation
                Write-Host "Remediation summary have been backed up to [$($remediationSummaryFilePath)]`n" -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host "You may want to use this file to perform any rollback operation for removed role assignments." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::DoubleDashLine)
            }

            if (($skippedRoleAssignments | Measure-Object).Count -ne 0)
            {
                Write-Host "Skipped following classic role assignment(s):" -ForegroundColor $([Constants]::MessageType.Update)
                $skippedRoleAssignments |Select-Object -Property SignInName , RoleDefinitionName , RoleAssignmentId | ft
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "`nBacking up skipped role assignment summary...`n"
                $skippedRoleAssignmentSummaryFilePath = "$($backupFolderPath)\SkippedRoleAssignmentSummary.csv"
                $skippedRoleAssignments | Export-CSV -Path $skippedRoleAssignmentSummaryFilePath -NoTypeInformation
                Write-Host "Skipped role assignment summary have been backed up to [$($skippedRoleAssignmentSummaryFilePath)]`n" -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::DoubleDashLine)
            }  
        }
    }    
}

function Restore-ClassicAdminAccounts
{
    <#
        .SYNOPSIS
        This command would help in performing rollback operation for control 'Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count'.

        .DESCRIPTION
        Rollback 'Azure_Subscription_AuthZ_Limit_ClassicAdmin_Count' Control.
        Restore classic admin role assignments in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be rolledback.
        
        .PARAMETER Force
        Specifies a forceful rollback without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the rollback operation.

        .INPUTS
        None. You cannot pipe objects to Restore-ClassicAdminAccounts.

        .OUTPUTS
        None. Restore-ClassicAdminAccounts does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Restore-ClassicAdminAccounts -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ClassicAdminRoleAssignments\RemediationSummary.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be rolledback")]
        $SubscriptionId,

        [Switch]
        [Parameter(HelpMessage="Specifies a forceful rollback without any prompts")]
        $Force,

        [Switch]
        [Parameter(HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the path to the file to be used as input for the rollback")]
        $FilePath
    )

    Write-Host "`n[Step 1 of 4] Preparing to restore classic role assignments in Subscription [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

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
            return
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
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop

    # Safe Check: Checking whether the current account is of type 'User'.
    if($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by 'User' account type." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    Write-Host "`n[Step 2 of 4] Validating whether the current user [$($context.Account.Id)] has required permissions to run the script for subscription [$($SubscriptionId)]..."
    Write-Host $([Constants]::SingleDashLine)

    # Safe Check: Current user need to be either UAA or Owner for the subscription.
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    Write-Host "*** To remove classic role assignments in a Subscription, user must have [Owner/User Access Administrator] role at subscription. *** `n" -ForegroundColor $([Constants]::MessageType.Info)

    Write-Host "**Metadata Details:**"
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"

    $requiredRoleDefinitionName = @("Owner", "User Access Administrator")
    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -in $requiredRoleDefinitionName} | Measure-Object).Count -le 0 )
    {
        Write-Host "WARNING: This script can only be run by an [$($requiredRoleDefinitionName -join ", ")]. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }
    else
    {
        Write-Host "Current user [$($context.Account.Id)] has the required permission for subscription [$($SubscriptionId)].`n" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
    }   

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ClassicRoleAssignments"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    if (![string]::IsNullOrEmpty($FilePath))
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            return
        }

        Write-Host "`n[Step 3 of 4] Fetching remediated classic role assignments from [$($FilePath)]... `n"
        Write-Host $([Constants]::SingleDashLine)

        $classicRoleAssignmentDetails = Import-Csv -LiteralPath $FilePath
        $totalClassicRoleAssignments = $($classicRoleAssignmentDetails | Measure-Object).Count

        if ($totalClassicRoleAssignments -eq 0)
        {
            Write-Host "No classic role assignment found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            return;
        }

        # Excluding 'AccountAdministrator' classic role from the collection as 'AccounAdministrator' assignment can't be removed using script.
        $classicRoleAssignmentDetails = $classicRoleAssignmentDetails | Where-Object { $_.RoleDefinitionName -notlike "AccountAdministrator"}

        Write-Host "Found [$($totalClassicRoleAssignments)] classic role assignments in the given CSV." -ForegroundColor $([Constants]::MessageType.Update)

        Write-Host "`nFollowing classic role assignments from the given CSV will be restored in subscription..." -ForegroundColor $([Constants]::MessageType.Warning)
        $classicRoleAssignmentDetails |Select-Object -Property SignInName , RoleDefinitionName , RoleAssignmentId | ft
        Write-Host $([Constants]::DoubleDashLine)

        if (-not $Force)
        {
            Write-Host "`nDo you want to restore all classic role assignments from the given CSV? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Classic role assignments will not be restored for subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                return
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Classic role assignments will be restored for subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host "`n[Step 4 of 4] Restoring all classic role assignments from given CSV file..."
        Write-Host $([Constants]::SingleDashLine)

        # Deleting classic role assignments.
        if ($totalClassicRoleAssignments -gt 0)
        {
            $restoredAssignments = @()
            $classicRoleAssignmentDetails | ForEach-Object {
                try 
                {
                    $currentRoleAssignment = $_
                    $eligibleClassicRoles = $currentRoleAssignment.RoleDefinitionName -split ';'
                    $eligibleClassicRoles | ForEach-Object {
                        $currentRole = $_
                        if($currentRole -in ("CoAdministrator", "ServiceAdministrator") -and $currentRoleAssignment.RoleAssignmentId.contains("/providers/Microsoft.Authorization/classicAdministrators/"))
                        {
                            $isServiceAdminAccount = $false
                            if($currentRole -eq "ServiceAdministrator")
                            {
                                $isServiceAdminAccount = $true;
                            }

                            $classicAssignments = [ClassicRoleAssignments]::new()
                            $res = $classicAssignments.RestoreClassicRoleAssignment($currentRoleAssignment.SignInName, $currentRoleAssignment.RoleDefinitionName, $currentRoleAssignment.RoleAssignmentId, $isServiceAdminAccount)

                            if(($null -ne $res) -and ($res.StatusCode -eq 202 -or $res.StatusCode -eq 200))
                            {
                                $restoredAssignments += $currentRoleAssignment | Select-Object @{N='SignInName';E={$currentRoleAssignment.SignInName}},
                                                                                               @{N='RoleDefinitionName';E={$currentRole}},
                                                                                               @{N='RoleAssignmentId';E={$currentRoleAssignment.RoleAssignmentId}}
                            }
                        }
                    }
                }
                catch
                {
                    Write-Host "`nError occurred while restoring classic role assignment. ErrorMessage [$($_)]`n" -ForegroundColor $([Constants]::MessageType.Error)  
                }
            }

            if(($restoredAssignments | Measure-Object).Count -ne 0)
            {
                Write-Host "Successfully restored following classic role assignment(s):" -ForegroundColor $([Constants]::MessageType.Update)
                $restoredAssignments |Select-Object -Property SignInName , RoleDefinitionName , RoleAssignmentId | ft
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "`nBacking up rollback summary...`n"
                $rollBackSummaryFilePath = "$($backupFolderPath)\RollbackSummary.csv"
                $restoredAssignments | Export-CSV -Path $rollBackSummaryFilePath -NoTypeInformation
                Write-Host "Rollback summary have been backed up to [$($rollBackSummaryFilePath)]" -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::DoubleDashLine)
            }
        }
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
            Write-Host "Error occurred while fetching auth header. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)   
        }
        return($headers)
    }

    [PSObject] GetClassicRoleAssignments([string] $subscriptionId)
    {
        $content = $null
        try
        {
            $armUri = "https://management.azure.com/subscriptions/$($subscriptionId)/providers/Microsoft.Authorization/classicadministrators?api-version=2015-06-01"
            $headers = $this.GetAuthHeader()
            # API to get classic role assignments
            $response = Invoke-WebRequest -Method Get -Uri $armUri -Headers $headers -UseBasicParsing
            $content = ConvertFrom-Json $response.Content
        }
        catch
        {
            Write-Host "Error occurred while fetching classic role assignment. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        }
        
        return($content)
    }

    [PSObject] DeleteClassicRoleAssignment([string] $roleAssignmentId, [bool] $isServiceAdminAccount)
    {
        $content = $null
        try
        {
            $armUri = "https://management.azure.com" + $roleAssignmentId + "?api-version=2015-06-01"
            if ($isServiceAdminAccount)
            {
                $armUri += "&adminType=serviceAdmin"
            }
            $headers = $this.GetAuthHeader()
            
            # API to remove classic role assignments
            $response = Invoke-WebRequest -Method Delete -Uri $armUri -Headers $headers -UseBasicParsing
            $content = $response
        }
        catch
        {
            Write-Host "Error occurred while deleting classic role assignment. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            throw;
        }
        
        return($content)
    }

    [PSObject] RestoreClassicRoleAssignment([string] $signInName, [string] $roleDefinitionName, [string] $roleAssignmentId, [bool] $isServiceAdminAccount)
    {
        $content = $null
        try
        {
            $armUri = "https://management.azure.com" + $roleAssignmentId + "?api-version=2015-06-01"
            if ($isServiceAdminAccount)
            {
                Write-Host "Service Administrator role assignment cannot be restored.`n" -ForegroundColor $([Constants]::MessageType.Warning)
            }
            else
            {
                $headers = $this.GetAuthHeader()
                $body = @{"properties"=@{emailAddress=$signInName;role=$roleDefinitionName;}}

                # API to assign classic role.
                $response = Invoke-WebRequest -Method Put -Uri $armUri -Headers $headers -Body ($body | ConvertTo-Json) -UseBasicParsing
                $content = $response
            }
        }
        catch
        {
            Write-Host "Error occurred while restoring classic role assignment. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            throw;
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