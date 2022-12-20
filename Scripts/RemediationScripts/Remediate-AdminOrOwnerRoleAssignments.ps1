<###
# Overview:
    This script is used to remove Admin/Owner (CoAdministrator, ServiceAdministrator, Owner) in a Subscription.

# Control ID:
    Azure_Subscription_AuthZ_Limit_Admin_Owner_Count

# Display Name:
    Minimize the number of admins/owners.

# Prerequisites:
    'Owner' or 'User Access Administrator' role is required at Subscription level.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of all Admin/Owner role assignments in a Subscription.
        3. Back up details of Admin/Owner role assignments that are to be remediated.
        4. Remove Admin/Owner role assignments from given CSV in the Subscription.

    To rollback:
        1. Validate and install the modules required to run the script.
        2. Get the list of all remediated Admin/Owner role assignments in a Subscription from given CSV.
        3. Restore Admin/Owner role assignments from given CSV in the Subscription.
           **Note: Service Administrator role assignment cannot be restore via script.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remove Admin/Owner role assignments in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        Step 1. To fetch Admin/Owner role assignments from a Subscription that will be remediated:
                Remove-AdminOrOwnerAccounts -SubscriptionId '00000000-xxxx-0000-xxxx-000000000000' -PerformPreReqCheck -DryRun

        Step 2. In the exported CSV file, set value to the column 'ToBeRemoved' to 'Yes' to remove Admin/Owner role assignments.

        Step 3. To remove all Admin/Owner role assignments available in given CSV from a Subscription:
                Remove-AdminOrOwnerAccounts -SubscriptionId '00000000-xxxx-0000-xxxx-000000000000' -FilePath 'C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202202201059\AdminOrOwnerRoleAssignments\AdminOrOwnerRoleAssignments.csv'

        To know more about the options supported by the remediation command, execute:
        Get-Help Remove-AdminOrOwnerAccounts -Detailed
        
    To rollback:
        1. Restore remediated 'Co-admin' role assignments in a subscription:
           Restore-AdminOrOwnerAccounts -SubscriptionId '00000000-xxxx-0000-xxxx-000000000000' -FilePath 'C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202202201059\AdminOrOwnerRoleAssignments\RemediationSummary.csv'    
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


function Remove-AdminOrOwnerAccounts
{
    <#
        .SYNOPSIS
        Remediates 'Azure_Subscription_AuthZ_Limit_Admin_Owner_Count' Control.

        .DESCRIPTION
        Remediates 'Azure_Subscription_AuthZ_Limit_Admin_Owner_Count' Control.
        Remove Admin/Owner role assignments in the Subscription. 
        
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
        None. You cannot pipe objects to Remove-AdminOrOwnerAccounts.

        .OUTPUTS
        None. Remove-AdminOrOwnerAccounts does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Remove-AdminOrOwnerAccounts -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Remove-AdminOrOwnerAccounts -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\AdminOrOwnerRoleAssignments\AdminOrOwnerRoleAssignments.csv

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
        Write-Host $([Constants]::SingleDashLine)
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    

    # Safe Check: Checking whether the current account is of type 'User'.
    if($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by 'User' account type." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    Write-Host "Validating whether the current user [$($context.Account.Id)] has required permissions to run the script for subscription [$($SubscriptionId)]..."
    Write-Host $([Constants]::SingleDashLine)

    # Safe Check: Current user need to be either UAA or Owner for the subscription.
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id

    Write-Host "*** To remove Admin/Owner role assignments in a Subscription, user must have [Owner/User Access Administrator] role at subscription. ***" -ForegroundColor $([Constants]::MessageType.Info)


    $requiredRoleDefinitionName = @("Owner", "User Access Administrator")
    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -in $requiredRoleDefinitionName -and ($_.Scope -eq "/subscriptions/$($SubscriptionId)" -or $_.Scope -contains "/providers/Microsoft.Management/managementGroups") } | Measure-Object).Count -le 0 )
    {
        Write-Host "WARNING: This script can only be run by an [$($requiredRoleDefinitionName -join ", ")]. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }
    else
    {
        Write-Host "Current user [$($context.Account.Id)] has the required permission for subscription [$($SubscriptionId)].`n" -ForegroundColor $([Constants]::MessageType.Update)
    }
    
    Write-Host $([Constants]::SingleDashLine)
 
    Write-Host "**Metadata Details:**"  -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch Admin/Owner role assignments in subscription [$($SubscriptionId)]... `n"
    Write-Host $([Constants]::SingleDashLine)
    
    # list of valid role assignment.
    $validRoleAssignments = @()

    # list to role assignment details.
    $roleAssignments = @()

    # No file path provided as input to the script. Fetch all Admin/Owner role assignments in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Admin/Owner role assignments in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        $scope = "/subscriptions/$SubscriptionId"
        $roleAssignments = Get-AzRoleAssignment -Scope $scope ; 
        $validRoleAssignments = $roleAssignments  | Where-Object { $_.ObjectType -ne "Unknown" }
        $validRoleAssignments = $validRoleAssignments | Select-Object @{N='SignInName'; E={$_.SignInName}},  
                                                                      @{N='RoleDefinitionName'; E={$_.RoleDefinitionName}},
                                                                      @{N='ObjectId' ; E={$_.ObjectId}}, 
                                                                      @{N='RoleId'; E={$_.RoleDefinitionId}}, @{N='Type'; E={$_.ObjectType }}, 
                                                                      @{N='RoleAssignmentId'; E={$_.RoleAssignmentId }},
                                                                      @{N='Scope'; E={$_.Scope}},
                                                                      @{N='ToBeRemoved';E={""}}
        
        # Getting all classic role assignments.
        $classicAssignments = [AdminOrOwnerRoleAssignments]::new()
        $res = $classicAssignments.GetClassicRoleAssignments($subscriptionId)
        $classicDistinctRoleAssignmentList = $res.value | Where-Object { ![string]::IsNullOrWhiteSpace($_.properties.emailAddress) }
        
        $validRoleAssignments += $classicDistinctRoleAssignmentList | select @{N='SignInName'; E={$_.properties.emailAddress}},  
                                                                            @{N='RoleDefinitionName'; E={$_.properties.role}},
                                                                            @{N='ObjectId' ; E={""}}, 
                                                                            @{N='RoleId'; E={[string]$_.name}}, @{N='Type'; E={$_.type }}, 
                                                                            @{N='RoleAssignmentId'; E={[string]$_.id }},
                                                                            @{N='Scope'; E={$scope}},
                                                                            @{N='ToBeRemoved';E={""}}

    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all Admin/Owner role assignments from [$($FilePath)]..." 

        $roleAssignments = Import-Csv -LiteralPath $FilePath
        $validRoleAssignments = $roleAssignments| Where-Object { $_.RoleDefinitionName -ne "AccountAdministrator" -and $_.ToBeRemoved -eq "Yes" }
        
    }

    $totalRoleAssignments = ($validRoleAssignments| Measure-Object).Count

    if ($totalRoleAssignments -eq 0)
    {
        Write-Host "No role assignment found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalRoleAssignments)] role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Admin/Owner role assignment(s).
    $AdminOrOwnerRoleAssignments = @()

    Write-Host "Separating Admin/Owner role assignments..."

    $validRoleAssignments | ForEach-Object { 
        $roleAssignment = $_
        $roleAssignmentList = $_.RoleDefinitionName.split(";");
        if($roleAssignmentList.count -gt 1)
        {
            $roleAssignmentList | ForEach-Object {
                if(($_ -eq "CoAdministrator" -or $_ -eq "ServiceAdministrator" -or $_ -eq "Owner") -and $roleAssignment.Scope -eq $scope)
                {
                    $roleName = $_
                    # Rename property name
                    $AdminOrOwnerRoleAssignments += $roleAssignment | Select-Object @{N='SignInName'; E={$_.SignInName}},  
                                                                                    @{N='RoleDefinitionName'; E={$roleName}}, 
                                                                                    @{N='ObjectId' ; E={$_.ObjectId}},
                                                                                    @{N='RoleId'; E={$_.RoleId}}, @{N='Type'; E={$_.Type }}, 
                                                                                    @{N='RoleAssignmentId'; E={$_.RoleAssignmentId }},
                                                                                    @{N='Scope'; E={$_.Scope}},
                                                                                    @{N='ToBeRemoved';E={""}} 
                }
            }
        }
        else
        {
            if(($roleAssignment.RoleDefinitionName -eq "CoAdministrator" -or $roleAssignment.RoleDefinitionName -eq "ServiceAdministrator" -or $roleAssignment.RoleDefinitionName -eq "Owner") -and $roleAssignment.Scope -eq "/subscriptions/$SubscriptionId")
            {
                # Rename property name
                $AdminOrOwnerRoleAssignments += $roleAssignment | Select-Object @{N='SignInName'; E={$_.SignInName}},  
                                                                                @{N='RoleDefinitionName'; E={$_.RoleDefinitionName}}, 
                                                                                @{N='ObjectId' ; E={$_.ObjectId}},
                                                                                @{N='RoleId'; E={$_.RoleId}}, @{N='Type'; E={$_.Type }}, 
                                                                                @{N='RoleAssignmentId'; E={$_.RoleAssignmentId }},
                                                                                @{N='Scope'; E={$_.Scope}},
                                                                                @{N='ToBeRemoved';E={""}} 
            }   
        }
    }
   
    $totalAdminOrOwnerRoleAssignments  = ($AdminOrOwnerRoleAssignments | Measure-Object).Count

    if ($totalAdminOrOwnerRoleAssignments  -eq 0)
    {
        Write-Host "No Admin/Owner role assignment found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$($totalAdminOrOwnerRoleAssignments)] Admin/Owner role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    $colsProperty = @{Expression={$_.SignInName};Label="SignInName";Width=30;Alignment="left"},
                    @{Expression={$_.RoleDefinitionName};Label="RoleDefinitionName";Width=30;Alignment="left"},
                    @{Expression={$_.RoleAssignmentId};Label="RoleAssignmentId";Width=100;Alignment="left"}
        
    $AdminOrOwnerRoleAssignments | Format-Table -Property $colsProperty -Wrap

    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\AdminOrOwnerRoleAssignments"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up Admin/Owner role assignment(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
    
        # Backing up Admin/Owner role assignment details.
        $backupFile = "$($backupFolderPath)\AdminOrOwnerRoleAssignments.csv"

        $AdminOrOwnerRoleAssignments | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Admin/Owner role assignment details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remove Admin/Owner role assignments from the subscription..." 
        Write-Host $([Constants]::SingleDashLine)
        

        if (-not $Force)
        {
            Write-Host "Do you want to remove all above listed Admin/Owner role assignments from the subscription? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Admin/Owner role assignments will not be removed from subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                return
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Admin/Owner role assignments will be removed from subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host "Removing Admin/Owner role assignment(s)..." -ForegroundColor $([Constants]::MessageType.Info)

        $removedAssignments = @()
        $skippedRoleAssignments = @()
        $AdminOrOwnerRoleAssignments | ForEach-Object {
            $currentRoleAssignment = $_
            try 
            {    
                    
                $roleAssignments = [AdminOrOwnerRoleAssignments]::new()
                if($currentRoleAssignment.RoleDefinitionName -in ("CoAdministrator", "ServiceAdministrator") -and $currentRoleAssignment.RoleAssignmentId.contains("/providers/Microsoft.Authorization/classicAdministrators/"))
                {
                    $isServiceAdminAccount = $false
                    if($currentRole -eq "ServiceAdministrator")
                    {
                        $isServiceAdminAccount = $true;
                    }

                    $res = $roleAssignments.DeleteRoleAssignment($currentRoleAssignment.RoleAssignmentId, $isServiceAdminAccount , "ClassicRole")
                }
                elseif($currentRoleAssignment.RoleDefinitionName -eq "Owner")
                {
                    $res = $roleAssignments.DeleteRoleAssignment($currentRoleAssignment.RoleAssignmentId, $false , "Role")
                }

                if(($null -ne $res) -and ($res.StatusCode -eq 202 -or $res.StatusCode -eq 200))
                {
                    $removedAssignments += $currentRoleAssignment | Select-Object @{N='SignInName'; E={$_.SignInName}},  
                                                                                  @{N='RoleDefinitionName'; E={$_.RoleDefinitionName}}, 
                                                                                  @{N='ObjectId' ; E={$_.ObjectId}},
                                                                                  @{N='RoleId'; E={$_.RoleId}}, @{N='Type'; E={$_.Type }}, 
                                                                                  @{N='RoleAssignmentId'; E={$_.RoleAssignmentId }},
                                                                                  @{N='Scope'; E={$_.Scope}} 
                }
                else
                {
                    $skippedRoleAssignments += $currentRoleAssignment | Select-Object @{N='SignInName'; E={$_.SignInName}},  
                                                                                        @{N='RoleDefinitionName'; E={$_.RoleDefinitionName}}, 
                                                                                        @{N='ObjectId' ; E={$_.ObjectId}},
                                                                                        @{N='RoleId'; E={$_.RoleId}}, @{N='Type'; E={$_.Type }}, 
                                                                                        @{N='RoleAssignmentId'; E={$_.RoleAssignmentId }},
                                                                                        @{N='Scope'; E={$_.Scope}}
                }
            }
            catch
            {
                $skippedRoleAssignments += $currentRoleAssignment  
            }
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

        if(($removedAssignments | Measure-Object).Count -ne 0)
        {
            Write-Host "Successfully removed following Admin/Owner role assignment(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $removedAssignments |Format-Table -Property $colsProperty -Wrap
            $remediationSummaryFilePath = "$($backupFolderPath)\RemediationSummary.csv"
            $removedAssignments | Export-CSV -Path $remediationSummaryFilePath -NoTypeInformation
            Write-Host "Remediation summary have been backed up to" -NoNewline
            Write-Host " [$($remediationSummaryFilePath)]`n" -ForegroundColor $([Constants]::MessageType.update)
            Write-Host "You may want to use this file to perform any rollback operation for removed role assignments." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::DoubleDashLine)
        }

        if (($skippedRoleAssignments | Measure-Object).Count -ne 0)
        {
            Write-Host "Error occured while removing Admin/Owner role assignment(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedRoleAssignments |Format-Table -Property $colsProperty -Wrap
            $skippedRoleAssignmentSummaryFilePath = "$($backupFolderPath)\SkippedRoleAssignmentSummary.csv"
            $skippedRoleAssignments | Export-CSV -Path $skippedRoleAssignmentSummaryFilePath -NoTypeInformation
            Write-Host "Skipped role assignment summary have been backed up to" -NoNewline
            Write-Host "[$($skippedRoleAssignmentSummaryFilePath)]`n" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
        }  
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remove Admin/Owner role assignments from the subscription..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "`nNext Steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`t1.Please set value in column 'ToBeRemoved' to 'Yes' in order to remove role assignments in file [$($backupFile)]"
        Write-Host "`t2.Run the same command with -FilePath [$($backupFile)] and without -DryRun, to remove Admin/Owner role assignments listed in the file."
        Write-Host "There MUST be at most 5 Admin/Owner in a subscription to pass the control.`n" -ForegroundColor $([Constants]::MessageType.Warning)
    }
}

function Restore-AdminOrOwnerAccounts
{
    <#
        .SYNOPSIS
        This command would help in performing rollback operation for control 'Azure_Subscription_AuthZ_Limit_Admin_Owner_Count'.

        .DESCRIPTION
        Rollback 'Azure_Subscription_AuthZ_Limit_Admin_Owner_Count' Control.
        Restore Admin/Owner role assignments in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be rolledback.
        
        .PARAMETER Force
        Specifies a forceful rollback without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the rollback operation.

        .INPUTS
        None. You cannot pipe objects to Restore-AdminOrOwnerAccounts.

        .OUTPUTS
        None. Restore-AdminOrOwnerAccounts does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Restore-AdminOrOwnerAccounts -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\AdminOrOwnerRoleAssignments\RemediationSummary.csv

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

    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script and validating the user..."
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
        Write-Host "[Step 1 of 3] Validating the user... "
        Write-Host $([Constants]::DoubleDashLine)
    }

   # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    

    # Safe Check: Checking whether the current account is of type 'User'.
    if($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by 'User' account type." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    Write-Host "Validating whether the current user [$($context.Account.Id)] has required permissions to run the script for subscription [$($SubscriptionId)]..."
    Write-Host $([Constants]::SingleDashLine)

    # Safe Check: Current user need to be either UAA or Owner for the subscription.
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id

    Write-Host "*** To add Admin/Owner role assignments in a Subscription, user must have [Owner/User Access Administrator] role at subscription. ***" -ForegroundColor $([Constants]::MessageType.Info)


    $requiredRoleDefinitionName = @("Owner", "User Access Administrator")
    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -in $requiredRoleDefinitionName -and ($_.Scope -eq "/subscriptions/$($SubscriptionId)" -or $_.Scope -contains "/providers/Microsoft.Management/managementGroups") } | Measure-Object).Count -le 0 )
    {
        Write-Host "WARNING: This script can only be run by an [$($requiredRoleDefinitionName -join ", ")]. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }
    else
    {
        Write-Host "Current user [$($context.Account.Id)] has the required permission for subscription [$($SubscriptionId)].`n" -ForegroundColor $([Constants]::MessageType.Update)
    }
    
    Write-Host $([Constants]::SingleDashLine)
 
    Write-Host "**Metadata Details:**"  -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Admin/Owner role assignment(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Admin/Owner role assignment(s) from" -NoNewline
    Write-Host " [$($FilePath)]..."
    $AdminOrOwnerRoleAssignmentDetails = Import-Csv -LiteralPath $FilePath
    $totalAdminOrOwnerRoleAssignments = $($AdminOrOwnerRoleAssignmentDetails | Measure-Object).Count

    if ($totalAdminOrOwnerRoleAssignments -eq 0)
    {
        Write-Host "No Admin/Owner role assignment found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return;
    }

    # Excluding 'AccountAdministrator' Admin/Owner role from the collection as 'AccounAdministrator' assignment can't be removed using script.
    $AdminOrOwnerRoleAssignmentDetails = $AdminOrOwnerRoleAssignmentDetails | Where-Object { $_.RoleDefinitionName -notlike "AccountAdministrator"}

    Write-Host "Found [$($totalAdminOrOwnerRoleAssignments)] Admin/Owner role assignments in the given CSV." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.SignInName};Label="SignInName";Width=30;Alignment="left"},
    @{Expression={$_.RoleDefinitionName};Label="RoleDefinitionName";Width=30;Alignment="left"},
    @{Expression={$_.RoleAssignmentId};Label="RoleAssignmentId";Width=100;Alignment="left"}
        
    $AdminOrOwnerRoleAssignmentDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\AdminOrOwnerRoleAssignments"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Restoring all Admin/Owner role assignments from given CSV file..."
    Write-Host $([Constants]::SingleDashLine)

    if (-not $Force)
    {
        Write-Host "`nDo you want to restore all Admin/Owner role assignments from the given CSV? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Admin/Owner role assignments will not be restored for subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            return
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Admin/Owner role assignments will be restored for subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    Write-Host "Service Administrator role assignment cannot be restored.`n" -ForegroundColor $([Constants]::MessageType.Warning)
    $restoredAssignments = @()
    $skippedRoleAssignments = @()
    $AdminOrOwnerRoleAssignmentDetails | ForEach-Object {
        $currentRoleAssignment = $_
        try 
        {
            $roleAssignments = [AdminOrOwnerRoleAssignments]::new()
            if($currentRoleAssignment.RoleDefinitionName -eq ("CoAdministrator") -and $currentRoleAssignment.RoleAssignmentId.contains("/providers/Microsoft.Authorization/classicAdministrators/"))
            {
                $res = $roleAssignments.RestoreRoleAssignment($currentRoleAssignment.SignInName, $currentRoleAssignment.RoleDefinitionName, $currentRoleAssignment.RoleAssignmentId, "ClassicRole")
            }
            elseif ($currentRoleAssignment.RoleDefinitionName -eq "Owner")
            {   
                $res = $roleAssignments.RestoreRoleAssignment($currentRoleAssignment.ObjectId, $currentRoleAssignment.RoleId, $currentRoleAssignment.RoleAssignmentId, "Role")
            }

            if(($null -ne $res) -and ($res.StatusCode -eq 202 -or $res.StatusCode -eq 201))
            {
                $restoredAssignments += $currentRoleAssignment
            }
            else
            {
                $skippedRoleAssignments += $currentRoleAssignment
            }
        }
        catch
        {
            $skippedRoleAssignments += $currentRoleAssignment  
        }
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)


    if(($restoredAssignments | Measure-Object).Count -ne 0)
    {
        Write-Host "Successfully restored following Admin/Owner role assignment(s):" -ForegroundColor $([Constants]::MessageType.Update)
        $restoredAssignments |Format-Table -Property $colsProperty -Wrap
        $rollBackSummaryFilePath = "$($backupFolderPath)\RollbackSummary.csv"
        $restoredAssignments | Export-CSV -Path $rollBackSummaryFilePath -NoTypeInformation
        Write-Host "Rollback summary have been backed up to" -NoNewline
        write-host "[$($rollBackSummaryFilePath)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
    }
    if (($skippedRoleAssignments | Measure-Object).Count -ne 0)
    {
        Write-Host "Error occured while restoring following Admin/Owner role assignment(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $skippedRoleAssignments |Format-Table -Property $colsProperty -Wrap
        $skippedRoleAssignmentSummaryFilePath = "$($backupFolderPath)\SkippedRoleAssignmentSummary.csv"
        $skippedRoleAssignments | Export-CSV -Path $skippedRoleAssignmentSummaryFilePath -NoTypeInformation
        Write-Host "Skipped role assignment summary have been backed up to" -NoNewline
        Write-Host "[$($skippedRoleAssignmentSummaryFilePath)]`n" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
    }  
        
}


class AdminOrOwnerRoleAssignments
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
            $armUri = "https://management.azure.com/subscriptions/$($subscriptionId)/providers/Microsoft.Authorization/classicadministrators?api-version=2015-07-01"
            $headers = $this.GetAuthHeader()
            # API to get Admin/Owner role assignments
            $response = Invoke-WebRequest -Method Get -Uri $armUri -Headers $headers -UseBasicParsing
            $content = ConvertFrom-Json $response.Content
        }
        catch
        {
            throw;
        }
        
        return($content)
    }

    [PSObject] DeleteRoleAssignment([string] $roleAssignmentId, [bool] $isServiceAdminAccount, [string] $ObjectType)
    {
        $content = $null
        try
        {
            if($objectType -eq "ClassicRole")
            {

                $armUri = "https://management.azure.com" + $roleAssignmentId + "?api-version=2015-07-01"
            }
            else
            {
                $armUri = "https://management.azure.com" + $roleAssignmentId + "?api-version=2022-04-01"
            }
            if ($isServiceAdminAccount)
            {
                $armUri += "&adminType=serviceAdmin"
            }
            $headers = $this.GetAuthHeader()
            
            # API to remove Admin/Owner role assignments
            $response = Invoke-WebRequest -Method Delete -Uri $armUri -Headers $headers -UseBasicParsing
            $content = $response
        }
        catch
        {
            throw;
        }
        
        return($content)
    }

    [PSObject] RestoreRoleAssignment([string] $userInfo, [string] $roleDefinitionId, [string] $roleAssignmentId, [string] $objectType)
    {
        $content = $null
        try
        {
             if($objectType -eq "ClassicRole")
            {

                $armUri = "https://management.azure.com" + $roleAssignmentId + "?api-version=2015-07-01"
            }
            else
            {
                $armUri = "https://management.azure.com" + $roleAssignmentId + "?api-version=2022-04-01"
            }
            $headers = $this.GetAuthHeader()
            if($objectType -eq "ClassicRole")
            {
                $body = @{"properties"=@{emailAddress=$userInfo;role=$roleDefinitionId;}}
            }
            else
            {
                $body = @{"properties"=@{principalId=$userInfo;roleDefinitionId="/providers/Microsoft.Authorization/roleDefinitions/$roleDefinitionId";}}
            }
            # API to assign Admin/Owner role.
            $response = Invoke-WebRequest -Method Put -Uri $armUri -Headers $headers -Body ($body | ConvertTo-Json) -UseBasicParsing
            $content = $response
        }
        catch
        {
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