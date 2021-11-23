<###
# Overview:
    This script is used to enable Auditing and Advanced Threat Protection for SQL Servers in a Subscription.

# Control ID:
    Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server

# Display Name:
    Enable advanced data security on your SQL servers

# Prerequisites:
    Contributor and higher privileges on the SQL Servers in a Subscription.
    However, there are certain settings that can also be configured at the Subscription level. This would need Contributor and higher privileges on the Subscription.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Servers in a Subscription that do not have Auditing or Advanced Threat Protection enabled.
        3. Back up details of SQL Servers that are going to be remediated.
        4. Enable Auditing and Advanced Threat Protection on the SQL Servers in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Servers in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable Auditing and Advanced Threat Protection on the SQL Servers in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable Auditing and Advanced Threat Protection on the SQL Servers in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable Auditing and Advanced Threat Protection on the SQL Servers in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the SQL Server details in a Subscription that will be remediated:

           Enable-AdvancedThreatProtectionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        2. To enable Auditing and Advanced Threat Protection on the SQL Servers in a Subscription:

           Enable-AdvancedThreatProtectionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000

        3. To enable Auditing and Advanced Threat Protection on the SQL Servers in a Subscription, from a previously taken snapshot:

           Enable-AdvancedThreatProtectionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableThreatDetectionForSQLServers\SQLServersWithThreatDetectionDisabled.csv

        To know more about the options supported by the remediation command, execute:

        Get-Help Enable-AdvancedThreatProtectionForSqlServers -Detailed

    To roll back:
        1. To disable Auditing and Advanced Threat Protection on the SQL Servers in a Subscription, from a previously taken snapshot:

           Disable-AdvancedThreatProtectionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableThreatDetectionForSQLServers\RemediatedSQLServers.csv

        To know more about the options supported by the roll back command, execute:

        Get-Help Disable-AdvancedThreatProtectionForSqlServers -Detailed
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
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.Sql", "Az.Synapse", "Az.Security")

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
}

function Enable-AdvancedThreatProtectionForSqlServers
{
    <#
        .SYNOPSIS
        Remediates 'Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server' Control.

        .DESCRIPTION
        Remediates 'Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server' Control.
        Auditing and Advanced Threat Protection must be enabled.

        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .EXAMPLE
        PS> Enable-AdvancedThreatProtectionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-AdvancedThreatProtectionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-AdvancedThreatProtectionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableThreatDetectionForSQLServers\SQLServersWithThreatDetectionDisabled.csv

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
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies a dry run of the actual remediation")]
        $DryRun,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Preparing to enable Auditing and Advanced Threat Protection for SQL Server(s) in Subscription: $($SubscriptionId)"

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

    Write-Host "*** To enable Auditing and Advanced Threat Protection for SQL Server(s) in a Subscription, Contributor and higher privileges on the SQL Server(s) in the Subscription are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "*** However, there are certain settings that can also be configured at the Subscription level. This would need Contributor and higher privileges on the Subscription. ***" -ForegroundColor $([Constants]::MessageType.Info)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all SQL Servers..."

    $sqlServerResources = @()

    # No file path provided as input to the script. Fetch all SQL Servers in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all SQL Servers in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all SQL Servers in a Subscription.
        # This will include SQL Servers associated with Synapse Workspaces as well.
        $sqlServers = Get-AzResource -ResourceType "Microsoft.Sql/servers" -ErrorAction Stop

        # Get all Synapse Workspaces in a Subscription
        $synapseWorkspaces = Get-AzResource -ResourceType "Microsoft.Synapse/workspaces" -ErrorAction Stop

        $standaloneSqlServers = $sqlServers

        # Filter SQL Servers not associated with a Synapse Workspace.
        # Synapse Workspace and the associated SQL Server have the same name.
        # Synapse Workspace names are unique.
        if (($synapseWorkspaces | Measure-Object).Count -gt 0)
        {
            $standaloneSqlServers = Compare-Object -ReferenceObject $sqlServers -DifferenceObject $synapseWorkspaces -Property { $_.ResourceName }
        }

        $sqlServerResources += $standaloneSqlServers | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                     @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                     @{N='ServerName';E={$_.ResourceName}},
                                                                     @{N='ResourceType';E={$_.ResourceType}},
                                                                     @{N='IsSynapseWorkspace';E={$false}}

        # Add Synapse Workspaces to this list.
        $sqlServerResources += $synapseWorkspaces | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                  @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                  @{N='ServerName';E={$_.ResourceName}},
                                                                  @{N='ResourceType';E={$_.ResourceType}},
                                                                  @{N='IsSynapseWorkspace';E={$true}}
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all SQL Servers from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

        # Importing the list of SQL servers to be remediated.
        $sqlServersDetails = Import-Csv -LiteralPath $FilePath

        $sqlServerResources += $sqlServersDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
    }

    $totalSqlServers = $sqlServerResources.Count

    if ($totalSqlServers -eq 0)
    {
        Write-Host "No SQL Servers found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalSqlServers) SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)

    # Includes SQL Servers where Auditing and Advanced Threat Protection are enabled.
    $sqlServersWithThreatDetectionEnabled = @()

    # Includes SQL Servers where Auditing or Advanced Threat Protection is not enabled.
    $sqlServersWithThreatDetectionDisabled = @()

    $isAnyEmailAddressConfiguredAtSubscriptionLevel = $false
    $emailAddressesConfiguredAtSubscriptionLevel = [String]::Empty
    $isEmailAccountAdminsConfiguredAtSubscriptionLevel = $false

    # Get contact details from Azure Security Center.
    $ascContactDetails = Get-AzSecurityContact -ErrorAction Stop

    if (-not [String]::IsNullOrWhiteSpace($ascContactDetails) -and ($ascContactDetails | Measure-Object).Count -gt 0)
    {
        if (-not [String]::IsNullOrWhiteSpace($ascContactDetails[0].Email))
        {
            $isAnyEmailAddressConfiguredAtSubscriptionLevel = $true
            $emailAddressesConfiguredAtSubscriptionLevel = $ascContactDetails.Email -join ", "
        }

        if ($ascContactDetails[0].AlertsToAdmins -eq "on")
        {
            $isEmailAccountAdminsConfiguredAtSubscriptionLevel = $true
        }
    }

    $isAtpEnabledAtSubscriptionLevel = $false

    # Check if Advanced Threat Protection for SQL Servers is enabled on the Subscription.
    $sqlServerPricingDetails = Get-AzSecurityPricing -Name "SqlServers" -ErrorAction Stop

    if (-not [String]::IsNullOrWhiteSpace($sqlServerPricingDetails) -and $sqlServerPricingDetails.PricingTier -eq "Standard")
    {
        $isAtpEnabledAtSubscriptionLevel = $true
    }

    $sqlServerResources | ForEach-Object {
        try
        {
            Write-Host "Fetching SQL Server resource: Resource ID - $($_.ResourceId)"

            $sqlServerAuditDetails = @()
            $sqlServerAtpSetting = @()
            $isAuditingEnabled = $false
            $isAtpEnabled = $false
            $isAnyAlertDisabled = $false
            $disabledAlerts = [String]::Empty
            $isAnyEmailAddressConfigured = $false
            $notificationRecipientsEmails = [String]::Empty
            $isEmailAccountAdminsConfigured = $false

            # A "master" variable that indicates if ATP is enabled and correctly configured.
            $isAtpConfigured = $false

            # Check if the SQL Server is a stand-alone SQL Server or is associated with a Synapse Workspace.
            if ($_.IsSynapseWorkspace -eq $false)
            {
                # SQL Server is a stand-alone SQL Server.
                # Get SQL Server audit details.
                $sqlServerAuditDetails = Get-AzSqlServerAudit -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ErrorAction Stop

                # Get SQL Server Advanced Threat Protection details.
                $sqlServerAtpSetting = Get-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ErrorAction Stop
            }
            else
            {
                # SQL Server is associated with a Synapse Workspace.
                # Synapse Workspace and the associated SQL Server have the same name.
                # Get SQL Server audit details.
                $sqlServerAuditDetails = Get-AzSynapseSqlAuditSetting -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName -ErrorAction Stop

                # Get SQL Server Advanced Threat Protection details.
                $sqlServerAtpSetting = Get-AzSynapseSqlAdvancedThreatProtectionSetting -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName -ErrorAction Stop
            }

            if ([String]::IsNullOrWhiteSpace($sqlServerAuditDetails))
            {
                throw "Error fetching Auditing settings."
            }

            if ([String]::IsNullOrWhiteSpace($sqlServerAtpSetting))
            {
                throw "Error fetching Advanced Threat Protection settings."
            }

            # Check if Auditing is enabled on the SQL Server.
            # Auditing is enabled if one or more of BlobStorageTargetState, EventHubTargetState or LogAnalyticsTargetState is enabled.
            $isAuditingEnabled = (-not [String]::IsNullOrWhiteSpace($sqlServerAuditDetails) -and ($sqlServerAuditDetails.BlobStorageTargetState -eq "Enabled" -or
                                                                                                  $sqlServerAuditDetails.EventHubTargetState -eq "Enabled" -or
                                                                                                  $sqlServerAuditDetails.LogAnalyticsTargetState -eq "Enabled"))

            # Check if Advanced Threat Protection is configured on the SQL Server.
            $isAtpEnabled = $sqlServerAtpSetting.ThreatDetectionState -eq "Enabled"
            $isAnyAlertDisabled = -not [String]::IsNullOrWhiteSpace($sqlServerAtpSetting.ExcludedDetectionTypes)
            $disabledAlerts = $sqlServerAtpSetting.ExcludedDetectionTypes -join ", "
            $isAnyEmailAddressConfigured = -not [String]::IsNullOrWhiteSpace($sqlServerAtpSetting.NotificationRecipientsEmails)
            $notificationRecipientsEmails = $sqlServerAtpSetting.NotificationRecipientsEmails
            $isEmailAccountAdminsConfigured = $sqlServerAtpSetting.EmailAdmins

            $isAtpConfigured = $isAtpEnabled -eq $true -and $isAnyAlertDisabled -eq $false -and ($isAnyEmailAddressConfiguredAtSubscriptionLevel -eq $true -or $isEmailAccountAdminsConfiguredAtSubscriptionLevel -eq $true -or $isAnyEmailAddressConfigured -eq $true -or $isEmailAccountAdminsConfigured -eq $true)

            # Check if Auditing and Advanced Threat Protection are enabled on the SQL Server.
            if ($isAuditingEnabled -eq $true -and $isAtpConfigured -eq $true)
            {
                $sqlServersWithThreatDetectionEnabled += $_
                Write-Host "Auditing and Advanced Threat Protection is already enabled on the SQL Server. Resource ID - $($_.ResourceId), Resource Group Name - $($_.ResourceGroupName), Resource Name - $($_.ServerName)." -ForegroundColor $([Constants]::MessageType.Info)
            }
            else
            {
                $sqlServersWithThreatDetectionDisabled += $_ | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                             @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                             @{N='ServerName';E={$_.ServerName}},
                                                                             @{N='ResourceType';E={$_.ResourceType}},
                                                                             @{N='IsSynapseWorkspace';E={$_.IsSynapseWorkspace}},
                                                                             @{N='IsAuditingEnabled';E={$isAuditingEnabled}},
                                                                             @{N='IsAtpEnabled';E={$isAtpEnabled}},
                                                                             @{N='IsAnyAlertDisabled';E={$isAnyAlertDisabled}},
                                                                             @{N='DisabledAlerts';E={$disabledAlerts}},
                                                                             @{N='IsAnyEmailAddressConfigured';E={$isAnyEmailAddressConfigured}},
                                                                             @{N='NotificationRecipientsEmails';E={$notificationRecipientsEmails}},
                                                                             @{N='IsEmailAccountAdminsConfigured';E={$isEmailAccountAdminsConfigured}},
                                                                             @{N='IsAnyEmailAddressConfiguredAtSubscriptionLevel';E={$isAnyEmailAddressConfiguredAtSubscriptionLevel}},
                                                                             @{N='EmailAddressesConfiguredAtSubscriptionLevel';E={$emailAddressesConfiguredAtSubscriptionLevel}},
                                                                             @{N='IsEmailAccountAdminsConfiguredAtSubscriptionLevel';E={$isEmailAccountAdminsConfiguredAtSubscriptionLevel}},
                                                                             @{N="IsAtpEnabledAtSubscriptionLevel";E={$isAtpEnabledAtSubscriptionLevel}},
                                                                             @{N="IsAtpConfigured";E={$isAtpConfigured}}
            }
        }
        catch
        {
            $sqlServersWithThreatDetectionDisabled += $_ | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                         @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                         @{N='ServerName';E={$_.ServerName}},
                                                                         @{N='ResourceType';E={$_.ResourceType}},
                                                                         @{N='IsSynapseWorkspace';E={$_.IsSynapseWorkspace}},
                                                                         @{N='IsAuditingEnabled';E={$isAuditingEnabled}},
                                                                         @{N='IsAtpEnabled';E={$isAtpEnabled}},
                                                                         @{N='IsAnyAlertDisabled';E={$isAnyAlertDisabled}},
                                                                         @{N='DisabledAlerts';E={$disabledAlerts}},
                                                                         @{N='IsAnyEmailAddressConfigured';E={$isAnyEmailAddressConfigured}},
                                                                         @{N='NotificationRecipientsEmails';E={$notificationRecipientsEmails}},
                                                                         @{N='IsEmailAccountAdminsConfigured';E={$isEmailAccountAdminsConfigured}},
                                                                         @{N='IsAnyEmailAddressConfiguredAtSubscriptionLevel';E={$isAnyEmailAddressConfiguredAtSubscriptionLevel}},
                                                                         @{N='EmailAddressesConfiguredAtSubscriptionLevel';E={$emailAddressesConfiguredAtSubscriptionLevel}},
                                                                         @{N='IsEmailAccountAdminsConfiguredAtSubscriptionLevel';E={$isEmailAccountAdminsConfiguredAtSubscriptionLevel}},
                                                                         @{N="IsAtpEnabledAtSubscriptionLevel";E={$isAtpEnabledAtSubscriptionLevel}},
                                                                         @{N="IsAtpConfigured";E={$isAtpConfigured}}

            Write-Host "Error fetching Auditing and Advanced Threat Protection configuration: Resource ID - $($_.ResourceId), Resource Group Name - $($_.ResourceGroupName), Resource Name - $($_.ServerName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

    $totalSqlServersWithThreatDetectionDisabled = ($sqlServersWithThreatDetectionDisabled | Measure-Object).Count

    if ($totalSqlServersWithThreatDetectionDisabled -eq 0)
    {
        Write-Host "No SQL Server found with Auditing or Advanced Threat Protection disabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalSqlServersWithThreatDetectionDisabled) SQL Server(s) with Auditing or Advanced Threat Protection disabled." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableThreatDetectionForSQLServers"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    # Backing up SQL Server details.
    $backupFile = "$($backupFolderPath)\SQLServersWithThreatDetectionDisabled.csv"
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up SQL Server details to $($backupFile)"

    $sqlServersWithThreatDetectionDisabled | Export-CSV -Path $backupFile -NoTypeInformation

    if (-not $DryRun)
    {
        Write-Host "*** There will be billing costs associated with enabling Advanced Threat Protection for SQL Servers. ***" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "*** It is recommended to understand them before enabling Advanced Threat Protection for SQL Servers. ***" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Note: This warning can be ignored if Advanced Threat Protection is already enabled for SQL Servers or if you are aware of the costs that will be incurred." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Do you still want to proceed?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y")
        {
            Write-Host "Auditing and Advanced Threat Protection will not be enabled for any SQL Server. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enabling Auditing and Advanced Threat Protection for SQL Servers..." -ForegroundColor $([Constants]::MessageType.Warning)

        # To hold results from the remediation.
        $remediatedSqlServers = @()

        # Includes SQL Servers that were skipped during remediation. There were errors remediating them.
        $skippedSqlServers = @()

        # List of privileged roles in a Subscription.
        # Safe Check: Current user must have Contributor/Owner/User Access Administrator access over the Subscription.
        $privilegedRoleDefinitionNames = @("Contributor", "Owner", "User Access Administrator")

        # Check if the user has higher privileges to configure Subscription level settings.
        $hasPrivilegedRolesInSubscription = $false

        # Flag to indicate if it has been checked whether the current user has privileged roles on the Subscription.
        # This is to avoid repetitive calls.
        $isPrivilegedRoleChecked = $false

        # Flag to indicate if Advanced Threat Protection for SQL Servers at the Subscription level was enabled as a part of this remediation.
        $isAtpEnabledAtSubscriptionLevelNow = $false

        # Flag to indicate if contact details were configured as a part of this remediation.
        $isContactDetailsConfiguredAtSubscriptionNow = $false

        if ($isAtpEnabledAtSubscriptionLevel -eq $false)
        {
            Write-Host "Advanced Threat Protection for SQL Servers is not enabled at the Subscription level." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Do you want to enable Advanced Threat Protection for SQL Servers at the Subscription level? This will configure Advanced Threat Protection for all SQL Servers in the Subscription." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

            $userInput = Read-Host -Prompt "(Y|N)"

            if ($userInput -eq "Y")
            {
                try
                {
                    $isPrivilegedRoleChecked = $true
                    $hasPrivilegedRolesInSubscription = Check-HasRolesInScope "$($context.Account.Id)" "/subscriptions/$($context.Subscription.Id)" $privilegedRoleDefinitionNames

                    if ($hasPrivilegedRolesInSubscription)
                    {
                        Write-Host "Current user [$($context.Account.Id)] has the required permissions to enable Advanced Threat Protection at the Subscription level." -ForegroundColor $([Constants]::MessageType.Info)
                        Write-Host "Enabling Advanced Threat Protection for SQL servers in the Subscription" -ForegroundColor $([Constants]::MessageType.Warning)

                        $sqlServerPricingDetails = Set-AzSecurityPricing -Name "SqlServers" -PricingTier "Standard" -ErrorAction Continue

                        if (-not [String]::IsNullOrWhiteSpace($sqlServerPricingDetails) -and $sqlServerPricingDetails.PricingTier -eq "Standard")
                        {
                            $isAtpEnabledAtSubscriptionLevel = $true
                            $isAtpEnabledAtSubscriptionLevelNow = $true

                            # Enabling Advanced Threat Protection at the Subscription level will also configure contact details. Hence, query them again.

                            # Get contact details from Azure Security Center.
                            $ascContactDetails = Get-AzSecurityContact -ErrorAction Stop

                            if (-not [String]::IsNullOrWhiteSpace($ascContactDetails) -and ($ascContactDetails | Measure-Object).Count -gt 0)
                            {
                                if (-not [String]::IsNullOrWhiteSpace($ascContactDetails[0].Email))
                                {
                                    $isAnyEmailAddressConfiguredAtSubscriptionLevel = $true
                                    $emailAddressesConfiguredAtSubscriptionLevel = $ascContactDetails.Email -join ", "
                                }

                                if ($ascContactDetails[0].AlertsToAdmins -eq "on")
                                {
                                    $isEmailAccountAdminsConfiguredAtSubscriptionLevel = $true
                                }
                            }

                            Write-Host "Advanced Threat Protection for SQL Servers successfully enabled in the Subscription." -ForegroundColor $([Constants]::MessageType.Update)
                        }
                        else
                        {
                            Write-Host "Error enabling Advanced Threat Protection for SQL servers in the Subscription." -ForegroundColor $([Constants]::MessageType.Error)

                            # Not terminating the script here.
                            # ATP can still be configured at the individual SQL Server levels.
                            Write-Host "Advanced Threat Protection can still be configured for the individual SQL Servers." -ForegroundColor $([Constants]::MessageType.Info)
                        }
                    }
                    else
                    {
                        Write-Host "Warning: Current user [$($context.Account.Id)] does not have the required permissions to configure Advanced Threat Protection at the Subscription level." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host "One of the following roles is required to enable Advanced Threat Protection at the Subscription level: [$($privilegedRoleDefinitionNames -join ", ")]" -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host "Advanced Threat Protection can still be configured for the individual SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning)
                    }
                }
                catch
                {
                    Write-Host "Error enabling Advanced Threat Protection for SQL servers in the Subscription. Error $($_)" -ForegroundColor $([Constants]::MessageType.Error)

                    # Not terminating the script here.
                    # ATP can still be configured at the individual SQL Server levels.
                    Write-Host "Advanced Threat Protection can still be configured for the individual SQL Servers." -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            else
            {
                Write-Host "Advanced Threat Protection can still be configured for the individual SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }

        if (-not ($isAnyEmailAddressConfiguredAtSubscriptionLevel -eq $true -or $isEmailAccountAdminsConfiguredAtSubscriptionLevel -eq $true))
        {
            Write-Host "Contact details are not configured in Azure Security Center." -ForegroundColor $([Constants]::MessageType.Warning)

            if (-not $isPrivilegedRoleChecked)
            {
                $hasPrivilegedRolesInSubscription = Check-HasRolesInScope "$($context.Account.Id)" "/subscriptions/$($context.Subscription.Id)" $privilegedRoleDefinitionNames
            }

            if ($hasPrivilegedRolesInSubscription)
            {
                Write-Host "Do you want to configure contact details in Azure Security Center? These details will be used to send out email notifications in the event of an alert." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

                $userInput = Read-Host -Prompt "(Y|N)"

                if ($userInput -eq "Y")
                {
                    try
                    {
                        Write-Host "Configuring contact details in Azure Security Center for the Subscription: $($SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host "*** The email address from this session - $($context.Account.Id) will be used as a recipient for email notifications on an alert. ***" -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host "*** Please use the Azure Portal to configure additional email addresses, if required. ***" -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host "*** Also, email notifications to Admins and Subscription Owners will be enabled. ***" -ForegroundColor $([Constants]::MessageType.Warning)

                        $ascContactDetails = Set-AzSecurityContact -Name "$($context.Account.Id)" -Email "$($context.Account.Id)" -AlertAdmin -NotifyOnAlert -ErrorAction Continue

                        # Check if contact details are successfully configured on the Subscription.
                        if (-not [String]::IsNullOrWhiteSpace($ascContactDetails) -and $ascContactDetails.Count -gt 0)
                        {
                            if (-not [String]::IsNullOrWhiteSpace($ascContactDetails[0].Email) -and $ascContactDetails[0].AlertsToAdmins -eq "on")
                            {
                                $isAnyEmailAddressConfiguredAtSubscriptionLevel = $true
                                $isEmailAccountAdminsConfiguredAtSubscriptionLevel = $true
                                $isContactDetailsConfiguredAtSubscriptionNow = $true
                                Write-Host "Contact details successfully configured on the Subscription: $($SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Update)
                            }
                        }
                        else
                        {
                            Write-Host "Error configuring contact details on the Subscription $($SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Error)

                            # Not terminating the script here.
                            # Contact details can still be configured at the individual SQL Server levels.
                            Write-Host "Contact details can still be configured for the individual SQL Servers." -ForegroundColor $([Constants]::MessageType.Error)
                        }
                    }
                    catch
                    {
                        Write-Host "Error configuring contact details on the Subscription $($SubscriptionId). Error $($_)" -ForegroundColor $([Constants]::MessageType.Error)

                        # Not terminating the script here.
                        # Contact details can still be configured at the individual SQL Server levels.
                        Write-Host "Contact details can still be configured for the individual SQL Servers." -ForegroundColor $([Constants]::MessageType.Error)
                    }
                }
                else
                {
                    Write-Host "Contact details can still be configured for the individual SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
            else
            {
                Write-Host "Warning: Current user [$($context.Account.Id)] does not have the required permissions to configure contact details in Azure Security Center." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "One of the following roles is required to configure contact details in Azure Security Center: [$($requiredRoleDefinitionNames -join ", ")]" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Contact details can still be configured for the individual SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }

        Write-Host "Checking if Auditing and Advanced Threat Protection are configured for the individual SQL servers." -ForegroundColor $([Constants]::MessageType.Info)

        # Storage Account details
        [String] $storageAccountResourceGroupName = [String]::Empty
        [String] $storageAccountName = [String]::Empty
        $storageAccount = $null
        $isCentralStorageAccount = $false
        $isStorageAccountPreferenceDecided = $false

        # Check Auditing and ATP settings at the SQL Server level.
        $sqlServersWithThreatDetectionDisabled  | ForEach-Object {
            Write-Host "Checking SQL Server Resource ID: $($_.ResourceId)" -ForegroundColor $([Constants]::MessageType.Info)

            try
            {
                $sqlServerInstance = $_

                $isAuditingEnabled = $sqlServerInstance.IsAuditingEnabled
                $isAtpEnabled = $sqlServerInstance.IsAtpEnabled
                $isAnyAlertDisabled = $sqlServerInstance.IsAnyAlertDisabled
                $disabledAlerts = $sqlServerInstance.DisabledAlerts
                $isAnyEmailAddressConfigured = $sqlServerInstance.IsAnyEmailAddressConfigured
                $notificationRecipientsEmails = $sqlServerInstance.NotificationRecipientsEmails
                $isEmailAccountAdminsConfigured = $sqlServerInstance.IsEmailAccountAdminsConfigured
                $isAtpConfigured = $sqlServerInstance.IsAtpConfigured

                # If Advanced Threat Protection and/or Contact details were configured in the Subscription now, get the Advanced Threat Protection settings for the SQL Server again.
                # This will ensure that any previous changes are not overwritten.
                # This will also cover cases where Advanced Threat Protection is enabled at the Subscription level, but, disabled at the SQL Server level.
                if ($isAtpEnabledAtSubscriptionLevelNow -or $isContactDetailsConfiguredAtSubscriptionNow)
                {
                    # Check if the SQL Server is a stand-alone SQL Server or is associated with a Synapse Workspace.
                    if ($sqlServerInstance.IsSynapseWorkspace -eq $false)
                    {
                        # SQL Server is a stand-alone SQL Server.
                        # Get SQL Server Advanced Threat Protection details.
                        $sqlServerAtpSetting = Get-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -ServerName $sqlServerInstance.ServerName -ErrorAction Stop
                    }
                    else
                    {
                        # SQL Server is associated with a Synapse Workspace.
                        # Synapse Workspace and the associated SQL Server have the same name.
                        # Get SQL Server Advanced Threat Protection details.
                        $sqlServerAtpSetting = Get-AzSynapseSqlAdvancedThreatProtectionSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -WorkspaceName $sqlServerInstance.ServerName -ErrorAction Stop
                    }

                    if ([String]::IsNullOrWhiteSpace($sqlServerAtpSetting))
                    {
                        throw "Error fetching Advanced Threat Protection settings."
                    }

                    # Check if Advanced Threat Protection is configured on the SQL Server.
                    $isAtpEnabled = $sqlServerAtpSetting.ThreatDetectionState -eq "Enabled"
                    $isAnyAlertDisabled = -not [String]::IsNullOrWhiteSpace($sqlServerAtpSetting.ExcludedDetectionTypes)
                    $disabledAlerts = $sqlServerAtpSetting.ExcludedDetectionTypes -join ", "
                    $isAnyEmailAddressConfigured = -not [String]::IsNullOrWhiteSpace($sqlServerAtpSetting.NotificationRecipientsEmails)
                    $notificationRecipientsEmails = $sqlServerAtpSetting.NotificationRecipientsEmails
                    $isEmailAccountAdminsConfigured = $sqlServerAtpSetting.EmailAdmins

                    $isAtpConfigured = $isAtpEnabled -eq $true -and $isAnyAlertDisabled -eq $false -and ($isAnyEmailAddressConfiguredAtSubscriptionLevel -eq $true -or $isEmailAccountAdminsConfiguredAtSubscriptionLevel -eq $true -or $isAnyEmailAddressConfigured -eq $true -or $isEmailAccountAdminsConfigured -eq $true)
                }

                if ($isAuditingEnabled -eq $false)
                {
                    if (-not $isStorageAccountPreferenceDecided)
                    {
                        $isStorageAccountPreferenceDecided = $true

                        Write-Host "Auditing requires one or more of Storage Account, Log Analytics Workspace or Event Hub to be configured for storing the audit logs." -ForegroundColor $([Constants]::MessageType.Info)
                        Write-Host "*** This script supports only Storage Accounts as a destination for storing the audit logs. ***" -ForegroundColor $([Constants]::MessageType.Info)
                        Write-Host "Do you still want to proceed?" -ForegroundColor $([Constants]::MessageType.Info) -NoNewline

                        $userInput = Read-Host -Prompt "(Y|N)"

                        if ($userInput -ne "Y")
                        {
                            Write-Host "If you prefer a different destination for storing the audit logs, please configure them and run this script again to configure Advanced Threat Protection." -ForegroundColor $([Constants]::MessageType.Update)
                            Write-Host "Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                            break
                        }

                        Write-Host "Do you prefer having a single Storage Account to store the auditing logs of all SQL servers in the Subscription?" -ForegroundColor $([Constants]::MessageType.Info) -NoNewline

                        $userInput = Read-Host -Prompt "(Y|N)"

                        if ($userInput -eq "Y")
                        {
                            Write-Host "You can use a previously created Storage Account to store the auditing logs by specifying its Name and Resource Group." -ForegroundColor $([Constants]::MessageType.Info)
                            Write-Host "If no such Storage Account exists, a new Storage Account with the specified name will be created to store the auditing logs." -ForegroundColor $([Constants]::MessageType.Info)
                            Write-Host "In this case, the Resource Group needs to be already present. If not, create the Resource Group and resume." -ForegroundColor $([Constants]::MessageType.Info)
                            Write-Host "Please ensure that you have sufficient permissions to create/access the Storage Account." -ForegroundColor $([Constants]::MessageType.Info)

                            $storageAccountResourceGroupName = Read-Host -Prompt "Resource Group Name: "
                            $storageAccountName = Read-Host -Prompt "Storage Account Name: "

                            $storageAccount = Create-StorageAccountIfNotExists $storageAccountResourceGroupName $storageAccountName

                            if (($storageAccount | Measure-Object).Count -ne 0)
                            {
                                Write-Host "Centralized Storage Account successfully created." -ForegroundColor $([Constants]::MessageType.Update)
                            }
                            else
                            {
                                Write-Host "Error creating a centralized Storage Account to store the auditing logs." -ForegroundColor $([Constants]::MessageType.Error)
                                Write-Host "Please ensure that you have sufficient permissions to create a Storage Account in this Resource Group." -ForegroundColor $([Constants]::MessageType.Error)
                                Write-Host "You may also run this script again and configure individal Storage Accounts for each SQL Server." -ForegroundColor $([Constants]::MessageType.Error)
                                Write-Host "Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                                break
                            }

                            $isCentralStorageAccount = $true
                        }
                        else
                        {
                            Write-Host "Individual Storage Accounts will be created for every SQL server in its respective Resource Group to store the auditing logs specific to them." -ForegroundColor $([Constants]::MessageType.Info)
                        }
                    }

                    if (-not $isCentralStorageAccount)
                    {
                        $storageAccountResourceGroupName = $sqlServerInstance.ResourceGroupName

                        # Storage Account name will be a concatenation of "auditlogs" + name of the SQL Server.
                        # Only the first 15 characters of the SQL Server's name will be considered, as there is a size limit of 24 characters for the name of a Storage Account.
                        # This will strip out non-alphanumeric characters as Storage Account names can only contain alphanumeric characters.
                        $storageAccountNameSuffix = $sqlServerInstance.ServerName -replace "\W"

                        # This check is required, else, String::Substring() will throw an error for strings less than 15 characters.
                        if ($storageAccountNameSuffix.Length -gt 15)
                        {
                            $storageAccountNameSuffix = $storageAccountNameSuffix.Substring(0, 15)
                        }

                        $storageAccountName = -join("auditlogs", $storageAccountNameSuffix.ToLower())

                        Write-Host "Creating a Storage Account for SQL Server: $($sqlServerInstance.ServerName)"

                        $storageAccount = Create-StorageAccountIfNotExists $storageAccountResourceGroupName $storageAccountName

                        if (($storageAccount | Measure-Object).Count -ne 0)
                        {
                            Write-Host "Storage Account - $($storageAccountName) successfully created." -ForegroundColor $([Constants]::MessageType.Update)
                        }
                        else
                        {
                            Write-Host "Error creating a Storage Account to store the auditing logs." -ForegroundColor $([Constants]::MessageType.Error)
                            Write-Host "Please ensure that you have sufficient permissions to create a Storage Account in this Resource Group." -ForegroundColor $([Constants]::MessageType.Error)
                            Write-Host "Skipping this SQL Server..." -ForegroundColor $([Constants]::MessageType.Error)
                            throw "Error creating Storage Account."
                        }
                    }

                    Write-Host "Enabling Auditing for SQL Server: $($sqlServerInstance.ServerName)"

                    # Check if the SQL Server is a stand-alone SQL Server or is associated with a Synapse Workspace.
                    if ($sqlServerInstance.IsSynapseWorkspace -eq $false)
                    {
                        # SQL Server is a stand-alone SQL Server.
                        Set-AzSqlServerAudit -ResourceGroupName $sqlServerInstance.ResourceGroupName -ServerName $sqlServerInstance.ServerName -BlobStorageTargetState Enabled -StorageAccountResourceId $storageAccount.Id
                        $sqlServerAuditDetails = Get-AzSqlServerAudit -ResourceGroupName $sqlServerInstance.ResourceGroupName -ServerName $sqlServerInstance.ServerName
                    }
                    else
                    {
                        # SQL Server is associated with a Synapse Workspace.
                        # Synapse Workspace and the associated SQL Server have the same name.
                        Set-AzSynapseSqlAuditSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -WorkspaceName $sqlServerInstance.ServerName -BlobStorageTargetState Enabled -StorageAccountResourceId $storageAccount.Id
                        $sqlServerAuditDetails = Get-AzSynapseSqlAuditSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -WorkspaceName $sqlServerInstance.ServerName
                    }

                    # Auditing is enabled if one or more of BlobStorageTargetState, EventHubTargetState or LogAnalyticsTargetState is enabled.
                    $isAuditingEnabled = (-not [String]::IsNullOrWhiteSpace($sqlServerAuditDetails) -and ($sqlServerAuditDetails.BlobStorageTargetState -eq "Enabled" -or
                                                                                                          $sqlServerAuditDetails.EventHubTargetState -eq "Enabled" -or
                                                                                                          $sqlServerAuditDetails.LogAnalyticsTargetState -eq "Enabled"))

                    if ($isAuditingEnabled)
                    {
                        Write-Host "Auditing is succesfully enabled for SQL Server: $($sqlServerInstance.ServerName)"
                    }
                    else
                    {
                        Write-Host "Error enabling Auditing for SQL Server: $($sqlServerInstance.ServerName)"
                        throw "Error enabling Auditing for SQL Server."
                    }
                }

                if ($isAtpConfigured -eq $false)
                {
                    # If an email address has already been configured for the SQL Server, retain that.
                    $notificationRecipientsEmails = $sqlServerInstance.NotificationRecipientsEmails

                    # If emails to Admins and Subscription Owners is enabled, retain that.
                    $emailAdmins = $sqlServerInstance.IsEmailAccountAdminsConfigured

                    # If no email address has already been configured for the SQL Server, or if email notifications to Admins and Subscription Owners is not enabled, check if contact details have been configured at the Subscription level.
                    if ([String]::IsNullOrWhiteSpace($notificationRecipientsEmails) -and $emailAdmins -eq $false)
                    {
                        $notificationRecipientsEmails = $emailAddressesConfiguredAtSubscriptionLevel
                        $emailAdmins = $isEmailAccountAdminsConfiguredAtSubscriptionLevel

                        # If no email address has already been configured at the Subscription level, or if email notifications to Admins and Subscription Owners is not enabled at the Subscription level, the current sign-in address will be used.
                        if ([String]::IsNullOrWhiteSpace($notificationRecipientsEmails) -and $emailAdmins -eq $false)
                        {
                            $notificationRecipientsEmails = $context.Account.Id
                            $emailAdmins = $true
                        }
                    }

                    # Check if the SQL Server is a stand-alone SQL Server or is associated with a Synapse Workspace.
                    if ($sqlServerInstance.IsSynapseWorkspace -eq $false)
                    {
                        # SQL Server is a stand-alone SQL Server.
                        Update-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -ServerName $sqlServerInstance.ServerName -ExcludedDetectionType "" -NotificationRecipientsEmail "$($notificationRecipientsEmails)" -EmailAdmin $emailAdmins
                        $sqlServerAtpSetting = Get-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -ServerName $sqlServerInstance.ServerName
                    }
                    else
                    {
                        # SQL Server is associated with a Synapse Workspace.
                        # Synapse Workspace and the associated SQL Server have the same name.
                        Update-AzSynapseSqlAdvancedThreatProtectionSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -WorkspaceName $sqlServerInstance.ServerName -ExcludedDetectionType "" -NotificationRecipientsEmail "$($notificationRecipientsEmails)" -EmailAdmin $emailAdmins
                        $sqlServerAtpSetting = Get-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -ServerName $sqlServerInstance.ServerName
                    }

                    $isAtpEnabled = $sqlServerAtpSetting.ThreatDetectionState -eq "Enabled"
                    $isAnyAlertDisabled = -not [String]::IsNullOrWhiteSpace($sqlServerAtpSetting.ExcludedDetectionTypes)
                    $disabledAlerts = $sqlServerAtpSetting.ExcludedDetectionTypes -join ", "
                    $isAnyEmailAddressConfigured = -not [String]::IsNullOrWhiteSpace($sqlServerAtpSetting.NotificationRecipientsEmails)
                    $notificationRecipientsEmails = $sqlServerAtpSetting.NotificationRecipientsEmails
                    $isEmailAccountAdminsConfigured = $sqlServerAtpSetting.EmailAdmins

                    # Check if Advanced Threat Protection is configured.
                    $isAtpConfigured = $isAtpEnabled -eq $true -and $isAnyAlertDisabled -eq $false -and ($isAnyEmailAddressConfiguredAtSubscriptionLevel -eq $true -or $isEmailAccountAdminsConfiguredAtSubscriptionLevel -eq $true -or $isAnyEmailAddressConfigured -eq $true -or $isEmailAccountAdminsConfigured -eq $true)

                    if ($isAtpConfigured -eq $true)
                    {
                        Write-Host "Advanced Threat Protection is succesfully configured for SQL Server: $($sqlServerInstance.ServerName)"
                    }
                    else
                    {
                        Write-Host "Error configuring Advanced Threat Protection for SQL Server: $($sqlServerInstance.ServerName)"
                        throw "Error configuring Advanced Threat Protection for SQL Server."
                    }
                }

                if ($isAuditingEnabled -eq $true -and $isAtpConfigured -eq $true)
                {
                    $remediatedSqlServers += $sqlServerInstance | Select-Object @{N='ResourceId';E={$sqlServerInstance.ResourceId}},
                                                                                @{N='ResourceGroupName';E={$sqlServerInstance.ResourceGroupName}},
                                                                                @{N='ServerName';E={$sqlServerInstance.ServerName}},
                                                                                @{N='ResourceType';E={$sqlServerInstance.ResourceType}},
                                                                                @{N='IsSynapseWorkspace';E={$sqlServerInstance.IsSynapseWorkspace}},
                                                                                @{N='IsAuditingEnabled';E={$isAuditingEnabled}},
                                                                                @{N='StorageAccountName';E={$storageAccountName}},
                                                                                @{N='IsAtpEnabled';E={$isAtpEnabled}},
                                                                                @{N='IsAnyAlertDisabled';E={$isAnyAlertDisabled}},
                                                                                @{N='DisabledAlerts';E={$disabledAlerts}},
                                                                                @{N='IsAnyEmailAddressConfigured';E={$isAnyEmailAddressConfigured}},
                                                                                @{N='NotificationRecipientsEmails';E={$notificationRecipientsEmails}},
                                                                                @{N='IsEmailAccountAdminsConfigured';E={$isEmailAccountAdminsConfigured}},
                                                                                @{N='IsAnyEmailAddressConfiguredAtSubscriptionLevel';E={$isAnyEmailAddressConfiguredAtSubscriptionLevel}},
                                                                                @{N='EmailAddressesConfiguredAtSubscriptionLevel';E={$emailAddressesConfiguredAtSubscriptionLevel}},
                                                                                @{N='IsEmailAccountAdminsConfiguredAtSubscriptionLevel';E={$isEmailAccountAdminsConfiguredAtSubscriptionLevel}},
                                                                                @{N="IsAtpEnabledAtSubscriptionLevel";E={$isAtpEnabledAtSubscriptionLevel}},
                                                                                @{N="IsAtpConfigured";E={$isAtpConfigured}}
                }
                else
                {
                    $skippedSqlServers += $sqlServerInstance | Select-Object @{N='ResourceId';E={$sqlServerInstance.ResourceId}},
                                                                             @{N='ResourceGroupName';E={$sqlServerInstance.ResourceGroupName}},
                                                                             @{N='ServerName';E={$sqlServerInstance.ServerName}},
                                                                             @{N='ResourceType';E={$sqlServerInstance.ResourceType}},
                                                                             @{N='IsSynapseWorkspace';E={$sqlServerInstance.IsSynapseWorkspace}},
                                                                             @{N='IsAuditingEnabled';E={$isAuditingEnabled}},
                                                                             @{N='StorageAccountName';E={$storageAccountName}},
                                                                             @{N='IsAtpEnabled';E={$isAtpEnabled}},
                                                                             @{N='IsAnyAlertDisabled';E={$isAnyAlertDisabled}},
                                                                             @{N='DisabledAlerts';E={$disabledAlerts}},
                                                                             @{N='IsAnyEmailAddressConfigured';E={$isAnyEmailAddressConfigured}},
                                                                             @{N='NotificationRecipientsEmails';E={$notificationRecipientsEmails}},
                                                                             @{N='IsEmailAccountAdminsConfigured';E={$isEmailAccountAdminsConfigured}},
                                                                             @{N='IsAnyEmailAddressConfiguredAtSubscriptionLevel';E={$isAnyEmailAddressConfiguredAtSubscriptionLevel}},
                                                                             @{N='EmailAddressesConfiguredAtSubscriptionLevel';E={$emailAddressesConfiguredAtSubscriptionLevel}},
                                                                             @{N='IsEmailAccountAdminsConfiguredAtSubscriptionLevel';E={$isEmailAccountAdminsConfiguredAtSubscriptionLevel}},
                                                                             @{N="IsAtpEnabledAtSubscriptionLevel";E={$isAtpEnabledAtSubscriptionLevel}},
                                                                             @{N="IsAtpConfigured";E={$isAtpConfigured}}
                }
            }
            catch
            {
                $skippedSqlServers += $sqlServerInstance
                Write-Host "Error enabling Auditing and Advanced Threat Protection on SQL Server. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this SQL Server. Auditing and Advanced Threat Protection will not be enabled." -ForegroundColor $([Constants]::MessageType.Warning)
                return
            }
        }

        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

        if ($($remediatedSqlServers | Measure-Object).Count -gt 0)
        {
            Write-Host "Auditing and Advanced Threat Protection successfully enabled for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $remediatedSqlServers | Format-Table -Property ResourceId, ResourceGroupName, ServerName, ResourceType, IsSynapseWorkspace, StorageAccountName

            # Write this to a file.
            $remediatedSqlServersFile = "$($backupFolderPath)\RemediatedSQLServers.csv"
            $remediatedSqlServers | Export-CSV -Path $remediatedSqlServersFile -NoTypeInformation
            Write-Host "This information has been saved to $($remediatedSqlServersFile)"
        }

        if ($($skippedSqlServers | Measure-Object).Count -gt 0)
        {
            Write-Host "Error enabling Advanced Threat Protection for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedSqlServers | Format-Table -Property ResourceId, ResourceGroupName, ServerName, ResourceType, IsSynapseWorkspace, IsAuditingEnabled, StorageAccountName, IsAtpConfigured

            # Write this to a file.
            $skippedSqlServersFile = "$($backupFolderPath)\SkippedSQLServers.csv"
            $skippedSqlServers | Export-CSV -Path $skippedSqlServersFile -NoTypeInformation
            Write-Host "This information has been saved to $($skippedSqlServersFile)"
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] SQL Server details have been backed up to $($backupFile). Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`nRun the same command with -FilePath $($backupFile) and without -DryRun, to enable Auditing and Advanced Threat Protection for all SQL Servers listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`n*** It is recommended to keep this file and use it for any subsequent roll back post the remediation. ***" -ForegroundColor $([Constants]::MessageType.Info)
    }
}

function Check-HasRolesInScope
{
    <#
        .SYNOPSIS
        Checks if a sign-in address has any of the specified roles at the given scope.

        .DESCRIPTION
        Checks if a sign-in address has any of the specified roles at the given scope.

        .PARAMETER AccountId
        Specifies the sign-in address, the roles associated with which are to be evaluated.

        .PARAMETER Scope
        Specifies the scope that needs to be evaluated against.

        .Parameter RoleDefinitionNames
        Specifies the list of roles that need to be evaluated against.

        .INPUTS
        None. You cannot pipe objects to Check-HasRolesInScope.

        .OUTPUTS
        System.Boolean. Check-HasRolesInScope returns True, if the sign-in address has any of the specified roles at the given scope. False, otherwise.

        .EXAMPLE
        PS> Check-HasRolesInScope -AccountId "abc@xyz.com" -Scope "/subscriptions/00000000-xxxx-0000-xxxx-000000000000" -RoleDefinitionNames "Contributor", "Owner", "User Access Administrator"

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the sign-in address, the roles associated with which are to be evaluated.")]
        $AccountId,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the scope that needs to be evaluated against.")]
        $Scope,

        [String[]]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the list of roles that need to be evaluated against.")]
        $RoleDefinitionNames
    )

    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $AccountId -Scope $Scope -ErrorAction Continue

    return (($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -in $RoleDefinitionNames } | Measure-Object).Count -gt 0)
}

function Create-StorageAccountIfNotExists
{
    <#
        .SYNOPSIS
        Check and create a Storage Account if it does not exist.

        .DESCRIPTION
        Check and create a Storage Account if it does not exist.

        .PARAMETER ResourceGroupName
        Specifies the name of the Resource Group where the Storage Account needs to be created.

        .PARAMETER StorageAccountName
        Specifies the name of the Storage Account to be created.

        .INPUTS
        None. You cannot pipe objects to Create-StorageAccountIfNotExists.

        .OUTPUTS
        Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount.
        Create-StorageAccountIfNotExists checks if a Storage Account is present and returns the same. If not, creates and returns the newly created Storage Account instance.

        .EXAMPLE
        PS> Create-StorageAccountIfNotExists -ResourceGroupName "RGName" -StorageAccountName "storageaccountname"

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the name of the Resource Group where the Storage Account needs to be created.")]
        $ResourceGroupName,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the name of the Storage Account that needs to be created.")]
        $Scope
    )

    Write-Host "Checking if Storage Account - $($StorageAccountName) is present in Resource Group - $($ResourceGroupName)..."

    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Continue

    if ([String]::IsNullOrWhiteSpace($storageAccount))
    {
        Write-Host "Storage Account does not exist. Creating a new Storage Account with the specified information..." -ForegroundColor $([Constants]::MessageType.Warning)
        $storageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -SkuName Standard_LRS -Location "East US" -ErrorAction Continue
    }

    return $storageAccount
}

function Disable-AdvancedThreatProtectionForSqlServers
{
    <#
        .SYNOPSIS
        Rolls back remediation done for Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server' Control.

        .DESCRIPTION
        Rolls back remediation done for Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server' Control.
        Disables Auditing and Advanced Threat Protection on the SQL Servers in the Subscription.

        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.

        .PARAMETER Force
        Specifies a forceful roll back without any prompts.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .EXAMPLE
        PS> Disable-AdvancedThreatProtectionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableThreatDetectionForSQLServers\SQLServersWithThreatDetectionDisabled.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

        [Switch]
        [Parameter(HelpMessage="Specifies a forceful roll back without any prompts")]
        $Force,

        [Switch]
        [Parameter(HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the path to the file to be used as input for the roll back")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 3] Preparing to disable Auditing and Advanced Threat Protection for SQL Servers in Subscription: $($SubscriptionId)"

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

    Write-Host "*** To disable Auditing and Advanced Threat Protection for SQL Server(s) in a Subscription, Contributor and higher privileges on the SQL Server(s) in the Subscription are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "*** If Advanced Threat Protection for SQL Servers was enabled at the Subscription level, or if contact details were configured in Azure Security Center using this script, Contributor and higher privileges on the Subscription are required for rolling back those changes. ***" -ForegroundColor $([Constants]::MessageType.Info)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all SQL Server details..."

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all SQL Servers details from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

    $sqlServerDetails = Import-Csv -LiteralPath $FilePath
    $validSqlServerDetails = $sqlServerDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ServerName)}
    $totalSqlServers = $($validSqlServerDetails.Count)

    if ($totalSqlServers -eq 0)
    {
        Write-Host "No SQL Server found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalSqlServers) SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableThreatDetectionForSQLServers"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "Auditing and Advanced Threat Protection will be disabled for SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host "*** Any Storage Accounts created to store the audit logs during the remediation, will not be deleted. ***" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host "It is recommended to examine and clean them up manually, if required." -ForegroundColor $([Constants]::MessageType.Warning)

    if (-not $Force)
    {
        Write-Host "Do you want to disable Auditing and Advanced Threat Protection for all SQL Servers?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Auditing and Advanced Threat Protection will not be disabled for SQL Servers. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Auditing and Advanced Threat Protection will be disabled for SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Disabling Auditing and Advanced Threat Protection for SQL Servers..." -ForegroundColor $([Constants]::MessageType.Warning)

    # We are relying on the state from the dry run output, i.e. before the remediation.
    # If any email addresses were configured or email notifications were enabled for Admins and Subscription Owners were enabled, these were done prior to the remediation.
    # Check is there are any Subscription level changes that are to be rolled back.
    $isAnyEmailAddressConfiguredAtSubscriptionLevel = $validSqlServerDetails[0].IsAnyEmailAddressConfiguredAtSubscriptionLevel
    $isEmailAccountAdminsConfiguredAtSubscriptionLevel = $validSqlServerDetails[0].IsEmailAccountAdminsConfiguredAtSubscriptionLevel

    if ($isAnyEmailAddressConfiguredAtSubscriptionLevel -or $isEmailAccountAdminsConfiguredAtSubscriptionLevel)
    {
        Write-Host "Contact details were already configured at the Subscription level. These were not configured during the remediation." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "These changes will not be rolled back." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        # Check if contact details were added during the remediation.
        # If contact details were added during the remediation, the current user's details would have been used.
        # This is assuming remediation and roll back are being done by the same user.

        # Get contact details from Azure Security Center.
        $ascContactDetails = Get-AzSecurityContact -Name "$($context.Account.Id)" -ErrorAction Continue

        if (-not [String]::IsNullOrWhiteSpace($ascContactDetails) -and $ascContactDetails.Count -gt 0)
        {
            # Current user was added as a contact during the remediation.
            # Reset contact details in Azure Security Center.
            $isContactRemoved = Remove-AzSecurityContact -Name "$($context.Account.Id)" -ErrorAction Continue

            if ($isContactRemoved)
            {
                Write-Host "Contact details of the current user successfully removed from Azure Security Center." -ForegroundColor $([Constants]::MessageType.Update)
            }
            else
            {
                Write-Host "*** Error removing contact details from Azure Security Center. Please remove them manually. ***" -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
        else
        {
            # No contact details were configured during the remediation.
            Write-Host "No contact details were configured during the remediation. Hence, there are no contact details configurations that are to be rolled back at the Subscription level." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }

    $isAtpEnabledAtSubscriptionLevel = $validSqlServerDetails.IsAtpEnabledAtSubscriptionLevel

    if ($isAtpEnabledAtSubscriptionLevel)
    {
        Write-Host "Advanced Threat Protection for SQL Servers was already configured at the Subscription level. These were not configured during the remediation." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "These changes will not be rolled back." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        # Check if Advanced Threat Protection for SQL Servers was enabled during the remediation.
        $sqlServerPricingDetails = Get-AzSecurityPricing -Name "SqlServers" -ErrorAction Continue

        if (-not [String]::IsNullOrWhiteSpace($sqlServerPricingDetails) -and $sqlServerPricingDetails.PricingTier -eq "Standard")
        {
            # Advanced Threat Protection for SQL Servers was enabled on the Subscription during the remediation.
            # Disable Advanced Threat Protection for SQL Servers on the Subscription.
            $sqlServerPricingDetails = Set-AzSecurityPricing -Name "SqlServers" -PricingTier "Free" -ErrorAction Continue

            if (-not [String]::IsNullOrWhiteSpace($sqlServerPricingDetails) -and $sqlServerPricingDetails.PricingTier -eq "Free")
            {
                Write-Host "Advanced Threat Protection for SQL Servers on the Subscription successfully disabled." -ForegroundColor $([Constants]::MessageType.Update)
            }
            else
            {
                Write-Host "*** Error disabling Advanced Threat Protection for SQL Servers on the Subscription. ***" -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
        else
        {
            # Advanced Threat Protection for SQL Servers was not enabled on the Subscription during the remediation.
            Write-Host "Advanced Threat Protection for SQL Servers was not enabled on the Subscription during the remediation. Hence, there is no rollback required at Subscription level." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }

    # Includes SQL Servers, to which, previously made changes were successfully rolled back.
    $rolledBackSqlServers = @()

    # Includes SQL Servers that were skipped during roll back. There were errors rolling back the changes made previously.
    $skippedSqlServers = @()

    # Flag to indicate if Advanced Threat Protection for SQL Servers at the Subscription level was disabled as a part of the roll back.
    $isAtpDisabledAtSubscriptionLevelNow = $false

    # Flag to indicate if contact details were removed as a part of the roll back.
    $isContactDetailsRemovedAtSubscriptionNow = $false

    # Roll back changes at SQL Server level.
    $validSqlServerDetails | ForEach-Object {
        try
        {
            $sqlServerInstance = $_
            $isAuditingDisabled = -not $sqlServerInstance.IsAuditingEnabled
            $isAtpConfigured = $sqlServerInstance.IsAtpConfigured

            Write-Host "Rolling back any changes made to SQL Server: Resource ID - $($sqlServerInstance.ResourceId)" -ForegroundColor $([Constants]::MessageType.Info)

            # The dry run output from prior to the remediation is used as a reference for rollback.
            # If Auditing is disabled in that output, it means, it was enabled during the remediation and this needs to be rolled back now.
            if (-not $isAuditingDisabled)
            {
                # Check if the SQL Server is a stand-alone SQL Server or is associated with a Synapse Workspace.
                if ($sqlServerInstance.IsSynapseWorkspace -eq "False")
                {
                    # SQL Server is a stand-alone SQL Server.
                    # Any exceptions when disabling Auditing on the SQL Server will be caught and the SQL Server will be considered as skipped for roll back.
                    Remove-AzSqlServerAudit -ResourceGroupName $sqlServerInstance.ResourceGroupName -ServerName $sqlServerInstance.ServerName -ErrorAction Continue
                    $isAuditingDisabled = $true
                }
                else
                {
                    # SQL Server is associated with a Synapse Workspace.
                    # Synapse Workspace and the associated SQL Server have the same name.
                    # Any exceptions when disabling Auditing on the SQL Server will be caught and the SQL Server will be considered as skipped for roll back.
                    Remove-AzSqlServerAudit -ResourceGroupName $sqlServerInstance.ResourceGroupName -ServerName $sqlServerInstance.ServerName -ErrorAction Continue
                    $isAuditingDisabled = $true
                }
            }

            if (-not $isAtpConfigured)
            {
                # If Advanced Threat Protection was not previously enabled, it will now be disabled.
                if (-not $sqlServerInstance.IsAtpEnabled)
                {
                    # Check if the SQL Server is a stand-alone SQL Server or is associated with a Synapse Workspace.
                    if ($sqlServerInstance.IsSynapseWorkspace -eq "False")
                    {
                        # SQL Server is a stand-alone SQL Server.
                        # Any exceptions when disabling Advanced Threat Protection on the SQL Server will be caught and the SQL Server will be considered as skipped for roll back.
                        Clear-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -ServerName $sqlServerInstance.ServerName
                    }
                    else
                    {
                        # SQL Server is associated with a Synapse Workspace.
                        # Synapse Workspace and the associated SQL Server have the same name.
                        # Any exceptions when disabling Advanced Threat Protection on the SQL Server will be caught and the SQL Server will be considered as skipped for roll back.
                        Reset-AzSynapseSqlAdvancedThreatProtectionSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -WorkspaceName $sqlServerInstance.ServerName
                    }
                }
                else
                {
                    # If Advanced Threat Protection was already enabled, but, changes were made to not exclude any alerts and/or email recipients were added, only those changes will be rolled back.
                    # Advanced Threat Protection will continue to be enabled.
                    $disabledAlerts = $sqlServerInstance.DisabledAlerts
                    $notificationRecipientsEmails = $sqlServerInstance.NotificationRecipientsEmails
                    $isEmailAccountAdminsConfigured = $sqlServerInstance.IsEmailAccountAdminsConfigured

                    $emailAdmins = $true

                    # If no email recipients were configured previously, they would have now been added.
                    # Also, the option to send email notifications to Admins and Subscription Owners would have been enabled.
                    # Both of these need to be rolled back.
                    if ([String]::IsNullOrWhiteSpace($notificationRecipientsEmails))
                    {
                        $emailAdmins = $false
                    }

                    if (-not [String]::IsNullOrWhiteSpace($disabledAlerts) -or [String]::IsNullOrWhiteSpace($notificationRecipientsEmails))
                    {
                        # Check if the SQL Server is a stand-alone SQL Server or is associated with a Synapse Workspace.
                        if ($sqlServerInstance.IsSynapseWorkspace -eq "False")
                        {
                            # SQL Server is a stand-alone SQL Server.
                            # Any exceptions when disabling Advanced Threat Protection on the SQL Server will be caught and the SQL Server will be considered as skipped for roll back.
                            $sqlServerAuditDetails = Update-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -ServerName $sqlServerInstance.ServerName -ExcludedDetectionType $disabledAlerts -NotificationRecipientsEmail "$($notificationRecipientsEmails)" -EmailAdmin $emailAdmins
                            $isAtpConfigured = $false
                        }
                        else
                        {
                            # SQL Server is associated with a Synapse Workspace.
                            # Synapse Workspace and the associated SQL Server have the same name.
                            # Any exceptions when disabling Advanced Threat Protection on the SQL Server will be caught and the SQL Server will be considered as skipped for roll back.
                            $sqlServerAuditDetails = Update-AzSynapseSqlAdvancedThreatProtectionSetting -ResourceGroupName $sqlServerInstance.ResourceGroupName -WorkspaceName $sqlServerInstance.ServerName -ExcludedDetectionType $disabledAlerts -NotificationRecipientsEmail "$($notificationRecipientsEmails)" -EmailAdmin $emailAdmins
                            $isAtpConfigured = $false
                        }
                    }
                }
            }

            if ($isAuditingDisabled -or -not $isAtpConfigured)
            {
                 $rolledBackSqlServers += $sqlServerInstance | Select-Object @{N='ResourceId';E={$sqlServerInstance.ResourceId}},
                                                                             @{N='ResourceGroupName';E={$sqlServerInstance.ResourceGroupName}},
                                                                             @{N='ServerName';E={$sqlServerInstance.ServerName}},
                                                                             @{N='ResourceType';E={$sqlServerInstance.ResourceType}},
                                                                             @{N='IsSynapseWorkspace';E={$sqlServerInstance.IsSynapseWorkspace}},
                                                                             @{N='IsAuditingEnabled';E={$isAuditingEnabled}},
                                                                             @{N='IsAtpConfigured';E={$isAtpConfigured}}
            }
            else
            {
                $skippedSqlServers += $sqlServerInstance | Select-Object @{N='ResourceId';E={$sqlServerInstance.ResourceId}},
                                                                         @{N='ResourceGroupName';E={$sqlServerInstance.ResourceGroupName}},
                                                                         @{N='ServerName';E={$sqlServerInstance.ServerName}},
                                                                         @{N='ResourceType';E={$sqlServerInstance.ResourceType}},
                                                                         @{N='IsSynapseWorkspace';E={$sqlServerInstance.IsSynapseWorkspace}},
                                                                         @{N='IsAuditingEnabled';E={$isAuditingEnabled}},
                                                                         @{N='IsAtpConfigured';E={$isAtpConfigured}}
            }
        }
        catch
        {
            $skippedSqlServers += $sqlServerInstance | Select-Object @{N='ResourceId';E={$sqlServerInstance.ResourceId}},
                                                                     @{N='ResourceGroupName';E={$sqlServerInstance.ResourceGroupName}},
                                                                     @{N='ServerName';E={$sqlServerInstance.ServerName}},
                                                                     @{N='ResourceType';E={$sqlServerInstance.ResourceType}},
                                                                     @{N='IsSynapseWorkspace';E={$sqlServerInstance.IsSynapseWorkspace}},
                                                                     @{N='IsAuditingEnabled';E={$isAuditingEnabled}},
                                                                     @{N='IsAtpConfigured';E={$isAtpConfigured}}

            Write-Host "Error rolling back Auditing and Advanced Threat Protection on the SQL Server. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this SQL Server. The resource is either partially rolled back or not rolled back at all." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host "It is recommended to manually roll back these changes." -ForegroundColor $([Constants]::MessageType.Info)
            return
        }
    }

    Write-Host $([Constants]::SingleDashLine)

    Write-Host "RollBack Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

    if ($($rolledBackSqlServers | Measure-Object).Count -gt 0)
    {
        Write-Host "Auditing and Advanced Threat Protection successfully disabled for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Update)
        $rolledBackSqlServers | Format-Table -Property ResourceId, ResourceGroupName, ServerName, ResourceType, IsSynapseWorkspace, IsAuditingEnabled, IsAtpConfigured

        # Write this to a file.
        $rolledBackSqlServersFile = "$($backupFolderPath)\RolledBackSQLServers.csv"
        $rolledBackSqlServers | Export-CSV -Path $rolledBackSqlServersFile -NoTypeInformation
        Write-Host "This information has been saved to $($rolledBackSqlServersFile)"
    }

    if ($($skippedSqlServers | Measure-Object).Count -gt 0)
    {
        Write-Host "Error disabling Auditing and Advanced Threat Protection for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $skippedSqlServers |  Format-Table -Property ResourceId, ResourceGroupName, ServerName, ResourceType, IsSynapseWorkspace, IsAuditingEnabled, IsAtpConfigured

        # Write this to a file.
        $skippedSqlServersFile = "$($backupFolderPath)\SkippedSQLServers.csv"
        $skippedSqlServers | Export-CSV -Path $skippedSqlServersFile -NoTypeInformation
        Write-Host "This information has been saved to $($skippedSqlServersFile)"
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

