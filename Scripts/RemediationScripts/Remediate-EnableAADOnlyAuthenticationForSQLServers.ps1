<###
# Overview:
    This script is used to Enable Azure AD Only Authentication for the SQL Servers in a Subscription.

# Control ID:
    Azure_SQLDatabase_AuthZ_Use_AAD_Only

# Display Name:
    Use AAD Only Authentication for SQL Server

# Prerequisites:
    Contributor and higher privileges on the SQL Servers in a Subscription.

# NOTE: Please run the script using -DryRun Switch and provide the output file of -DryRun switch as input for actual remediation.
    
# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script and validate the user.
        2. Get the list of SQL Servers in a Subscription that do not have Azure AD Only Authentication enabled.
        3. Back up details of SQL Servers that are going to be remediated.
        4. Enable Azure AD Only Authentication on the SQL Servers in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Servers in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable Azure AD Only Authentication on the SQL Servers in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable Azure AD Only Authentication on the SQL Servers in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable Azure AD Only Authentication on the SQL Servers in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the SQL Server details in a Subscription that will be remediated:

           Enable-AADOnlyAuthenticationForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        2. To review the SQL Server details in a Subscription that will be remediated with pre-requisites check:

           Enable-AADOnlyAuthenticationForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun -PerformPreReqCheck

        3. To enable Azure AD Only Authentication on the SQL Servers in a Subscription, from a previously taken snapshot:

           Enable-AADOnlyAuthenticationForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForSQLServers\SQLServersWithADAdminDisabled.csv

        To know more about the options supported by the remediation command, execute:

        Get-Help Enable-AADOnlyAuthenticationForSqlServers -Detailed

    To roll back:
        1. To disable Azure AD Only Authentication on the SQL Servers in a Subscription, from a previously taken snapshot:

           Disable-AADOnlyAuthenticationForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForSQLServers\RemediatedSQLServers.csv

        To know more about the options supported by the roll back command, execute:

        Get-Help Disable-AADOnlyAuthenticationForSqlServers -Detailed
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

    Write-Host "Required modules: $($requiredModules -join ', ')", "Az.Sql", "Az.Synapse" -ForegroundColor $([Constants]::MessageType.Info)
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

    # Checking if 'Az.Sql' module >=2.10.0 is available and installing otherwise.
    Write-Host "Checking if Az.Sql>=2.10.0 is present..."

    $azSql = Get-InstalledModule -Name "Az.Sql" -MinimumVersion 2.10.0 -ErrorAction SilentlyContinue
    if(($azSql|Measure-Object).Count -eq 0)
    {
        Write-Host "Installing module Az.Sql with version 2.10.0..." -ForegroundColor $([Constants]::MessageType.Warning)
        Install-Module -Name Az.Sql -Scope CurrentUser -Repository 'PSGallery' -MinimumVersion 2.10.0 -Force
    }
    else
    {
        Write-Host "Az.Sql module of required version is available." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Checking if 'Az.Synapse' module >=1.5.0 is available and installing otherwisee.
    Write-Host "Checking if Az.Synapse>=1.5.0 is present..."

    $azSynapse = Get-InstalledModule -Name "Az.Synapse" -MinimumVersion 1.5.0 -ErrorAction SilentlyContinue
    if(($azSynapse|Measure-Object).Count -eq 0)
    {
        Write-Host "Installing module Az.Synapse with version 1.5.0..." -ForegroundColor $([Constants]::MessageType.Warning)
        Install-Module -Name Az.Synapse -Scope CurrentUser -Repository 'PSGallery' -MinimumVersion 1.5.0 -Force
    }
    else
    {
        Write-Host "Az.Synapse module of required version is available." -ForegroundColor $([Constants]::MessageType.Update)
    }
}

function Enable-AADOnlyAuthenticationForSqlServers
{
    <#
        .SYNOPSIS
        Remediates 'Azure_SQLDatabase_AuthZ_Use_AAD_Only' Control.

        .DESCRIPTION
        Remediates 'Azure_SQLDatabase_AuthZ_Use_AAD_Only' Control.
        Azure AD Only Authentication must be enabled.

        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .EXAMPLE
        PS> Enable-AADOnlyAuthenticationForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-AADOnlyAuthenticationForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        .EXAMPLE
        PS> Enable-AADOnlyAuthenticationForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForSQLServers\SQLServersWithADAdminDisabled.csv

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
    
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 4] Validating and install the modules required to run the script and validating the user..."
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
        Write-Host "[Step 1 of 4] validating the user..."
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..."

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of $($context.Account.Id) is: $($context.Account.Type)" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run this script..." -ForegroundColor $([Constants]::MessageType.Update)
    }

    Write-Host "*** To enable Azure AD Only Authentication for SQL Server(s) in a Subscription, Contributor and higher privileges on the SQL Server(s) in the Subscription are required. ***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all SQL Server(s)..."

    $sqlServerResources = @()

    # No file path provided as input to the script. Fetch all SQL Servers in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
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
             $standaloneSqlServers = Compare-Object -ReferenceObject $sqlServers -DifferenceObject $synapseWorkspaces -Property { $_.Name } -PassThru
         }

         $sqlServerResources += $standaloneSqlServers | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                      @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                      @{N='ServerName';E={$_.Name}},
                                                                      @{N='ResourceType';E={$_.ResourceType}},
                                                                      @{N='IsSynapseWorkspace';E={$false}},
                                                                      @{N='IsAADAdminPreviouslyConfigured';E={$false}},
                                                                      @{N='EmailId';E={""}}
                                                                       
         # Add Synapse Workspaces to this list.
         $sqlServerResources += $synapseWorkspaces | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                   @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                   @{N='ServerName';E={$_.Name}},
                                                                   @{N='ResourceType';E={$_.ResourceType}},
                                                                   @{N='IsSynapseWorkspace';E={$true}},
                                                                   @{N='IsAADAdminPreviouslyConfigured';E={$false}},
                                                                   @{N='EmailId';E={""}}
    }  
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all SQL Server(s) from:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "$($FilePath)" 

        # Importing the list of SQL servers to be remediated.
        $sqlServersDetails = Import-Csv -LiteralPath $FilePath

        $sqlServerResources = $sqlServersDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
    }

    $totalSqlServers = ($sqlServerResources|Measure-Object).Count

    if ($totalSqlServers -eq 0)
    {
        Write-Host "No SQL Servers found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalSqlServers) SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)

    # Includes SQL Servers where Azure AD Only Authentication is enabled.
    $sqlServersWithAADOnlyAuthEnabled = @()

    # Includes SQL Servers where Azure AD Only Authentication is disabled.
    $sqlServersWithAADOnlyAuthDisabled = @()

    # Includes SQL Servers Skipped
    $sqlServersWithAADOnlyAuthEvaluationSkipped = @()
    Write-Host "Checking if Azure AD Only Authentication is enabled on SQL Server(s)..."

    $sqlServerResources | ForEach-Object {
        try
        {
            $sqlServerInstance = $_

            if($_.IsSynapseWorkspace -eq $true)
            {
                $adAdmin = Get-AzSynapseSqlActiveDirectoryAdministrator -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName -ErrorAction Ignore
            }
            else
            {
                $adAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName
            }
             
            # Check if Azure AD Only Authentication are enabled on the SQL Server.
            if (($adAdmin|Measure-Object).Count -ne 0)
            {
                $sqlServerInstance.IsAADAdminPreviouslyConfigured = $true
                $sqlServerInstance.EmailId = "NA(as AAD Admin is already configured)"
                if ($adAdmin.IsAzureADOnlyAuthentication -eq $true)
                {
                    $sqlServersWithAADOnlyAuthEnabled += $sqlServerInstance
                }
                else
                {
                    $sqlServersWithAADOnlyAuthDisabled += $sqlServerInstance
                }
            }
            else
            {
                $sqlServersWithAADOnlyAuthDisabled += $sqlServerInstance                                                 
            }
        }
        catch
        {
            $sqlServersWithAADOnlyAuthEvaluationSkipped += $sqlServerInstance 
        }
    }

    $colsProperty3 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"}

    if (($sqlServersWithAADOnlyAuthEvaluationSkipped | Measure-Object).Count -ne 0)
    {
        Write-Host "`nError checking if AAD Only Authenticaton is enabled for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $sqlServersWithAADOnlyAuthEvaluationSkipped | Format-Table -Property $colsProperty3 -Wrap
    }

    $totalSQLServersWithAADOnlyAuthDisabled = ($sqlServersWithAADOnlyAuthDisabled | Measure-Object).Count

    if ($totalSQLServersWithAADOnlyAuthDisabled -eq 0)
    {
        Write-Host "`nNo SQL Server found with Azure AD Only Authentication disabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "`nFound $($totalSQLServersWithAADOnlyAuthDisabled) SQL Server(s) with Azure AD Only Authentication disabled." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableAADOnlyAuthForSQLServers"
   
    $sqlServersWithAADOnlyAuthDisabled | Format-Table -Property $colsProperty3 -Wrap
    
    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    # Backing up SQL Server details.
    $backupFile = "$($backupFolderPath)\SqlServersWithAADOnlyAuthDisabled.csv"
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up SQL Server details..."
   
    $sqlServersWithAADOnlyAuthDisabled | Export-CSV -Path $backupFile -NoTypeInformation -ErrorAction Stop
    Write-Host "SQL Server(s) details have been backed up to:" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "$($backupFile)"
    Write-Host $([Constants]::DoubleDashLine)

    if (-not $DryRun)
    {
        Write-Host "[Step 4 of 4] Enabling Azure AD Only Authentication for SQL Server(s)..." 
        Write-Host "Do you want to enable AAD Only Authentication for SQL Server(s)?`n" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y")
        {
            Write-Host "Azure AD Only Authentication will not be enabled for any SQL Server. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }

        # To hold results from the remediation.
        $remediatedSqlServers = @()

        # Includes SQL Servers that were skipped during remediation. There were errors remediating them.
        $skippedSqlServers = @()
       
        Write-Host "Enabling Azure AD Only Authentication for SQL Server(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        $sqlServersWithAADOnlyAuthDisabled  | ForEach-Object {
            $sqlServerInstance = $_
            try
            {
                # To enable AAD Only, AAD Admin should be set. We are first checking if it is previously set on the resource and proceeding for AAD Only.
                if($_.IsAADAdminPreviouslyConfigured -eq $true)
                {
                    if($_.IsSynapseWorkspace -eq $true)
                    {
                        $aadOnlyAuth = Enable-AzSynapseActiveDirectoryOnlyAuthentication -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName
                    }
                    else
                    {
                        $aadOnlyAuth = Enable-AzSqlServerActiveDirectoryOnlyAuthentication -ServerName $_.ServerName -ResourceGroupName $_.ResourceGroupName
                    }

                    if (($aadOnlyAuth|Measure-Object).Count -ne 0)
                    {
                        $remediatedSqlServers += $sqlServerInstance 
                    }
                    else
                    {
                        $skippedSqlServers += $sqlServerInstance                   
                    }
                }
                # If AAD Admin has not been previously set, we are setting it based on the EmailId input from the user and then enabling AAD Only.
                else
                {
                    if(![String]::IsNullOrWhiteSpace($_.EmailId))
                    {
                        if($_.IsSynapseWorkspace -eq $true)
                        {
                            $adAdmin = Set-AzSynapseSqlActiveDirectoryAdministrator -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName -DisplayName $_.EmailId

                            if (($adAdmin|Measure-Object).Count -ne 0)
                            {
                                $aadOnlyAuth = Enable-AzSynapseActiveDirectoryOnlyAuthentication -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName
                            }
                        }
                        else
                        {
                            $adAdmin = Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -DisplayName $_.EmailId
                            if (($adAdmin|Measure-Object).Count -ne 0)
                            {
                                $aadOnlyAuth = Enable-AzSqlServerActiveDirectoryOnlyAuthentication -ServerName $_.ServerName -ResourceGroupName $_.ResourceGroupName
                            }
                        }

                        if (($aadOnlyAuth|Measure-Object).Count -ne 0)
                        {
                            $remediatedSqlServers += $sqlServerInstance 
                        }
                        else
                        {
                            $skippedSqlServers += $sqlServerInstance                   
                        }
                    }
                    else
                    {
                       $skippedSqlServers += $sqlServerInstance   
                    } 
                }
            } 
            catch
            {
                $skippedSqlServers += $sqlServerInstance
            }
        }

        $colsProperty1 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.ResourceType};Label="Resource Type";Width=30;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"},
                         @{Expression={$_.EmailId};Label="Email Id";Width=35;Alignment="left"}

        $colsProperty2 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.ResourceType};Label="Resource Type";Width=30;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"}
               
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

        if ($($remediatedSqlServers | Measure-Object).Count -gt 0)
        {
            Write-Host "Azure AD Only Authentication successfully enabled for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $remediatedSqlServers | Format-Table -Property $colsProperty1 -Wrap

            # Write this to a file.
            $remediatedSqlServersFile = "$($backupFolderPath)\RemediatedSQLServers.csv"
            $remediatedSqlServers | Export-CSV -Path $remediatedSqlServersFile -NoTypeInformation
            Write-Host "This information has been saved to $($remediatedSqlServersFile)"
            Write-Host "Use this file only for rollback.`n" -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($skippedSqlServers | Measure-Object).Count -gt 0)
        {
            Write-Host "Error enabling AAD Only Authenticaton for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedSqlServers | Format-Table -Property $colsProperty2 -Wrap

            # Write this to a file.
            $skippedSqlServersFile = "$($backupFolderPath)\SkippedSQLServers.csv"
            $skippedSqlServers | Export-CSV -Path $skippedSqlServersFile -NoTypeInformation
            Write-Host "This information has been saved to $($skippedSqlServersFile)"
        }
        Write-Host $([Constants]::DoubleDashLine)

    }
    else
    {
        Write-Host "[Step 4 of 4] Enabling Azure AD Only Authentication for SQL Servers..."
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Please provide corresponding AD Administrator Email Id for SQL Servers (in the blank cells) 'EmailId' column of the below file:"  -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "$($backupFile)"
        Write-Host "`nNext steps:"  -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun switch, to enable Azure AD Only Authentication for all SQL Servers listed in the file."
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Disable-AADOnlyAuthenticationForSqlServers
{
    <#
        .SYNOPSIS
        Rolls back remediation done for Azure_SQLDatabase_AuthZ_Use_AAD_Only' Control.

        .DESCRIPTION
        Rolls back remediation done for Azure_SQLDatabase_AuthZ_Use_AAD_Only' Control.
        Disables Azure AD Only Authentication on the SQL Servers in the Subscription.

        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.

        .PARAMETER Force
        Specifies a forceful roll back without any prompts.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .EXAMPLE
        PS> Disable-AADOnlyAuthenticationForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForSQLServers\SQLServersWithADAdminDisabled.csv

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

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 3] Validating and install the modules required to run the script and validating the user..."
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
        Write-Host "[Step 1 of 3] Validating the user..."
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host $([Constants]::SingleDashLine)  
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..."

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of $($context.Account.Id) is: $($context.Account.Type)" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run this script."  -ForegroundColor $([Constants]::MessageType.Update)
    }

    Write-Host "*** To disable Azure AD Only Authentication for SQL Server(s) in a Subscription, Contributor and higher privileges on the SQL Server(s) in the Subscription are required. ***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all SQL Server details..."

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all SQL Server(s) details from:" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "$($FilePath)"

    $sqlServerDetails = Import-Csv -LiteralPath $FilePath
    $validSqlServerDetails = $sqlServerDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ServerName)}
    $totalSqlServers = $(($validSqlServerDetails|measure-object).Count)

    if ($totalSqlServers -eq 0)
    {
        Write-Host "No SQL Server found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalSqlServers) SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableADAdminForSQLServers"

    $colsProperty3 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"}

   
    $validSqlServerDetails | Format-Table -Property $colsProperty3 -Wrap

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Disabling Azure AD Only Authentication for SQL Server(s)..." 
   
    if (-not $Force)
    {
        Write-Host "Do you want to disable Azure AD Only Authentication for all SQL Server(s)?`n" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Azure AD Only Authentication will not be disabled for SQL Server(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Azure AD Only Authentication will be disabled for SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    # Includes SQL Servers, to which, previously made changes were successfully rolled back.
    $rolledBackSqlServers = @()

    Write-Host "Disabling Azure AD Only Authentication for SQL Server(s)..." -ForegroundColor $([Constants]::MessageType.Info)

    # Includes SQL Servers that were skipped during roll back. There were errors rolling back the changes made previously.
    $skippedSqlServers = @()
    $validSqlServerDetails | ForEach-Object {
        $sqlServerInstance = $_
        try
        {
            # Disabling AAD Only.
            if($_.IsSynapseWorkspace -eq $true)
            {
                $aadOnlyAuth = Disable-AzSynapseActiveDirectoryOnlyAuthentication -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName

                # On success of disabling AAD Only, we also remove admin set by the Enable script in case it was not previously configured.
                # Order is important, first AAD Only should be disabled and then AAD Admin should be removed if applicable.
                if(($aadOnlyAuth|Measure-Object).Count -ne 0 -and $_.IsAADAdminPreviouslyConfigured -eq $false)
                {
                    $adAdmin = Remove-AzSynapseSqlActiveDirectoryAdministrator -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName
                }

                if($_.IsAADAdminPreviouslyConfigured -eq $false)
                {
                    # $adAdmin does not return any object on success so not checking the object count, but in case of any error the control will move into catch block and this code is not executed.
                    $rolledBackSqlServers += $sqlServerInstance 
                }
                else
                {
                    if (($aadOnlyAuth|Measure-Object).Count -ne 0)
                    {
                        $rolledBackSqlServers += $sqlServerInstance 
                    }
                    else
                    {
                        $skippedSqlServers += $sqlServerInstance                   
                    }
                }
            }
            else
            {
                $aadOnlyAuth = Disable-AzSqlServerActiveDirectoryOnlyAuthentication -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName

                # On success of disabling AAD Only, we also remove admin set by the Enable script in case it was not previously configured.
                # Order is important, first AAD Only should be disabled and then AAD Admin should be removed if applicable.
                if(($aadOnlyAuth|Measure-Object).Count -ne 0 -and $_.IsAADAdminPreviouslyConfigured -eq $false)
                {
                    $adAdmin =  Remove-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName
                }

                if($_.IsAADAdminPreviouslyConfigured -eq $false)
                {
                    if (($adAdmin|Measure-Object).Count -ne 0)
                    {
                        $rolledBackSqlServers += $sqlServerInstance 
                    }
                    else
                    {
                        $skippedSqlServers += $sqlServerInstance                   
                    }
                }
                else
                {
                    if (($aadOnlyAuth|Measure-Object).Count -ne 0)
                    {
                        $rolledBackSqlServers += $sqlServerInstance 
                    }
                    else
                    {
                        $skippedSqlServers += $sqlServerInstance                   
                    }
                }
            }
        }
        catch
        {
            $skippedSqlServers += $sqlServerInstance 
        }
    }

    $colsProperty1 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.ResourceType};Label="Resource Type";Width=30;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"},
                         @{Expression={$_.EmailId};Label="Email Id";Width=35;Alignment="left"}

    $colsProperty2 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.ResourceType};Label="Resource Type";Width=30;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"}

    Write-Host $([Constants]::SingleDashLine)

    Write-Host "RollBack Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

    if ($($rolledBackSqlServers | Measure-Object).Count -gt 0)
    {
        Write-Host "Azure AD Only Authentication successfully disabled for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Update)
        $rolledBackSqlServers | Format-Table -Property $colsProperty2 -Wrap

        # Write this to a file.
        $rolledBackSqlServersFile = "$($backupFolderPath)\RolledBackSQLServers.csv"
        $rolledBackSqlServers | Export-CSV -Path $rolledBackSqlServersFile -NoTypeInformation
        Write-Host "This information has been saved to $($rolledBackSqlServersFile)"
    }

    if ($($skippedSqlServers | Measure-Object).Count -gt 0)
    {
        Write-Host "Error disabling Azure AD Only Authentication for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $skippedSqlServers |  Format-Table -Property $colsProperty1 -Wrap

        # Write this to a file.
        $skippedSqlServersFile = "$($backupFolderPath)\SkippedSQLServers.csv"
        $skippedSqlServers | Export-CSV -Path $skippedSqlServersFile -NoTypeInformation
        Write-Host "This information has been saved to $($skippedSqlServersFile)"
    }
    Write-Host $([Constants]::DoubleDashLine)
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

