<###
# Overview:
    This script is used to enable Transparent Data Encryption (TDE) for SQL Servers in a Subscription.

# Control ID:
    Azure_SQLDatabase_DP_Enable_TDE

# Display Name:
    Transparent data encryption (TDE) must be enabled.

# Prerequisites:
    Contributor and higher privileges on the SQL Servers in a Subscription.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Servers in a Subscription that do not have Transparent Data Encryption (TDE) enabled.
        3. Back up details of SQL Servers that are going to be remediated.
        4. Enable Transparent Data Encryption (TDE) on the SQL Servers in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Servers in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable Transparent Data Encryption (TDE) on the SQL Servers in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable Transparent Data Encryption (TDE) on the SQL Servers in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable Transparent Data Encryption (TDE) on the SQL Servers in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the SQL Servers details in a Subscription that will be remediated:
    
           Enable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        2. To enable Transparent Data Encryption (TDE) on the SQL Servers in a Subscription:
       
           Enable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000

        3. To enable Transparent Data Encryption (TDE) on the SQL Servers in a Subscription, from a previously taken snapshot:
       
           Enable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSqlServers\SqlServersWithTDEDisabled.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-TransparentDataEncryptionForSqlServers -Detailed

    To roll back:
        1. To disable Transparent Data Encryption (TDE) on the SQL Servers in a Subscription, from a previously taken snapshot:

           Disable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSqlServers\SqlServersWithTDEDisabled.csv
        
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Disable-TransparentDataEncryptionForSqlServers -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.Sql", "Az.Synapse")

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

function Enable-TransparentDataEncryptionForSqlServers
{
    <#
        .SYNOPSIS
        Remediates 'Azure_SQLDatabase_DP_Enable_TDE' Control.

        .DESCRIPTION
        Remediates 'Azure_SQLDatabase_DP_Enable_TDE' Control.
        Transparent data encryption (TDE) must be enabled. 
        
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

        .EXAMPLE
        PS> Enable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSqlServers\SqlServersWithTDEDisabled.csv

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
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Preparing to enable Transparent data encryption (TDE) for SQL Server database(s) in Subscription: $($SubscriptionId)"

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

    Write-Host "*** To enable Transparent data encryption (TDE) for SQL Server database(s) in a Subscription, Contributor and higher privileges on the SQL Servers are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all SQL Servers..."

    $sqlServersResources = @()
    $databaseList = @()

    # No file path provided as input to the script. Fetch all SQL Servers in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all SQL Servers in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        $sqlServerResources = @()

        # Get all SQL Servers in a Subscription
        $sqlServers = Get-AzResource -ResourceType "Microsoft.Sql/servers" -ErrorAction Stop

        # Get all Synapse Workspaces in a Subscription
        $synapseWorkspaces = Get-AzResource -ResourceType "Microsoft.Synapse/workspaces" -ErrorAction Stop

        # Filter SQL Servers not associated with a Synapse Workspace.
        # Synapse Workspace and the associated SQL Server have the same name.
        # Synapse Workspace names are unique.
        $standaloneSqlServers = Compare-Object -ReferenceObject $sqlServers -DifferenceObject $synapseWorkspaces -Property { $_.ResourceName } -PassThru

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

        $totalSqlServers = ($sqlServerResources | Measure-Object).Count

        if ($totalSqlServers -eq 0)
        {
            Write-Host "No SQL Server found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
    
        Write-Host "Found $($totalSqlServers) SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "NOTE: Each SQL Server may have multiple databases."
        Write-Host "Fetching SQL databases..."

        # Includes SQL Servers where Transparent Data Encryption (TDE) is disabled.
        $sqlServersWithTdeDisabled = @()

        $sqlServerResources | ForEach-Object{
            $sqlDatabasesWithTdeEnabled = @()
            $sqlDatabasesWithTdeDisabled = @()
            $sqlDatabaseList = @()
            try
            {
                if (-not $_.IsSynapseWorkspace)
                {
                    $databaseList = Get-AzSqlDatabase -ServerName $_.ServerName -ResourceGroupName $_.ResourceGroupName
                    $databaseList | ForEach-Object{
                        if ($_.DatabaseName -ne 'master')
                        {
                            $databaseConfigDetails = Get-AzSqlDatabaseTransparentDataEncryption -ServerName $_.ServerName -DatabaseName $_.DatabaseName -ResourceGroupName $_.ResourceGroupName
                            if (-not [String]::IsNullOrWhiteSpace($databaseConfigDetails))
                            {
                                if ($databaseConfigDetails.State -eq "Enabled")
                                {
                                    $sqlDatabasesWithTdeEnabled += $_.DatabaseName
                                }
                                else
                                {
                                    $sqlDatabasesWithTdeDisabled += $_.DatabaseName
                                }
                            }
                            else
                            {
                                Write-Host "Error occurred while getting database details for SQL Server: Resource Group Name - $($_.ResourceGroupName), Server Name - $($_.ServerName), Database Name - $($_.DatabaseName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                                Write-Host "Skipping this SQL Server database. Transparent Data Encryption (TDE) will not be enabled for this database."
                            }
                        }
                    }
                }
                else
                {   
                    $databaseList = Get-AzSynapseSqlPool -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName
                    $databaseList | ForEach-Object{  
                        $databaseConfigDetails = Get-AzSynapseSqlPoolTransparentDataEncryption -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.WorkspaceName -Name $_.SqlPoolName
                        if ($databaseConfigDetails.State -eq "Enabled")
                        {
                            $sqlDatabasesWithTdeEnabled += $_.SqlPoolName
                        }
                        else
                        {
                            $sqlDatabasesWithTdeDisabled += $_.SqlPoolName
                        }
                    }
                }

                if (($sqlDatabasesWithTdeDisabled | Measure-Object).Count -ne 0)
                {
                    $sqlServersWithTdeDisabled += $_ | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                @{N='ServerName';E={$_.ServerName}},
                                                                @{N='ResourceType';E={$_.ResourceType}},
                                                                @{N='IsSynapseWorkspace';E={$_.IsSynapseWorkspace}},
                                                                @{N='DatabasesWithTDEDisabled';E={$sqlDatabasesWithTdeDisabled -join ', '}},
                                                                @{N='DatabasesWithTDEEnabled';E={$sqlDatabasesWithTdeEnabled -join ', '}}
                }
            }
            catch
            {
                Write-Host "Error occurred while getting SQL Server details: Resource Group Name - $($_.ResourceGroupName), Server Name - $($_.ServerName), Database Name - $($sqlDatabaseList). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this SQL Server database. Transparent Data Encryption (TDE) will not be enabled for this database."
            }
        }
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all SQL databases from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

        $sqlServersWithTdeDisabled = Import-Csv -LiteralPath $FilePath
    }

    $totalSqlServersWithTdeDisabled = ($sqlServersWithTdeDisabled | Measure-Object).Count
    if ($totalSqlServersWithTdeDisabled -eq 0)
    {
        Write-Host "No SQL Server found with Transparent Data Encryption (TDE) disabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalSqlServersWithTdeDisabled) SQL Server(s) with Transparent Data Encryption (TDE) disabled." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableTDEForSqlServers"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up SQL Server details to $($backupFolderPath)"
    
    # Backing up SQL Server database details.
    $backupFile = "$($backupFolderPath)\SqlServersWithTDEDisabled.csv"
    $sqlServersWithTdeDisabled | Export-CSV -Path $backupFile -NoTypeInformation

    if (-not $DryRun)
    {
        Write-Host "SQL Server details have been backed up to $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)    
        if (-not $Force)
        {
            Write-Host "Do you want to enable Transparent Data Encryption (TDE) for all SQL Servers? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Transparent Data Encryption (TDE) will not be enabled for SQL Servers. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Transparent Data Encryption (TDE) will be enabled for SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enabling Transparent Data Encryption (TDE) for SQL Servers..." -ForegroundColor $([Constants]::MessageType.Warning)

        # To hold results from the remediation.
        $remediationSummary = @()
        $totalRemediatedSqlServers = 0
       
        $sqlServersWithTdeDisabled | ForEach-Object{
            $databaseList = @()
            $databaseDetail = $_
            $serverName = $databaseDetail.ServerName
            $databaseList = $databaseDetail.DatabasesWithTDEDisabled -split ', '
            $resourceGroupName = $databaseDetail.ResourceGroupName
            $resourceType = $databaseDetail.ResourceType
            $isSynapseWorkspace = $databaseDetail.IsSynapseWorkspace
            $remediatedSqlDatabases = @()
            $skippedSqlDatabases = @()           

            try
            {
                if ($isSynapseWorkspace -eq $false)
                {
                    $databaseList | ForEach-Object{
                        $databaseName = $_ 
                        $tdeStatus = $(Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $resourceGroupName -ServerName $serverName -DatabaseName $databaseName -State 'Enabled').State
                        if ($tdeStatus -eq 'Enabled')
                        {
                            $remediatedSqlDatabases += $databaseName
                        }
                        else
                        {
                            $skippedSqlDatabases += $databaseName
                        }
                    }
                }
                else
                {
                    $databaseList | ForEach-Object{
                        $sqlPoolName = $_
                        $tdeStatus = $(Set-AzSynapseSqlPoolTransparentDataEncryption -ResourceGroupName $resourceGroupName -WorkspaceName $serverName -Name $sqlPoolName -State 'Enabled' -ErrorAction Continue).State
                        if ($tdeStatus -eq 'Enabled')
                        {
                            $remediatedSqlDatabases += $sqlPoolName
                            
                        }
                        else
                        {
                            $skippedSqlDatabases += $sqlPoolName
                        }
                    }
                }

                if ([String]::IsNullOrWhiteSpace($skippedSqlDatabases))
                {
                    $totalRemediatedSqlServers += 1
                }

                $remediationSummary += $databaseDetail | Select-Object @{N='ServerName';E={$serverName}},
                                                                       @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                       @{N='ResourceType';E={$resourceType}},
                                                                       @{N='IsSynapseWorkspace';E={$isSynapseWorkspace}},
                                                                       @{N='RemediatedSqlDatabases';E={$remediatedSqlDatabases -join ', '}},
                                                                       @{N='SkippedSqlDatabases';E={$skippedSqlDatabases -join ', '}}
            }
            catch
            {
                Write-Host "Error occurred while enabling Transparent Data Encryption (TDE) for SQL Server: Server Name - $($serverName), Resource Group Name - $($resourceGroupName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this SQL Server. Transparent Data Encryption (TDE) will not be enabled for this Server."
            }
        }       

        Write-Host $([Constants]::SingleDashLine)

        if (($totalRemediatedSqlServers | Measure-Object).Count -eq $totalSqlServersWithTdeDisabled)
        {
            Write-Host "Transparent Data Encryption (TDE) successfully enabled for all $($totalSqlServersWithTdeDisabled) SQL Servers." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "Transparent Data Encryption (TDE) successfully enabled for $($($totalRemediatedSqlServers | Measure-Object).Count) out of $($totalSqlServersWithTdeDisabled) SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning)
        }
                                     
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($remediationSummary | Measure-Object).Count -gt 0)
        {
            Write-Host "Transparent Data Encryption (TDE) enabled for the following SQL Servers:" -ForegroundColor $([Constants]::MessageType.Update)
            $remediationSummary | Format-Table -Property ServerName, ResourceGroupName, RemediatedSqlDatabases, SkippedSqlDatabases

            # Write this to a file.
            $remediationSummaryFile = "$($backupFolderPath)\RemediationSummary.csv"
            $remediationSummary | Export-CSV -Path $remediationSummaryFile -NoTypeInformation
            Write-Host "This information has been saved to $($remediationSummaryFile)"
            Write-Host "Use $($remediationSummaryFile) file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] SQL Server details have been backed up to $($backupFile). Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`nRun the same command with -FilePath $($backupFile) and without -DryRun, to enable Transparent Data Encryption (TDE) for all SQL Servers listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`n*** It is recommended to keep this file and use it for any subsequent roll back post the remediation. ***" -ForegroundColor $([Constants]::MessageType.Info)
    }
}

function Disable-TransparentDataEncryptionForSqlServers
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_SQLDatabase_DP_Enable_TDE' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_SQLDatabase_DP_Enable_TDE' Control.
        Disables Transparent Data Encryption (TDE) on the SQL Server in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
                
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .EXAMPLE
        PS> Disable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSqlServers\RemediatedSqlDatabases.csv
        
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
    Write-Host "[Step 1 of 3] Preparing to disable Transparent Data Encryption (TDE) for SQL Servers in Subscription: $($SubscriptionId)"

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

    Write-Host "*** To disable Transparent Data Encryption (TDE) for SQL Servers in a Subscription, Contributor and higher privileges on the SQL Servers are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all SQL Server database details..."
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    $sqlServerDetails = @()
    $validSqlServerDetails = @()
    Write-Host "Fetching all SQL Server details from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)
    $sqlServerDetails = Import-Csv -LiteralPath $FilePath
    $validSqlServerDetails = $sqlServerDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ServerName) -and ![String]::IsNullOrWhiteSpace($_.RemediatedSqlDatabases)}
    $totalSqlServers = $($validSqlServerDetails | Measure-Object).Count
    
    if ($totalSqlServers -eq 0)
    {
        Write-Host "No SQL Server found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalSqlServers) SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableTDEForSqlServers"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "Transparent Data Encryption (TDE) will be disabled for SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning)
    if (-not $Force)
    {
        Write-Host "Do you want to disable Transparent Data Encryption (TDE) for all SQL Servers? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Transparent Data Encryption (TDE) will not be disabled for SQL Servers. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Transparent Data Encryption (TDE) will be disabled for SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Disabling Transparent Data Encryption (TDE) for SQL Servers..." -ForegroundColor $([Constants]::MessageType.Warning)
   
    $rollbackSummary = @()
    $totalRolledbackSqlServers = 0
    
    $validSqlServerDetails | ForEach-Object{
        $databaseList = @()
        $databaseDetail = $_       
        $serverName = $databaseDetail.ServerName
        $databaseList = $databaseDetail.RemediatedSqlDatabases -split ', '
        $resourceGroupName = $databaseDetail.ResourceGroupName
        $resourceType = $databaseDetail.ResourceType
        $isSynapseWorkspace = $databaseDetail.IsSynapseWorkspace

        # Includes SQL databases, to which, previously made changes were successfully rolled back.
        $rolledbackSqlDatabases  = @()

        # Includes SQL databases that were skipped during roll back. There were errors rolling back the changes made previously.
        $skippedSqlDatabases = @()
    
        try
        {
            if ($isSynapseWorkspace -eq $false)
            {
                $databaseList | ForEach-Object{
                    $databaseName = $_
                    $tdeStatus = $(Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $resourceGroupName -ServerName $serverName -DatabaseName $databaseName -State 'Disabled').State
                    if ($tdeStatus -eq 'Disabled')
                    {
                        $rolledbackSqlDatabases  += $databaseName
                    }
                    else
                    {
                        $skippedSqlDatabases += $databaseName
                    }
                }
            }
            else
            {
                $databaseList | ForEach-Object{
                    $sqlPoolName = $_

                    # Capturing output in $setTdeState to avoid unused logs in console.
                    $setTdeState = Set-AzSynapseSqlPoolTransparentDataEncryption -ResourceGroupName $resourceGroupName -WorkspaceName $serverName -Name $sqlPoolName -State 'Disabled'
                    $tdeStatus = $(Get-AzSynapseSqlPoolTransparentDataEncryption -ResourceGroupName $resourceGroupName -WorkspaceName $serverName -Name $sqlPoolName).State

                    if ($tdeStatus -eq 'Disabled')
                    {
                        $rolledbackSqlDatabases += $sqlPoolName
                    }
                    else
                    {
                        $skippedSqlDatabases += $sqlPoolName
                    }
                }
            }

            if ([String]::IsNullOrWhiteSpace($skippedSqlDatabases))
            {
                $totalRolledbackSqlServers += 1
            }

            $rollbackSummary += $databaseDetail | Select-Object @{N='ServerName';E={$serverName}},
                                                                @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                @{N='ResourceType';E={$resourceType}},
                                                                @{N='IsSynapseWorkspace';E={$isSynapseWorkspace}},
                                                                @{N='RolledbackSqlDatabases';E={$rolledbackSqlDatabases -join ', '}},
                                                                @{N='SkippedSqlDatabases';E={$skippedSqlDatabases -join ', '}}                                
        }
        catch
        {
            Write-Host "Error occurred while disabling Transparent Data Encryption (TDE) for SQL Server: Server Name - $($serverName), Resource Group Name - $($resourceGroupName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this SQL Server. Transparent Data Encryption (TDE) will not be disabled for this Server."
        }
    }
    
    if ($($rollbackSummary | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "`nRollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        $rollbackSummary | Format-Table -Property ServerName, ResourceGroupName, RolledbackSqlDatabases, SkippedSqlDatabases

        # Write this to a file.
        $rollbackSummaryFile = "$($backupFolderPath)\RollbackSummary.csv"
        $rollbackSummary | Export-CSV -Path $rollbackSummaryFile -NoTypeInformation
        Write-Host "This information has been saved to $($rollbackSummaryFile)"
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
