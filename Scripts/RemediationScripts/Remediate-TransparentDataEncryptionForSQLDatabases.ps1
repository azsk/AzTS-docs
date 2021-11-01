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
        3. Back up details of SQL Server databases that are going to be remediated.
        4. Enable Transparent Data Encryption (TDE) on the SQL Server databases in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Servers in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable Transparent Data Encryption (TDE) on the SQL Server databases in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable Transparent Data Encryption (TDE) on the SQL Server databases in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable Transparent Data Encryption (TDE) on the SQL Server databases in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the SQL Server database details in a Subscription that will be remediated:
    
           Enable-TransparentDataEncryptionForSQLDatabases -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        2. To enable Transparent Data Encryption (TDE) on the SQL Server databases in a Subscription:
       
           Enable-TransparentDataEncryptionForSQLDatabases -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000

        3. To enable Transparent Data Encryption (TDE) on the SQL Server databases in a Subscription, from a previously taken snapshot:
       
           Enable-TransparentDataEncryptionForSQLDatabases -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSQLServerDatabases\SQLServerDatabasesWithTDEDisabled.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-TransparentDataEncryptionForSQLDatabases -Detailed

    To roll back:
        1. To disable Transparent Data Encryption (TDE) on the SQL Server databases in a Subscription, from a previously taken snapshot:

           Disable-TransparentDataEncryptionForSQLDatabases -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSQLServerDatabases\RemediatedSQLServerDatabases.csv
        
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Disable-TransparentDataEncryptionForSQLDatabases -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Sql")

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

function Enable-TransparentDataEncryptionForSQLDatabases
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
        PS> Enable-TransparentDataEncryptionForSQLDatabases -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-TransparentDataEncryptionForSQLDatabases -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-TransparentDataEncryptionForSQLDatabases -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSQLServerDatabases\SQLServerDatabasesWithTDEDisabled.csv

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

    # Includes SQL Servers where Transparent Data Encryption (TDE) is enabled.
    $sqlServerDatabasesWithTDEEnabled = @()

    # Includes SQL Servers where Transparent Data Encryption (TDE) is not enabled.
    $sqlServerDatabasesWithTDEDisabled = @()

    # Includes SQL Servers that were skipped during remediation. There were errors remediating them.
    $skippedSQLServerDatabases = @()

    # No file path provided as input to the script. Fetch all SQL Servers in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all SQL Servers in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all SQL Servers in a Subscription      
        $sqlServersResources = Get-AzSqlServer
        $totalSQLServers = ($sqlServersResources | Measure-Object).Count

        if ($totalSQLServers -eq 0)
        {
            Write-Host "No SQL Server found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
    
        Write-Host "Found $($totalSQLServers) SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "NOTE: Each SQL Server may have multiple databases."
        Write-Host "Fetching SQL Server databases..."

        $totalSQLServerDatabases = 0
        $sqlServersResources | ForEach-Object{
            $databaseList = Get-AzSqlDatabase -ServerName $_.ServerName -ResourceGroupName $_.ResourceGroupName
            $databaseList | ForEach-Object{
                if ($_.DatabaseName -ne 'master')
                {
                    $databaseConfigDetails = Get-AzSqlDatabaseTransparentDataEncryption -ServerName $_.ServerName -DatabaseName $_.DatabaseName -ResourceGroupName $_.ResourceGroupName
                    $totalSQLServerDatabases += 1
                    if ($databaseConfigDetails.State -eq "Enabled")
                    {
                        $sqlServerDatabasesWithTDEEnabled += $databaseConfigDetails
                    }
                    else
                    {
                        $sqlServerDatabasesWithTDEDisabled += $databaseConfigDetails
                    }
                }                
            }
        }

        Write-Host "Found $($totalSQLServerDatabases) SQL Server databases." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all SQL Server databases from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

        $sqlServerDatabasesWithTDEDisabled = Import-Csv -LiteralPath $FilePath
    }

    $totalSQLServerDatabasesWithTDEDisabled = ($sqlServerDatabasesWithTDEDisabled | Measure-Object).Count
    if ($totalSQLServerDatabasesWithTDEDisabled -eq 0)
    {
        Write-Host "No SQL Server database found with Transparent Data Encryption (TDE) disabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalSQLServerDatabasesWithTDEDisabled) SQL Server database(s) with Transparent Data Encryption (TDE) disabled." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableTDEForSQLServerDatabases"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up SQL Server database details to $($backupFolderPath)"
    
    # Backing up SQL Server database details.
    $backupFile = "$($backupFolderPath)\SQLServerDatabasesWithTDEDisabled.csv"
    $sqlServerDatabasesWithTDEDisabled | Export-CSV -Path $backupFile -NoTypeInformation

    if (-not $DryRun)
    {
        Write-Host "SQL Server database details have been backed up to $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)    
        if (-not $Force)
        {
            Write-Host "Do you want to enable Transparent Data Encryption (TDE) for all SQL Server databases? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Transparent Data Encryption (TDE) will not be enabled for SQL Server databases. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Transparent Data Encryption (TDE) will be enabled for SQL Server databases." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enabling Transparent Data Encryption (TDE) for SQL Server databases..." -ForegroundColor $([Constants]::MessageType.Warning)

        # To hold results from the remediation.
        $remediatedSQLServerDatabases = @()
        $skippedSQLServerDatabases = @()

        $sqlServerDatabasesWithTDEDisabled | ForEach-Object{
            $databaseDetail = $_
            $serverName = $_.ServerName
            $databaseName = $_.DatabaseName
            $resourceGroupName = $_.ResourceGroupName

            try
            {
                $tdeStatus = $(Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $resourceGroupName -ServerName $serverName -DatabaseName $databaseName -State 'Enabled').State
                
                if ($tdeStatus -eq 'Enabled')
                {
                    $remediatedSQLServerDatabases += $databaseDetail
                }
                else
                {
                    $skippedSQLServerDatabases += $databaseDetail
                }
            }
            catch
            {
                $skippedSQLServerDatabases += $databaseDetail
                Write-Host "Error occurred while enabling Transparent Data Encryption (TDE) for SQL Server database: Resource Group Name - $($resourceGroupName), Server Name - $($serverName), Database Name - $($databaseName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this database. Transparent Data Encryption (TDE) will not be enabled for this database."
            }           
        }

        Write-Host $([Constants]::SingleDashLine)

        if (($remediatedSQLServerDatabases | Measure-Object).Count -eq $totalSQLServerDatabasesWithTDEDisabled)
        {
            Write-Host "Transparent Data Encryption (TDE) successfully enabled for all $($totalSQLServerDatabasesWithTDEDisabled) SQL Server database(s)." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "Transparent Data Encryption (TDE) successfully enabled for $($($remediatedSQLServerDatabases | Measure-Object).Count) out of $($totalSQLServerDatabasesWithTDEDisabled) SQL Server database(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }
        
        $colsProperty = @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                        @{Expression={$_.DatabaseName};Label="Database Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.State};Label="State";Width=20;Alignment="left"}
                              
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($remediatedSQLServerDatabases | Measure-Object).Count -gt 0)
        {
            Write-Host "Transparent Data Encryption (TDE) successfully enabled for the following SQL Server database(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $remediatedSQLServerDatabases | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $remediatedSQLServerDatabasesFile = "$($backupFolderPath)\RemediatedSQLServerDatabases.csv"
            $remediatedSQLServerDatabases | Export-CSV -Path $remediatedSQLServerDatabasesFile -NoTypeInformation
            Write-Host "This information has been saved to $($remediatedSQLServerDatabasesFile)"
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($skippedSQLServerDatabases | Measure-Object).Count -gt 0)
        {
            Write-Host "Error occurred while enabling Transparent Data Encryption (TDE) for the following SQL Server database(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedSQLServerDatabases | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $skippedSQLServerDatabasesFile = "$($backupFolderPath)\SkippedSQLServerDatabases.csv"
            $skippedSQLServerDatabases | Export-CSV -Path $skippedSQLServerDatabasesFile -NoTypeInformation
            Write-Host "This information has been saved to $($skippedSQLServerDatabasesFile)"
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] SQL Server database details have been backed up to $($backupFile). Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`nRun the same command with -FilePath $($backupFile) and without -DryRun, to enable Transparent Data Encryption (TDE) for all SQL Server databases listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
    }
}

function Disable-TransparentDataEncryptionForSQLDatabases
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_SQLDatabase_DP_Enable_TDE' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_SQLDatabase_DP_Enable_TDE' Control.
        Disables Transparent Data Encryption (TDE) on the SQL Server databases in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
                
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .EXAMPLE
        PS> Disable-TransparentDataEncryptionForSQLDatabases -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSQLServerDatabases\RemediatedSQLServerDatabases.csv
        
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

    Write-Host "Fetching all SQL Server database details from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)
    $sqlServerDetails = Import-Csv -LiteralPath $FilePath
    $validSQLServerDetails = $sqlServerDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ServerName) -and ![String]::IsNullOrWhiteSpace($_.DatabaseName)}
    $totalSQLServerDatabases = $($validSQLServerDetails.Count)

    if ($totalSQLServerDatabases -eq 0)
    {
        Write-Host "No SQL Server database found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalSQLServerDatabases) SQL Server database(s)." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableTDEForSQLServerDatabases"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "Transparent Data Encryption (TDE) will be disabled for SQL Server databases." -ForegroundColor $([Constants]::MessageType.Warning)
    if (-not $Force)
    {
        Write-Host "Do you want to disable Transparent Data Encryption (TDE) for all SQL Server databases? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Transparent Data Encryption (TDE) will not be disabled for SQL Server databases. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Transparent Data Encryption (TDE) will be disabled for SQL Server databases." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Disabling Transparent Data Encryption (TDE) for SQL Server databases..." -ForegroundColor $([Constants]::MessageType.Warning)

    # Includes SQL Server databases, to which, previously made changes were successfully rolled back.
    $sqlServersRolledBack = @()

    # Includes SQL Server databases that were skipped during roll back. There were errors rolling back the changes made previously.
    $skippedSQLServerDatabases = @()

    $validSQLServerDetails | ForEach-Object {
        $databaseDetail = $_
        $serverName = $_.ServerName
        $databaseName = $_.DatabaseName
        $resourceGroupName = $_.ResourceGroupName
        try
        {
            $tdeStatus = $(Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $resourceGroupName -ServerName $serverName -DatabaseName $databaseName -State 'Disabled').State
                
            if ($tdeStatus -eq 'Disabled')
            {
                $sqlServersRolledBack += $databaseDetail
            }
            else
            {
                $skippedSQLServerDatabases += $databaseDetail
            }
        }
        catch
        {
            $skippedSQLServerDatabases += $databaseDetail
            Write-Host "Error occurred while disabling Transparent Data Encryption (TDE) for SQL Server database: Resource Group Name - $($resourceGroupName), Server Name - $($serverName), Database Name - $($databaseName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this database. Transparent Data Encryption (TDE) will not be disabled for this database."
        }
    }

    if (($skippedSQLServerDatabases | Measure-Object).Count -eq 0)
    {
        Write-Host "Transparent Data Encryption (TDE) successfully disabled for all $($totalSQLServerDatabases) SQL Server database(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Transparent Data Encryption (TDE) successfully disabled for $($($sqlServersRolledBack | Measure-Object).Count) out of $($totalSQLServerDatabases) SQL Server database(s)." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    $colsProperty = @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                    @{Expression={$_.DatabaseName};Label="Database Name";Width=20;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                    @{Expression={$_.State};Label="State";Width=20;Alignment="left"}

    if ($($sqlServersRolledBack | Measure-Object).Count -gt 0 -or $($skippedSQLServerDatabases | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "`nRollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($sqlServersRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Transparent Data Encryption (TDE) successfully disabled for the following SQL Server database(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $sqlServersRolledBack | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $sqlServersRolledBackFile = "$($backupFolderPath)\RolledBackSQLServerDatabases.csv"
            $sqlServersRolledBack | Export-CSV -Path $sqlServersRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to $($sqlServersRolledBackFile)"
        }

        if ($($skippedSQLServerDatabases | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError occurred while disabling Transparent Data Encryption (TDE) for the following SQL Server database(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedSQLServerDatabases | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $skippedSQLServerDatabasesFile = "$($backupFolderPath)\SkippedSQLServerDatabases.csv"
            $skippedSQLServerDatabases | Export-CSV -Path $skippedSQLServerDatabasesFile -NoTypeInformation
            Write-Host "This information has been saved to $($skippedSQLServerDatabasesFile)"
        }
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
