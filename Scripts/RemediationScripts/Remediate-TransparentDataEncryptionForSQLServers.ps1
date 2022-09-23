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
       
           Enable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSQLServers\SQLServersWithTDEDisabled.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-TransparentDataEncryptionForSqlServers -Detailed

    To roll back:
        1. To disable Transparent Data Encryption (TDE) on the SQL Servers in a Subscription, from a previously taken snapshot:

           Disable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSQLServers\SQLServersWithTDEDisabled.csv
        
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

    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "$($_) module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host $([Constants]::SingleDashLine)
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

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .EXAMPLE
        PS> Enable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSQLServers\SQLServersWithTDEDisabled.csv

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
        $FilePath,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used")]
        $Path,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies script is run as a subroutine of AutoRemediation Script")]
        $AutoRemediation,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used")]
        $TimeStamp
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Prepare to enable Transparent data encryption (TDE) for SQL Server database(s) in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    if(-not($AutoRemediation))
    {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    # Checking if the current account type is "User"
    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "This script can only be run by `User` Account Type. Account Type of [$($context.Account.Id)] is [$($context.Account.Type)]." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        return
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run this script." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "To enable Transparent data encryption (TDE) for SQL Server database(s) in a Subscription, Contributor and higher privileges on the SQL Servers are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Fetch all SQL Servers"
    Write-Host $([Constants]::SingleDashLine)

    $sqlServerResources = @()
    # Includes SQL Servers where Transparent Data Encryption (TDE) is disabled.
    $sqlServersWithTdeDisabled = @()
    # Includes SQL Servers where Transparent Data Encryption (TDE) is enabled.
    $sqlServersWithTdeEnabled = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    # Control Id
    $controlIds = "Azure_SQLDatabase_DP_Enable_TDE"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "Fetching all SQL Servers failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No SQL Server(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            try
            {
                $sqlServerResource = Get-AzResource -ResourceId $_.ResourceId -ErrorAction SilentlyContinue
                $sqlServerResources += $sqlServerResource | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ServerName';E={$_.Name}},
                                                                        @{N='ResourceType';E={$_.ResourceType}},
                                                                        @{N='IsSynapseWorkspace';E={$false}},
                                                                        @{N='EmailId';E={""}}
            }
            catch
            {
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Valid resource id(s) not found in input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        $totalSqlServers = ($sqlServerResources | Measure-Object).Count

        if ($totalSqlServers -eq 0)
        {
            Write-Host "No SQL Server found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            return
        }
    
        Write-Host "Found [$($totalSqlServers)] SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "NOTE: Each SQL Server may have multiple databases." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        # Write-Host "Fetching SQL databases for SQL Server(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        # Write-Host $([Constants]::SingleDashLine)

        $sqlServerResources | ForEach-Object{
            $sqlDatabasesWithTdeEnabled = @()
            $sqlDatabasesWithTdeDisabled = @()
            $sqlDatabasesSkipped = @()
            try
            {
                Write-Host "Fetching SQL databases details for SQL Server: [$($_.ServerName)]..." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
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
                                $sqlDatabasesSkipped += $_.DatabaseName
                                Write-Host "Error occurred while getting database details for SQL Server: Resource Group Name: [$($_.ResourceGroupName)], Server Name: [$($_.ServerName)], Database Name: [$($_.DatabaseName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                                Write-Host "Skipping this SQL Server database..." -ForegroundColor $([Constants]::MessageType.Warning)
                                Write-Host $([Constants]::SingleDashLine)
                            }
                        }
                    }
                }
                else
                {   
                    $databaseList = Get-AzSynapseSqlPool -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName
                    $databaseList | ForEach-Object{  
                        $databaseConfigDetails = Get-AzSynapseSqlPoolTransparentDataEncryption -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.WorkspaceName -Name $_.SqlPoolName
                        if(-not [String]::IsNullOrWhiteSpace($databaseConfigDetails))
                        {
                            if ($databaseConfigDetails.State -eq "Enabled")
                            {
                                $sqlDatabasesWithTdeEnabled += $_.SqlPoolName
                            }
                            else
                            {
                                $sqlDatabasesWithTdeDisabled += $_.SqlPoolName
                            }
                        }else{
                            $sqlDatabasesSkipped += $_.DatabaseName
                            Write-Host "Error occurred while getting SQL pool details for SQL Server: Resource Group Name: [$($_.ResourceGroupName)], Server Name: [$($_.ServerName)], SQL Pool Name: [$($_.SqlPoolName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                            Write-Host "Skipping this SQL pool..." -ForegroundColor $([Constants]::MessageType.Warning)
                            Write-Host $([Constants]::SingleDashLine)
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
                else
                {
                    $sqlServersWithTdeEnabled += $_
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ServerName))
                    $logResource.Add("Reason","TDE is already enabled for all the databases of the SQL Server")    
                    $logSkippedResources += $logResource
                }

                if(($sqlDatabasesSkipped|Measure-Object).Count -eq 0)
                {
                    Write-Host "Successfully fetched SQL databases for the SQL Server." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
                else 
                {
                    $totalDatabases = ($databaseList|Measure-Object).Count
                    $totalDatabasesSkipped = ($sqlDatabasesSkipped|Measure-Object).Count
                    $totalDatabasesProcessed = $totalDatabases - $totalDatabasesSkipped
                    Write-Host "Successfully fetched [$($totalDatabasesProcessed)] databases details out of [$($totalDatabases)] for the SQL Server." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
            catch
            {
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ServerName))
                $logResource.Add("Reason","Error occurred while getting SQL Server details: Resource Group Name: [$($_.ResourceGroupName)], Server Name: [$($_.ServerName)]. Error: [$($_)]")    
                $logSkippedResources += $logResource
                Write-Host "Error occurred while getting SQL Server details: Resource Group Name: [$($_.ResourceGroupName)], Server Name: [$($_.ServerName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this SQL Server..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        Write-Host "Processed SQL databases for SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else 
    {
        # No file path provided as input to the script. Fetch all SQL Servers in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            # Get all SQL Servers in a Subscription
            Write-Host "Fetching all SQL Servers in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $sqlServers = Get-AzResource -ResourceType "Microsoft.Sql/servers" -ErrorAction Stop
            Write-Host "Successfully fetched all the SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            # Get all Synapse Workspaces in a Subscription
            Write-Host "Fetching all the Synapse Workspace(s) present in the Subscription: [$($context.Subscription.Name)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $synapseWorkspaces = Get-AzResource -ResourceType "Microsoft.Synapse/workspaces" -ErrorAction Stop
            Write-Host "Successfully fetched all the Synapse Workspace(s)." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            # Filter SQL Servers not associated with a Synapse Workspace.
            # Synapse Workspace and the associated SQL Server have the same name.
            # Synapse Workspace names are unique.
            Write-Host "Filtering out SQL Server(s) associated with Synapse Workspace(s) to avoid redundancy..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $standaloneSqlServers = Compare-Object -ReferenceObject @($sqlServers | Select-Object) -DifferenceObject @($synapseWorkspaces | Select-Object) -Property { $_.ResourceName } -PassThru
            Write-Host "Succesfully filtered out SQL Server(s) associated with Synapse Workspace(s)." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

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
                return
            }
        
            Write-Host "Found [$($totalSqlServers)] SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "NOTE: Each SQL Server may have multiple databases." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)

            $sqlServerResources | ForEach-Object{
                $sqlDatabasesWithTdeEnabled = @()
                $sqlDatabasesWithTdeDisabled = @()
                $sqlDatabasesSkipped = @()
                try
                {
                    Write-Host "Fetching SQL databases details for SQL Server: [$($_.ServerName)]..." -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host $([Constants]::SingleDashLine)
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
                                    $sqlDatabasesSkipped += $_.DatabaseName
                                    Write-Host "Error occurred while getting database details for SQL Server: Resource Group Name: [$($_.ResourceGroupName)], Server Name: [$($_.ServerName)], Database Name: [$($_.DatabaseName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                                    Write-Host "Skipping this SQL Server database..." -ForegroundColor $([Constants]::MessageType.Warning)
                                    Write-Host $([Constants]::SingleDashLine)
                                }
                            }
                        }
                    }
                    else
                    {   
                        $databaseList = Get-AzSynapseSqlPool -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName
                        $databaseList | ForEach-Object{  
                            $databaseConfigDetails = Get-AzSynapseSqlPoolTransparentDataEncryption -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.WorkspaceName -Name $_.SqlPoolName
                            if(-not [String]::IsNullOrWhiteSpace($databaseConfigDetails))
                            {
                                if ($databaseConfigDetails.State -eq "Enabled")
                                {
                                    $sqlDatabasesWithTdeEnabled += $_.SqlPoolName
                                }
                                else
                                {
                                    $sqlDatabasesWithTdeDisabled += $_.SqlPoolName
                                }
                            }else{
                                $sqlDatabasesSkipped += $_.DatabaseName
                                Write-Host "Error occurred while getting SQL pool details for SQL Server: Resource Group Name: [$($_.ResourceGroupName)], Server Name: [$($_.ServerName)], SQL Pool Name: [$($_.SqlPoolName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                                Write-Host "Skipping this SQL pool..." -ForegroundColor $([Constants]::MessageType.Warning)
                                Write-Host $([Constants]::SingleDashLine)
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
                    if(($sqlDatabasesSkipped|Measure-Object).Count -eq 0)
                    {
                        Write-Host "Successfully fetched SQL databases for the SQL Server." -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    else 
                    {
                        $totalDatabases = ($databaseList|Measure-Object).Count
                        $totalDatabasesSkipped = ($sqlDatabasesSkipped|Measure-Object).Count
                        $totalDatabasesProcessed = $totalDatabases - $totalDatabasesSkipped
                        Write-Host "Successfully fetched [$($totalDatabasesProcessed)] databases details out of [$($totalDatabases)] for the SQL Server." -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                }
                catch
                {
                    Write-Host "Error occurred while getting SQL Server details: Resource Group Name: [$($_.ResourceGroupName)], Server Name: [$($_.ServerName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this SQL Server..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                return
            }

            Write-Host "Fetching all SQL databases from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $sqlServersWithTdeDisabled = Import-Csv -LiteralPath $FilePath
            Write-Host "Successfully fetched all the databases." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }

    $totalSqlServersWithTdeDisabled = ($sqlServersWithTdeDisabled | Measure-Object).Count
    if ($totalSqlServersWithTdeDisabled -eq 0)
    {
        Write-Host "No SQL Server found with Transparent Data Encryption (TDE) disabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        if($AutoRemediation -and ($sqlServersWithTdeEnabled|Measure-Object).Count -gt 0)
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
        return
    }

    Write-Host "Found [$($totalSqlServersWithTdeDisabled)] SQL Server(s) with Transparent Data Encryption (TDE) disabled." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 3 of 4] Back up SQL Server details"
    Write-Host $([Constants]::SingleDashLine)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableTDEForSQLServers"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
    
    # Backing up SQL Server database details.
    Write-Host "Backing up App Services details to [$($backupFolderPath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $backupFile = "$($backupFolderPath)\SQLServersWithTDEDisabled.csv"
    $sqlServersWithTdeDisabled | Export-CSV -Path $backupFile -NoTypeInformation -ErrorAction Stop
    Write-Host "SQL Server(s) details have been backed up to [$($backupFile)]." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    if (-not $DryRun)
    {
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "Do you want to enable Transparent Data Encryption (TDE) for all SQL Servers? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                
                $userInput = Read-Host -Prompt "(Y|N)"
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "Transparent Data Encryption (TDE) will not be enabled for SQL Servers. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
                Write-Host "User has provided consent to enable Transparent Data Encryption (TDE) fpr all SQL Servers." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                Write-Host "'Force' flag is provided. Transparent Data Encryption (TDE) will be enabled for SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host "[Step 4 of 4] Enable Transparent Data Encryption (TDE) for SQL Servers"
        Write-Host $([Constants]::SingleDashLine)


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
                Write-Host "Enabling Transparent Data Encryption (TDE) for the SQL Server: [$($_.ServerName)]..." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
                if ($isSynapseWorkspace -eq $false)
                {
                    $databaseList | ForEach-Object{
                        $databaseName = $_ 
                        $tdeDetail = Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $resourceGroupName -ServerName $serverName -DatabaseName $databaseName -State 'Enabled'
                        $tdeStatus = $tdeDetail.State
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
                        $tdeDetail = Set-AzSynapseSqlPoolTransparentDataEncryption -ResourceGroupName $resourceGroupName -WorkspaceName $serverName -Name $sqlPoolName -State 'Enabled'
                        $tdeStatus = $tdeDetail.State
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
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ServerName))
                    $logRemediatedResources += $logResource
                    Write-Host "Successfully enabled Transparent Data Encryption (TDE) for the SQL Server." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }   
                else
                {
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ServerName))
                    $logResource.Add("Reason","Encountered error while enabling Transparent Data Encryption for the SQL Server in the database(s): [$($skippedSqlDatabases)]")    
                    $logSkippedResources += $logResource
                    Write-Host "Encountered error while enabling Transparent Data Encryption for the SQL Server in the database(s): [$($skippedSqlDatabases)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host $([Constants]::SingleDashLine)
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
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ServerName))
                $logResource.Add("Reason","Error occurred while enabling Transparent Data Encryption (TDE) for SQL Server: Server Name: [$($serverName)], Resource Group Name : [$($resourceGroupName)]. Error: [$($_)]")    
                $logSkippedResources += $logResource
                Write-Host "Error occurred while enabling Transparent Data Encryption (TDE) for SQL Server: Server Name: [$($serverName)], Resource Group Name: [$($resourceGroupName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this SQL Server... (Transparent Data Encryption (TDE) will not be enabled for this Server)" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)

            }
        }

        if (($totalRemediatedSqlServers | Measure-Object).Count -eq $totalSqlServersWithTdeDisabled)
        {
            Write-Host "Transparent Data Encryption (TDE) successfully enabled for all [$($totalSqlServersWithTdeDisabled)] SQL Servers." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "Transparent Data Encryption (TDE) successfully enabled for [$($($totalRemediatedSqlServers | Measure-Object).Count)] out of [$($totalSqlServersWithTdeDisabled)] SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning)
        }                    
        Write-Host $([Constants]::DoubleDashLine)
        
        if($AutoRemediation)
        {
            $remediationSummaryFile = "$($backupFolderPath)\RemediationSummary.csv"
            $remediationSummary | Export-CSV -Path $remediationSummaryFile -NoTypeInformation
            Write-Host "The information related SQL Servers where Transparent Data Encryption (TDE) successfully enabled has been saved to [$($remediationSummaryFile)].Use the file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
        else 
        {
            Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
            if ($($remediationSummary | Measure-Object).Count -gt 0)
            {
                Write-Host "Transparent Data Encryption (TDE) enabled for the following SQL Servers:" -ForegroundColor $([Constants]::MessageType.Update)
                $remediationSummary | Format-Table -Property ServerName, ResourceGroupName, RemediatedSqlDatabases, SkippedSqlDatabases
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $remediationSummaryFile = "$($backupFolderPath)\RemediationSummary.csv"
                $remediationSummary | Export-CSV -Path $remediationSummaryFile -NoTypeInformation
                Write-Host "This information has been saved to [$($remediationSummaryFile)].Use the file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        if($AutoRemediation)
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                    $logControl.RollbackFile = $remediationSummaryFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "[Step 4 of 4] Enable Transparent Data Encryption (TDE) for SQL Servers"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:"  -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun to enable Transparent Data Encryption (TDE) for all SQL Servers listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
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
        PS> Disable-TransparentDataEncryptionForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableTDEForSQLServers\RemediatedSqlDatabases.csv
        
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
    Write-Host "[Step 1 of 3] Prepare to disable Transparent Data Encryption (TDE) for SQL Servers in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "This script can only be run by `User` Account Type. Account Type of [$($context.Account.Id)] is [$($context.Account.Type)]." -ForegroundColor $([Constants]::MessageType.Warning)
        return
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run this script."  -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "To disable Transparent Data Encryption (TDE) for SQL Servers in a Subscription, Contributor and higher privileges on the SQL Servers are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Fetch all SQL Server database details"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::SingleDashLine)
        return
    }

    $sqlServerDetails = @()
    $validSqlServerDetails = @()
    Write-Host "Fetching all SQL Server(s) details from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $sqlServerDetails = Import-Csv -LiteralPath $FilePath
    Write-Host "Successfully fetched all the SQL Server(s) details." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    $validSqlServerDetails = $sqlServerDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ServerName) -and ![String]::IsNullOrWhiteSpace($_.RemediatedSqlDatabases)}
    $totalSqlServers = $($validSqlServerDetails | Measure-Object).Count
    
    if ($totalSqlServers -eq 0)
    {
        Write-Host "No SQL Server found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }

    Write-Host "Found [$($totalSqlServers)] SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
    write-Host $([Constants]::SingleDashLine)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableTDEForSQLServers"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    if (-not $Force)
    {
        Write-Host "Do you want to disable Transparent Data Encryption (TDE) for all SQL Servers? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "Transparent Data Encryption (TDE) will not be disabled for SQL Servers. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "User has provided consent to disable Transparent Data Encryption (TDE) for all SQL Servers." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. Transparent Data Encryption (TDE) will be disabled for SQL Servers." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 3 of 3] Disable Transparent Data Encryption (TDE) for SQL Servers"
    Write-Host $([Constants]::SingleDashLine)
   
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
            Write-Host "Disabling Transparent Data Encryption (TDE) for the SQL Server: [$($_.ServerName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            if ($isSynapseWorkspace -eq $false)
            {
                $databaseList | ForEach-Object{
                    $databaseName = $_
                    $tdeDetail = Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $resourceGroupName -ServerName $serverName -DatabaseName $databaseName -State 'Disabled'
                    $tdeStatus = $tdeDetail.State
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

                    $tdeDetail = Set-AzSynapseSqlPoolTransparentDataEncryption -ResourceGroupName $resourceGroupName -WorkspaceName $serverName -Name $sqlPoolName -State 'Disabled'
                    $tdeStatus = $tdeDetail.State

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
                Write-Host "Successfully disabled Transparent Data Encryption (TDE) for the SQL Servers." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else 
            {
                Write-Host "Encountered error while disabling Transparent Data Encryption for the SQL Server in the databases: [$($skippedSqlDatabases)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
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
            Write-Host "Error occurred while disabling Transparent Data Encryption (TDE) for SQL Server: Server Name: [$($serverName)], Resource Group Name: [$($resourceGroupName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this SQL Server (Transparent Data Encryption (TDE) will not be disabled for this Server)..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    
    if ($($rollbackSummary | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        $rollbackSummary | Format-Table -Property ServerName, ResourceGroupName, RolledbackSqlDatabases, SkippedSqlDatabases
        Write-Host $([Constants]::SingleDashLine)
        # Write this to a file.
        $rollbackSummaryFile = "$($backupFolderPath)\RollbackSummary.csv"
        $rollbackSummary | Export-CSV -Path $rollbackSummaryFile -NoTypeInformation
        Write-Host "Rollback Summary information has been saved to [$($rollbackSummaryFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
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
