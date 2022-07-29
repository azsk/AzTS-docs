<###
# Overview:
    This script is used to Enable Azure AD admin for the SQL Servers in a Subscription.

# Control ID:
    Azure_SQLDatabase_AuthZ_Use_AAD_Admin

# Display Name:
    Use AAD Authentication for SQL Database

# Prerequisites:
    Contributor and higher privileges on the SQL Servers in a Subscription.

# NOTE: Please run the script using -DryRun Switch and provide the output file of -DryRun switch as input for actual remediation.
    
# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script and validate the user.
        2. Get the list of SQL Servers in a Subscription that do not have Azure AD admin enabled.
        3. Back up details of SQL Servers that are going to be remediated.
        4. Enable Azure AD admin on the SQL Servers in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Servers in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable Azure AD admin on the SQL Servers in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable Azure AD admin on the SQL Servers in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable Azure AD admin on the SQL Servers in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the SQL Server details in a Subscription that will be remediated:

           Enable-ADAdminForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        2. To review the SQL Server details in a Subscription that will be remediated with pre-requisites check:

           Enable-ADAdminForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun -PerformPreReqCheck

        3. To enable Azure AD admin on the SQL Servers in a Subscription, from a previously taken snapshot:

           Enable-ADAdminForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForSQLServers\SQLServersWithADAdminDisabled.csv

        To know more about the options supported by the remediation command, execute:

        Get-Help Enable-ADAdminForSqlServers -Detailed

    To roll back:
        1. To disable Azure AD admin on the SQL Servers in a Subscription, from a previously taken snapshot:

           Disable-ADAdminForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForSQLServers\RemediatedSQLServers.csv

        To know more about the options supported by the roll back command, execute:

        Get-Help Disable-ADAdminForSqlServers -Detailed
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

function Enable-ADAdminForSqlServers
{
    <#
        .SYNOPSIS
        Remediates 'Azure_SQLDatabase_AuthZ_Use_AAD_Admin' Control.

        .DESCRIPTION
        Remediates 'Azure_SQLDatabase_AuthZ_Use_AAD_Admin' Control.
        Azure AD admin must be enabled.

        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .EXAMPLE
        PS> Enable-ADAdminForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-ADAdminForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-ADAdminForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForSQLServers\SQLServersWithADAdminDisabled.csv

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
        $FilePath,

        [String]
        $Path,

        [Switch]
        $AutoRemediation,

        [String]
        $TimeStamp
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Preparing to enable AAD for SQL Servers in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
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
    if ($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of [$($context.Account.Id)] is: [$($context.Account.Type)]" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run this script..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "Note: To enable Azure AD admin for SQL Server(s) in a Subscription, Contributor and higher privileges on the SQL Server(s) in the Subscription are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
   
    Write-Host "[Step 2 of 4] Preparing to fetch all SQL Server(s)"
    Write-Host $([Constants]::SingleDashLine)
    $sqlServerResources = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    # Control Id
    $controlIds = "Azure_SQLDatabase_AuthZ_Use_AAD_Admin"

    if ($AutoRemediation) 
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            break
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
            break
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
                Write-Host "Valid resource id(s) not found in input json file. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "WARNING: Skipping the Resource [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Valid resource id(s) not found in input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        
    }
    else
    {
        # No file path provided as input to the script. Fetch all SQL Servers in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            # Get all SQL Servers in a Subscription.
            # This will include SQL Servers associated with Synapse Workspaces as well.
            Write-Host "Fetching all the SQL Server(s) present in the Subscription : [$($context.Subscription.Name)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $sqlServers = Get-AzResource -ResourceType "Microsoft.Sql/servers" -ErrorAction Stop
            Write-Host "Successfully fetched all the SQL Server(s)" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            
            # Get all Synapse Workspaces in a Subscription
            Write-Host "Fetching all the Synapse Workspace(s) present in the Subscription : [$($context.Subscription.Name)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $synapseWorkspaces = Get-AzResource -ResourceType "Microsoft.Synapse/workspaces" -ErrorAction Stop
            Write-Host "Successfully fetched all the Synapse Workspace(s)" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            $standaloneSqlServers = $sqlServers

            # Filter SQL Servers not associated with a Synapse Workspace.
            # Synapse Workspace and the associated SQL Server have the same name.
            # Synapse Workspace names are unique.
            Write-Host "Filtering out SQL Server(s) associated with Synapse Workspace(s) to avoid redundancy..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            if (($synapseWorkspaces | Measure-Object).Count -gt 0)
            {
                $standaloneSqlServers = Compare-Object -ReferenceObject $sqlServers -DifferenceObject $synapseWorkspaces -Property { $_.Name } -PassThru
            }

            $sqlServerResources += $standaloneSqlServers | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ServerName';E={$_.Name}},
                                                                        @{N='ResourceType';E={$_.ResourceType}},
                                                                        @{N='IsSynapseWorkspace';E={$false}},
                                                                        @{N='EmailId';E={""}}

            Write-Host "Succesfully filtered out SQL Server(s) associated with Synapse Workspace(s)" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
                                                                        
            # Add Synapse Workspaces to this list.
            $sqlServerResources += $synapseWorkspaces | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                    @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                    @{N='ServerName';E={$_.Name}},
                                                                    @{N='ResourceType';E={$_.ResourceType}},
                                                                    @{N='IsSynapseWorkspace';E={$true}},
                                                                    @{N='EmailId';E={""}}

        }  
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                break
            }

            Write-Host "Fetching all SQL Server(s) from file [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine) 

            # Importing the list of SQL servers to be remediated.
            $sqlServersDetails = Import-Csv -LiteralPath $FilePath

            $sqlServerResources = $sqlServersDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
            Write-Host "Succesfully fetched list of SQL Server(s)" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
    }

    $totalSqlServers = ($sqlServerResources|Measure-Object).Count

    if ($totalSqlServers -eq 0)
    {
        Write-Host "No SQL Servers found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found [$($totalSqlServers)] SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Includes SQL Servers where Azure AD admin is enabled.
    $sqlServersWithADAdminEnabled = @()

    # Includes SQL Servers where Azure AD admin is disabled.
    $sqlServersWithADAdminDisabled = @()
    Write-Host "Checking if Azure AD admin is enabled on SQL Server(s)..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

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
             
            # Check if Azure AD admin are enabled on the SQL Server.
            if (($adAdmin|Measure-Object).Count -ne 0)
            {
                $sqlServersWithADAdminEnabled += $sqlServerInstance
            }
            else
            {
                $SQLServersWithADAdminDisabled += $sqlServerInstance                                                 
            }
        }
        catch
        {
            $SQLServersWithADAdminDisabled += $sqlServerInstance 
        }
    }

    $totalSQLServersWithADAdminDisabled = ($SQLServersWithADAdminDisabled | Measure-Object).Count

    if ($totalSQLServersWithADAdminDisabled -eq 0)
    {
        Write-Host "No SQL Server found with Azure AD admin disabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    $colsProperty3 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"}

    Write-Host "Found [$($totalSQLServersWithADAdminDisabled)] SQL Server(s) with Azure AD admin disabled." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "SQL Server(s) having Azure AD Admin disabled are as follows:"
    Write-Host $([Constants]::SingleDashLine)
    $SQLServersWithADAdminDisabled | Format-Table -Property $colsProperty3 -Wrap
    Write-Host $([Constants]::SingleDashLine)

    $sqlServersWithADAdminEnabled | ForEach-Object {
        $logResource = @{}
        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
        $logResource.Add("ResourceName",($_.ServerName))
        $logResource.Add("Reason","AAD is already enabled.")    
        $logSkippedResources += $logResource
    }

    # Backing up SQL Server details.
    Write-Host "[Step 3 of 4] Backing up SQL Server details"
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableADAdminForSQLServers"
    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
    $backupFile = "$($backupFolderPath)\SQLServersWithADAdminDisabled.csv"
   
    $SQLServersWithADAdminDisabled | Export-CSV -Path $backupFile -NoTypeInformation -ErrorAction Stop
    Write-Host "SQL Server(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    if (-not $DryRun)
    {
        Write-Host "[Step 4 of 4] Enabling Azure AD admin for SQL Server(s)" 
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Do you want to enable AD Admin for SQL Server(s)?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if ($userInput -ne "Y")
        {
            Write-Host "Azure AD admin will not be enabled for any SQL Server. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }

        # To hold results from the remediation.
        $remediatedSqlServers = @()

        # Includes SQL Servers that were skipped during remediation. There were errors remediating them.
        $skippedSqlServers = @()
       
        Write-Host "Enabling Azure AD admin for SQL Server(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $SQLServersWithADAdminDisabled  | ForEach-Object {
            $sqlServerInstance = $_
            try
            {
                Write-Host "Enabling Azure AD admin for SQL Server : [$($sqlServerInstance.ServerName)]..." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
                if(![String]::IsNullOrWhiteSpace($_.EmailId))
                {
                    if($_.IsSynapseWorkspace -eq $true)
                    {
                        $adAdmin = Set-AzSynapseSqlActiveDirectoryAdministrator -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName -DisplayName $_.EmailId
                    }
                    else
                    {
                        $adAdmin = Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -DisplayName $_.EmailId
                    }

                    if (($adAdmin|Measure-Object).Count -ne 0)
                    {
                        $remediatedSqlServers += $sqlServerInstance 
                        Write-Host "Successfully enabled Azure AD admin for SQL Server: [$($sqlServerInstance.ServerName)]" -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                        $logResource = @{}
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        $logResource.Add("ResourceName",($_.ServerName)) 
                        $logRemediatedResources += $logResource
                    }
                    else
                    {
                        $skippedSqlServers += $sqlServerInstance 
                        Write-Host "Unsuccessful in enabling Azure AD admin for SQL Server: [$($sqlServerInstance.ServerName)]" -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host $([Constants]::SingleDashLine)  
                        $logResource = @{}
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        $logResource.Add("ResourceName",($_.ServerName))
                        $logResource.Add("Reason","Azure AD Admin was not successfully enabled for the SQL Server: [$($_.ServerName)]")    
                        $logSkippedResources += $logResource                
                    }
                }
                else
                {
                    $skippedSqlServers += $sqlServerInstance   
                    Write-Host "Unsuccessful in enabling Azure AD admin for SQL Server: [$($sqlServerInstance.ServerName)] since Email Id: [$($_.EmailId)], is empty." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host $([Constants]::SingleDashLine)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ServerName))
                    $logResource.Add("Reason","Unsuccessful in enabling Azure AD admin for SQL Server: [$($sqlServerInstance.ServerName)] since Email Id: [$($_.EmailId)], is empty.")    
                    $logSkippedResources += $logResource    
                } 
            } 
            catch
            {
                $skippedSqlServers += $sqlServerInstance
                Write-Host "Error while enabling Azure AD admin for SQL Server: [$($sqlServerInstance.ServerName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine) 
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ServerName))
                $logResource.Add("Reason","Error while enabling Azure AD admin for SQL Server: [$($sqlServerInstance.ServerName)]. Error: [$($_)]")    
                $logSkippedResources += $logResource 
            }
        }

        $colsProperty1 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.ResourceType};Label="Resource Type";Width=30;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"},
                         @{Expression={$_.EmailId};Label="Display Name";Width=35;Alignment="left"}

        $colsProperty2 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.ResourceType};Label="Resource Type";Width=30;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"}
               
        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation)
        {
            if ($($remediatedSqlServers | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $remediatedSqlServersFile = "$($backupFolderPath)\RemediatedSQLServers.csv"
                $remediatedSqlServers | Export-CSV -Path $remediatedSqlServersFile -NoTypeInformation
                Write-Host "Azure AD admin successfully enabled for the SQL Server(s) and this information has been saved to [$($remediatedSqlServersFile)]. Use this file only for rollback." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($skippedSqlServers | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $skippedSqlServersFile = "$($backupFolderPath)\SkippedSQLServers.csv"
                $skippedSqlServers | Export-CSV -Path $skippedSqlServersFile -NoTypeInformation
                Write-Host "Error enabling AD Admin for SQL the Server(s) and this information has been saved to $($skippedSqlServersFile)" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            if ($($remediatedSqlServers | Measure-Object).Count -gt 0)
            {
                Write-Host "Azure AD admin successfully enabled for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Update)
                $remediatedSqlServers | Format-Table -Property $colsProperty1 -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $remediatedSqlServersFile = "$($backupFolderPath)\RemediatedSQLServers.csv"
                $remediatedSqlServers | Export-CSV -Path $remediatedSqlServersFile -NoTypeInformation
                Write-Host "This information has been saved to [$($remediatedSqlServersFile)]. Use this file only for rollback." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($skippedSqlServers | Measure-Object).Count -gt 0)
            {
                Write-Host "Error enabling AD Admin for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $skippedSqlServers | Format-Table -Property $colsProperty2 -Wrap
                Write-Host $([Constants]::SingleDashLine)

                # Write this to a file.
                $skippedSqlServersFile = "$($backupFolderPath)\SkippedSQLServers.csv"
                $skippedSqlServers | Export-CSV -Path $skippedSqlServersFile -NoTypeInformation
                Write-Host "This information has been saved to $($skippedSqlServersFile)" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
            # Write-Host $([Constants]::DoubleDashLine)
        }

        if($AutoRemediation){
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 100  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "[Step 4 of 4] Enabling Azure AD admin for SQL Servers"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Please provide corresponding AD Administrator Email Id for SQL Servers in the 'EmailId' column of the below file: [$($backupFile)]"  -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:"  -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath [$($backupFile)] and without -DryRun switch, to enable Azure AD admin for all SQL Servers listed in the file."
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Disable-ADAdminForSqlServers
{
    <#
        .SYNOPSIS
        Rolls back remediation done for Azure_SQLDatabase_AuthZ_Use_AAD_Admin' Control.

        .DESCRIPTION
        Rolls back remediation done for Azure_SQLDatabase_AuthZ_Use_AAD_Admin' Control.
        Disables Azure AD admin on the SQL Servers in the Subscription.

        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.

        .PARAMETER Force
        Specifies a forceful roll back without any prompts.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .EXAMPLE
        PS> Disable-ADAdminForSqlServers -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForSQLServers\SQLServersWithADAdminDisabled.csv

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
    Write-Host "[Step 1 of 3] Preparing to disable AAD for SQL Servers in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
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
        Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of [$($context.Account.Id)] is: [$($context.Account.Type)]" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run this script."  -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "Note: To disable Azure AD admin for SQL Server(s) in a Subscription, Contributor and higher privileges on the SQL Server(s) in the Subscription are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
   
    Write-Host "[Step 2 of 3] Preparing to fetch all SQL Server details"
    Write-Host $([Constants]::SingleDashLine)

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all SQL Server(s) details from: [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $sqlServerDetails = Import-Csv -LiteralPath $FilePath
    $validSqlServerDetails = $sqlServerDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ServerName)}
    $totalSqlServers = $(($validSqlServerDetails|measure-object).Count)
    Write-Host "Successfully fetched SQL Server(s) details" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    if ($totalSqlServers -eq 0)
    {
        Write-Host "No SQL Server found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found [$($totalSqlServers)] SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableADAdminForSQLServers"

    $colsProperty3 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"}

    Write-Host "The SQL Server(s) found are as follows:"
    $validSqlServerDetails | Format-Table -Property $colsProperty3 -Wrap
    Write-Host $([Constants]::SingleDashLine)
    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "[Step 3 of 3] Disabling Azure AD admin for SQL Server(s)" 
    Write-Host $([Constants]::SingleDashLine)
    if (-not $Force)
    {
        Write-Host "Do you want to disable Azure AD admin for all SQL Server(s)?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "Azure AD admin will not be disabled for SQL Server(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Azure AD admin will be disabled for SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

    # Includes SQL Servers, to which, previously made changes were successfully rolled back.
    $rolledBackSqlServers = @()

    Write-Host "Disabling Azure AD admin for SQL Server(s)..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    # Includes SQL Servers that were skipped during roll back. There were errors rolling back the changes made previously.
    $skippedSqlServers = @()
    $validSqlServerDetails | ForEach-Object {
        
        $sqlServerInstance = $_
        try
        {
            Write-Host "Disabling Azure AD Admin for the SQL Server: [$($_.ServerName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            if($_.IsSynapseWorkspace -eq $true)
            {
                $adAdmin = Remove-AzSynapseSqlActiveDirectoryAdministrator -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.ServerName
                $rolledBackSqlServers += $sqlServerInstance
            }
            else
            {
                $adAdmin =  Remove-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName -ErrorAction Continue
            }

            if(($adAdmin| Measure-Object).Count -gt 0)
            {
                $rolledBackSqlServers += $sqlServerInstance 
                Write-Host "Successfully disabled Azure AD Admin for SQL Server: [$($_.ServerName)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                $skippedSqlServers += $sqlServerInstance 
                Write-Host "Unsuccessful in disabling Azure AD Admin for SQL Server: [$($_.ServerName)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        catch
        {
            $skippedSqlServers += $sqlServerInstance 
            Write-Host "Error while disabling Azure AD Admin for SQL Server: [$($_.ServerName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
        }
    }

    $colsProperty1 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.ResourceType};Label="Resource Type";Width=30;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"},
                         @{Expression={$_.EmailId};Label="Display Name";Width=35;Alignment="left"}

    $colsProperty2 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.ResourceType};Label="Resource Type";Width=30;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"}

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "RollBack Summary:"

    if ($($rolledBackSqlServers | Measure-Object).Count -gt 0)
    {
        Write-Host "Azure AD admin successfully disabled for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Update)
        $rolledBackSqlServers | Format-Table -Property $colsProperty2 -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $rolledBackSqlServersFile = "$($backupFolderPath)\RolledBackSQLServers.csv"
        $rolledBackSqlServers | Export-CSV -Path $rolledBackSqlServersFile -NoTypeInformation
        Write-Host "This information has been saved to [$($rolledBackSqlServersFile)]" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($($skippedSqlServers | Measure-Object).Count -gt 0)
    {
        Write-Host "Error disabling Azure AD admin for the following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $skippedSqlServers |  Format-Table -Property $colsProperty1 -Wrap
        Write-Host $([Constants]::SingleDashLine)
        # Write this to a file.
        $skippedSqlServersFile = "$($backupFolderPath)\SkippedSQLServers.csv"
        $skippedSqlServers | Export-CSV -Path $skippedSqlServersFile -NoTypeInformation
        Write-Host "This information has been saved to [$($skippedSqlServersFile)]" -ForegroundColor $([Constants]::MessageType.Warning)
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

