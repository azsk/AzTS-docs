﻿<###
# Overview:
    This script is used to set required TLS version for SQL Server in a Subscription.

# Control ID:
    Azure_SQLDatabase_DP_Use_Secure_TLS_Version

# Display Name:
    Use Approved TLS Version in SQL Server.

# Prerequisites:
    1. Contributor or higher privileges on the SQL Servers in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Servers in a Subscription that do not use the required TLS version
        3. Back up details of SQL Servers that are to be remediated.
        4. Set the required TLS version on the all SQL Servers in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Servers in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the previous TLS versions on all SQL Servers in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the required TLS version in all SQL Servers in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the previous TLS versions in all SQL Servers in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the SQL Servers in a Subscription that will be remediated:
           Set-SQLServerRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To set minimal required TLS version  of all SQL Servers in a Subscription:
           Set-SQLServerRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To set minimal required TLS version on the of all SQL Servers in a Subscription, from a previously taken snapshot:
           Set-SQLServerRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSQLServerMinReqTLSVersion\sqlServersWithoutReqMinTLSVersion.csv

        4. To set minimal required TLS version of all SQL Servers in a Subscription without taking back up before actual remediation:
           Set-SQLServerRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Set-SQLServerRequiredTLSVersion -Detailed

    To roll back:
        1. To reset minimal required TLS version of all SQL Servers in a Subscription, from a previously taken snapshot:
           Reset-SQLServerRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSQLServerMinReqTLSVersion\RemediatedsqlServersFileforMinTLS.csv
        
        To know more about the options supported by the roll back command, execute:
        Get-Help Reset-SQLServerRequiredTLSVersion -Detailed        
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

    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)    
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    $AzSqlModule = $availableModules | Where-Object{$_.Name -eq "Az.Sql"} | Sort-Object -Property Version -Descending | Select-Object -First 1
    $AzSqlVersion = $AzSqlModule.Version
    
    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "[$($_)] module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            if($_ -eq "Az.Sql" -and $AzSqlVersion -lt "4.2.0")
            {
                Write-Host "[$($_)] module is present but the version is older." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Installing required version of [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
                Install-Module -Name $_ -AllowClobber -Force -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
                Write-Host "Required version of [$($_)] module is installed." -ForegroundColor $([Constants]::MessageType.Update)
            }
            else
            {
                Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
            }
        }
    }
}

function Set-SQLServerRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Remediates 'Azure_SQLServer_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Remediates 'Azure_SQLServer_DP_Use_Secure_TLS_Version' Control.
        Sets the required minimal TLS version on the all SQL Servers in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER SkipBackup
        Specifies that no back up will be taken by the script before remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Set-SQLServerRequiredTLSVersion.

        .OUTPUTS
        None. Set-SQLServerRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-SQLServerRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-SQLServerRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-SQLServerRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSQLServerMinReqTLSVersion\sqlServersWithoutReqMinTLSVersion.csv

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

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies no back up will be taken by the script before remediation")]
        $SkipBackup,

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
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 5] Validate and install the modules required to run the script and validate the user"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)            
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 5] Validate the user"
        Write-Host $([Constants]::SingleDashLine)
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

    Write-Host "To Set minimal TLS version for SQL Servers in a Subscription, Contributor or higher privileges on the SQL Servers are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 5] Fetch all SQL Servers"
    Write-Host $([Constants]::SingleDashLine)
    $sqlServerResources = @()
    $requiredMinTLSVersion = 1.2


    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()
    
    # Control Id
    $controlIds = "Azure_SQLDatabase_DP_Use_Secure_TLS_Version"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
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
            Write-Host $([Constants]::DoubleDashLine)
            return
        } 

        $validResources | ForEach-Object { 
            try
            {
                $name = $_.ResourceName
                $resourceGroupName = $_.ResourceGroupName
                $resSqlServer = Get-AzSqlServer  -Name $name -ResourceGroupName $resourceGroupName  -ErrorAction SilentlyContinue
                $sqlServerResources = $sqlServerResources + $resSqlServer
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
    }
    else
    {
        # No file path provided as input to the script. Fetch all SQL Servers in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all SQL Server(s) in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all SQL Server(s) in the Subscription
            $sqlServerResources = Get-AzSqlServer  -ErrorAction SilentlyContinue
            $totalsqlServerResources = ($sqlServerResources | Measure-Object).Count
        
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }

            Write-Host "Fetching all SQL Servers(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $sqlServerResourcesFromFile = Import-Csv -LiteralPath $FilePath
            $validsqlServerResources = $sqlServerResourcesFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.ServerName) }
    
            $validsqlServerResources | ForEach-Object {
                $resourceGroupName = $_.ResourceGroupName        
                $serverName = $_.ServerName               

                try
                {
                    $sqlServerResources += (Get-AzSqlServer -ResourceGroupName $resourceGroupName -ServerName $serverName -ErrorAction SilentlyContinue) 

                }
                catch
                {
                    Write-Host "Error fetching SQL Server: [$($serverName)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this SQL Server..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
        }
    }
    
    $totalsqlServerResources = ($sqlServerResources | Measure-Object).Count

    if ($totalsqlServerResources -eq 0)
    {
        Write-Host "No SQL Servers found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($totalsqlServerResources)] SQL Server(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
 
     
    # Includes SQL Servers where minimal required TLS version is set  
    $sqlServersWithReqMinTLSVersion = @()

    # Includes SQL Servers where minimal required TLS version is not set   
    $sqlServersWithoutReqMinTLSVersion = @()

    # Includes SQL Servers that were skipped during remediation. There were errors remediating them.
    $sqlServersSkipped = @()

     
    Write-Host "[Step 3 of 5] Fetching SQL Servers with Minimal TLS less than required Minimal TLS version"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating SQL Server(s) for which Minimal TLS is less than required TLS version ..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $sqlServerResources | ForEach-Object {
        $sqlServer = $_        
        if($_.MinimalTlsVersion -lt $requiredMinTLSVersion) 
        {
            $sqlServersWithoutReqMinTLSVersion +=  $sqlServer | Select-Object @{N='ServerName';E={$_.ServerName}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='Location';E={$_.Location}},
                                                                        @{N='ServerVersion';E={$_.ServerVersion}},
                                                                        @{N='MinimalTlsVersion';E={$_.MinimalTlsVersion}}
        }
        else{
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ServerName))
                $logResource.Add("Reason","Minimal TLS Version already set to required Minimal TLS Version")    
                $logSkippedResources += $logResource
        }
    }

    $totalsqlServersWithoutReqMinTLSVersion = ($sqlServersWithoutReqMinTLSVersion | Measure-Object).Count
     
    if ($totalsqlServersWithoutReqMinTLSVersion  -eq 0)
    {
        Write-Host "No SQL Server(s) found where TLS is less than required TLS version. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        
        if($AutoRemediation -and ($sqlServerResources |Measure-Object).Count -gt 0) 
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

    Write-Host "Found [$($totalsqlServersWithoutReqMinTLSVersion)] SQL servers where TLS version is either not set or less than required minimal TLS version." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
     
    if(-not($AutoRemediation))
    {
        Write-Host "Following SQL Servers are having TLS version either not set or less than required minimal TLS version less than required TLS Version:" -ForegroundColor $([Constants]::MessageType.Info)
        $colsProperty =     @{Expression={$_.ServerName};Label="Server Name";Width=14;Alignment="left"},
                            @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=14;Alignment="left"},
                            @{Expression={$_.minimalTlsVersion};Label="Minimal TLS Version";Width=7;Alignment="left"}

        $sqlServersWithoutReqMinTLSVersion | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSQLServerMinReqTLSVersion"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 4 of 5] Backing up SQL Server(s) details"
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
        if(-not $SkipBackup)
        {
            # Backing up SQL Server details.
            $backupFile = "$($backupFolderPath)\sqlServersWithoutReqMinTLSVersion.csv"
            $sqlServersWithoutReqMinTLSVersion | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "SQL Server(s) details have been successful backed up to [$($backupFolderPath)]" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
  
    
    if (-not $DryRun)
    {  
        # Here AutoRemediation switch is used as there is no need to take user input at BRS level if user has given consent to proceed with the remediation in AutoRemediation Script.
        if(-not $AutoRemediation)
        {

            Write-Host "TLS Version will be set to required TLS version for all SQL Servers(s)." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            if (-not $Force)
            {
                Write-Host "Do you want to set TLS version to required TLS version for all SQL Server(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                
                $userInput = Read-Host -Prompt "(Y|N)" #TODO: 
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "TLS version will not be changed for any SQL Server(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    return
                }
                else
                {
                    Write-Host "Minimal TLS version will be changed for all SQL Server(s)" -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. TLS version will be changed to required TLS version for all SQL Server(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host "[Step 5 of 5] Configuring Minimal TLS version for SQL Server(s)"
        Write-Host $([Constants]::SingleDashLine)
        # To hold results from the remediation.
        $sqlServersRemediated = @()
    
        # Remediate Controls by setting minimum TLS version to required TLS version
        $sqlServersWithoutReqMinTLSVersion | ForEach-Object {
            $sqlServer = $_
            $serverName = $_.ServerName;
            $resourceGroupName = $_.ResourceGroupName; 
            $tls = $_.MinimalTlsVersion;

            # Holds the list of SQL Servers where TLS version change is skipped
            $sqlServersSkipped = @()
            
             
            try
            {   
                $sqlServerTls = Set-AzSqlServer -ServerName $serverName  -ResourceGroupName $resourceGroupName -MinimalTlsVersion $requiredMinTLSVersion

                if ($sqlServerTls.MinimalTlsVersion -ne $requiredMinTLSVersion)
                {
                    $sqlServersSkipped += $sqlServer
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ServerName))
                    $logResource.Add("Reason", "Error while setting the minimum required TLS version for SQL Server")
                    $logSkippedResources += $logResource    
                }
                else
                {
                    $sqlServersRemediated += $sqlServer | Select-Object @{N='ServerName';E={$serverName}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='Location';E={$_.Location}},
                                                                        @{N='ServerVersion';E={$_.ServerVersion}}, 
                                                                        @{N='MinimalTlsVersionBefore';E={$tls}},
                                                                        @{N='MinimalTlsVersionAfter';E={$sqlServerTls.MinimalTlsVersion}}

                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ServerName))
                    $logRemediatedResources += $logResource
 
                }
            }
            catch
            {
                $sqlServersSkipped += $sqlServer
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ServerName))
                $logResource.Add("Reason", "Error while setting the minimum required TLS version for SQL Server")
                $logSkippedResources += $logResource 
            }
        }

        $totalRemediatedSQLServers = ($sqlServersRemediated | Measure-Object).Count
         

        if ($totalRemediatedSQLServers -eq $sqlServersWithoutReqMinTLSVersion)
        {
            Write-Host "TLS Version changed to required TLS version for all [$($totalsqlServersWithoutReqMinTLSVersion)] SQL Server(s) ." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "TLS Version changed to required TLS version for [$($totalRemediatedSQLServers)] out of [$($totalsqlServersWithoutReqMinTLSVersion)] SQL Server(s)" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        $colsProperty = @{Expression={$_.ServerName};Label="Server Name";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersionBefore};Label="Minimal TLS Ver. Before";Width=7;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersionAfter};Label="Minimal TLS Ver. After";Width=7;Alignment="left"}
  
        if($AutoRemediation)
        {
            if ($($sqlServersRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $sqlServersRemediatedFile = "$($backupFolderPath)\RemediatedsqlServersFileforMinTLS.csv"
                $sqlServersRemediated| Export-CSV -Path $sqlServersRemediatedFile -NoTypeInformation
                Write-Host "The information related to SQL Server(s) where minimum required TLS version is successfully set has been saved to [$($sqlServersRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($sqlServersSkipped | Measure-Object).Count -gt 0)
            {   
                # Write this to a file.
                $sqlServerSkippedFile = "$($backupFolderPath)\SkippedsqlServersFileforMinTLS.csv"
                $sqlServersSkipped | Export-CSV -Path $sqlServerSkippedFile -NoTypeInformation
                Write-Host "The information related to SQL Server(s) where minimum required TLS version is not set has been saved to [$($sqlServersSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($sqlServersRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Successfully set the Minimal TLS version to required Minimal TLS version on the following SQL Server(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $sqlServersRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $sqlServersRemediatedFile = "$($backupFolderPath)\RemediatedsqlServersFileforMinTLS.csv"
                $sqlServersRemediated| Export-CSV -Path $sqlServersRemediatedFile -NoTypeInformation
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "This information has been saved to [$($sqlServersRemediatedFile)]"
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($sqlServersSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error changing minimal TLS version for following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $sqlServersSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $sqlServerSkippedFile = "$($backupFolderPath)\SkippedsqlServersFileforMinTLS.csv"
                $sqlServersSkipped | Export-CSV -Path $sqlServerSkippedFile -NoTypeInformation
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "This information has been saved to [$($sqlServerResourcesSkippedFile)]"
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
                    $logControl.RollbackFile = $sqlServersRemediatedFile
                }
            }
            
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "[Step 5 of 5] Changing minimal TLS version for SQL Servers(s)"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps: " -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to change the minimal TLS version to required TLS version for all SQL Server(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Reset-SQLServerRequiredTLSVersion
{
     <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_SQLServer_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_SQLServer_DP_Use_Secure_TLS_Version' Control.
        Resets minimal TLS Version in all SQL Servers in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .Parameter ExcludeNonProductionSlots
        Specifies exclusion of non-production slots from roll back.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-SQLServerRequiredTLSVersion.

        .OUTPUTS
        None. Reset-SQLServerRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-SQLServerRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSQLServerMinReqTLSVersion\RemediatedsqlServersFileforMinTLS.csv


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
            Write-Host "[Step 1 of 4] Validate and install the modules required to run the script and validate the user"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites"	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)	
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 4] Validate the user" 
        Write-Host $([Constants]::SingleDashLine) 
    }  

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        
        Write-Host "Connecting to Azure account..."
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        # Setting up context for the current Subscription.
        $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    }

    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    # Note about the required access required for remediation

    Write-Host "To reset TLS Versions for SQL Server(s) in a Subscription, Contributor or higher privileges on the SQL Server(s) are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all SQL Server(s)"
    Write-Host $([Constants]::SingleDashLine)
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Fetching all SQL Server(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
       
    $sqlServersFromFile = Import-Csv -LiteralPath $FilePath
    $validsqlServers = $sqlServersFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.ServerName) }
    
    $sqlServers = @()
    $sqlServerList = @()

    $validsqlServers | ForEach-Object {
        $server = $_
        $serverName = $_.ServerName
        $resourceGroupName = $_.ResourceGroupName
        $minimalTlsVersionBefore = $_.MinimalTlsVersionBefore
        $minimalTlsVersionAfter = $_.MinimalTlsVersionAfter

        try
        {
            $sqlServerList = ( Get-AzSqlServer -ServerName $serverName  -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue) 
            $sqlServers += $sqlServerList | Select-Object @{N='ServerName';E={$ServerName}},
                                                                    @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                    @{N='Location';E={$_.Location}},
                                                                    @{N='ServerVersion';E={$_.ServerVersion}},
                                                                    @{N='MinimalTlsVersionAfter';E={$_.MinimalTlsVersion}},
                                                                    @{N='MinimalTlsVersionBefore';E={$minimalTlsVersionBefore}}
                                                                


        }
        catch
        {
            Write-Host "Error fetching SQL Server : [$($serverName)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this SQL Server..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
    }


        
    # Includes SQL Servers
    $sqlServersWithChangedTLS = @()
 
    Write-Host "[Step 3 of 4] Fetching SQL Servers with changed TLS Versions(s)"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating SQL Servers where TLS version is changed..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $sqlServers | ForEach-Object {
        $sqlServer = $_        
            if($_.MinimalTlsVersionAfter -ne $_.MinimalTlsVersionBefore)
            {
                $sqlServersWithChangedTLS += $sqlServer
            }
    }

    $totalsqlServersWithChangedTLS = ($sqlServersWithChangedTLS | Measure-Object).Count
     
    if ($totalsqlServersWithChangedTLS  -eq 0)
    {
        Write-Host "No SQL Servers found where minimal TLS version need to be changed.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return
    } 

    
    Write-Host "Found [$($totalsqlServersWithChangedTLS)] SQL Servers " -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
    
     # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\resetSQLServerMinReqTLSVersion"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    } 
    
    if (-not $Force)
    {
        Write-Host "Do you want to reset minimal TLS Version for all SQL Server(s)?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "Minimal TLS Version will not be reseted for any of the SQL Server(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. TLS Version will  be reseted for all of the SQL Server(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

  
 
    Write-Host "[Step 4 of 4] Resetting the minimal TLS Version for SQL Server(s)"
    Write-Host $([Constants]::SingleDashLine)
    # Includes SQL Server(s), to which, previously made changes were successfully rolled back.
    $sqlServersRolledBack = @()

    # Includes SQL Server(s) that were skipped during roll back. There were errors rolling back the changes made previously.
    $sqlServersSkipped = @()

   
     # Roll back by resetting TLS Version
        $sqlServersWithChangedTLS | ForEach-Object {
            $sqlServer = $_
            $serverName = $_.ServerName
            $resourceGroupName = $_.ResourceGroupName
            $minimalTlsVersionBefore = $_.MinimalTlsVersionBefore
            $minimalTlsVersionAfter = $_.MinimalTlsVersionAfter

           
            try
            {  
                if([String]::IsNullOrWhiteSpace($minimalTlsVersionBefore))
                {
                    $sqlServersSkipped += $sqlServer
                    Write-Host "The TLS version for the SQL Server: [$($_.ServerName)] can't be rolled back as it was set to null before remediation and TLS version can't be set to null." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                    return;
                }
                $sqlserverResource =  Set-AzSqlServer -ServerName $serverName  -ResourceGroupName $resourceGroupName -MinimalTlsVersion $minimalTlsVersionBefore

                if ($sqlserverResource.MinimalTlsVersion -ne $minimalTlsVersionBefore)
                {
                    $sqlServersSkipped += $sqlServer
                       
                }
                else
                {
                   
                    $sqlServersRolledBack += $sqlServer | Select-Object @{N='ServerName';E={$ServerName}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='Location';E={$_.Location}},
                                                                        @{N='ServerVersion';E={$_.ServerVersion}}, 
                                                                        @{N='MinimalTlsVersionBefore';E={$MinimalTlsVersionAfter}},
                                                                        @{N='MinimalTlsVersionAfter';E={$sqlserverResource.MinimalTlsVersion}}
                }
            }
            catch
            {
                $sqlServersSkipped += $sqlServer
            }
       }
    

    $totalSqlServersRolledBack = ($sqlServersRolledBack | Measure-Object).Count

    if ($totalsqlServersRolledBack -eq $totalsqlServersWithChangedTLS)
    {
        Write-Host "TLS Version resetted for all [$($totalsqlServersWithChangedTLS)] SQL Server(s) ." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "TLS Version resetted for [$($totalSqlServersRolledBack)] out of [$($totalsqlServersWithChangedTLS)] SQL Servers(s)" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
    
    Write-Host "Rollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
    
    $colsProperty = @{Expression={$_.ServerName};Label="Server Name";Width=14;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resrouce Group";Width=10;Alignment="left"},
                    @{Expression={$_.MinimalTlsVersionBefore};Label="Minimal Tls Version Before";Width=10;Alignment="left"},
                    @{Expression={$_.MinimalTlsVersionAfter};Label="Minimal Tls Version After";Width=10;Alignment="left"}
        

    if ($($sqlServersRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "Resetting TLS for following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Update)
        $sqlServersRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $sqlServersRolledBackFile = "$($backupFolderPath)\RolledBackSQLServerForMinimalTls.csv"
        $sqlServersRolledBack| Export-CSV -Path $sqlServersRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to [$($sqlServersRolledBackFile)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($($sqlServersSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error resetting TLS for following SQL Server(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $sqlServersSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
        
        # Write this to a file.
        $sqlServersSkippedFile = "$($backupFolderPath)\RollbackSkippedSQLServerForMinimalTls.csv"
        $sqlServersSkipped | Export-CSV -Path $sqlServersSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to [$($sqlServersSkippedFile)]"
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