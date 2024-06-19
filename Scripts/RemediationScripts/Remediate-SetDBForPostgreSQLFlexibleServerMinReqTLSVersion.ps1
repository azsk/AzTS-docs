<###
# Overview:
    This script is used to set minimium required TLS version and enable secure transport communication for Azure Database for PostgreSQL flexible server in a Subscription.

# Control ID:
    Azure_DBForPostgreSQLFlexibleServer_DP_Use_Secure_TLS_Version

# Display Name:
    Use approved version of TLS for Azure Database for PostgreSQL - Flexible Servers.
    
# Prerequisites:    
    Contributor or higher priviliged role on the Azure Database for PostgreSQL flexible server(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Azure Database for PostgreSQL flexible server(s) in a Subscription that have server parameter ssl_min_protocol_version set as versions less than minimum required TLS version or server parameter require_secure_transport is set to OFF .
        3. Back up details of Azure Database for PostgreSQL flexible server(s) that are to be remediated.
        4. Set supported minimum required TLS version by updating server parameter ssl_min_protocol_version as minimum required TLS version and enable secure transport communication by updating server parameter require_secure_transport to ON for Azure Database for PostgreSQL flexible server(s).

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Azure Database for PostgreSQL flexible server(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the server parameter ssl_min_protocol_version to original value and set server parameter require_secure_transport to ON as per input file.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set supported TLS version for Azure Database for PostgreSQL flexible server(s) in the Subscription. Refer `Examples`, below.
    
    After script execution: 
        As ssl_min_protocol_version is Static parameter that needs server restart for updated value to take effect, server restart is recommended to be done seperately after script execution.
        This script does not restart server to avoid any disruptions to the operations.
    
    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set supported TLS version for Azure Database for PostgreSQL flexible server(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Azure Database for PostgreSQL flexible server(s) in a Subscription that will be remediated:
    
           Set-SecureTLSVersionForDBForPostgreSQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Set TLS version and enable secure transport communication for Azure Database for PostgreSQL flexible server(s) in the Subscription:
       
           Set-SecureTLSVersionForDBForPostgreSQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Set TLS version and enable secure transport communication for Azure Database for PostgreSQL flexible server(s) in the Subscription, from a previously taken snapshot:
       
           Set-SecureTLSVersionForDBForPostgreSQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForDBForPostgreSQLFlexibleServer\DBForPostgreSQLFlexibleServerDetailsBackUp.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Set-SecureTLSVersionForDBForPostgreSQLFlexibleServer -Detailed

    To roll back:
        1. Set TLS version and enable secure transport communication for Azure Database for PostgreSQL flexible server(s) in the Subscription, from a previously taken snapshot:
           Reset-SecureTLSVersionForDBForPostgreSQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForDBForPostgreSQLFlexibleServer/DBForPostgreSQLFlexibleServerDetailsBackUp.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Set-SecureTLSVersionForDBForPostgreSQLFlexibleServer -Detailed        
###>


function Setup-Prerequisites {
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
    $requiredModules = @("Az.Accounts", "Az.PostgreSql")

    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)    
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_) {
            Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host $([Constants]::SingleDashLine)
}


function Set-SecureTLSVersionForDBForPostgreSQLFlexibleServer {
    <#
        .SYNOPSIS
        Remediates 'Azure_DBForPostgreSQLFlexibleServer_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Remediates 'Azure_DBForPostgreSQLFlexibleServer_DP_Use_Secure_TLS_Version' Control.
        Set secure TLS version as minimum required TLS version and enable secure transport communication in Azure Database for PostgreSQL flexible server(s) in the Subscription. 
        
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
        None. You cannot pipe objects to Set-SecureTLSVersionForDBForPostgreSQLFlexibleServer.

        .OUTPUTS
        None. Set-SecureTLSVersionForDBForPostgreSQLFlexibleServer does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-SecureTLSVersionForDBForPostgreSQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-SecureTLSVersionForDBForPostgreSQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-SecureTLSVersionForDBForPostgreSQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForDBForPostgreSQLFlexibleServer\DBForPostgreSQLFlexibleServerDetailsBackUp.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies a forceful remediation without any prompts")]
        $Force,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", HelpMessage = "Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage = "Specifies a dry run of the actual remediation")]
        $DryRun,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the path to the file to be used as input for the remediation")]
        $FilePath,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used")]
        $Path,

        [Switch]        
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies script is run as a subroutine of AutoRemediation Script")]
        $AutoRemediation,

        [String]        
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used")]
        $TimeStamp
    )

    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script and validating the user..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)            
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else {
        Write-Host "[Step 1 of 4] Validate the user... "
        Write-Host $([Constants]::SingleDashLine)
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context)) {
        Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)        
        Write-Host $([Constants]::SingleDashLine)
    }
    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop   

    if (-not($AutoRemediation)) {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }
    Write-Host "To set secure TLS version for Azure Database for PostgreSQL flexible server(s) in the Subscription, Contributor or higher privileged role assignment on the Azure Database for PostgreSQL flexible server(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)  

    Write-Host "[Step 2 of 4] Fetch all Azure Database for PostgreSQL flexible server(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Container details.
    $DBForPostgreSQLFlexibleServerDetails = @()

    # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources = @()	

    $controlIds = "Azure_DBForPostgreSQLFlexibleServer_DP_Use_Secure_TLS_Version"

    # No file path provided as input to the script. Fetch all Azure Database for PostgreSQL flexible server(s) in the Subscription.

    if ($AutoRemediation) {
        if (-not (Test-Path -Path $Path)) {	
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	
        }

        Write-Host "Fetching all Azure Database for PostgreSQL flexible server(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };

        $validResources = $resourceDetails.FailedResourceList | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }	
        if (($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0) {
            	
            Write-Host "No Azure Database for PostgreSQL flexible server(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	
        
        }
        $validResources | ForEach-Object { 	
            try {
                $DBForPostgreSQLFSResource = Get-AzPostgreSqlFlexibleServer -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                $tlsparameterValue = (Get-AzPostgreSqlFlexibleServerConfiguration -Name $([Constants]::ParameterName_TLS)  -ResourceGroupName $_.ResourceGroupName -ServerName $_.ResourceName -SubscriptionId $SubscriptionId).Value
                $sslparameterValue = (Get-AzPostgreSqlFlexibleServerConfiguration -Name $([Constants]::ParameterName_SSL)  -ResourceGroupName $_.ResourceGroupName -ServerName $_.ResourceName -SubscriptionId $SubscriptionId).Value
                $DBForPostgreSQLFlexibleServerDetails += $DBForPostgreSQLFSResource  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                @{N = 'ResourceName'; E = { $_.Name } }, 
                @{N = 'TLSVersion'; E = { $tlsparameterValue } },
                @{N = 'SecureTransportStatus'; E = { $sslparameterValue } }
            }
            catch {
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host "Skipping the Resource:  [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)	
                $logResource = @{}
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                $logResource.Add("ResourceName", ($_.ResourceName))	
                $logResource.Add("Reason", "Valid resource id(s) not found in input json file.")    	
                $logSkippedResources += $logResource	
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Error fetching Azure Database for PostgreSQL flexible server(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }	
        }	
    }
    else {	
        if ([String]::IsNullOrWhiteSpace($FilePath)) {
            Write-Host "Fetching all Azure Database for PostgreSQL flexible server(s) in Subscription: [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all Azure Database for PostgreSQL flexible server(s) in a Subscription
            $servers = @();
            $servers = Get-AzPostgreSqlFlexibleServer -ErrorAction Stop
            $servers | ForEach-Object { 	
                $tlsparameterValue = (Get-AzPostgreSqlFlexibleServerConfiguration -Name $([Constants]::ParameterName_TLS)  -ResourceGroupName $_.Id.Split("/")[4] -ServerName $_.Name -SubscriptionId $SubscriptionId).Value
                $sslparameterValue = (Get-AzPostgreSqlFlexibleServerConfiguration -Name $([Constants]::ParameterName_SSL)  -ResourceGroupName $_.Id.Split("/")[4] -ServerName $_.Name -SubscriptionId $SubscriptionId).Value
                $DBForPostgreSQLFlexibleServerDetails += $_  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                @{N = 'ResourceName'; E = { $_.Name } }, 
                @{N = 'TLSVersion'; E = { $tlsparameterValue } },
                @{N = 'SecureTransportStatus'; E = { $sslparameterValue } }
            }        

        }
        else {
            if (-not (Test-Path -Path $FilePath)) {
                Write-Host "ERROR: Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }

            Write-Host "Fetching all Azure Database for PostgreSQL flexible server(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $DBForPostgreSQLFSResources = Import-Csv -LiteralPath $FilePath

            $validDBForPostgreSQLFSResources = $DBForPostgreSQLFSResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

            $validDBForPostgreSQLFSResources | ForEach-Object {
                $resourceId = $_.ResourceId

                try {                
                    $DBForPostgreSQLFSResource = Get-AzPostgreSqlFlexibleServer -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
            
                    $tlsparameterValue = (Get-AzPostgreSqlFlexibleServerConfiguration -Name $([Constants]::ParameterName_TLS)  -ResourceGroupName $_.ResourceGroupName -ServerName $_.ResourceName -SubscriptionId $SubscriptionId).Value
                    $sslparameterValue = (Get-AzPostgreSqlFlexibleServerConfiguration -Name $([Constants]::ParameterName_SSL)  -ResourceGroupName $_.ResourceGroupName -ServerName $_.ResourceName -SubscriptionId $SubscriptionId).Value
                    $DBForPostgreSQLFlexibleServerDetails += $DBForPostgreSQLFSResource  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                    @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                    @{N = 'ResourceName'; E = { $_.Name } }, 
                    @{N = 'TLSVersion'; E = { $tlsparameterValue } },
                    @{N = 'SecureTransportStatus'; E = { $sslparameterValue } }

                }
                catch {
                    Write-Host "Error fetching Azure Database for PostgreSQL flexible server(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
        }
                                                                
    }
    
    $totalDBForPostgreSQLFS = ($DBForPostgreSQLFlexibleServerDetails | Measure-Object).Count

    if ($totalDBForPostgreSQLFS -eq 0) {
        Write-Host "No Azure Database for PostgreSQL flexible server(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }
  
    Write-Host "Found [$($totalDBForPostgreSQLFS)] Azure Database for PostgreSQL flexible server(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Azure Database for PostgreSQL flexible server(s) for which server parameter require_secure_transport in not ON
    $DBForPostgreSQLFSWithNonSecureTLSVersionEnabled = @()

    Write-Host "Separating Azure Database for PostgreSQL flexible server(s) for which only secure TLS version is not set or secure transport communication is disabled..." -ForegroundColor $([Constants]::MessageType.Info)

    $DBForPostgreSQLFlexibleServerDetails | ForEach-Object {
        if (-not ( (CheckIfOnlySecureTLSVersionConfigured($_.TLSVersion)) -and (CheckIfSSLConfigured($_.SecureTransportStatus)))) {
            $DBForPostgreSQLFSWithNonSecureTLSVersionEnabled += $_
        }
        else {
            $logResource = @{}
            $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
            $logResource.Add("ResourceName", ($_.ResourceName))	
            $logResource.Add("Reason", "TLS version(s) and secure transport configured on this Resource.")    	
            $logSkippedResources += $logResource	
        }
    }
   
    $totalDBForPostgreSQLFSWithNonSecureTLSVersionEnabled = ($DBForPostgreSQLFSWithNonSecureTLSVersionEnabled  | Measure-Object).Count

    if ($totalDBForPostgreSQLFSWithNonSecureTLSVersionEnabled -eq 0) {
        Write-Host "No Azure Database for PostgreSQL flexible server(s) found with non-secure TLS version enabled and secure transport communication is disabled.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        
        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
        return
    }

    Write-Host "Found [$($totalDBForPostgreSQLFSWithNonSecureTLSVersionEnabled )] Azure Database for PostgreSQL flexible server(s) for which non secure TLS version is enabled ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.TLSVersion }; Label = "TLSVersion"; Width = 30; Alignment = "left" },
    @{Expression = { $_.SecureTransportStatus }; Label = "SecureTransportStatus"; Width = 40; Alignment = "left" }

    if (-not $AutoRemediation) {
        Write-Host "Azure Database for PostgreSQL flexible server(s) with non-secure TLS version enabled are:"
        $DBForPostgreSQLFSWithNonSecureTLSVersionEnabled  | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }    
    

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSecureTLSVersionForDBForPostgreSQLFlexibleServer"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 3 of 4] Back up Azure Database for PostgreSQL flexible server(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Azure Database for PostgreSQL flexible server(s) details.
        $backupFile = "$($backupFolderPath)\DBForPostgreSQLFlexibleServerDetailsBackUp.csv"
        $DBForPostgreSQLFSWithNonSecureTLSVersionEnabled  | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Azure Database for PostgreSQL flexible server(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enable secure TLS version on Azure Database for PostgreSQL flexible server(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)
        

        if (-not $Force) {
            Write-Host "Do you want to enable secure TLS version and secure transport communication on Azure Database for PostgreSQL flexible server(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if ($userInput -ne "Y") {
                Write-Host "TLS version and secure transport communication will not be changed for Azure Database for PostgreSQL flexible server(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
        }
        else {
            Write-Host "'Force' flag is provided. Secure TLS version and secure transport communication will be enabled on Azure Database for PostgreSQL flexible server(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        # List for storing remediated Azure Database for PostgreSQL flexible server(s)
        $DBForPostgreSQLFSRemediated = @()

        # List for storing skipped Azure Database for PostgreSQL flexible server(s)
        $DBForPostgreSQLFSSkipped = @()

        Write-Host "Setting secure TLS version and enable secure transport communication on Azure Database for PostgreSQL flexible server(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of Azure Database for PostgreSQL flexible server(s) which needs to be remediated.
        $DBForPostgreSQLFSWithNonSecureTLSVersionEnabled  | ForEach-Object {
            $DBForPostgreSQLFS = $_
            $prevTlsVersion = $DBForPostgreSQLFS.TLSVersion
            $sslStatus = $DBForPostgreSQLFS.SecureTransportStatus
            try {
                if ( -not(CheckIfOnlySecureTLSVersionConfigured($_.TLSVersion))) {
                    $paramValueTLS = (Update-AzPostgreSqlFlexibleServerConfiguration -Name $([Constants]::ParameterName_TLS)  -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -Value $([Constants]::MinRequiredTLSVersionValue)).Value 
                }
                else {
                    $paramValueTLS = $DBForPostgreSQLFS.TLSVersion
                }

                if (-not (CheckIfSSLConfigured($_.SecureTransportStatus))) {
                    $paramValueSSL = (Update-AzPostgreSqlFlexibleServerConfiguration -Name $([Constants]::ParameterName_SSL)  -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -Value $([Constants]::EnableSSLParameterValue)).Value 
                }
                else {
                    $paramValueSSL = $DBForPostgreSQLFS.SecureTransportStatus
                }

                if ((CheckIfOnlySecureTLSVersionConfigured($paramValueTLS)) -and (CheckIfSSLConfigured($paramValueSSL))) {
                    $DBForPostgreSQLFS | Add-Member -NotePropertyName prevTLSVersion -NotePropertyValue $prevTlsVersion
                    $DBForPostgreSQLFS | Add-Member -NotePropertyName prevSecureTransportStatus -NotePropertyValue $sslStatus
                    $DBForPostgreSQLFS.TLSVersion = $paramValueTLS
                    $DBForPostgreSQLFS.SecureTransportStatus = $paramValueSSL
                    
                    $DBForPostgreSQLFSRemediated += $DBForPostgreSQLFS
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))	
                    $logRemediatedResources += $logResource	
                }
                else {
                    $DBForPostgreSQLFSSkipped += $_
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))
                    $logResource.Add("Reason", "Error setting server parameter ssl_min_protocol_version or require_secure_transport: [$($DBForPostgreSQLFS)]")            
                    $logSkippedResources += $logResource	

                }                
            }
            catch {
                $DBForPostgreSQLFSSkipped += $_
                $logResource = @{}	
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                $logResource.Add("ResourceName", ($_.ResourceName))	
                $logResource.Add("Reason", "Encountered error while setting server parameter ssl_min_protocol_version and require_secure_transport")    	
                $logSkippedResources += $logResource	
                Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host $([Constants]::DoubleDashLine)
        
        
        if ($AutoRemediation) {
            if ($($DBForPostgreSQLFSRemediated | Measure-Object).Count -gt 0) {
                
                # Write this to a file.
                $DBForPostgreSQLFSRemediatedFile = "$($backupFolderPath)\RemediatedDBForPostgreSQLFS.csv"
                $DBForPostgreSQLFSRemediated | Export-CSV -Path $DBForPostgreSQLFSRemediatedFile -NoTypeInformation

                Write-Host "The information related to Azure Database for PostgreSQL flexible server(s) where server parameter ssl_min_protocol_version and require_secure_transport changed has been saved to [$($DBForPostgreSQLFSRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        
            if ($($DBForPostgreSQLFSSkipped | Measure-Object).Count -gt 0) {
                $DBForPostgreSQLFSSkipped | Format-Table -Property $colsProperty -Wrap            
                # Write this to a file.
                $DBForPostgreSQLFSSkippedFile = "$($backupFolderPath)\SkippedDBForPostgreSQLFS.csv"
                $DBForPostgreSQLFSSkipped | Export-CSV -Path $DBForPostgreSQLFSSkippedFile -NoTypeInformation
                Write-Host "The information related to Azure Database for PostgreSQL flexible server(s) where server parameter ssl_min_protocol_version or require_secure_transport not changed has been saved to [$($DBForPostgreSQLFSSkippedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

        }
        else {

            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            if ($($DBForPostgreSQLFSRemediated | Measure-Object).Count -gt 0) {
                Write-Host "Successfully set secure TLS version and enabled secure transport communication on the following DBForPostgreSQLFS(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $DBForPostgreSQLFSRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $DBForPostgreSQLFSRemediatedFile = "$($backupFolderPath)\RemediatedDBForPostgreSQLFS.csv"
                $DBForPostgreSQLFSRemediated | Export-CSV -Path $DBForPostgreSQLFSRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($DBForPostgreSQLFSRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            }
        
            if ($($DBForPostgreSQLFSSkipped | Measure-Object).Count -gt 0) {

                Write-Host "Error while setting up the server parameter ssl_min_protocol_version or require_secure_transport for Azure Database for PostgreSQL flexible server(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $DBForPostgreSQLFSSkipped | Format-Table -Property $colsProperty -Wrap
            
                # Write this to a file.
                $DBForPostgreSQLFSSkippedFile = "$($backupFolderPath)\SkippedDBForPostgreSQLFS.csv"
                $DBForPostgreSQLFSSkipped | Export-CSV -Path $DBForPostgreSQLFSSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($DBForPostgreSQLFSSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            }
        }
        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $DBForPostgreSQLFSRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else {
        Write-Host "[Step 4 of 4] Enable secure TLS version and secure transport communication on Azure Database for PostgreSQL flexible server(s) in the Subscription." 
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath [$($backupFile)] and without -DryRun, to set secure TLS version for Azure Database for PostgreSQL flexible server(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Reset-SecureTLSVersionForDBForPostgreSQLFlexibleServer {
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_DBForPostgreSQLFlexibleServer_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_DBForPostgreSQLFlexibleServer_DP_Use_Secure_TLS_Version' Control.
        Change TLS version and secure transport communication to Previous Value on Azure Database for PostgreSQL flexible server(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-SecureTLSVersionForDBForPostgreSQLFlexibleServer.

        .OUTPUTS
        None. Reset-SecureTLSVersionForDBForPostgreSQLFlexibleServer does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-SecureTLSVersionForDBForPostgreSQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForDBForPostgreSQLFlexibleServer\RemediatedDBForPostgreSQLFS.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

        [Switch]
        [Parameter(HelpMessage = "Specifies a forceful roll back without any prompts")]
        $Force,

        [Switch]
        [Parameter(HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the path to the file to be used as input for the roll back")]
        $FilePath
    )

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 3] Validate and install the modules required to run the script and validate the user..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites"	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)	
            return
        }
    }
    else {
        Write-Host "[Step 1 of 3] Validate the user..." 
        Write-Host $([Constants]::SingleDashLine)
    }  

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context)) {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else {
        # Setting up context for the current Subscription.
        $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    }

    
    
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    # Note about the required access required for remediation

    Write-Host "To set secure TLS version and secure transport communication for Azure Database for PostgreSQL flexible server(s) in the Subscription, Contributor or higher privileged role assignment on the Azure Database for PostgreSQL flexible server(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Azure Database for PostgreSQL flexible server(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "Input file:  [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Fetching all Azure Database for PostgreSQL flexible server(s) from" -NoNewline
    Write-Host " [$($FilePath)\...]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $DBForPostgreSQLFlexibleServerDetails = Import-Csv -LiteralPath $FilePath

    $validDBForPostgreSQLFSDetails = $DBForPostgreSQLFlexibleServerDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalDBForPostgreSQLFS = $(($validDBForPostgreSQLFSDetails | Measure-Object).Count)

    if ($totalDBForPostgreSQLFS -eq 0) {
        Write-Host "No Azure Database for PostgreSQL flexible server(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$(($validDBForPostgreSQLFSDetails|Measure-Object).Count)] Azure Database for PostgreSQL flexible server(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 20; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 20; Alignment = "left" },
    @{Expression = { $_.TLSVersion }; Label = "TLSVersion"; Width = 20; Alignment = "left" },
    @{Expression = { $_.prevTLSVersion }; Label = "PreviousTLSVersion"; Width = 20; Alignment = "left" },
    @{Expression = { $_.SecureTransportStatus }; Label = "SecureTransportStatus"; Width = 20; Alignment = "left" },
    @{Expression = { $_.prevSecureTransportStatus }; Label = "PreviousSecureTransportStatus"; Width = 20; Alignment = "left" }
        
    $validDBForPostgreSQLFSDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSecureTLSVersionForDBForPostgreSQLFlexibleServer"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Set TLS version and secure transport communication to previous value on all Azure Database for PostgreSQL flexible server(s) in the Subscription"
    Write-Host $([Constants]::SingleDashLine)

    if ( -not $Force) {
        
        Write-Host "Do you want to change TLS version and secure transport communication for all Azure Database for PostgreSQL flexible server(s) mentioned in the file?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y") {
            Write-Host "TLS version and secure transport communication will not be rolled back on Azure Database for PostgreSQL flexible server(s) mentioned in the file. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "TLS version and secure transport communication will be rolled back on Azure Database for PostgreSQL flexible server(s) mentioned in the file." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "'Force' flag is provided. TLS version will be rolled back on Azure Database for PostgreSQL flexible server(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Service Fabric resource.
    $DBForPostgreSQLFSRolledBack = @()

    # List for storing skipped rolled back DBForPostgreSQLFS resource.
    $DBForPostgreSQLFSSkipped = @()


    $validDBForPostgreSQLFSDetails | ForEach-Object {
        $DBForPostgreSQLFS = $_
        $TlsVersionBeforeRollback = $DBForPostgreSQLFS.TLSVersion
        $SecureTransportStatusBeforeRollback = $DBForPostgreSQLFS.SecureTransportStatus
        try {   
            if ($DBForPostgreSQLFS.TLSVersion -ne $DBForPostgreSQLFS.prevTLSVersion ) {
                
                $tlsVersionRolledBack = (Update-AzPostgreSqlFlexibleServerConfiguration -Name $([Constants]::ParameterName_TLS)  -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -Value $_.prevTLSVersion).Value 
            }
            else {

                $tlsVersionRolledBack = $DBForPostgreSQLFS.TLSVersion
            }

            if ($DBForPostgreSQLFS.SecureTransportStatus -ne $DBForPostgreSQLFS.prevSecureTransportStatus) {
               
                $secureTransportStatusRolledback = (Update-AzPostgreSqlFlexibleServerConfiguration -Name $([Constants]::ParameterName_SSL)  -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -Value $_.prevSecureTransportStatus).Value 
            }
            else {

                $secureTransportStatusRolledback = $DBForPostgreSQLFS.SecureTransportStatus
            }
            
            $DBForPostgreSQLFS.TLSVersion = $tlsVersionRolledBack
            $DBForPostgreSQLFS.prevTLSVersion = $TlsVersionBeforeRollback
            $DBForPostgreSQLFS.SecureTransportStatus = $secureTransportStatusRolledback
            $DBForPostgreSQLFS.prevSecureTransportStatus = $SecureTransportStatusBeforeRollback

            $DBForPostgreSQLFSRolledBack += $DBForPostgreSQLFS
        }
        catch {
            $DBForPostgreSQLFSSkipped += $DBForPostgreSQLFS
        }
    }

        
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
    if ($($DBForPostgreSQLFSRolledBack | Measure-Object).Count -gt 0) {
        Write-Host "TLS version and secure transport communication has been rolled back on the following Azure Database for PostgreSQL flexible server(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
        $DBForPostgreSQLFSRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $DBForPostgreSQLFSRolledBackFile = "$($backupFolderPath)\RolledBackDBForPostgreSQLFS.csv"
        $DBForPostgreSQLFSRolledBack | Export-CSV -Path $DBForPostgreSQLFSRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($DBForPostgreSQLFSRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }

    if ($($DBForPostgreSQLFSSkipped | Measure-Object).Count -gt 0) {
        Write-Host "Error while rolling back TLS version or secure transport communication on Azure Database for PostgreSQL flexible server(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
        $DBForPostgreSQLFSSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

            
        # Write this to a file.
        $DBForPostgreSQLFSSkippedFile = "$($backupFolderPath)\RollbackSkippedDBForPostgreSQLFS.csv"
        $DBForPostgreSQLFSSkipped | Export-CSV -Path $DBForPostgreSQLFSSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($DBForPostgreSQLFSSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }
}
function  CheckIfOnlySecureTLSVersionConfigured {
    param (
        [String] $TLSVersion 
    )
    #Check if TLS Versions less than minimum required TLS versions are supported
    $supportedTLSVersions = @();
    $nonCompliantTLSVersions = @();
    try {
        $supportedTLSVersions = $TLSVersion.ToLower().Replace([Constants]::TLSversionPattern, "").Split(',');
        $supportedTLSVersions | ForEach-Object {
            if ([double] $_ -lt [Constants]::MinRequiredTLSVersion) {
                $nonCompliantTLSVersions += $_
            }
        }
    }
    Catch {
        return $false
    }
    if ($nonCompliantTLSVersions.Count -gt 0) {
        return $false
    }
    else {
        Return $true
    }
    
}

function  CheckIfSSLConfigured {
    param (
        [String] $RequireSecureTransport 
    )
    #Check if server parameter 'require_Secure_transport' is set as ON    
    if ($RequireSecureTransport -eq $([Constants]::EnableSSLParameterValue)) {
        return $true
    }
    else {
        Return $false
    }    
}

# Defines commonly used constants.
class Constants {
    # Defines commonly used colour codes, corresponding to the severity of the log...
    static [Hashtable] $MessageType = @{
        Error   = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info    = [System.ConsoleColor]::Cyan
        Update  = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }
    static [String] $ParameterName_SSL = "require_secure_transport"
    static [String] $EnableSSLParameterValue = "ON"
    static [String] $DisableSSLParameterValue = "OFF"	
    static [String] $ParameterName_TLS = "ssl_min_protocol_version"
    static [String] $TLSversionPattern = "tlsv"
    static [double] $MinRequiredTLSVersion = 1.2
    static [String] $MinRequiredTLSVersionValue = "TLSv1.2"
    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}