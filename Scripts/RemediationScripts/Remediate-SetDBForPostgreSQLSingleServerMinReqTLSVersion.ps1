<###
# Overview:
    This script is used to set minimium required TLS version and enable ssl enforcement for Azure Database for PostgreSQL single server in a Subscription.
# Control ID:
    Azure_DBforPostgreSQL_DP_Use_Secure_TLS_Version
# Display Name:
    Use approved version of TLS for Azure Database for PostgreSQL - single Server.
    
# Prerequisites:    
    Contributor or higher priviliged role on the Azure Database for PostgreSQL single server(s) is required for remediation.
# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Azure Database for PostgreSQL single server(s) in a Subscription that have server parameter minimaltlsversion set as versions less than minimum required TLS version or parameter SslEnforcement is set to OFF .
        3. Back up details of Azure Database for PostgreSQL single server(s) that are to be remediated.
        4. Set supported minimum required TLS version by updating parameter minimaltlsversion as minimum required TLS version and enable SslEnforcement by updating server parameter SslEnforcement to ON for Azure Database for PostgreSQL single server(s).
    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Azure Database for PostgreSQL single server(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the server parameter minimaltlsversion to original value and set server parameter SslEnforcement to ON as per input file.
# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set supported TLS version for Azure Database for PostgreSQL single server(s) in the Subscription. Refer `Examples`, below.
    
    After script execution: 
        As minimaltlsversion is Static parameter that needs server restart for updated value to take effect, server restart is recommended to be done seperately after script execution.
        This script does not restart server to avoid any disruptions to the operations.
    
    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set supported TLS version for Azure Database for PostgreSQL single server(s) in the Subscription. Refer `Examples`, below.
# Examples:
    To remediate:
        1. To review the Azure Database for PostgreSQL single server(s) in a Subscription that will be remediated:
    
           Set-SecureTLSVersionForDBForPostgreSQLSingleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun
        2. Set TLS version and enable ssl enforcement for Azure Database for PostgreSQL single server(s) in the Subscription:
       
           Set-SecureTLSVersionForDBForPostgreSQLSingleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck
        3. Set TLS version and enable ssl enforcement for Azure Database for PostgreSQL single server(s) in the Subscription, from a previously taken snapshot:
       
           Set-SecureTLSVersionForDBForPostgreSQLSingleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForDBForPostgreSQLSingleServer\DBForPostgreSQLSingleServerDetailsBackUp.csv
        To know more about the options supported by the remediation command, execute:
        
        Get-Help Set-SecureTLSVersionForDBForPostgreSQLSingleServer -Detailed
    To roll back:
        1. Set TLS version and enable ssl enforcement for Azure Database for PostgreSQL single server(s) in the Subscription, from a previously taken snapshot:
           Reset-SecureTLSVersionForDBForPostgreSQLSingleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForDBForPostgreSQLSingleServer/DBForPostgreSQLSingleServerDetailsBackUp.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Set-SecureTLSVersionForDBForPostgreSQLSingleServer -Detailed        
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
    $AzAccountsModule = $availableModules | Where-Object{$_.Name -eq "Az.Accounts"} | Sort-Object -Property Version -Descending | Select-Object -First 1
    $AzAccountsVersion = $AzAccountsModule.Version

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_) {
            Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else {
            if($_ -eq "Az.Accounts" -and $AzAccountsVersion -lt "2.19.0")
            {
                Write-Host "[$($_)] module is present but the version is older." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Installing required version of [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
                Install-Module -Name $_ -AllowClobber -Force -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
                Write-Host "Required version of [$($_)] module is installed." -ForegroundColor $([Constants]::MessageType.Update)
            }
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host $([Constants]::SingleDashLine)
}

function Set-SecureTLSVersionForDBForPostgreSQLSingleServer {
    <#
        .SYNOPSIS
        Remediates 'Azure_DBforPostgreSQL_DP_Use_Secure_TLS_Version' Control.
        .DESCRIPTION
        Remediates 'Azure_DBForPostgreSQL_DP_Use_Secure_TLS_Version' Control.
        Set secure TLS version as minimum required TLS version and enable ssl enforcement in Azure Database for PostgreSQL single server(s) in the Subscription. 
        
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
        None. You cannot pipe objects to Set-SecureTLSVersionForDBForPostgreSQLSingleServer.
        .OUTPUTS
        None. Set-SecureTLSVersionForDBForPostgreSQLSingleServer does not return anything that can be piped and used as an input to another command.
        .EXAMPLE
        PS> Set-SecureTLSVersionForDBForPostgreSQLSingleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun
        .EXAMPLE
        PS> Set-SecureTLSVersionForDBForPostgreSQLSingleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck
        .EXAMPLE
        PS> Set-SecureTLSVersionForDBForPostgreSQLSingleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForDBForPostgreSQLSingleServer\DBForPostgreSQLSingleServerDetailsBackUp.csv
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
    Write-Host "To set secure TLS version for Azure Database for PostgreSQL single server(s) in the Subscription, Contributor or higher privileged role assignment on the Azure Database for PostgreSQL single server(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::DoublDashLine)  

    Write-Host "[Step 2 of 4] Fetch all Azure Database for PostgreSQL single server(s)..."
    Write-Host $([Constants]::SingleDashLine)

    # list to store Container details.
    $DBForPostgreSQLSingleServerDetails = @()

    # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources = @()	

    $controlIds = "Azure_DBforPostgreSQL_DP_Use_Secure_TLS_Version"

    # No file path provided as input to the script. Fetch all Azure Database for PostgreSQL single server(s) in the Subscription.
    if ($AutoRemediation) {
        if (-not (Test-Path -Path $Path)) {	
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	
        }

        Write-Host "Fetching all Azure Database for PostgreSQL single server(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };

        $validResources = $resourceDetails.FailedResourceList | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }	
        if (($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0) {

            Write-Host "No Azure Database for PostgreSQL single server(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	    
        }
        $validResources | ForEach-Object { 	
            try {
                $DBForPostgreSQLSSResource = Get-AzPostgreSqlServer -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                $DBForPostgreSQLSingleServerDetails += $DBForPostgreSQLSSResource  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                @{N = 'ResourceName'; E = { $_.Name } }, 
                @{N = 'TLSVersion'; E = { $_.$([Constants]::ParameterName_TLS) } },
                @{N = 'SSLEnforcement'; E = { $_.sslEnforcement } }
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
                Write-Host "Error fetching Azure Database for PostgreSQL single server(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }	
        }	
    }
    else {	
        if ([String]::IsNullOrWhiteSpace($FilePath)) {
            Write-Host "Fetching all Azure Database for PostgreSQL single server(s) in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all Azure Database for PostgreSQL single server(s) in a Subscription
            $servers = @();
            $servers = Get-AzPostgreSqlServer -ErrorAction Stop
            $servers | ForEach-Object {
                $DBForPostgreSQLSingleServerDetails += $_  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                @{N = 'ResourceName'; E = { $_.Name } }, 
                @{N = 'TLSVersion'; E = { $_.$([Constants]::ParameterName_TLS) } },
                @{N = 'SSLEnforcement'; E = { $_.$([Constants]::ParameterName_SSL) } }
            }        
        }
        else {
            if (-not (Test-Path -Path $FilePath)) {
                Write-Host "ERROR: Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }

            Write-Host "Fetching all Azure Database for PostgreSQL single server(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $DBForPostgreSQLResources = Import-Csv -LiteralPath $FilePath

            $validDBForPostgreSQLSSResources = $DBForPostgreSQLResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
            $validDBForPostgreSQLSSResources | ForEach-Object {
                $resourceId = $_.ResourceId
                try {                
                    $DBForPostgreSQLResource = Get-AzPostgreSqlServer -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                    $DBForPostgreSQLSingleServerDetails += $DBForPostgreSQLResource  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                    @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                    @{N = 'ResourceName'; E = { $_.Name } }, 
                    @{N = 'TLSVersion'; E = { $_.$([Constants]::ParameterName_TLS) } },
                    @{N = 'SSLEnforcement'; E = { $_.$([Constants]::ParameterName_SSL) } }
                }
                catch {
                    Write-Host "Error fetching Azure Database for PostgreSQL single server(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
        }                                                         
    }

    $totalDBForPostgreSQLSS = ($DBForPostgreSQLSingleServerDetails | Measure-Object).Count

    if ($totalDBForPostgreSQLSS -eq 0) {
        Write-Host "No Azure Database for PostgreSQL single server(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalDBForPostgreSQLSS)] Azure Database for PostgreSQL single server(s)." -ForegroundColor $([Constants]::MessageType.Update)                                                                    
    Write-Host $([Constants]::SingleDashLine)

    # list for storing Azure Database for PostgreSQL single server(s) for which parameter sslEnforcement is Off or minimalTlsVersion is less than TBv1.2.
    $DBForPostgreSQLSSWithNonSecureTLSVersionEnabledOrSSLDisabled = @()

    Write-Host "Separating Azure Database for PostgreSQL single server(s) for which only secure TLS version is not set or sslEnforcement is disabled..." -ForegroundColor $([Constants]::MessageType.Info)

    $DBForPostgreSQLSingleServerDetails | ForEach-Object {
        if (-not ( (CheckIfOnlySecureTLSVersionConfigured($_.TLSVersion)) -and (CheckIfSSLConfigured($_.SSLEnforcement)))) {
            $DBForPostgreSQLSSWithNonSecureTLSVersionEnabledOrSSLDisabled += $_
        }
        else {
            $logResource = @{}
            $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
            $logResource.Add("ResourceName", ($_.ResourceName))	
            $logResource.Add("Reason", "TLS version(s) and SSL configured on this Resource.")    	
            $logSkippedResources += $logResource	
        }
    }

    $totalDBForPostgreSQLSSWithNonSecureTLSVersionEnabledOrSSLDisabled = ($DBForPostgreSQLSSWithNonSecureTLSVersionEnabledOrSSLDisabled  | Measure-Object).Count

    if ($totalDBForPostgreSQLSSWithNonSecureTLSVersionEnabledOrSSLDisabled -eq 0) {
        Write-Host "No Azure Database for PostgreSQL single server(s) found with non-secure TLS version enabled or ssl enforcement is disabled.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)

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

    Write-Host "Found [$($totalDBForPostgreSQLSSWithNonSecureTLSVersionEnabledOrSSLDisabled )] Azure Database for PostgreSQL single server(s) for which non secure TLS version is enabled or ssl enforcement is disabled." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.TLSVersion }; Label = "TLSVersion"; Width = 30; Alignment = "left" },
    @{Expression = { $_.SSLEnforcement }; Label = "SSLEnforcement"; Width = 40; Alignment = "left" }

    if (-not $AutoRemediation) {
        Write-Host "Azure Database for PostgreSQL single server(s) with non-secure TLS version enabled or SSL enforcement disabled are:"
        $DBForPostgreSQLSSWithNonSecureTLSVersionEnabledOrSSLDisabled  | Format-Table -Property $colsProperty -Wrap
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSecureTLSVersionForDBForPostgreSQLSingleServer"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Back up Azure Database for PostgreSQL single server(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Azure Database for PostgreSQL single server(s) details.
        $backupFile = "$($backupFolderPath)\DBForPostgreSQLSingleServerDetailsBackUp.csv"
        $DBForPostgreSQLSSWithNonSecureTLSVersionEnabledOrSSLDisabled  | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Azure Database for PostgreSQL single server(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enable secure TLS version on Azure Database for PostgreSQL single server(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)

        if (-not $Force) {
            Write-Host "Do you want to enable secure TLS version and enable SSL enforcement on Azure Database for PostgreSQL single server(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)

            $userInput = Read-Host -Prompt "(Y|N)"

            if ($userInput -ne "Y") {
                Write-Host "TLS version and SSL enforcement will not be changed for Azure Database for PostgreSQL single server(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
        }
        else {
            Write-Host "'Force' flag is provided. Secure TLS version and SSL enforcement will be enabled on Azure Database for PostgreSQL single server(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        # List for storing remediated Azure Database for PostgreSQL single server(s)
        $DBForPostgreSQLSSRemediated = @()

        # List for storing skipped Azure Database for PostgreSQL single server(s)
        $DBForPostgreSQLSSSkipped = @()

        Write-Host "Setting secure TLS version and enable SSL enforcement on Azure Database for PostgreSQL single server(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of Azure Database for PostgreSQL single server(s) which needs to be remediated.
        $DBForPostgreSQLSSWithNonSecureTLSVersionEnabledOrSSLDisabled  | ForEach-Object {
            $DBForPostgreSQLSS = $_
            $prevTlsVersion = $DBForPostgreSQLSS.TLSVersion
            $sslStatus = $DBForPostgreSQLSS.SSLEnforcement
            try {
                $paramValueTLS = $DBForPostgreSQLSS.TLSVersion
                $paramValueSSL = $DBForPostgreSQLSS.SSLEnforcement
                if ( -not (CheckIfSSLConfigured($_.SSLEnforcement))) {
                    $UpdateDBForPostgreSQLSS = Update-AzPostgreSqlServer -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -sslEnforcement $([Constants]::EnableSSLParameterValue) -minimalTlsVersion $([Constants]::MinRequiredTLSVersionValue)
                    $paramValueSSL = $UpdateDBForPostgreSQLSS.$([Constants]::ParameterName_SSL)
                    $paramValueTLS = $UpdateDBForPostgreSQLSS.$([Constants]::ParameterName_TLS)
                }
                else {
                    $UpdateDBForPostgreSQLSS = Update-AzPostgreSqlServer -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -minimalTlsVersion $([Constants]::MinRequiredTLSVersionValue)
                    $paramValueSSL = $UpdateDBForPostgreSQLSS.$([Constants]::ParameterName_SSL)
                    $paramValueTLS = $UpdateDBForPostgreSQLSS.$([Constants]::ParameterName_TLS)
                }

                if ((CheckIfSSLConfigured($paramValueSSL)) -and (CheckIfOnlySecureTLSVersionConfigured($paramValueTLS))) {
                    $DBForPostgreSQLSS | Add-Member -NotePropertyName prevTLSVersion -NotePropertyValue $prevTlsVersion
                    $DBForPostgreSQLSS | Add-Member -NotePropertyName prevSSLEnforcement -NotePropertyValue $sslStatus
                    $DBForPostgreSQLSS.TLSVersion = $paramValueTLS
                    $DBForPostgreSQLSS.SSLEnforcement = $paramValueSSL

                    $DBForPostgreSQLSSRemediated += $DBForPostgreSQLSS
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))	
                    $logRemediatedResources += $logResource	
                }
                else {
                    $DBForPostgreSQLSSSkipped += $_
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))
                    $logResource.Add("Reason", "Error setting parameter TLSVersion or ssl enforcement: [$($DBForPostgreSQLSS)]")            
                    $logSkippedResources += $logResource	

                }                
            }
            catch {
                $DBForPostgreSQLSSSkipped += $_
                $logResource = @{}	
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                $logResource.Add("ResourceName", ($_.ResourceName))	
                $logResource.Add("Reason", "Encountered error while setting parameter TLSVersion and ssl enforcement")    	
                $logSkippedResources += $logResource	
                Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host $([Constants]::DoubleDashLine)

        if ($AutoRemediation) {
            if ($($DBForPostgreSQLSSRemediated | Measure-Object).Count -gt 0) {

                # Write this to a file.
                $DBForPostgreSQLSSRemediatedFile = "$($backupFolderPath)\RemediatedDBForPostgreSQLSS.csv"
                $DBForPostgreSQLSSRemediated | Export-CSV -Path $DBForPostgreSQLSSRemediatedFile -NoTypeInformation

                Write-Host "The information related to Azure Database for PostgreSQL single server(s) where parameter TLSVersion or ssl enforcement changed has been saved to [$($DBForPostgreSQLSSRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($DBForPostgreSQLSSSkipped | Measure-Object).Count -gt 0) {
                $DBForPostgreSQLSSSkipped | Format-Table -Property $colsProperty -Wrap            
                # Write this to a file.
                $DBForPostgreSQLSSSkippedFile = "$($backupFolderPath)\SkippedDBForPostgreSQLSS.csv"
                $DBForPostgreSQLSSSkipped | Export-CSV -Path $DBForPostgreSQLSSSkippedFile -NoTypeInformation
                Write-Host "The information related to Azure Database for PostgreSQL single server(s) where parameter TLSVersion or ssl enforcement not changed has been saved to [$($DBForPostgreSQLSSSkippedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else {

            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            if ($($DBForPostgreSQLSSRemediated | Measure-Object).Count -gt 0) {
                Write-Host "Successfully set secure TLS version and enabled ssl enforcement on the following DBForPostgreSQLSS(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $DBForPostgreSQLSSRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $DBForPostgreSQLSSRemediatedFile = "$($backupFolderPath)\RemediatedDBForPostgreSQLSS.csv"
                $DBForPostgreSQLSSRemediated | Export-CSV -Path $DBForPostgreSQLSSRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($DBForPostgreSQLSSRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            }

            if ($($DBForPostgreSQLSSSkipped | Measure-Object).Count -gt 0) {

                Write-Host "Error while setting up the parameter TLSVersion or ssl enforcement for Azure Database for PostgreSQL single server(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $DBForPostgreSQLSSSkipped | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $DBForPostgreSQLSSSkippedFile = "$($backupFolderPath)\SkippedDBForPostgreSQLSS.csv"
                $DBForPostgreSQLSSSkipped | Export-CSV -Path $DBForPostgreSQLSSSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($DBForPostgreSQLSSSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            }
            Write-Host $([Constants]::DoubleDashLine)
        }
        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $DBForPostgreSQLSSRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enable secure TLS version on Azure Database for PostgreSQL single server(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath [$($backupFile)] and without -DryRun, to set secure TLS version for Azure Database for PostgreSQL single server(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Reset-SecureTLSVersionForDBForPostgreSQLSingleServer {
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_DBForPostgreSQLSingleServer_DP_Use_Secure_TLS_Version' Control.
        .DESCRIPTION
        Rolls back remediation done for 'Azure_DBForPostgreSQLSingleServer_DP_Use_Secure_TLS_Version' Control.
        Change TLS version and SSL enforcement to Previous Value on Azure Database for PostgreSQL single server(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.
        .INPUTS
        None. You cannot pipe objects to Reset-SecureTLSVersionForDBForPostgreSQLSingleServer.
        .OUTPUTS
        None. Reset-SecureTLSVersionForDBForPostgreSQLSingleServer does not return anything that can be piped and used as an input to another command.
        .EXAMPLE
        PS> Reset-SecureTLSVersionForDBForPostgreSQLSingleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForDBForPostgreSQLSingleServer\RemediatedDBForPostgreSQLSS.csv
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

    Write-Host $([Constants]::DoubleDashLine)	
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
    Write-Host "To set secure TLS version and ssl enforcement for Azure Database for PostgreSQL single server(s) in the Subscription, Contributor or higher privileged role assignment on the Azure Database for PostgreSQL single server(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Azure Database for PostgreSQL single server(s)..."
    Write-Host $([Constants]::SingleDashLine)

    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "Input file:  [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Fetching all Azure Database for PostgreSQL single server(s) from" -NoNewline
    Write-Host " [$($FilePath)]" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $DBForPostgreSQLSingleServerDetails = Import-Csv -LiteralPath $FilePath

    $validDBForPostgreSQLSSDetails = $DBForPostgreSQLSingleServerDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalDBForPostgreSQLSS = $(($validDBForPostgreSQLSSDetails | Measure-Object).Count)

    if ($totalDBForPostgreSQLSS -eq 0) {
        Write-Host "No Azure Database for PostgreSQL single server(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$(($validDBForPostgreSQLSSDetails|Measure-Object).Count)] Azure Database for PostgreSQL single server(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.TLSVersion }; Label = "TLSVersion"; Width = 30; Alignment = "left" },
    @{Expression = { $_.prevTLSVersion }; Label = "PreviousTLSVersion"; Width = 30; Alignment = "left" },
    @{Expression = { $_.SSLEnforcement }; Label = "SSLEnforcement"; Width = 30; Alignment = "left" },
    @{Expression = { $_.prevSSLEnforcement }; Label = "previousSSLEnforcement"; Width = 30; Alignment = "left" }

    $validDBForPostgreSQLSSDetails | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSecureTLSVersionForDBForPostgreSQLSingleServer"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Set TLS version and SSLEnforcement to previous value on all Azure Database for PostgreSQL single server(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if ( -not $Force) {    
        Write-Host "Do you want to change TLS version and SSLEnforcement for all Azure Database for PostgreSQL single server(s) mentioned in the file?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y") {
            Write-Host "TLS version and SSLEnforcement will not be rolled back on Azure Database for PostgreSQL single server(s) mentioned in the file. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "TLS version and SSLEnforcement will be rolled back on Azure Database for PostgreSQL single server(s) mentioned in the file." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "'Force' flag is provided. TLS version and SSLEnforcement will be rolled back on Azure Database for PostgreSQL single server(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Service Fabric resource.
    $DBForPostgreSQLSSRolledBack = @()

    # List for storing skipped rolled back DBForPostgreSQLSS resource.
    $DBForPostgreSQLSSSkipped = @()

    $validDBForPostgreSQLSSDetails | ForEach-Object {
        $DBForPostgreSQLSS = $_
        $TlsVersionBeforeRollback = $_.TLSVersion
        $SSLEnforcementBeforeRollback = $_.SSLEnforcement
        try {   
            if ($_.SSLEnforcement -ne $_.prevSSLEnforcement) {
                $RolledBackDBForPOstgreSQLSS = Update-AzPostgreSqlServer -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -sslEnforcement $_.prevSSLEnforcement
                $SSLEnforcementRolledback = $RolledBackDBForPOstgreSQLSS.$([Constants]::ParameterName_SSL)
                $tlsVersionRolledBack = $RolledBackDBForPOstgreSQLSS.$([Constants]::ParameterName_TLS)
            } elseif($_.TLSVersion -ne $_.prevTLSVersion ){
                $tlsVersionRolledBack = (Update-AzPostgreSqlServer -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -minimalTlsVersion $_.prevTLSVersion).$([Constants]::ParameterName_TLS)
            } else {
                $SSLEnforcementRolledback = $_.SSLEnforcement
                $tlsVersionRolledBack = $_.TLSVersion
            }

            $DBForPostgreSQLSS.TLSVersion = $tlsVersionRolledBack
            $DBForPostgreSQLSS.prevTLSVersion = $TlsVersionBeforeRollback
            $DBForPostgreSQLSS.SSLEnforcement = $SSLEnforcementRolledback
            $DBForPostgreSQLSS.prevSSLEnforcement = $SSLEnforcementBeforeRollback
            $DBForPostgreSQLSSRolledBack += $DBForPostgreSQLSS
        }
        catch {
            $DBForPostgreSQLSSSkipped += $DBForPostgreSQLSS
        }
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

    if ($($DBForPostgreSQLSSRolledBack | Measure-Object).Count -gt 0) {
        Write-Host "TLS version and SSL enforcement has been rolled back on the following Azure Database for PostgreSQL single server(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
        $DBForPostgreSQLSSRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $DBForPostgreSQLSSRolledBackFile = "$($backupFolderPath)\RolledBackDBForPostgreSQLSS.csv"
        $DBForPostgreSQLSSRolledBack | Export-CSV -Path $DBForPostgreSQLSSRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($DBForPostgreSQLSSRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }

    if ($($DBForPostgreSQLSSSkipped | Measure-Object).Count -gt 0) {
        Write-Host "Error while rolling back TLS version or SSL enforcement on Azure Database for PostgreSQL single server(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
        $DBForPostgreSQLSSSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $DBForPostgreSQLSSSkippedFile = "$($backupFolderPath)\RollbackSkippedDBForPostgreSQLSS.csv"
        $DBForPostgreSQLSSSkipped | Export-CSV -Path $DBForPostgreSQLSSSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($DBForPostgreSQLSSSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }
    Write-Host $([Constants]::DoubleDashLine)
}

function  CheckIfOnlySecureTLSVersionConfigured {
    param (
        [String] $TLSVersion 
    )
    #Check if TLS Versions less than minimum required TLS versions are supported
    $supportedTLSVersions = @();
    $nonCompliantTLSVersions = @();
    try {
        $supportedTLSVersions = $TLSVersion.ToLower() -replace [Constants]::TLSversionPattern, '' -replace '_', '.';
        $supportedTLSVersions | ForEach-Object {
            if ([double] $_ -lt [Constants]::MinRequiredTLSVersion) {
                $nonCompliantTLSVersions += $_
            }
        }
    }
    catch {
        return $false
    }
    if ($nonCompliantTLSVersions.Count -gt 0) {
        return $false
    }
    else {
        return $true
    }    
}

function  CheckIfSSLConfigured {
    param (
        [String] $SSLParameter 
    )
    #Check if server parameter 'sslEnforcement' is set as ON    
    if ($SSLParameter -eq $([Constants]::EnableSSLParameterValue)) {
        return $true
    }
    else {
        return $false
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
    static [String] $ParameterName_SSL = "sslEnforcement"
    static [String] $EnableSSLParameterValue = "Enabled"
    static [String] $DisableSSLParameterValue = "Disabled"	
    static [String] $ParameterName_TLS = "minimalTlsVersion"
    static [String] $TLSversionPattern = "tls"
    static [double] $MinRequiredTLSVersion = 1.2
    static [String] $MinRequiredTLSVersionValue = "TLS1_2"
    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}