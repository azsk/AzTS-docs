<###
# Overview:
    This script is used to set minimium required TLS version and enable secure client protocol for Redis Enterprise in a Subscription.

#NOTE:
    1. In case of geo replication setting is enabled and is associated with Geo replication group on the Redis Enterprise the configuration client protocol will not be possible to set and will be excluded from remediation.
    2. Rollback is not feasible for Redis Enterprise TLS version (as TLS verison 1.2 is supported and you cannot set any other version now. Previously created version).

# Control ID:
    Azure_RedisEnterprise_DP_Use_TLS_Encrypted_Connections

# Display Name:
   Use approved version of TLS and enable secure client protocol for Redis Enterprise
    
# Prerequisites:    
    Contributor or higher priviliged role on the Redis Enterprise(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Redis Enterprise(s) in a Subscription that have TLS version set as versions less than minimum required TLS version or secure client protocol is disabled.
        3. Back up details of Redis Enterprise(s) that are to be remediated.
        4. Set supported minimum required TLS version and set enable secure client protocol for Redis Enterprise(s).

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Redis Enterprise(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set TLS version and client protocol value which were configured before remediation as per input file.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set supported TLS version and enable secure client protocol for Redis Enterprise(s) in the Subscription. Refer `Examples`, below.
    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set previous TLS version and disable secure client protocol for Redis Enterprise(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Redis Enterprise(s) in a Subscription that will be remediated:
    
            Set-SecureTLSEncryptedConnectionsForRedisEnterprise -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Set TLS version and enable secure client protocol as 'Encrypted' for Redis Enterprise(s) in the Subscription:
       
           Set-SecureTLSEncryptedConnectionsForRedisEnterprise -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Set TLS version and enable secure client protocol as 'Encrypted' for Redis Enterprise(s) in the Subscription, from a previously taken snapshot:
       
           Set-SecureTLSEncryptedConnectionsForRedisEnterprise -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForRedisEnterprise\RedisEnterpriseDetailsBackUp.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Set-SecureTLSEncryptedConnectionsForRedisEnterprise -Detailed

    To roll back:
        1. Set TLS version and enable secure client protocol as 'PlainText" for Redis Enterprise(s) in the Subscription, from a previously taken snapshot:
           Reset-SecureTLSEncryptedConnectionsForRedisEnterprise -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForRedisEnterprise/RedisEnterpriseDetailsBackUp.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Set-SecureTLSEncryptedConnectionsForRedisEnterprise -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.RedisEnterpriseCache")

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

function Set-SecureTLSEncryptedConnectionsForRedisEnterprise {
    <#
        .SYNOPSIS
        Remediates 'Azure_RedisEnterprise_DP_Use_TLS_Encrypted_Connections' Control.

        .DESCRIPTION
        Remediates 'Azure_RedisEnterprise_DP_Use_TLS_Encrypted_Connections' Control.
        Set secure TLS version as minimum required TLS version and enable secure client protocol as 'Encrypted' in Redis Enterprise(s) in the Subscription. 
        
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
        None. You cannot pipe objects to Set-SecureTLSEncryptedConnectionsForRedisEnterprise.

        .OUTPUTS
        None. Set-SecureTLSEncryptedConnectionsForRedisEnterprise does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-SecureTLSEncryptedConnectionsForRedisEnterprise -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-SecureTLSEncryptedConnectionsForRedisEnterprise -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-SecureTLSEncryptedConnectionsForRedisEnterprise -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForRedisEnterprise\RedisEnterpriseDetailsBackUp.csv

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
    Write-Host "To set secure TLS version for Redis Enterprise(s) in the Subscription, Contributor or higher privileged role assignment on the Redis Enterprise(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)  

    Write-Host "[Step 2 of 4] Fetch all Redis Enterprise(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Container details.
    $RedisEnterpriseDetails = @()

    # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources = @()	

    $controlIds = "Azure_RedisEnterprise_DP_Use_TLS_Encrypted_Connections"
    $SecureClientProtocolDatabases = [SecureClientProtocolDatabases]::new()

    # No file path provided as input to the script. Fetch all Redis Enterprise(s) in the Subscription.
    if ($AutoRemediation) {
        if (-not (Test-Path -Path $Path)) {	
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	
        }

        Write-Host "Fetching all Redis Enterprise(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };

        $validResources = $resourceDetails.FailedResourceList | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }	
        if (($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0) {
            	
            Write-Host "No Redis Enterprise(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	    
        }
        $validResources | ForEach-Object { 	
            try {
                $redis = $_
                $databases = @()   
                $RedisEnterpriseResource = Get-AzRedisEnterpriseCache -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction Stop
                $database = Get-AzRedisEnterpriseCacheDatabase -ClusterName $RedisEnterpriseResource.Name -ResourceGroupName  $RedisEnterpriseResource.Id.Split("/")[4] 
                if (($database | measure-object).Count -gt 0) {
                    $databases += $database | Select-Object @{N = 'Name'; E = { $database.Name } },
                    @{N = 'ClientProtocol'; E = { $database.ClientProtocol } },
                    @{N = 'GeoReplicationGroupNickname'; E = { $database.GeoReplicationGroupNickname } }
                }
                $RedisEnterpriseDetails += $RedisEnterpriseResource | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                @{N = 'ResourceName'; E = { $_.Name } }, 
                @{N = 'TLSVersion'; E = { $RedisEnterpriseResource.MinimumTlsVersion } },
                @{N = 'Databases'; E = { $databases } }
            }
            catch {
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host "Skipping the Resource: [$($redis.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)	
                $logResource = @{}
                $logResource.Add("ResourceGroupName", ($redis.ResourceGroupName))	
                $logResource.Add("ResourceName", ($redis.ResourceName))	
                $logResource.Add("Reason", "Valid resource id(s) not found in input json file.")    	
                $logSkippedResources += $logResource	
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Error fetching Redis Enterprise(s) resource: Resource ID:  [$($redis.ResourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }	
        }	
    }
    else {	
        if ([String]::IsNullOrWhiteSpace($FilePath)) {
            Write-Host "Fetching all Redis Enterprise(s) in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all Redis Enterprise(s) in a Subscription
            $redisEnterprise = @();
            $redisEnterprise = Get-AzRedisEnterpriseCache -ErrorAction Stop
            if (($redisEnterprise | Measure-Object).Count -gt 0) {
                $redisEnterprise | ForEach-Object {
                    $databases = @()   
                    $redisEnterpriseResource = $_
                    $database = Get-AzRedisEnterpriseCacheDatabase -ClusterName $redisEnterpriseResource.Name -ResourceGroupName  $redisEnterpriseResource.Id.Split("/")[4] 
                        
                    if (($database | measure-object).Count -gt 0) {
                        $databases += $database | Select-Object @{N = 'Name'; E = { $database.Name } },
                        @{N = 'ClientProtocol'; E = { $database.ClientProtocol } },
                        @{N = 'GeoReplicationGroupNickname'; E = { $database.GeoReplicationGroupNickname } }
                    }
 
                    $RedisEnterpriseDetails += $redisEnterpriseResource | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                    @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                    @{N = 'ResourceName'; E = { $_.Name } }, 
                    @{N = 'TLSVersion'; E = { $RedisEnterpriseResource.MinimumTlsVersion } },
                    @{N = 'Databases'; E = { $databases } }
                }
            }                
        }
        else {
            if (-not (Test-Path -Path $FilePath)) {
                Write-Host "ERROR: Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }

            Write-Host "Fetching all Redis Enterprise(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $RedisEnterpriseResources = Import-Csv -LiteralPath $FilePath

            $validRedisEnterpriseResources = $RedisEnterpriseResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
            $resourceId = $_.ResourceId
            $validRedisEnterpriseResources | ForEach-Object {
                
                try {
                    $databases = @()   
                    $RedisEnterpriseResource = Get-AzRedisEnterpriseCache -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction Stop
                    $database = Get-AzRedisEnterpriseCacheDatabase -ClusterName $RedisEnterpriseResource.Name -ResourceGroupName  $RedisEnterpriseResource.Id.Split("/")[4] 
                    if (($database | measure-object).Count -gt 0) {
                        $databases += $database | Select-Object @{N = 'Name'; E = { $database.Name } },
                        @{N = 'ClientProtocol'; E = { $database.ClientProtocol } },
                        @{N = 'GeoReplicationGroupNickname'; E = { $database.GeoReplicationGroupNickname } }
                    }

                    $RedisEnterpriseDetails += $RedisEnterpriseResource  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                    @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                    @{N = 'ResourceName'; E = { $_.Name } }, 
                    @{N = 'TLSVersion'; E = { $RedisEnterpriseResource.MinimumTlsVersion } },
                    @{N = 'Databases'; E = { $databases } }
                }
                catch {
                    Write-Host "Error fetching Redis Enterprise(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
        }                                                         
    }
    
    $totalRedisEnterprise = ($RedisEnterpriseDetails | Measure-Object).Count

    if ($totalRedisEnterprise -eq 0) {
        Write-Host "No Redis Enterprise(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }
  
    Write-Host "Found [$($totalRedisEnterprise)] Redis Enterprise(s)." -ForegroundColor $([Constants]::MessageType.Update)                                                                    
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Redis Enterprise(s) for which server parameter require_secure_transport in Off or ssl_min_protocol_version is less than TBv1.2.
    $RedisEnterpriseWithNonSecureTLSVersionEnabledOrSecureCommunicationDisabled = @()

    Write-Host "Separating Redis Enterprise(s) for which only secure TLS version is not set or secure client protocol is disabled..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    
    $RedisEnterpriseDetails | ForEach-Object {
        $redisEnterprise = $_
        $geoReplication = $false
        $unsecureDatabase = @()
        $redisEnterprise.Databases | ForEach-Object {
            $db = $_
            if ([String]::IsNullOrWhiteSpace($_.GeoReplicationGroupNickname)) {
                if ( -not (CheckSecureClientConfiguration($_.ClientProtocol))) {
                    $unsecureDatabase += $db.Name 
                }
            }
            else {
                $geoReplication = $true
            }
        }
            
        if (( ( -not (CheckIfOnlySecureTLSVersionConfigured($_.TLSVersion)) -or ($unsecureDatabase | Measure-Object).Count -gt 0)) -and ( -not $geoReplication)) {
            $RedisEnterpriseWithNonSecureTLSVersionEnabledOrSecureCommunicationDisabled += $redisEnterprise | Select-Object @{N = 'ResourceId'; E = { $_.ResourceId } },
            @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName } },
            @{N = 'ResourceName'; E = { $_.ResourceName } }, 
            @{N = 'TLSVersion'; E = { $_.TLSVersion } },
            @{N = 'SecureClientProtocolDisabledDatabases'; E = { $unsecureDatabase } }
        }
        else {
            $logResource = @{}
            $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
            $logResource.Add("ResourceName", ($_.ResourceName))	
            $logResource.Add("Reason", "TLS version(s) and secure transport configured on this Resource.")    	
            $logSkippedResources += $logResource	
        }
    }
   
    $totalRedisEnterpriseWithNonSecureTLSVersionEnabledOrSecureCommunicationDisabled = ($RedisEnterpriseWithNonSecureTLSVersionEnabledOrSecureCommunicationDisabled  | Measure-Object).Count

    if ($totalRedisEnterpriseWithNonSecureTLSVersionEnabledOrSecureCommunicationDisabled -eq 0) {
        Write-Host "No Redis Enterprise(s) found with non-secure TLS version enabled or secure client protocol is disabled.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        
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

    Write-Host "Found [$($totalRedisEnterpriseWithNonSecureTLSVersionEnabledOrSecureCommunicationDisabled )] Redis Enterprise(s) for which non-secure TLS version enabled or secure client protocol is disabled." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.TLSVersion }; Label = "TLSVersion"; Width = 30; Alignment = "left" },
    @{Expression = { $_.SecureClientProtocolDisabledDatabases }; Label = "SecureClientProtocolDisabledDatabases"; Width = 40; Alignment = "left" }

    if (-not $AutoRemediation) {
        Write-Host "Redis Enterprise(s) with non-secure TLS version enabled or secure communication disabled are:"
        $RedisEnterpriseWithNonSecureTLSVersionEnabledOrSecureCommunicationDisabled  | Format-Table -Property $colsProperty -Wrap
    }    
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSecureTLSVersionForRedisEnterprise"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 3 of 4] Back up Redis Enterprise(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Redis Enterprise(s) details.
        $backupFile = "$($backupFolderPath)\RedisEnterpriseDetailsBackUp.csv"
        $RedisEnterpriseWithNonSecureTLSVersionEnabledOrSecureCommunicationDisabled  | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Redis Enterprise(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun) {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "[Step 4 of 4] Enable secure TLS version on Redis Enterprise(s) in the Subscription..." 
        Write-Host "Note: Redis Enterprise(s) for which geo replication is enabled will not be remediated through this script..." -ForegroundColor $([Constants]::MessageType.Warning)

        Write-Host $([Constants]::SingleDashLine)
        
        if (-not $Force) {
            Write-Host "Do you want to enable secure TLS version and secure client protocol on Redis Enterprise(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)  
            $userInput = Read-Host -Prompt "(Y|N)"

            if ($userInput -ne "Y") {
                Write-Host "TLS version and secure client protocol will not be changed for Redis Enterprise(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
        }
        else {
            Write-Host "'Force' flag is provided. Secure TLS version and secure client protocol will be enabled on Redis Enterprise(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        # List for storing remediated Redis Enterprise(s)
        $RedisEnterpriseRemediated = @()

        # List for storing skipped Redis Enterprise(s)
        $RedisEnterpriseSkipped = @()

        Write-Host "Setting secure TLS version and enable secure client protocol on Redis Enterprise(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of Redis Enterprise(s) which needs to be remediated.
        $RedisEnterpriseWithNonSecureTLSVersionEnabledOrSecureCommunicationDisabled  | ForEach-Object {
            $redisEnterprise = $_
            try {
                if ( -not(CheckIfOnlySecureTLSVersionConfigured($_.TLSVersion))) {
                    $redis = Update-AzRedisEnterpriseCache  -MinimumTlsVersion $([Constants]::MinRequiredTLSVersion)  -ResourceGroupName $_.ResourceGroupName  -Name $_.ResourceName 
                    $paramValueTLS = $redis.MinimumTlsVersion
                }
                else {
                    $paramValueTLS = $redisEnterprise.TLSVersion
                }

                $secureClientProtocolEnabledDatabasesLocal = @()
                $secureClientProtocolDisabledDatabasesLocal = @()
                if (($_.SecureClientProtocolDisabledDatabases | Measure-Object).count -gt 0) {
                    $_.SecureClientProtocolDisabledDatabases | ForEach-Object {
                        $database = $SecureClientProtocolDatabases.EnableSecureClientProtocol($subscriptionId, $redisEnterprise.ResourceName, $redisEnterprise.ResourceGroupName, $_, "Enable")
                        if ((CheckIfOnlySecureTLSVersionConfigured($paramValueTLS)) -and (CheckSecureClientConfiguration($database.properties.clientProtocol))) {
                            $secureClientProtocolEnabledDatabasesLocal += $_
                        }
                        else {
                            $secureClientProtocolDisabledDatabasesLocal += $_
                        }
                    }
                }
                $redisEnterprise | Add-Member -NotePropertyName SecureClientProtocolEnabledDatabases -NotePropertyValue ($secureClientProtocolEnabledDatabasesLocal -join ",")
                $redisEnterprise.SecureClientProtocolDisabledDatabases = ($secureClientProtocolDisabledDatabasesLocal -join ",")
                   
                if ((CheckIfOnlySecureTLSVersionConfigured($paramValueTLS)) -and ($secureClientProtocolDisabledDatabasesLocal | Measure-Object).Count -eq 0) {
                    $redisEnterprise.TLSVersion = $paramValueTLS
                    
                    $RedisEnterpriseRemediated += $redisEnterprise
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))	
                    $logRemediatedResources += $logResource	
                }
                else {
                    $RedisEnterpriseSkipped += $_
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))
                    $logResource.Add("Reason", "Error setting secure TLS version or enabling secure client protocol: [$($redisEnterprise)]")            
                    $logSkippedResources += $logResource	

                }                
            }
            catch {
                $redisEnterprise | Add-Member -NotePropertyName SecureClientProtocolEnabledDatabases -NotePropertyValue ($secureClientProtocolEnabledDatabasesLocal -join ",")
                $redisEnterprise.SecureClientProtocolDisabledDatabases = ($secureClientProtocolDisabledDatabasesLocal -join ",")
                    
                $RedisEnterpriseSkipped += $_
                $logResource = @{}	
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                $logResource.Add("ResourceName", ($_.ResourceName))	
                $logResource.Add("Reason", "Encountered error while setting secure TLS version or enabling secure client protocol")    	
                $logSkippedResources += $logResource	
                Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        $colsPropertySummaryPassed = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
        @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
        @{Expression = { $_.TLSVersion }; Label = "TLSVersion"; Width = 30; Alignment = "left" },
        @{Expression = { $_.SecureClientProtocolEnabledDatabases -join "," }; Label = "SecureClientProtocolEnabledDatabases"; Width = 40; Alignment = "left" }

        $colsPropertySummaryFailed = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
        @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
        @{Expression = { $_.TLSVersion }; Label = "TLSVersion"; Width = 30; Alignment = "left" },
        @{Expression = { $_.SecureClientProtocolDisabledDatabases -join "," }; Label = "SecureClientProtocolDisabledDatabases"; Width = 40; Alignment = "left" }
        
        if ($AutoRemediation) {
            if ($($RedisEnterpriseRemediated | Measure-Object).Count -gt 0) {
                
                # Write this to a file.
                $RedisEnterpriseRemediatedFile = "$($backupFolderPath)\RemediatedRedisEnterprise.csv"
                $RedisEnterpriseRemediated | Export-CSV -Path $RedisEnterpriseRemediatedFile -NoTypeInformation

                Write-Host "The information related to Redis Enterprise(s) where server parameter ssl_min_protocol_version and require_secure_transport changed has been saved to [$($RedisEnterpriseRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        
            if ($($RedisEnterpriseSkipped | Measure-Object).Count -gt 0) {
                $RedisEnterpriseSkipped | Format-Table -Property $colsPropertySummaryFailed -Wrap            
                # Write this to a file.
                $RedisEnterpriseSkippedFile = "$($backupFolderPath)\SkippedRedisEnterprise.csv"
                $RedisEnterpriseSkipped | Export-CSV -Path $RedisEnterpriseSkippedFile -NoTypeInformation
                Write-Host "The information related to Redis Enterprise(s) where server parameter ssl_min_protocol_version or require_secure_transport not changed has been saved to [$($RedisEnterpriseSkippedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else {

            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            if ($($RedisEnterpriseRemediated | Measure-Object).Count -gt 0) {
                Write-Host "Successfully set secure TLS version and enabled secure client protocol on the following redisEnterprise(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                
                $RedisEnterpriseRemediated | Format-Table -Property $colsPropertySummaryPassed -Wrap

                # Write this to a file.
                $RedisEnterpriseRemediatedFile = "$($backupFolderPath)\RemediatedRedisEnterprise.csv"
                $RedisEnterpriseRemediated | Export-CSV -Path $RedisEnterpriseRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($RedisEnterpriseRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            }
        
            if ($($RedisEnterpriseSkipped | Measure-Object).Count -gt 0) {

                Write-Host "Error while setting up the server parameter ssl_min_protocol_version or require_secure_transport for Redis Enterprise(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $RedisEnterpriseSkipped | Format-Table -Property $colsPropertySummaryFailed -Wrap
            
                # Write this to a file.
                $RedisEnterpriseSkippedFile = "$($backupFolderPath)\SkippedRedisEnterprise.csv"
                $RedisEnterpriseSkipped | Export-CSV -Path $RedisEnterpriseSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($RedisEnterpriseSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
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
                    $logControl.RollbackFile = $RedisEnterpriseRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "[Step 4 of 4] Enable secure TLS version on Redis Enterprise(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath [$($backupFile)] and without -DryRun, to set secure TLS version for Redis Enterprise(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Reset-SecureTLSEncryptedConnectionsForRedisEnterprise {
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_RedisEnterprise_DP_Use_TLS_Encrypted_Connections' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_RedisEnterprise_DP_Use_TLS_Encrypted_Connections' Control.
        Change TLS version and secure client protocol to Previous Value on Redis Enterprise(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-SecureTLSEncryptedConnectionsForRedisEnterprise.

        .OUTPUTS
        None. Reset-SecureTLSEncryptedConnectionsForRedisEnterprise does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-SecureTLSEncryptedConnectionsForRedisEnterprise -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForRedisEnterprise\RemediatedRedisEnterprise.csv

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
    Write-Host "To set secure client protocol for Redis Enterprise(s) in the Subscription, Contributor or higher privileged role assignment on the Redis Enterprise(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Redis Enterprise(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "Input file:  [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Fetching all Redis Enterprise(s) from" -NoNewline
    Write-Host " [$($FilePath)]" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $RedisEnterpriseDetails = Import-Csv -LiteralPath $FilePath

    $validRedisEnterpriseDetails = $RedisEnterpriseDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalRedisEnterprise = $(($validRedisEnterpriseDetails | Measure-Object).Count)

    if ($totalRedisEnterprise -eq 0) {
        Write-Host "No Redis Enterprise(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$(($validRedisEnterpriseDetails|Measure-Object).Count)] Redis Enterprise(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.TLSVersion }; Label = "TLSVersion"; Width = 20; Alignment = "left" },
    @{Expression = { $_.SecureClientProtocolEnabledDatabases -join "," }; Label = "SecureClientProtocolEnabledDatabases"; Width = 30; Alignment = "left" },
 
    $validRedisEnterpriseDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSecureForRedisEnterprise"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 3 of 3] Set secure client protocol to previous value on all Redis Enterprise(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if ( -not $Force) {    
        Write-Host "Do you want to change secure client protocol for all Redis Enterprise(s) mentioned in the file?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y") {
            Write-Host "Secure client protocol will not be rolled back on Redis Enterprise(s) mentioned in the file. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "Secure client protocol will be rolled back on Redis Enterprise(s) mentioned in the file." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "'Force' flag is provided.Secure client protocol will be rolled back on Redis Enterprise(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Service Fabric resource.
    $RedisEnterpriseRolledBack = @()

    # List for storing skipped rolled back redisEnterprise resource.
    $RedisEnterpriseSkipped = @()

    $SecureClientProtocolDatabases = [SecureClientProtocolDatabases]::new()

    $validRedisEnterpriseDetails | ForEach-Object {
        $redisEnterprise = $_
        try {   
            $secureClientProtocolEnabledDatabasesLocal = @()
            $secureClientProtocolDisabledDatabasesLocal = @()
            $redisEnterprise.SecureClientProtocolEnabledDatabases | ForEach-Object {
            
                $database = $SecureClientProtocolDatabases.EnableSecureClientProtocol($subscriptionId, $redisEnterprise.ResourceName, $redisEnterprise.ResourceGroupName, $_, "disable")
                if ((CheckIfOnlySecureTLSVersionConfigured($paramValueTLS)) -and (CheckSecureClientConfiguration($database.properties.clientProtocol))) {
                    $secureClientProtocolEnabledDatabasesLocal += $_
                }
                else {
                    $secureClientProtocolDisabledDatabasesLocal += $_
                }
            }
             
            $redisEnterprise.SecureClientProtocolEnabledDatabases = $secureClientProtocolEnabledDatabasesLocal -join ","
            $redisEnterprise.SecureClientProtocolDisabledDatabases = $secureClientProtocolDisabledDatabasesLocal -join ","
            $RedisEnterpriseRolledBack += $redisEnterprise
            
        }
        catch {
            $redisEnterprise.SecureClientProtocolEnabledDatabases = $secureClientProtocolEnabledDatabasesLocal -join ","
            $RedisEnterpriseSkipped += $redisEnterprise
        }
    }
   

    $colsPropertySummaryFailed = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.TLSVersion }; Label = "TLSVersion"; Width = 30; Alignment = "left" },
    @{Expression = { $_.SecureClientProtocolEnabledDatabases -join "," }; Label = "SecureClientProtocolEnabledDatabases"; Width = 40; Alignment = "left" }

    $colsPropertySummaryPassed = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.TLSVersion }; Label = "TLSVersion"; Width = 30; Alignment = "left" },
    @{Expression = { $_.SecureClientProtocolDisabledDatabases -join "," }; Label = "SecureClientProtocolDisabledDatabases"; Width = 40; Alignment = "left" }

    Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
        
    if ($($RedisEnterpriseRolledBack | Measure-Object).Count -gt 0) {
        Write-Host "TLS version and secure client protocol has been rolled back on the following Redis Enterprise(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
        $RedisEnterpriseRolledBack | Format-Table -Property $colsPropertySummaryPassed -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $RedisEnterpriseRolledBackFile = "$($backupFolderPath)\RolledBackRedisEnterprise.csv"
        $RedisEnterpriseRolledBack | Export-CSV -Path $RedisEnterpriseRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($RedisEnterpriseRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }

    if ($($RedisEnterpriseSkipped | Measure-Object).Count -gt 0) {
        Write-Host "Error while rolling back TLS version or secure client protocol on Redis Enterprise(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
        $RedisEnterpriseSkipped | Format-Table -Property $colsPropertySummaryFailed -Wrap
        Write-Host $([Constants]::SingleDashLine)
            
        # Write this to a file.
        $RedisEnterpriseSkippedFile = "$($backupFolderPath)\RollbackSkippedRedisEnterprise.csv"
        $RedisEnterpriseSkipped | Export-CSV -Path $RedisEnterpriseSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($RedisEnterpriseSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }
    Write-Host $([Constants]::DoubleDashLine)
}
function  CheckIfOnlySecureTLSVersionConfigured {
    param (
        [String] $TLSVersion 
    )
    #Check if TLS Versions less than minimum required TLS versions are supported
    $nonCompliantTLSVersions = @();
    try {
        if ([double] $TLSVersion -lt [Constants]::MinRequiredTLSVersion) {
            $nonCompliantTLSVersions += $_
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

function  CheckSecureClientConfiguration {
    param (
        [String] $RequireSecureTransport 
    )
    #Check if server parameter 'require_Secure_transport' is set as ON    
    if ($RequireSecureTransport -eq $([Constants]::SecureClientProtocolValue)) {
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
    static [String] $SecureClientProtocolValue = "Encrypted"
    static [String] $UnsecureClientProtocolValue = "PlainText"	
    static [double] $MinRequiredTLSVersion = 1.2
    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}

class SecureClientProtocolDatabases {
    [PSObject] GetAuthHeader() {
        [psobject] $headers = $null
        try {
            $resourceAppIdUri = "https://management.azure.com/"
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
            $headers = @{"Authorization" = $header; "Content-Type" = "application/json"; }
        }
        catch {
            Write-Host "Error occurred while fetching auth header. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)   
        }
        return($headers)
    }

    [PSObject] GetDatabase([string] $subscriptionId, [string] $resourceName, [string] $resourceGroup, [string] $databaseName) {
        $content = $null
        try {
            $armUri = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroup)/providers/Microsoft.Cache/redisEnterprise/$($resourceName)/databases/$($databaseName)?api-version=2024-02-01"
            $headers = $this.GetAuthHeader()
            $method = "GET"
            # API to set local accounts Profile config to Bastion
            $response = Invoke-WebRequest -Method $method -Uri $armUri -Headers $headers -UseBasicParsing
            $content = $response.Content
        }
        catch {
            Write-Host "Error occurred while fetching redisEnterprise configurations. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        }
        return($content)
    }

    

    [PSObject] EnableSecureClientProtocol([string] $subscriptionId, [string] $resourceName, [string] $resourceGroup, [string] $databaseName, [string] $operationType) {
        $content = $null
        $result = $null
        
        try {
            $response = $this.GetDatabase($subscriptionId, $resourceName, $resourceGroup, $databaseName)
            $armUri = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroup)/providers/Microsoft.Cache/redisEnterprise/$($resourceName)/databases/$($databaseName)?api-version=2024-02-01"
            $headers = $this.GetAuthHeader()
            $method = "Put"
            
            if ($operationType -eq "Enable") {
                $response = $response.Replace('"clientProtocol":"Plaintext"', '"clientProtocol":"Encrypted"')  
            }
            else {
                $response = $response.Replace('"clientProtocol":"Encrypted"', '"clientProtocol":"Plaintext"')
            
            }  
            $result = Invoke-WebRequest -Method $method -Uri $armUri -Headers $headers -Body $response -UseBasicParsing
            $content = ConvertFrom-Json $result.Content
        }
        catch {
            Write-Host "Error occurred while enabling secure Redis Enterprise. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        }
        return($content)
    }
}