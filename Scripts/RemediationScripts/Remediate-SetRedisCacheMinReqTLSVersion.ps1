<###
# Overview:
    This script is used to remediate TLS Version on Redis Cache in a Subscription.

# Control ID:
    Azure_RedisCache_DP_Use_Secure_TLS_Version

# Display Name:
    Use approved version of TLS for Azure RedisCache.

# Prerequisites:
    Contributor or higher priviliged role on the Redis Cache(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Redis Cache(s) in a Subscription that TLS Version less than 1.2.
        3. Back up details of Redis Cache(s) that are to be remediated.
        4. Remediate TLS Version on Redis Cache(s) in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Redis Cache(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Roll back port on all Redis Cache(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remediate TLS Version on Redis Cache(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remove access to security scanner identity on all Redis Cache(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Redis Cache(s) in a Subscription that will be remediated:
    
           Set-RedisCacheMinReqTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Set required MinTLSVersion on Redis Cache(s) in the Subscription:
       
           Set-RedisCacheMinReqTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Set required MinTLSVersion on Redis Cache(s) in the Subscription, from a previously taken snapshot:
       
           Set-RedisCacheMinReqTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\MinTLSVersionForRedisCache\NonCompliantTLSRedisCache.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Set-RedisCacheMinReqTLSVersion -Detailed

    To roll back:
        1. Revert back Minimum TLS Version on Redis Cache(s) in the Subscription, from a previously taken snapshot:
           Reset-MinTLSVersionOnRedisCache -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\MinTLSVersionForRedisCache\RemediatedRedisCache.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Reset-RedisCacheMinReqTLSVersion-Detailed        
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

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
             Write-Host "[$($_)] module is installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
}


function Set-RedisCacheMinReqTLSVersion
{
    <#
        .SYNOPSIS
        Remediates 'Azure_RedisCache_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Remediates 'Azure_RedisCache_DP_Use_Secure_TLS_Version' Control.
        Use approved version of TLS for Azure RedisCache. 
        
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
        
        .PARAMETER SkipBackup
        Specifies that no back up will be taken by the script before remediation.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Set-RedisCacheMinReqTLSVersion.

        .OUTPUTS
        None. Set-RedisCacheMinReqTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-RedisCacheMinReqTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-RedisCacheMinReqTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-RedisCacheMinReqTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\MinTLSVersionForRedisCache\NonCompliantTLSRedisCache.csv

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
            Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script and validating the user..."
            Write-Host $([Constants]::SingleDashLine)
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
        Write-Host "[Step 1 of 4] Validating the user... "
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    if(-not($AutoRemediation))
    {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    } 
    
    Write-Host "*** To Set MinTLSVersion on Redis Cache in a Subscription, Contributor or higher privileges on the Redis Cache are required.***" -ForegroundColor $([Constants]::MessageType.Info)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Redis Cache(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store resource details.
    $RedisCacheDetails = @()

    #Required Min TLS Version
    $requiredMinTLSVersion = 1.2

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    #Control id for the control
    $controlIds = "Azure_RedisCache_DP_Use_Secure_TLS_Version"

        # No file path provided as input to the script. Fetch all Redis Cache(s) in the Subscription.
    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "Fetching all Redis Cache(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Redis Cache(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            try
            {
                $RedisCacheDetail =  Get-AzRedisCache -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                $RedisCacheDetails += $RedisCacheDetail | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                      @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                      @{N='ResourceName';E={$_.Name}},
                                                                      @{N='MinimumTlsVersion';E={$_.MinimumTlsVersion}}

            }
            catch
            {
                Write-Host "Valid resource information not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..."
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Valid ResourceName(s)/ResourceGroupName not found in input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }
    else
    {
        # No file path provided as input to the script. Fetch all Redis Cache(s) in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            try
            {
                Write-Host "Fetching all Redis Cache(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

                # Get all Redis Cache(s) in a Subscription
                $RedisCacheDetails =  Get-AzRedisCache -ErrorAction Stop

                # Seperating required properties
                $RedisCacheDetails = $RedisCacheDetails | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ResourceName';E={$_.Name}},
                                                                        @{N='MinimumTlsVersion';E={$_.MinimumTlsVersion}}
            }
            catch
            {
                Write-Host "Error fetching Redis Cache(s) from the subscription. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                $logResource = @{}
                $logResource.Add("SubscriptionID",($SubscriptionId))
                $logResource.Add("Reason","Error fetching Redis Cache(s) information from the subscription.")    
                $logSkippedResources += $logResource
            }    
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                break
            }

            Write-Host "Fetching all Redis Cache(s) from [$($FilePath)]..." 

            $RedisCacheResources = Import-Csv -LiteralPath $FilePath
            $validRedisCacheResources = $RedisCacheResources| Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
        
            $validRedisCacheResources| ForEach-Object {
            $resourceId = $_.ResourceId
                try
                {
                    $RedisCacheResource =  Get-AzRedisCache -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
            
                    $RedisCacheDetails += $RedisCacheResource  | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                              @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                              @{N='ResourceName';E={$_.Name}},
                                                                              @{N='MinimumTlsVersion';E={$_.MinimumTlsVersion}}
                }
                catch
                {
                    Write-Host "Error fetching Redis Cache(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason","Error fetching Redis Cache(s) information.")    
                    $logSkippedResources += $logResource
                }
            }
        }
    }

    $totalRedisCache = ($RedisCacheDetails| Measure-Object).Count

    if ($totalRedisCache -eq 0)
    {
        Write-Host "No Redis Cache(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalRedisCache)] Redis Cache(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Redis Cache(s) where required TLS Version is not configured
    $NonCompliantTLSRedisCache = @()

    Write-Host "Separating Redis Cache(s) for which TLS Version [$($requiredMinTLSVersion)] is not configured..."

    $RedisCacheDetails | ForEach-Object {
        $RedisCache = $_
        if($_.MinimumTlsVersion -lt $requiredMinTLSVersion)
        {
            $NonCompliantTLSRedisCache += $RedisCache
        }
        else
        {
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason","Minimum required TLS Version configured set on Redis Cache.")    
            $logSkippedResources += $logResource
        }
    }
   
    $totalNonCompliantTLSRedisCache  = ($NonCompliantTLSRedisCache | Measure-Object).Count

    if ($totalNonCompliantTLSRedisCache  -eq 0)
    {
        Write-Host "No Redis Cache(s) found with non compliant less than [$($requiredMinTLSVersion)] Min TLS Version.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$($totalNonCompliantTLSRedisCache)] Redis Cache(s) for which Min TLS Version [$($requiredMinTLSVersion)] is not configured." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.MinimumTlsVersion};Label="MinimumTLSVersion";Width=10;Alignment="left"}
        
    $NonCompliantTLSRedisCache | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\MinTLSVersionForRedisCache"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up Redis Cache(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        # Backing up Redis Cache(s) details.
        $backupFile = "$($backupFolderPath)\NonCompliantTLSRedisCache.csv"

        $NonCompliantTLSRedisCache | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Redis Cache(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Use approved version of TLS for Azure RedisCache..." 
        Write-Host $([Constants]::SingleDashLine)
        
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "Do you want to Use approved version of TLS [$($requiredMinTLSVersion)] for Azure RedisCache? " -ForegroundColor $([Constants]::MessageType.Warning)
            
                $userInput = Read-Host -Prompt "(Y|N)"

                if($userInput -ne "Y")
                {
                    Write-Host "Minimum required TLS Version [$($requiredMinTLSVersion)] will not be configured on Redis Cache(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    break
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. Minimum required TLS Version will be configured on Redis Cache(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }

        # List for storing remediated Redis Cache(s)
        $RedisCacheRemediated = @()

        # List for storing skipped Redis Cache(s)
        $RedisCacheSkipped = @()

        Write-Host "Configuring Min TLS Version [$($requiredMinTLSVersion)] on Redis Cache(s)." -ForegroundColor $([Constants]::MessageType.Info)

        # Loop through the list of Redis Cache(s) which needs to be remediated.
        $NonCompliantTLSRedisCache | ForEach-Object {
            $RedisCache = $_
            $RedisCache | Add-Member -NotePropertyName isMinTLSVersionSetPostRemediation -NotePropertyValue $false
            $RedisCache | Add-Member -NotePropertyName PreviousMinimumTlsVersion -NotePropertyValue $RedisCache.MinimumTlsVersion

            Write-Host "Configuring TLS Version [$($requiredMinTLSVersion)] on [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Info)
            try
            {
                # Need to remove this line befor PR review
                if($_.ResourceGroupName -eq 'v-hararoraTestRG')
                {
                $RedisCacheResource = Set-AzRedisCache -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -MinimumTlsVersion $requiredMinTLSVersion
                if($RedisCacheResource.MinimumTlsVersion -ge $requiredMinTLSVersion)
                {
                    $RedisCache.isMinTLSVersionSetPostRemediation = $true
                    $RedisCache.MinimumTlsVersion = $requiredMinTLSVersion
                    $RedisCacheRemediated += $RedisCache
                    
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logRemediatedResources += $logResource
                    Write-Host "Successfully set the minimum required TLS version on Redis Cache." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
                else
                {
                    $RedisCache.isMinTLSVersionSetPostRemediation = $false
                    $RedisCacheSkipped += $RedisCache
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Error occured while setting the minimum required TLS version on Redis cache.")
                    $logSkippedResources += $logResource
                    Write-Host "Skipping this Redis Cache resource." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }
                }
            }
            catch
            {
                $RedisCacheSkipped += $RedisCache
                Write-Host $([Constants]::SingleDashLine)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason", "Error while setting the minimum required TLS version on Redis cache.")
                $logSkippedResources += $logResource
                Write-Host "Skipping this Redis Cache resource." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        $colsPropertyRemediated = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                                  @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                                  @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                                  @{Expression={$_.MinimumTlsVersion};Label="MinimumTLSVersion";Width=10;Alignment="left"},
                                  @{Expression={$_.PreviousMinimumTlsVersion};Label="PreviousMinimumTlsVersion";Width=10;Alignment="left"},
                                  @{Expression={$_.isMinTLSVersionSetPostRemediation};Label="isMinTLSVersionSetPostRemediation";Width=10;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($RedisCacheRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "TLS Version [$($requiredMinTLSVersion)] configured on the following Redis Cache(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
           
            $RedisCacheRemediated | Format-Table -Property $colsPropertyRemediated -Wrap

            # Write this to a file.
            $RedisCacheRemediatedFile = "$($backupFolderPath)\RemediatedRedisCache.csv"
            $RedisCacheRemediated | Export-CSV -Path $RedisCacheRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($RedisCacheRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($RedisCacheSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error configuring Minimum required TLS Version on the following Redis Cache(s)in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
            $RedisCacheSkipped | Format-Table -Property $colsProperty -Wrap
            # Write this to a file.
            $RedisCacheSkippedFile = "$($backupFolderPath)\SkippedRedisCache.csv"
            $RedisCacheSkipped | Export-CSV -Path $RedisCacheSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($RedisCacheSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }

        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $RedisCacheRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Use approved version of TLS[$($requiredMinTLSVersion)] for Azure RedisCache..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "*    Run the same command with -FilePath $($backupFile) and without -DryRun, configure TLS Version on Redis Cache(s) listed in the file."
    }
}

function Reset-RedisCacheMinReqTLSVersion
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_RedisCache_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_RedisCache_DP_Use_Secure_TLS_Version' Control.
        Use approved version of TLS for Azure RedisCache. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-MinTLSVersionOnRedisCache.

        .OUTPUTS
        None. Reset-MinTLSVersionOnRedisCache does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-MinTLSVersionOnRedisCache -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\MinTLSVersionForRedisCache\RemediatedRedisCache.csv

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

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script and validating the user..."
            Write-Host $([Constants]::SingleDashLine)
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
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "*** To configure TLS Version on Redis Cache in a Subscription, Contributor or higher privileges on the Redis Cache are required.***" -ForegroundColor $([Constants]::MessageType.Info)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Redis Cache(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Redis Cache(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $RedisCacheDetails = Import-Csv -LiteralPath $FilePath

    $validRedisCacheDetails = $RedisCacheDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalRedisCache = $(($validRedisCacheDetails|Measure-Object).Count)

    if ($totalRedisCache -eq 0)
    {
        Write-Host "No Redis Cache(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($validRedisCacheDetails|Measure-Object).Count)] Redis Cache(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.MinimumTlsVersion};Label="MinimumTlsVersion";Width=50;Alignment="left"},
                    @{Expression={$_.PreviousMinimumTlsVersion};Label="PreviousMinimumTlsVersion";Width=50;Alignment="left"},
                    @{Expression={$_.isMinTLSVersionSetPostRemediation};Label="isMinTLSVersionSetPostRemediation";Width=50;Alignment="left"}
        
    $validRedisCacheDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RollbackTLSOnRedisCache"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Reverting back TLS Versions for all Redis Cache(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        
        Write-Host "Do you want to roll back previous TLS Versions on all Redis Cache(s) mentioned in the file ?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Minimum TLS Version will not be rolled back for any Redis Cache(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
            Write-Host "Rolling back TLS Versions on Redis Cache(s) in the Subscription." -ForegroundColor $([Constants]::MessageType.Update)

    }
    else
    {
        Write-Host "'Force' flag is provided. Previous TLS Versions will be configured on Redis Cache(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    # List for storing rolled back Redis Cache resource.
    $RedisCacheRolledBack = @()

    # List for storing skipped rolled back Redis Cache resource.
    $RedisCacheSkipped = @()

    $validRedisCacheDetails | ForEach-Object {
        $RedisCache = $_
        $RedisCache | Add-Member -NotePropertyName isMinTLSVersionRolledback -NotePropertyValue $false
        try
        {
            $RedisCacheResource = Set-AzRedisCache -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -MinimumTlsVersion $_.PreviousMinimumTlsVersion
        
            if($RedisCacheResource.MinimumTlsVersion -eq $_.PreviousMinimumTlsVersion)
            {
                $RedisCache.PreviousMinimumTlsVersion = $RedisCache.MinimumTLSVersion
                $RedisCache.MinimumTlsVersion = $RedisCacheResource.MinimumTlsVersion
                $RedisCache.isMinTLSVersionSetPostRemediation = $false
                $RedisCache.isMinTLSVersionRolledback = $true
                $RedisCacheRolledBack += $RedisCache    
            }
            else
            {
                $RedisCache.isMinTLSVersionRolledback = $false
                $RedisCacheSkipped += $RedisCache
            }
        }
        catch
        {
            $RedisCacheSkipped += $RedisCache
        }
    }

    $colsPropertyRollBack = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.MinimumTlsVersion};Label="MinimumTlsVersion";Width=50;Alignment="left"},
                    @{Expression={$_.PreviousMinimumTlsVersion};Label="PreviousMinimumTlsVersion";Width=50;Alignment="left"},
                    @{Expression={$_.isMinTLSVersionRolledback};Label="isMinTLSVersionRolledBack";Width=50;Alignment="left"}
     


    if ($($RedisCacheRolledBack | Measure-Object).Count -gt 0 -or $($RedisCacheSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($RedisCacheRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "TLS Version is rolled back successfully on following Redis Cache(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
            $RedisCacheRolledBack | Format-Table -Property $colsPropertyRollBack -Wrap

            # Write this to a file.
            $RedisCacheRolledBackFile = "$($backupFolderPath)\RolledBackRedisCache.csv"
            $RedisCacheRolledBack | Export-CSV -Path $RedisCacheRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($RedisCacheRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
        }

        if ($($RedisCacheSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error configuring TLS Version on following Redis Cache(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
            $RedisCacheSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $RedisCacheSkippedFile = "$($backupFolderPath)\RollbackSkippedRedisCache.csv"
            $RedisCacheSkipped | Export-CSV -Path $RedisCacheSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($RedisCacheSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
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
