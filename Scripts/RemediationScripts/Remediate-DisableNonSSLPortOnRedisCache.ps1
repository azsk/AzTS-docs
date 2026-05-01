<###
# Overview:
    This script is used to disable Non-SSL port on Redis Cache in a Subscription.

# Control ID:
    Azure_RedisCache_DP_Use_SSL_Port

# Display Name:
    Non-SSL port must not be enabled.

# Prerequisites:
    
    Contributor or higher priviliged role on the Redis Cache(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Redis Cache(s) in a Subscription that have Non-SSL port enabled.
        3. Back up details of Redis Cache(s) that are to be remediated.
        4. Disable Non-SSL port on Redis Cache(s) in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Redis Cache(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Enable Non-SSL port on all Redis Cache(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script Disable Non-SSL port on Redis Cache(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remove access to security scanner identity on all Redis Cache(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Redis Cache(s) in a Subscription that will be remediated:
    
           Disable-NonSSLPortOnRedisCache -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Disable Non-SSL port on Redis Cache(s) in the Subscription:
       
           Disable-NonSSLPortOnRedisCache -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Disable Non-SSL port on Redis Cache(s) in the Subscription, from a previously taken snapshot:
       
           Disable-NonSSLPortOnRedisCache -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\DisableNonSSLPortForRedisCache\RedisCacheWithNonSSLPortEnabled.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Disable-NonSSLPortOnRedisCache -Detailed

    To roll back:
        1. Enable Non-SSL port on Redis Cache(s) in the Subscription, from a previously taken snapshot:
           Enable-NonSSLPortOnRedisCache -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\DisableNonSSLPortForRedisCache\RemediatedRedisCache.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Enable-NonSSLPortOnRedisCache -Detailed        
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

    Write-Host "Required modules: $($requiredModules -join ', ')"     
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Check if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
             Write-Host "[$($_)] module is installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host $([Constants]::SingleDashLine)
}


function Disable-NonSSLPortOnRedisCache
{
    <#
        .SYNOPSIS
        Remediates 'Azure_RedisCache_DP_Use_SSL_Port' Control.

        .DESCRIPTION
        Remediates 'Azure_RedisCache_DP_Use_SSL_Port' Control.
        Disable Non-SSL port on Redis Cache(s) in the Subscription. 
        
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
        None. You cannot pipe objects to Disable-NonSSLPortOnRedisCache.

        .OUTPUTS
        None. Disable-NonSSLPortOnRedisCache does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-NonSSLPortOnRedisCache -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Disable-NonSSLPortOnRedisCache -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Disable-NonSSLPortOnRedisCache -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\DisableNonSSLPortForRedisCache\RedisCacheWithNonSSLPortEnabled.csv

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
    Write-Host "[Step 1 of 4] Prepare to disable NON SSL port for Redis Cache in Subscription: [$($SubscriptionId)]"    
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
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "No active Azure login session found. You may try running command 'Connect-AzAccount -Subscription 'subsId'' to connect to azure account. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
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
    
	    
    Write-Host "To Disable Non-SSL port on Redis Cache in a Subscription, Contributor or higher privileges on the Redis Cache are required." -ForegroundColor $([Constants]::MessageType.Warning)   
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Fetch all Redis Cache(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Container details.
    $RedisCacheDetails = @()

     # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    # Control Id
    $controlIds = "Azure_RedisCache_DP_Use_SSL_Port"

    if($AutoRemediation)
    {
        if (-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Please verify if path is correct or failing controls details are available on the given path. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }

        Write-Host "Fetch all Redis Cache for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Redis Cache(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            $resourceId = $_.ResourceId
            try
            {
                $RedisCacheResource =  Get-AzRedisCache -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue            
                $RedisCacheDetails += $RedisCacheResource  | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                          @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                          @{N='ResourceName';E={$_.Name}},
                                                                          @{N='Enable_Non_SSLPort';E={$_.EnableNonSslPort}}
            }
            catch
            {
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skip the Resource: [$($_.ResourceName)]..."
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
         # No file path provided as input to the script. Fetch all Redis Cache(s) in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetch all Redis Cache(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all Redis Cache(s) in a Subscription
        $RedisCacheDetails =  Get-AzRedisCache -ErrorAction Stop

        # Seperating required properties
        $RedisCacheDetails = $RedisCacheDetails | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                          @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                          @{N='ResourceName';E={$_.Name}},
                                                                          @{N='Enable_Non_SSLPort';E={$_.EnableNonSslPort}}
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }

        Write-Host "Fetch all Redis Cache(s) from [$($FilePath)]..." 

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
                                                                          @{N='Enable_Non_SSLPort';E={$_.EnableNonSslPort}}
            }
            catch
            {
                Write-Host "Error fetching Redis Cache(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }

    }
   

    $totalRedisCache = ($RedisCacheDetails| Measure-Object).Count

    if ($totalRedisCache -eq 0)
    {
        Write-Host "No Redis Cache(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }
  
    Write-Host "Found [$($totalRedisCache)] Redis Cache(s)." -ForegroundColor $([Constants]::MessageType.Update)                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Redis Cache(s) for which Non-SSL port is enabled.
    $RedisCacheWithNonSSLPortEnabled = @()

    Write-Host "Separate Redis Cache(s) for which Non-SSL port is enabled."

    $RedisCacheDetails | ForEach-Object {
        $RedisCache = $_
        if($_.Enable_Non_SSLPort)
        {
            $RedisCacheWithNonSSLPortEnabled += $RedisCache
        }
    }
   
    $totalRedisCacheWithNonSSLPortEnabled  = ($RedisCacheWithNonSSLPortEnabled | Measure-Object).Count

    if ($totalRedisCacheWithNonSSLPortEnabled  -eq 0)
    {
        Write-Host "No Redis Cache(s) found with Non-SSL port enabled.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($totalRedisCacheWithNonSSLPortEnabled)] Redis Cache(s) for which Non-SSL port is enabled." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)



    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.Enable_Non_SSLPort};Label="Enabled Non-SSL Port";Width=10;Alignment="left"}
        
    $RedisCacheWithNonSSLPortEnabled | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DisableNonSSLPortForRedisCache"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Back up Redis Cache(s) details."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        
    
        # Backing up Redis Cache(s) details.
        $backupFile = "$($backupFolderPath)\RedisCacheWithNonSSLPortEnabled.csv"

        $RedisCacheWithNonSSLPortEnabled | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Redis Cache(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Disable Non-SSL port on Redis Cache(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)
        

        if (-not $Force)
        {
            Write-Host "Do you want to disable Non-SSL port on Redis Cache(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Non-SSL port will not be disabled on Redis Cache(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Non-SSL port will be disabled on Redis Cache(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        # List for storing remediated Redis Cache(s)
        $RedisCacheRemediated = @()

        # List for storing skipped Redis Cache(s)
        $RedisCacheSkipped = @()

        Write-Host "Disabling Non-SSL port on Redis Cache(s)." -ForegroundColor $([Constants]::MessageType.Info)

        # Loop through the list of Redis Cache(s) which needs to be remediated.
        $RedisCacheWithNonSSLPortEnabled | ForEach-Object {
            $RedisCache = $_
            try
            {
                $RedisCacheResource = Set-AzRedisCache -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -EnableNonSslPort $false
                if($RedisCacheResource.EnableNonSslPort -eq $false)
                {
                    $RedisCacheRemediated += $RedisCache
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                    $logResource.Add("ResourceName",($_.ResourceName))	
                    $logRemediatedResources += $logResource	
                }
                else
                {
                    $RedisCacheSkipped += $RedisCache
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Error disabling Non-SSL port on Redis Cache(s): [$($RedisCache)]")               
                    $logSkippedResources += $logResource	
                }
            }
            catch
            {
                $RedisCacheSkipped += $RedisCache
                $logResource = @{}	
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                $logResource.Add("ResourceName",($_.ResourceName))	
                $logResource.Add("Reason","Encountered error while disabling Non-SSL port on Redis Cache(s) configuration")    	
                $logSkippedResources += $logResource	
                Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)	
            }
        }

        Write-Host $([Constants]::DoubleDashLine)

        if($AutoRemediation)
        {

        if ($($RedisCacheRemediated | Measure-Object).Count -gt 0)
        {
          
           $RedisCacheRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $RedisCacheRemediatedFile = "$($backupFolderPath)\RemediatedRedisCache.csv"
            $RedisCacheRemediated | Export-CSV -Path $RedisCacheRemediatedFile -NoTypeInformation

            Write-Host "This information related to Redis Cache where Non SSL port disbaled has been saved to [$($RedisCacheRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($RedisCacheSkipped | Measure-Object).Count -gt 0)
        {
            
            $RedisCacheSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $RedisCacheSkippedFile = "$($backupFolderPath)\SkippedRedisCache.csv"
            $RedisCacheSkipped | Export-CSV -Path $RedisCacheSkippedFile -NoTypeInformation
            Write-Host "This information related to Redis Cache where Non SSL port disbaled has been saved to [$($RedisCacheSkippedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
            
        }
        else
        {
            Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($RedisCacheRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Non-SSL port is disabled on the following Redis Cache(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
           
                $RedisCacheRemediated | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)

                # Write this to a file.
                $RedisCacheRemediatedFile = "$($backupFolderPath)\RemediatedRedisCache.csv"
                $RedisCacheRemediated | Export-CSV -Path $RedisCacheRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($RedisCacheRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            }

            if ($($RedisCacheSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "`nError disabling Non-SSL port on the following Redis Cache(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                $RedisCacheSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
            
                # Write this to a file.
                $RedisCacheSkippedFile = "$($backupFolderPath)\SkippedRedisCache.csv"
                $RedisCacheSkipped | Export-CSV -Path $RedisCacheSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($RedisCacheSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            }
        }
        if($AutoRemediation){
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                    $logControl.RollbackFile = $appServicesRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Disable Non-SSL port on Redis Cache(s) in the Subscription..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "`nNext steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, Disable Non-SSL port on Redis Cache(s) listed in the file."
    }
}

function Enable-NonSSLPortOnRedisCache
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_RedisCache_DP_Use_SSL_Port' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_RedisCache_DP_Use_SSL_Port' Control.
        Enable Non-SSL port on Redis Cache(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Enable-NonSSLPortOnRedisCache.

        .OUTPUTS
        None. Enable-NonSSLPortOnRedisCache does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-NonSSLPortOnRedisCache -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableSecurityScanningIdentityForRedisCache\RemediatedRedisCache.csv

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
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 3] Validate the user..." 
        Write-Host $([Constants]::SingleDashLine)
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

    Write-Host "To Enable Non-SSL port on Redis Cache in a Subscription, Contributor or higher privileges on the Redis Cache are required." -ForegroundColor $([Constants]::MessageType.Info)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Redis Cache(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Fetch all Redis Cache(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $RedisCacheDetails = Import-Csv -LiteralPath $FilePath

    $validRedisCacheDetails = $RedisCacheDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalRedisCache = $(($validRedisCacheDetails|Measure-Object).Count)

    if ($totalRedisCache -eq 0)
    {
        Write-Host "No Redis Cache(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$(($validRedisCacheDetails|Measure-Object).Count)] Redis Cache(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{N='Enable_Non_SSLPort';E={$_.Enable_Non_SSLPort}}
        
    $validRedisCacheDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableNonSSLPortOnRedisCache"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Enable SSL port for all Redis Cache(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        
        Write-Host "Do you want to enable Non-SSL port on all Redis Cache(s) mentioned the file in the ?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Non-SSL port is not enabled on Redis Cache(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }
            Write-Host "Enable Non-SSL port on Redis Cache(s) in the Subscription." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. Non-SSL port will be enabled on Redis Cache(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Redis Cache resource.
    $RedisCacheRolledBack = @()

    # List for storing skipped rolled back Redis Cache resource.
    $RedisCacheSkipped = @()

    $validRedisCacheDetails | ForEach-Object {
        $RedisCache = $_
        try
        {
            $RedisCacheResource = Set-AzRedisCache -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -EnableNonSslPort $true
        
            if($RedisCacheResource.EnableNonSslPort -eq $true)
            {
                $RedisCacheRolledBack += $RedisCache    
            }
            else
            {
                $RedisCacheSkipped += $RedisCache
            }
        }
        catch
        {
            $RedisCacheSkipped += $RedisCache
        }
    }


    if ($($RedisCacheRolledBack | Measure-Object).Count -gt 0 -or $($RedisCacheSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($RedisCacheRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Non-SSL port is enabled on following Redis Cache(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
            $RedisCacheRolledBack | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)

            # Write this to a file.
            $RedisCacheRolledBackFile = "$($backupFolderPath)\RolledBackRedisCache.csv"
            $RedisCacheRolledBack | Export-CSV -Path $RedisCacheRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($RedisCacheRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
        }

        if ($($RedisCacheSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError enabling Non-SSL port on following Redis Cache(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
            $RedisCacheSkipped | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            
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
