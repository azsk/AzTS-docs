<###
# Overview:
    This script is used to set required TLS version for Front Door in a Subscription.

# Control ID:
    Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial

# Display Name:
    [Trial] Front Door should have Approved Minimum TLS version.

# Prerequisites:
    1. Contributor or higher privileges on the Front Doors in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of Front Doors custom domains in a Subscription that do not use the required TLS version.
        3. Back up details of Front Doors custom domains that are required to be remediated.
        4. Set the required TLS version on the custom domains in all Front Doors in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Front Doors in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the previous TLS versions for all Front Doors in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the required TLS version on the Front Doors. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the previous TLS versions on the Front Doors. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Front Doors in a Subscription that will be remediated:
           Set-FrontDoorRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To set minimum required TLS version on all custom domains of Front Doors in a Subscription:
           Set-FrontDoorRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To set minimum required TLS version on all custom domains of Front Doors in a Subscription, from a previously taken snapshot:
           Set-FrontDoorRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetFrontDoorRequiredTLSVersion\FrontDoorWithoutMinReqTLSVersion.csv

        4. To set minimum required TLS version on all custom domains of Front Doors in a Subscription without taking back up before actual remediation:
           Set-FrontDoorRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Set-FrontDoorRequiredTLSVersion -Detailed

    To roll back:
        1. To reset minimum required TLS version on all custom domains of Front Door in a Subscription, from a previously taken snapshot:
           Reset-FrontDoorRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetFrontDoorRequiredTLSVersion\RemediatedFrontDoors.csv
        
        To know more about the options supported by the roll back command, execute:
        Get-Help Reset-FrontDoorRequiredTLSVersion -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.FrontDoor", "Azure")
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

function Set-FrontDoorRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Remediates 'Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial' Control.

        .DESCRIPTION
        Remediates 'Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial' Control.
        Sets the required TLS version on all the custom domains in all Front Door in the Subscription. 
        
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
        None. You cannot pipe objects to Set-FrontDoorRequiredTLSVersion.

        .OUTPUTS
        None. Set-FrontDoorRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-FrontDoorRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-FrontDoorRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-FrontDoorRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForFrontDoors\FrontDoorWithoutMinReqTLSVersion.csv

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
    Write-Host "[Step 1 of 4] Prepare to set required TLS version for all custom domain of Front Door in Subscription: [$($SubscriptionId)]"
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
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
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

    Write-Host "To Set Minimum TLS version for front door in a Subscription, Contributor or higher privileges on the Front Doors are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Fetch all Front Doors"
    Write-Host $([Constants]::SingleDashLine)

    $FrontDoorResourceType = "Microsoft.Network/frontDoors"
    $FrontDoorResources = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    $controlIds = "Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial"
    
    # No file path provided as input to the script. Fetch all Front Doors in the Subscription.
    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
        Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::SingleDashLine)
        return
        }
        Write-Host "Fetching all Front Doors failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceName)}
        
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No  Front Door(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        $validResources | ForEach-Object {
            try
            {
            $name = $_.ResourceName
            $resFrontDoor = Get-AzFrontDoor -Name $name -ErrorAction SilentlyContinue
            $FrontDoorResources += $resFrontDoor
            }
            catch
            {
            Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping the Resource: [$($_.ResourceName)]..."
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
    # Fetch all front doors in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all Front Doors in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            # Get all Front Doors in a Subscription
            $FrontDoorResources = Get-AzFrontDoor -ErrorAction Stop
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                return
            }

            Write-Host "Fetching all Front Doors from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $frontdoorDetails = Import-Csv -LiteralPath $FilePath
            $validFrontDoorDetails = $frontdoorDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
            
            $FrontDoorResources = $validFrontDoorDetails
        }
    }
    $totalFrontDoors = ($FrontDoorResources | Measure-Object).Count

    if ($totalFrontDoors -eq 0)
    {
        Write-Host "No Front Door found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }
  
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Found [$($totalFrontDoors)] Front Door(s)." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "Found [$($totalFrontDoors)] Front Door Endpoint(s)." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)   
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetMinTLSVersionForFrontDoors"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
    
    # Includes required version of TLS
    $requiredMinTLSVersion = 1.2

    # Includes Front Door Endpoints where Minimum required TLS version is not set to 1.2.
    $nonCompliantEndpoints = @()

    # Includes Front Door Endpoints where Minimum required TLS version is either set to 1.2 or blank.
    $compliantEndpoints = @()

    # Includes Front Doors that were skipped during remediation. There were errors remediating them.
    $frontDoorEPsSkipped = @()

    $isMinTLSVersionSetOnCustomDomain = @()

    $FrontDoorEndpoints = @()

    $frontDoorWithoutReqMinTLSVersion = @()

    Write-Host "[Step 3 of 4] Fetch all Front Door configurations"
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        $FrontDoorResources | ForEach-Object {
        $frontDoorResource = $_
        $resourceId = $_.Id
        $resourceName = $_.Name
        $EndpointsWithoutReqTls = @()
        #$frontendPoints = $_.FrontendEndPoints
        $resourceGroupName= $_.Id.Split('/')[4]; 
        try
        {
            Write-Host "Fetching Front Door Endpoint configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            
            $FrontDoorEndpoints = Get-AzFrontDoorFrontendEndpoint -FrontDoorName $resourceName -ResourceGroupName $resourceGroupName
        
            if($FrontDoorEndpoints){
            Write-Host "Front Door Configurations successfully fetched." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            }
        
            foreach ($item in $FrontDoorEndpoints) 
            {
                $minTLSVersionofEndpoint = [decimal]$item.MinimumTlsVersion
           
                if(($minTLSVersionofEndpoint | Measure-Object).Count -gt 0)
                {
                    if($minTLSVersionofEndpoint -lt $requiredMinTLSVersion)
                    {
                        Write-Host "Minimum TLS Version is not set on the custom domain : " $item.Name  -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                
                        $isMinTLSVersionSetOnCustomDomain = $false;
                        $nonCompliantEndpoints += $item | Select-Object @{N='ResourceID';E={$item.Id}},
                                                    @{N='ResourceGroupName';E={$item.Id.Split('/')[4]}},
                                                    @{N='ResourceName';E={$item.Id.Split('/')[8]}},
                                                    @{N='HostName';E={$item.Name}},
                                                    @{N='MinimumTlsVersion';E={$item.MinimumTlsVersion}},
                                                    @{N='isMinTLSVersionSetOnCustomDomain';E={$isMinTLSVersionSetOnCustomDomain}}
                
                        #$EndpointsWithoutReqTls += $item 
                        $isMinTLSVersionSetOnCustomDomain = $false;
                    }
                    else
                    {
                        $compliantEndpoints += $item
                    }
                }
                else
                {
                    $compliantEndpoints += $item
                }   
            }
        }
        catch
        {
            $frontDoorEPsSkipped += $frontDoorResource
            Write-Host "Error fetching Front Door configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason","Encountered error while fetching Front Door configuration")    
            $logSkippedResources += $logResource
            Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)
        }
    }} #Ended for-each object for FrontDoorResources
    else
    {
       $nonCompliantEndpoints = $FrontDoorResources
    }
    
    $totalNonCompliantEpCount = ($nonCompliantEndpoints | Measure-Object).Count

    if ($totalNonCompliantEpCount -eq 0)
    {
        Write-Host "No Front Door(s) found having minimum TLS version less than required minimum TLS version. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        
        if($AutoRemediation -and ($compliantEndpoints|Measure-Object).Count -gt 0) 
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


    Write-Host "Found [$($totalNonCompliantEpCount)] Front Door Endpoint(s) having minimum TLS version less than required minimum TLS version." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetMinTLSVersionForFrontDoors"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    if (-not $DryRun)
    {
        if(-not $SkipBackup)
        {
            Write-Host "Backing up Front Doors details to [$($backupFolderPath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            $backupFile = "$($backupFolderPath)\FrontDoorsWithoutReqMinTLSVersion.csv"
            $nonCompliantEndpoints | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "Front Doors details have been backed up to [$($backupFile)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        Write-Host "Minimum required TLS Version will be set on all custom domains of front doors." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)

        # Here AutoRemediation switch is used as there is no need to take user input at BRS level if user has given consent to proceed with the remediation in AutoRemediation Script.
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "Do you want to set minimum required TLS Version for all Custom Domains? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                
                $userInput = Read-Host -Prompt "(Y|N)"
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "Minimum required TLS Version will not be set for any Custom Domain. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
                Write-Host "User has provided consent to set minimum required TLS Version on Custom Domains for all Front Doors." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                Write-Host "'Force' flag is provided. Minimum required TLS Version will be set on the for all Front Doors without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host $([Constants]::SingleDashLine)
        Write-Host "`[Step 4 of 4] Set minimum required TLS Version for FrontDoors"
        Write-Host $([Constants]::SingleDashLine)
        # To hold results from the remediation.
        $customDomainsRemediated = @()
        $frontDoorEPsSkipped = @()
        
        $nonCompliantEndpoints | ForEach-Object {
            $frontdoorEndpoint = $_
            $resourceId = $_.ResourceID
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName
            $hostName = $_.HostName
            $minimumTlsVersion = $_.MinimumTlsVersion
            $isMinTlsVersionSetOnCustomDomain = $_.isMinTLSVersionSetOnCustomDomain
            $isMinTLSVersionSetOnCustomDomainPostRemediation = $_.MinimumTlsVersion;
            
            $frontdoorEndpoint | Add-Member -NotePropertyName isMinTLSVersionSetOnCustomDomainPostRemediation -NotePropertyValue $isMinTLSVersionSetOnCustomDomainPostRemediation
            $frontdoorEndpoint | Add-Member -NotePropertyName PreviousMinimumTlsVersion -NotePropertyValue $MinimumTlsVersion

            Write-Host "Setting minimum required TLS Version for  Front Door : Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            
            if (-not [System.Convert]::ToBoolean($isMinTlsVersionSetOnCustomDomain))
            {
                try
                {
                    Write-Host "Setting minimum required TLS version on custom domain :" $hostName -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host $([Constants]::SingleDashLine)
                    
                    $resource = Enable-AzFrontDoorCustomDomainHttps -ResourceGroupName $resourceGroupName -FrontDoorName $resourceName -FrontendEndpointName $hostName -MinimumTlsVersion $requiredMinTLSVersion
                    
                    if($resource.MinimumTlsVersion -eq $requiredMinTLSVersion)
                    {
                        $frontdoorEndpoint.isMinTLSVersionSetOnCustomDomainPostRemediation = $true
                        $frontdoorEndpoint.minimumTlsVersion = $resource.MinimumTlsVersion
                        $customDomainsRemediated += $frontdoorEndpoint
                        Write-Host "Minimum required TLS version for Front Door endpoint has been set successfully for :" $hostName -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    else
                    {
                        $frontDoorsSkipped += $frontdoorEndpoint
                        $logResource = @{}
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        $logResource.Add("ResourceName",($_.ResourceName))
                        $logResource.Add("Reason", "Error while setting the minimum required TLS version. Skipping this Front Door endpoint :" + $hostName )
                        $logSkippedResources += $logResource
                        Write-Host "Error while setting the minimum required TLS version for this Front Door Endpoint :" $hostName -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "Skipping this Front Door endpoint." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                        return
                    }
                }
                catch
                {
                    $frontDoorsSkipped += $frontdoorEndpoint
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Error while setting the minimum required TLS version on the custom domain. Skipping this Front Door.")
                    $logSkippedResources += $logResource
                    Write-Host "Error while setting the minimum required TLS version on the custom domain of Front Door." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
            }
        }

        if (($customDomainsRemediated | Measure-Object).Count -eq $totalNonCompliantEpCount)
        {
            Write-Host "Successfully set the minimum required TLS version for all [$($totalNonCompliantEpCount)] Front Door Endpoint(s)." -ForegroundColor $([Constants]::MessageType.Update)
            
        }
        else
        {
            Write-Host "Minimum required TLS version is successfully set on the custom domains for [$($($customDomainsRemediated | Measure-Object).Count)] out of [$($totalNonCompliantEpCount)] Front Door(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                        @{Expression={$_.HostName};Label="Host Name";Width=20;Alignment="left"},
                        @{Expression={$_.isMinTlsVersionSetOnCustomDomain};Label="Is minimum required TLS version set on custom domain - Prior to remediation?";Width=20;Alignment="left"},
                        @{Expression={$_.isMinTLSVersionSetOnCustomDomainPostRemediation};Label="Is minimum required TLS version set on the custom domain - Post remediation?";Width=20;Alignment="left"}


        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation)
        {
            if ($($customDomainsRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $customDomainsRemediatedFile = "$($backupFolderPath)\RemediatedFrontDoorsForMinReqTLSVersion.csv"
                $customDomainsRemediated | Export-CSV -Path $customDomainsRemediatedFile -NoTypeInformation
                Write-Host "The information related to Front Door Endpoint(s) where minimum required TLS version is successfully set has been saved to [$($customDomainsRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($frontDoorsSkipped | Measure-Object).Count -gt 0)
            {   
                # Write this to a file.
                $frontDoorSkippedFile = "$($backupFolderPath)\SkippedFrontDoorForMinReqTLSVersion.csv"
                $frontDoorsSkipped | Export-CSV -Path $frontDoorSkippedFile -NoTypeInformation
                Write-Host "The information related to Front Door Endpoint(s) where minimum required TLS version is not set has been saved to [$($frontDoorSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($customDomainsRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Successfully set minimum required TLS version for the following Front Door Endpoint(s):" -ForegroundColor $([Constants]::MessageType.Update)
                $customDomainsRemediated | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $customDomainsRemediatedFile = "$($backupFolderPath)\RemediatedFrontDoorForMinReqTLSVersion.csv"
                $customDomainsRemediated | Export-CSV -Path $customDomainsRemediatedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($customDomainsRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($frontDoorsSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error while setting the minimum required TLS Version for the following Front Door Endpoint(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $frontDoorsSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $frontDoorSkippedFile = "$($backupFolderPath)\SkippedFrontDoorsForMinReqTLSVersion.csv"
                $frontDoorsSkipped | Export-CSV -Path $frontDoorSkippedFile -NoTypeInformation 
                Write-Host "This information has been saved to [$($frontDoorSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
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
                    $logControl.RollbackFile = $customDomainsRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "[Step 4 of 4] Back up Front Doors details"
        Write-Host $([Constants]::SingleDashLine)
        # Backing up Front Doors details.
        $backupFile = "$($backupFolderPath)\frontDoorsWithoutReqMinTLSVersion.csv"
        $nonCompliantEndpoints | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Front Door endpoint(s) details have been backed up to [$($backupFile)]. Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to set minimum required TLS Version for all custom domains of Front Doors listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
}

function Reset-FrontDoorRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_FrontDoor_DP_Use_Secure_TLS_Version_Trial' Control.
        Resets Minimum TLS Version on the custom domain in all Front Doors in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-FrontDoorRequiredTLSVersion.

        .OUTPUTS
        None. Reset-FrontDoorRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-FrontDoorRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForFrontDoors\RemediatedFrontDoorForMinReqTLSVersion.csv

        .EXAMPLE
        PS> Reset-FrontDoorRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck  -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForFrontDoors\RemediatedFrontDoorForMinReqTLSVersion.csv

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
    Write-Host "[Step 1 of 3] Prepare to reset minimum TLS version on Front Doors in Subscription: [$($SubscriptionId)]"
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
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "To Reset Minimum TLS version for for Front Doors in a Subscription, Contributor or higher privileges on the Front Doors are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Fetch all Front Doors"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }

    Write-Host "Fetching all Front Doors from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $frontdoorDetails = Import-Csv -LiteralPath $FilePath
    $validFrontDoorEndpointDetails += $frontdoorDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) 
                                                                ![String]::IsNullOrWhiteSpace($_.ResourceGroupName)
                                                                ![String]::IsNullOrWhiteSpace($_.ResourceName)
                                                                ![String]::IsNullOrWhiteSpace($_.HostName)
                                                                ![String]::IsNullOrWhiteSpace($_.MinimumTlsVersion) 
                                                                ![String]::IsNullOrWhiteSpace($_.isMinTLSVersionSetOnCustomDomain)
                                                                ![String]::IsNullOrWhiteSpace($_.PreviousMinimumTlsVersion)}

    $totalFrontDoors = $(($validFrontDoorEndpointDetails|Measure-Object).Count)

    if ($totalFrontDoors -eq 0)
    {
        Write-Host "No Front door found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }

    Write-Host "Found [$($totalFrontDoors)] Front Door Endpoint(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetMinTLSVersionForFrontDoors"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "Minimum TLS Version will be reset on the following Front Door Endpoint(s):"
    $validFrontDoorEndpointDetails | Select-Object @{N="Resource Id"; E={$_.ResourceId}}, @{N="Resource Group Name"; E={$_.ResourceGroupName}}, @{N="Resource Name"; E={$_.ResourceName}}| Format-Table -AutoSize -Wrap
    Write-Host $([Constants]::SingleDashLine)

    if (-not $Force)
    {
        Write-Host "Do you want to reset minimum TLS Version for all Front Door Endpoints? " -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "Minimum TLS Version will not be reset for any Front Door endpoint. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "User has provided consent to reset minimum TLS Version on all Front Doors endpoint." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. Minimum TLS Version will be reset on all Front Door endpoints without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 3 of 3] Reset Minimum TLS Version for Front Door Endpoints" 
    Write-Host $([Constants]::SingleDashLine)

    # Includes Front Doors, to which, previously made changes were successfully rolled back.
    $frontDoorsRolledBack = @()

    # Includes Front Doors that were skipped during roll back. There were errors rolling back the changes made previously.
    $frontDoorsEndpointSkipped = @()

    $validFrontDoorEndpointDetails | ForEach-Object {
        $frontdoorEndpoint = $_
        $resourceId = $_.ResourceID
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.ResourceName
        $hostName = $_.HostName
        $minimumTlsVersion = $_.MinimumTlsVersion
        $isMinTlsVersionSetOnCustomDomain = $_.isMinTLSVersionSetOnCustomDomain
        $isMinTLSVersionRolledBackCustomDomainPostRemediation = $_.MinimumTlsVersion
        
        #Using this logic as Decimal 1.0 is getting rounded off to 1.
        if($_.PreviousMinimumTlsVersion -eq '1')
        {
            $requiredMinTLSVersion = '1.0'
        }
        else
        {
            $requiredMinTLSVersion = $_.PreviousMinimumTlsVersion
        }

        $frontdoorEndpoint | Add-Member -NotePropertyName isMinTLSVersionRolledBackCustomDomainPostRemediation -NotePropertyValue $isMinTLSVersionRolledBackCustomDomainPostRemediation
        
        try
        {
            Write-Host "Fetching Front Door Endpoint configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            $resource = Enable-AzFrontDoorCustomDomainHttps -ResourceGroupName $resourceGroupName -FrontDoorName $resourceName -FrontendEndpointName $hostName -MinimumTlsVersion $requiredMinTLSVersion
                    
                    if($resource.MinimumTlsVersion -eq $requiredMinTLSVersion){
                       $frontdoorEndpoint.isMinTLSVersionRolledBackCustomDomainPostRemediation = $true
                       $frontdoorEndpoint.isMinTlsVersionSetOnCustomDomain = $false
                        $frontdoorEndpoint.minimumTlsVersion = $resource.MinimumTlsVersion
                        $frontDoorsRolledBack += $frontdoorEndpoint
                        Write-Host "Minimum required TLS version for Front Door Endpoint has been Rolled back successfully for : "  $hostName  -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    else
                    {
                        $frontDoorsEndpointSkipped += $frontdoorEndpoint
                        $logResource = @{}
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        $logResource.Add("ResourceName",($_.ResourceName))
                        $logResource.Add("Reason", "Error while Rolling back the minimum required TLS version. Skipping this Front Door endpoint.")
                        $logSkippedResources += $logResource
                        Write-Host "Error while Rolling back the minimum required TLS version for this Front Door endpoint." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "Skipping this Front Door Endpoint." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                        return
                    }
                    
                }
                catch
                {
                    $frontDoorsEndpointSkipped += $frontdoorEndpoint
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Error while resetting the minimum required TLS version on the custom domain. Skipping this Front Door endpoint.")
                    $logSkippedResources += $logResource
                    Write-Host "Error while resetting the minimum required TLS version on the custom domain of Front Door." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
                
            
        }

        Write-Host "Successfully rolled back changes on the Front Door endpoint." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)

    if (($frontDoorsEndpointSkipped | Measure-Object).Count -eq 0)
    {
        Write-Host "Minimum TLS Version successfully reset on the for all [$($totalFrontDoors)] Front Door Endpoint(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Minimum TLS Version successfully reset for [$($($frontDoorsRolledBack | Measure-Object).Count)] out of [$($totalFrontDoors)] Front Door Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                        @{Expression={$_.HostName};Label="Host Name";Width=20;Alignment="left"},
                        @{Expression={$_.isMinTlsVersionSetOnCustomDomain};Label="Is minimum required TLS version set on custom domain?";Width=20;Alignment="left"},
                        @{Expression={$_.isMinTLSVersionRolledBackCustomDomainPostRemediation};Label="Is minimum required TLS version reset on the custom domain - Post Roll back?";Width=20;Alignment="left"}


    if ($($frontDoorsRolledBack | Measure-Object).Count -gt 0 -or $($frontDoorsEndpointSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($frontDoorsRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Minimum TLS Version successfully reset on the following Front Door Endpoint(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $frontDoorsRolledBack | Format-Table -Property $colsProperty -Wrap -AutoSize
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $frontDoorsRolledBackFile = "$($backupFolderPath)\RolledBackFrontDoors.csv"
            $frontDoorsRolledBack | Export-CSV -Path $frontDoorsRolledBackFile -NoTypeInformation
            Write-Host "Note: This information has been saved to [$($frontDoorsRolledBackFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($frontDoorsEndpointSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error resetting minimum TLS Version for the following Front Door Endpoint(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $frontDoorsEndpointSkipped | Format-Table -Property $colsProperty -Wrap -AutoSize
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $frontDoorSkippedFile = "$($backupFolderPath)\RollbackSkippedFrontDoors.csv"
            $frontDoorsEndpointSkipped | Export-CSV -Path $frontDoorSkippedFile -NoTypeInformation
            Write-Host "Note: This information has been saved to [$($frontDoorSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
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
