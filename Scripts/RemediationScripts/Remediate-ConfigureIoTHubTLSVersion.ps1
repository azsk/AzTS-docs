<##########################################

# Overview:
    This script ensures all IoT Hubs in the subscription are configured to enforce a secure TLS version (e.g., TLS 1.2).

# ControlId: 
    Azure_IoTHub_DP_Use_Secure_TLS_Version

# Pre-requisites:
    1. You will need Contributor or higher privileged role on IoT Hub.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Install and validate required modules for managing IoT Hubs.
        2. Fetch all IoT Hubs in the subscription and check their current TLS configuration.
        3. Update non-compliant IoT Hubs to enforce the specified minimum TLS version.
    
    To roll back:
        1. Validate and install the modules required to run the script.
        2. Fetch the backup of original TLS configurations (if available).
        3. Restore the original TLS settings for IoT Hubs from the backup.

# Step to execute script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remediate resource type in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to rollback on all resource type in the Subscription. Refer `Examples`, below.

# Command to execute:
    To remediate:
        1. Run below command to configure IoT Hub TLS version for all IoT Hubs in the subscription:
           
            Set-MinTLSVersionForIoTHub  -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck
        
        To know more about parameter execute:
            Get-Help Set-MinTLSVersionForIoTHub  -Detailed
            
        To roll back:
        1. Run below command to roll back Microsoft Defender for subscription with all the resource type. 
           
            Set-MinTLSVersionForIoTHub  -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath  C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\IoTHub\RemediatedResourceType.csv
        
        To know more about parameter execute:
   
            Get-Help Set-MinTLSVersionForIoTHub  -Detailed

########################################
#>

function Setup-Prerequisites
{
    <#
    .SYNOPSIS
    This command would check pre requisites modules.
    .DESCRIPTION
    This command would check pre requisites modules to perform remediation.
    #>

    $requiredModules = ("Az.Accounts", "Az.IotHub")
    
    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_) {
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module is installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host "All required modules are present." -ForegroundColor $([Constants]::MessageType.Update)
}

function Fetch-API {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Method,
        
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Body = @{},
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Headers = @{}
    )

    $cloudEnvironmentResourceManagerUrl = (Get-AzContext).Environment.ResourceManagerUrl
    $accessTokenSecure = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl -AsSecureString -WarningAction SilentlyContinue
    $accessToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($accessTokenSecure.Token)
    )
    $authHeader = "Bearer " + $accessToken
    $Headers["Authorization"] = $authHeader
    $Headers["Content-Type"] = "application/json"

    try {
        switch ($Method.ToUpper()) {
            "GET" {
                $response = Invoke-WebRequest -Uri $Uri -Method Get -Headers $Headers -UseBasicParsing -ErrorAction Stop
            }
            "POST" {
                $jsonBody = $Body | ConvertTo-Json
                $response = Invoke-WebRequest -Uri $Uri -Method Post -Headers $Headers -Body $jsonBody -UseBasicParsing -ErrorAction Stop
            }
            "PUT" {
                $jsonBody = $Body | ConvertTo-Json
                $response = Invoke-WebRequest -Uri $Uri -Method Put -Headers $Headers -Body $jsonBody -UseBasicParsing -ErrorAction Stop
            }
            "DELETE" {
                $response = Invoke-WebRequest -Uri $Uri -Method Delete -Headers $Headers -UseBasicParsing -ErrorAction Stop
            }
            default {
                throw "Unsupported HTTP method: $Method"
            }
        }

        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
            return $response.Content | ConvertFrom-Json
        }
        else {
            throw "API call failed with status code $($response.StatusCode)"
        }
    }
    catch {
        Write-Error "Error occurred: $_"
    }
}

function Set-MinTLSVersionForIoTHub  {
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
            Write-Host "[Step 1 of 4] Validate and install the modules required to run the script and validate the user..."
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)    
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
        Write-Host "[Step 1 of 4] Validate the user..."
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

    Write-Host "***To Set MinTLSVersion on IoT Hubs in a Subscription, Contributor or higher privileges on the IoT Hubs are required.***" -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all IoT Hub(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store resource details.
    $IoTHubDetails = @()

    #Required Min TLS Version
    $requiredMinTLSVersion = 1.2

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources = @()
    $iotHubsAPI = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Devices/IotHubs?api-version=2023-06-30" 

    #Control id for the control
    $controlIds = "Azure_IoTHub_DP_Use_Secure_TLS_Version"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "Fetching all IoT Hub(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $subId = $controlForRemediation.SubscriptionId
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No IoT Hub(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            try
            {
                $iotHubResourceAPI = "https://management.azure.com/subscriptions/$subId/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Devices/IotHubs/$($_.ResourceName)?api-version=2023-06-30" 
                $IoTHubDetail = Fetch-API -Method Get -Uri $iotHubResourceAPI -ErrorAction Stop

                $IoTHubDetails += $IoTHubDetail | Select-Object @{N='ResourceId';E={$_.Id}},
                                                               @{N='ResourceGroupName';E={$_.ResourceGroup}},
                                                               @{N='ResourceName';E={$_.Name}},
                                                               @{N='MinimumTlsVersion';E={$_.Properties.MinTlsVersion}},
                                                               @{N='Location';E={$_.Location}},
                                                               @{N='Sku';E={$_.Sku}}
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
        # No file path provided as input to the script. Fetch all IoT Hub(s) in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            try
            {
                Write-Host "Fetching all IoT Hub(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

                # Get all IoT Hub(s) in a Subscription
                $IoTHubDetails = Fetch-API -Method Get -Uri $iotHubsAPI -ErrorAction Stop

                # Seperating required properties
                $IoTHubDetails = $IoTHubDetails.value | Select-Object @{N='ResourceId';E={$_.Id}},
                                                               @{N='ResourceGroupName';E={$_.ResourceGroup}},
                                                               @{N='ResourceName';E={$_.Name}},
                                                               @{N='MinimumTlsVersion';E={$_.Properties.MinTlsVersion}},
                                                               @{N='Location';E={$_.Location}},
                                                               @{N='Sku';E={$_.Sku}}
            }
            catch
            {
                Write-Host "Error fetching IoT Hub(s) from the subscription. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                $logResource = @{}
                $logResource.Add("SubscriptionID",($SubscriptionId))
                $logResource.Add("Reason","Error fetching IoT Hub(s) information from the subscription.")    
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

            Write-Host "Fetching all IoT Hub(s) from [$($FilePath)]..." 

            $IoTHubResources = Import-Csv -LiteralPath $FilePath
            $validIoTHubResources = $IoTHubResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
        
            $validIoTHubResources | ForEach-Object {
            $resourceId = $_.ResourceId
                try
                {
                    $iotHubResourceAPI = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Devices/IotHubs/$($_.ResourceName)?api-version=2023-06-30" 
                    $IoTHubDetail = Fetch-API -Method Get -Uri $iotHubResourceAPI -ErrorAction Stop

            
                    $IoTHubDetails += $IoTHubDetail | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                     @{N='ResourceGroupName';E={$_.ResourceGroup}},
                                                                     @{N='ResourceName';E={$_.Name}},
                                                                     @{N='MinimumTlsVersion';E={$_.Properties.MinTlsVersion}},
                                                                     @{N='Location';E={$_.Location}},
                                                                     @{N='Sku';E={$_.Sku}}
                }
                catch
                {
                    Write-Host "Error fetching IoT Hub(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason","Error fetching IoT Hub(s) information.")    
                    $logSkippedResources += $logResource
                }
            }
        }
    }

    $totalIoTHub = ($IoTHubDetails | Measure-Object).Count

    if ($totalIoTHub -eq 0)
    {
        Write-Host "No IoT Hub(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalIoTHub)] IoT Hub(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing IoT Hub(s) where required TLS Version is not configured
    $NonCompliantTLSIoTHub = @()

    Write-Host "Separating IoT Hub(s) for which TLS Version [$($requiredMinTLSVersion)] is not configured..."

    $IoTHubDetails | ForEach-Object {
        $IoTHub = $_
        if(!$_.MinimumTlsVersion -or $_.MinimumTlsVersion -lt $requiredMinTLSVersion)
        {
            $NonCompliantTLSIoTHub += $IoTHub
        }
        else
        {
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason","Minimum required TLS Version configured set on IoT Hub.")    
            $logSkippedResources += $logResource
        }
    }

    $totalNonCompliantIoTHub = ($NonCompliantTLSIoTHub | Measure-Object).Count

    if ($totalNonCompliantIoTHub -eq 0)
    {
        Write-Host "No IoT Hub(s) found with non-compliant TLS Version less than [$($requiredMinTLSVersion)]. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$($totalNonCompliantIoTHub)] IoT Hub(s) with non-compliant TLS Version:" -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.MinimumTlsVersion};Label="MinimumTLSVersion";Width=10;Alignment="left"}
        
    $NonCompliantTLSIoTHub | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\MinTLSVersionForIoTHub"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up IoT Hub(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        # Backing up IoT Hub(s) details
        $backupFile = "$($backupFolderPath)\NonCompliantTLSIoTHub.csv"

        $NonCompliantTLSIoTHub | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "IoT Hub(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remediating non-compliant Azure IoT Hubs..." 
        Write-Host $([Constants]::SingleDashLine)
        
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "This step will configure TLS version [$($requiredMinTLSVersion)] for all non-compliant [$($NonCompliantTLSIoTHub.count)] IoT Hub(s)." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Do you want to Continue? " -ForegroundColor $([Constants]::MessageType.Warning)
            
                $userInput = Read-Host -Prompt "(Y|N)"

                if($userInput -ne "Y")
                {
                    Write-Host "Minimum required TLS Version [$($requiredMinTLSVersion)] will not be configured on IoT Hub(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    break
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. Minimum required TLS Version will be configured on IoT Hub(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }

        # List for storing remediated IoT Hub(s)
        $IoTHubRemediated = @()

        # List for storing skipped IoT Hub(s)
        $IoTHubSkipped = @()

        $setIotHubUri 

        Write-Host "Configuring Min TLS Version [$($requiredMinTLSVersion)] on all listed IoT Hub(s)." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of IoT Hub(s) which needs to be remediated.
        $NonCompliantTLSIoTHub | ForEach-Object {
            $IoTHub = $_
            $IoTHub | Add-Member -NotePropertyName isMinTLSVersionSetPostRemediation -NotePropertyValue $false
            $IoTHub | Add-Member -NotePropertyName PreviousMinimumTlsVersion -NotePropertyValue $IoTHub.MinimumTlsVersion

            Write-Host "Configuring TLS Version [$($requiredMinTLSVersion)] on [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Info)
            try
            {
                $setIotHubUri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Devices/IotHubs/$($_.ResourceName)?api-version=2023-06-30"

                $iotHubBody = @{
                    location = $_.Location
                    Sku = $_.Sku
                    properties = @{
                        MinTLSVersion = $requiredMinTLSVersion
                    }
                }

                $IoTHubResource = Fetch-API -Method "PUT" -Uri $setIotHubUri -Body $iotHubBody

                if($IoTHubResource.Properties.MinTlsVersion -ge $requiredMinTLSVersion)
                {
                    $IoTHub.isMinTLSVersionSetPostRemediation = $true
                    $IoTHub.MinimumTlsVersion = $requiredMinTLSVersion
                    $IoTHubRemediated += $IoTHub
                    
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logRemediatedResources += $logResource
                    Write-Host "Successfully set the minimum required TLS version on IoT Hub [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
                else
                {
                    $IoTHub.isMinTLSVersionSetPostRemediation = $false
                    $IoTHubSkipped += $IoTHub
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Error occurred while setting the minimum required TLS version on IoT Hub.")
                    $logSkippedResources += $logResource
                    Write-Host "Skipping this IoT Hub resource." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }  
            }
            catch
            {
                $IoTHubSkipped += $IoTHub
                Write-Host $([Constants]::SingleDashLine)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason", "Error while setting the minimum required TLS version on IoT Hub.")
                $logSkippedResources += $logResource
                Write-Host "Skipping this IoT Hub resource." -ForegroundColor $([Constants]::MessageType.Warning)
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
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)

        if ($($IoTHubRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "TLS Version [$($requiredMinTLSVersion)] configured on the following IoT Hub(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
        
            $IoTHubRemediated | Format-Table -Property $colsPropertyRemediated -Wrap

            # Write this to a file.
            $IoTHubRemediatedFile = "$($backupFolderPath)\RemediatedIoTHub.csv"
            $IoTHubRemediated | Export-CSV -Path $IoTHubRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($IoTHubRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($IoTHubSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error configuring Minimum required TLS Version on the following IoT Hub(s) in the subscription: " -ForegroundColor $([Constants]::MessageType.Error)
            $IoTHubSkipped | Format-Table -Property $colsProperty -Wrap
            # Write this to a file.
            $IoTHubSkippedFile = "$($backupFolderPath)\SkippedIoTHub.csv"
            $IoTHubSkipped | Export-CSV -Path $IoTHubSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($IoTHubSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }

        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $IoTHubRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remediating non-compliant Azure IoT Hubs..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, configure TLS Version on IoT Hub(s) listed in the file."
    }
}

function Reset-MinTLSVersionForIoTHub 
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_IoTHub_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_IoTHub_DP_Use_Secure_TLS_Version' Control.
        Use approved version of TLS for Azure IoT Hubs. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-MinTLSVersionForIoTHub .

        .OUTPUTS
        None. Reset-MinTLSVersionForIoTHub  does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-MinTLSVersionForIoTHub  -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\MinTLSVersionForIoTHub\RemediatedIoTHub.csv

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

    Write-Host "*** To configure TLS Version on IoT Hubs in a Subscription, Contributor or higher privileges on the IoT Hubs are required.***" -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all IoT Hub(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all IoT Hub(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $IoTHubDetails = Import-Csv -LiteralPath $FilePath

    $validIoTHubDetails = $IoTHubDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalIoTHub = $(($validIoTHubDetails|Measure-Object).Count)

    if ($totalIoTHub -eq 0)
    {
        Write-Host "No IoT Hub(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($validIoTHubDetails|Measure-Object).Count)] IoT Hub(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.MinimumTlsVersion};Label="MinimumTlsVersion";Width=50;Alignment="left"},
                    @{Expression={$_.PreviousMinimumTlsVersion};Label="PreviousMinimumTlsVersion";Width=50;Alignment="left"},
                    @{Expression={$_.isMinTLSVersionSetPostRemediation};Label="isMinTLSVersionSetPostRemediation";Width=50;Alignment="left"}
        
    $validIoTHubDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RollbackTLSOnIoTHub"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Rolling back TLS Versions for all IoT Hub(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        Write-Host "Please note: This will not roll back IoT Hub(s) resources where previous minimum TLS Version was default."  -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Do you want to continue roll back operation?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Minimum TLS Version will not be rolled back for any IoT Hub(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
    }
    else
    {
        Write-Host "'Force' flag is provided. Previous TLS Versions will be configured on IoT Hub(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    # List for storing rolled back IoT Hub resource.
    $IoTHubRolledBack = @()

    # List for storing skipped rolled back IoT Hub resource.
    $IoTHubSkipped = @()

    # List for IoT Hub(s) where previous MinTLSVersion was default
    $IoTHubWithDefaultValue = @()

    Write-Host "Starting Roll back operation..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $validIoTHubDetails | ForEach-Object {
        $IoTHub = $_
        $IoTHub | Add-Member -NotePropertyName isMinTLSVersionRolledback -NotePropertyValue $false
        try
        {
            Write-Host "Rolling back TLS Versions on IoT Hub(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Info)
            $setIotHubUri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Devices/IotHubs/$($_.ResourceName)?api-version=2023-06-30"

            # The 'Sku' field in the input CSV is in string format like a PowerShell hashtable (e.g., "@{name=S1; tier=Standard; capacity=1}").
            # To ensure the 'Sku' field is correctly serialized into a nested JSON object, we parse this string into a proper hashtable.
            # This step ensures the final JSON output matches the expected format, improving compatibility with downstream consumers of the data.
            $skuString = $_.Sku -replace '@{', '' -replace '}', ''
            $skuHash = @{}
            foreach ($pair in $skuString -split ';') {
                $key, $value = $pair -split '='
                $skuHash[$key.Trim()] = $value.Trim()
            }

            $iotHubBody = @{
                location   = $_.Location
                Sku        = @{
                    name     = $skuHash['name']
                    tier     = $skuHash['tier']
                    capacity = [int]$skuHash['capacity']
                }
                properties = @{
                    MinTLSVersion = $_.PreviousMinimumTlsVersion
                }
            }

            $IoTHubResource = Fetch-API -Method "PUT" -Uri $setIotHubUri -Body $iotHubBody

            if($IoTHubResource.Properties.MinTlsVersion -eq $_.PreviousMinimumTlsVersion)
            {
                Write-Host "Succesfully rolled back TLS Versions on IoT Hub(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $IoTHub.PreviousMinimumTlsVersion = $IoTHub.MinimumTLSVersion
                $IoTHub.MinimumTlsVersion = $IoTHubResource.Properties.MinTlsVersion
                $IoTHub.isMinTLSVersionSetPostRemediation = $false
                $IoTHub.isMinTLSVersionRolledback = $true
                $IoTHubRolledBack += $IoTHub    
            }
            else
            {
                $IoTHub.isMinTLSVersionRolledback = $false
                $IoTHubSkipped += $IoTHub
            }
        }
        catch
        {
            $IoTHubSkipped += $IoTHub
        }
    }

    $colsPropertyRollBack = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.MinimumTlsVersion};Label="MinimumTlsVersion";Width=50;Alignment="left"},
                    @{Expression={$_.PreviousMinimumTlsVersion};Label="PreviousMinimumTlsVersion";Width=50;Alignment="left"},
                    @{Expression={$_.isMinTLSVersionRolledback};Label="isMinTLSVersionRolledBack";Width=50;Alignment="left"}
     
    if ($($IoTHubRolledBack | Measure-Object).Count -gt 0 -or $($IoTHubSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($IoTHubRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "TLS Version is rolled back successfully on following IoT Hub(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Update)
            $IoTHubRolledBack | Format-Table -Property $colsPropertyRollBack -Wrap

            # Write this to a file.
            $IoTHubRolledBackFile = "$($backupFolderPath)\RolledBackIoTHub.csv"
            $IoTHubRolledBack | Export-CSV -Path $IoTHubRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($IoTHubRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($IoTHubSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error configuring TLS Version on following IoT Hub(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $IoTHubSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $IoTHubSkippedFile = "$($backupFolderPath)\RollbackSkippedIoTHub.csv"
            $IoTHubSkipped | Export-CSV -Path $IoTHubSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($IoTHubSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)

            Write-Host "Note: TLS settings for [$($IoTHubWithDefaultValue.count)] out of total count [$($validIoTHubDetails.count)] is not configured for IoT Hub resource(s) because TLS Version was previously set to default." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
        }
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

    static [String] $DoubleDashLine = "=" * 120
    static [String] $SingleDashLine = "-" * 120
}