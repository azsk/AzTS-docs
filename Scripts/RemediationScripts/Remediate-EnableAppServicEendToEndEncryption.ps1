<##########################################

# Overview:
    This script ensures all App Services in the subscription are configured to End-to-end TLS encryption enabled.

# ControlId: 
    Azure_AppService_DP_Configure_EndToEnd_TLS

# Pre-requisites:
    1. You will need Owner role on subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Install and validate required modules for managing App Services.
        2. Fetch all App Services in the subscription and check their End-to-end TLS encryption configuration.
        3. Update non-compliant App Services to enforce End-to-end TLS encryption enabled.
    
    To roll back:
        1. Validate and install the modules required to run the script.
        2. Fetch the backup of original End-to-end TLS encryption configurations.
        3. Restore the original End-to-end TLS encryption configurations for App Services from the backup.

# Step to execute script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remediate resource type in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to rollback on all resource type in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the App Services in a Subscription that will be remediated:
           Enable-EndToEndTLSForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To enable End-to-end TLS encryption on all App Services in a Subscription:
           Enable-EndToEndTLSForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To enable End-to-end TLS encryption on all App Services in a Subscription, from a previously taken snapshot:
           Enable-EndToEndTLSForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\Enable-EndToEndTLSForAppServices\AppServicesWithNonCompliant.csv

        To know more about parameter execute:
            Get-Help Enable-EndToEndTLSForAppServices -Detailed

    To roll back:
        1. To configure AllAllowed on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Disable-EndToEndTLSForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\DisableEndToEndTLSForAppServices\RemediatedForAppServices.csv
       
        To know more about the options supported by the roll back command, execute:
        Get-Help Disable-EndToEndTLSForAppServices -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Websites", "Az.Resources", "Azure")
    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_) {
            Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "$($_) module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host $([Constants]::SingleDashLine)
}

function Enable-EndToEndTLSForAppServices {
    <#
        .SYNOPSIS
        Remediates 'Azure_AppService_DP_Configure_EndToEnd_TLS' Control.

        .DESCRIPTION
        Remediates 'Azure_AppService_DP_Configure_EndToEnd_TLS' Control.
        Enable End-to-end TLS encryption for App Services in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER InputFilePath
        Specifies the path to the file to be used as input for the remediation.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Enable-EndToEndTLSForAppServices.

        .OUTPUTS
        None. Enable-EndToEndTLSForAppServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-EndToEndTLSForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-EndToEndTLSForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-EndToEndTLSForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -InputFilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202209131040\Enable-EndToEndTLSForAppServices\AppServicesInputFilePath.csv

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
    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    if (-not($AutoRemediation)) {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }
    Write-Host "To enable End-to-end TLS encryption for App Services in a Subscription, Contributor or higher privileges on the App Services are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Fetch all App Services"
    Write-Host $([Constants]::SingleDashLine)

     # list to store resource details.
    $AppServicesDetails = @()
   

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources = @()
    $appServicesAPI = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Web/sites?api-version=2024-04-01" 

    #Control id for the control
    $controlIds = "Azure_AppService_DP_Configure_EndToEnd_TLS"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "Fetching all App Services failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $subId = $controlForRemediation.SubscriptionId
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No App Services found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            try
            {
                $appServiceResourceAPI = "https://management.azure.com/subscriptions/$subId/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Web/sites/$($_.Name)?api-version=2024-04-01" 
                $AppServiceDetail = Fetch-API -Method Get -Uri $appServiceResourceAPI -ErrorAction Stop

                $AppServicesDetails += $AppServiceDetail | Select-Object @{N='ResourceId';E={$_.Id}},
                                                               @{N='ResourceGroupName';E={$_.properties.ResourceGroup}},
                                                               @{N='Name';E={$_.Name}},
                                                               @{N='EndToEndEncryptionEnabled';E={$_.Properties.EndToEndEncryptionEnabled}},
                                                               @{N='Location';E={$_.Location}},
                                                               @{N='Sku';E={$_.Sku}}
            }
            catch
            {
                Write-Host "Valid resource information not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.Name)]..."
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.properties.ResourceGroup))
                $logResource.Add("Name",($_.Name))
                $logResource.Add("Reason","Valid ResourceName(s)/ResourceGroupName not found in input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }


        }
    }
    else
    {
        # No file path provided as input to the script. Fetch all App Services in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            try
            {
                Write-Host "Fetching all App Services in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

                # Get all App Services in a Subscription
                $AppServicesDetail = Fetch-API -Method Get -Uri $appServicesAPI -ErrorAction Stop

                # Seperating required properties
                $AppServicesDetails = $AppServicesDetail.value | Select-Object @{N='ResourceId';E={$_.Id}},
                                                               @{N='ResourceGroupName';E={$_.properties.ResourceGroup}},
                                                               @{N='ResourceName';E={$_.Name}},
                                                               @{N='EndToEndEncryptionEnabled';E={$_.Properties.EndToEndEncryptionEnabled}},
                                                               @{N='Location';E={$_.Location}},
                                                               @{N='Sku';E={$_.Sku}}
            }
            catch
            {
                Write-Host "Error fetching App Services from the subscription. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                $logResource = @{}
                $logResource.Add("SubscriptionID",($SubscriptionId))
                $logResource.Add("Reason","Error fetching App Services information from the subscription.")    
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

            Write-Host "Fetching all App Services from [$($FilePath)]..." 

            $AppServicesResources = Import-Csv -LiteralPath $FilePath
            $validAppServicesResources = $AppServicesResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
        
            $validAppServicesResources | ForEach-Object {
            $resourceId = $_.ResourceId
                try
                {
                    $appServicesResourceAPI = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Web/sites/$($_.Name)?api-version=2024-04-01" 
                    
                    Write-Host "App Service API URL: [$($_.appServicesResourceAPI)]"

                    $AppServicesDetail = Fetch-API -Method Get -Uri $appServicesResourceAPI -ErrorAction Stop

                    
                    $AppServicesDetails += $AppServicesDetail | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                     @{N='ResourceGroupName';E={$_.properties.ResourceGroup}},
                                                                     @{N='ResourceName';E={$_.Name}},
                                                                     @{N='EndToEndEncryptionEnabled';E={$_.Properties.EndToEndEncryptionEnabled}},
                                                                     @{N='Location';E={$_.Location}},
                                                                     @{N='Sku';E={$_.Sku}}
                }
                catch
                {
                    Write-Host "Error fetching App Service resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.Name))               
                    $logResource.Add("Reason","Error fetching App Services information.")    
                    $logSkippedResources += $logResource
                }
            }
        }
    }

    $totalAppServices = ($AppServicesDetails | Measure-Object).Count

    if ($totalAppServices -eq 0)
    {
        Write-Host "No App Services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalAppServices)] App Services." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)

    # list for storing App Services where End-to-end TLS encryption is not enabled
    $NonCompliantAppServices = @()

    # Non Compliant App Services with End-to-end TLS as default
    $EndToEndTLSwithDefaultValue = @()

    Write-Host "Separating App Services for which End-to-end TLS encryption is not enabled..."

    $AppServicesDetails | ForEach-Object {
        $AppService = $_
      
        if(-not $_.EndToEndEncryptionEnabled)
        {

            $NonCompliantAppServices += $AppService
             Write-Host "Separating App Service for which End-to-end TLS encryption [$($AppService)] is not configured..."
          
        }
        else
        {
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.Resourcproperties.ResourceGroup))
            $logResource.Add("ResourceName",($_.ResourcName))
            $logResource.Add("Reason","End-to-end TLS encryption enabled on App Services.")    
            $logSkippedResources += $logResource
        }
    }

    $totalNonCompliantAppServices = ($NonCompliantAppServices | Measure-Object).Count

    if ($totalNonCompliantAppServices -eq 0)
    {
        Write-Host "No App Services found with non-compliant disabled End-to-end TLS encryption . Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$($totalNonCompliantAppServices)] App Services with non-compliant disabled End-to-end TLS encryption:" -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.EndToEndEncryptionEnabled};Label="EndToEndEncryptionEnabled";Width=10;Alignment="left"}
        
    $NonCompliantAppServices | Format-Table -Property $colsProperty -Wrap

     # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EndToEndTLSEncryptionForAppService"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up App Service details..."
    Write-Host $([Constants]::SingleDashLine)

     if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        # Backing up App Services details
        $backupFile = "$($backupFolderPath)\NonCompliantEndToEndTLSAppService.csv"

        $NonCompliantAppServices | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "App Services details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remediating non-compliant App Services..." 
        Write-Host $([Constants]::SingleDashLine)
        
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                
                Write-Host "This step will enable End-to-end TLS encryption for all non-compliant [$($NonCompliantAppServices.count)] App Services." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Do you want to Continue? " -ForegroundColor $([Constants]::MessageType.Warning)
            
                $userInput = Read-Host -Prompt "(Y|N)"

                if($userInput -ne "Y")
                {
                    Write-Host "End-to-end TLS encryption will not be enabled on App Services in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    break
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. End-to-end TLS encryption will be enable on App Services in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }

        # List for storing remediated App Services
        $AppServicesRemediated = @()

        # List for storing skipped App Services   $AppServicesSkipped = @()

        $setAppServiceUri 

        Write-Host "Enabling End-to-end TLS encryption on all listed App Services." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of App Services which needs to be remediated.
        $NonCompliantAppServices | ForEach-Object {
            $AppService = $_
            
           $AppService | Add-Member -NotePropertyName isEndToEndTLSEncryptionSetPostRemediation -NotePropertyValue $true
           $AppService | Add-Member -NotePropertyName PreviousEndToEndTLSEncryption -NotePropertyValue $AppService.EndToEndEncryptionEnabled

            Write-Host "Enabling End-to-end TLS encryption on [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Info)
            try
            {
                $setAppServicesUri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Web/sites/$($_.ResourceName)?api-version=2024-04-01"
               
                $appServiceBody = @{
                    properties = @{
                        endToEndEncryptionEnabled = $true
                    }
                    location = $_.Location
                   }
                   
                    $AppServiceResource = Fetch-API -Method "PUT" -Uri $setAppServicesUri -Body $appServiceBody                 
                   
                if($AppServiceResource.Properties.EndToEndEncryptionEnabled)
                {
                    $AppService.isEndToEndTLSEncryptionSetPostRemediation = $true
                    $AppService.EndToEndEncryptionEnabled = $true
                    $AppServicesRemediated += $AppService                    
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logRemediatedResources += $logResource
                    Write-Host "Successfully Enabled End-to-end TLS encryption on App Service [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
                else
                {
                    $AppService.isEndToEndTLSEncryptionSetPostRemediation = $false
                    $AppServicesSkipped += $AppService
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Error while Enabling End-to-end TLS encryption on App Service.")
                    $logSkippedResources += $logResource
                    Write-Host "Skipping this App Service resource." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }


                
            }
            catch
            {
                $AppServicesSkipped += $AppService
                Write-Host $([Constants]::SingleDashLine)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason", "Error while Enabling End-to-end TLS encryption on App Service.")
                $logSkippedResources += $logResource
                Write-Host "Skipping this App Service resource." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
         $colsPropertyRemediated = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                                @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                                @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                                @{Expression={$_.EndToEndEncryptionEnabled};Label="EndToEndEncryptionEnabled";Width=10;Alignment="left"},
                                @{Expression={$_.PreviousEndToEndTLSEncryption};Label="PreviousMinimumTlsVersion";Width=10;Alignment="left"},
                                @{Expression={$_.isEndToEndTLSEncryptionSetPostRemediation};Label="isMinTLSVersionSetPostRemediation";Width=10;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)

        if ($($AppServicesRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Enabled End-to-end TLS encryption on the following App Services in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
        
            $AppServicesRemediated | Format-Table -Property $colsPropertyRemediated -Wrap

            # Write this to a file.
            $AppServiceRemediatedFile = "$($backupFolderPath)\RemediatedForAppServices.csv"
            $AppServicesRemediated | Export-CSV -Path $AppServiceRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($AppServiceRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($AppServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error Enabling End-to-end TLS encryption on the following App Services in the subscription: " -ForegroundColor $([Constants]::MessageType.Error)
            $AppServicesSkipped | Format-Table -Property $colsProperty -Wrap
            # Write this to a file.
            $AppServicesSkippedFile = "$($backupFolderPath)\SkippedAppServices.csv"
            $AppServicesSkipped | Export-CSV -Path $AppServicesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($AppServicesSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }

        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $AppServiceRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }

    }
     else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remediating non-compliant App Services..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, Enable End-to-end TLS encryption on App Services listed in the file."
    }


}

function Reset-EndToEndTLSForAppServices
{
 <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_AppService_DP_Configure_EndToEnd_TLS' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_AppService_DP_Configure_EndToEnd_TLS' Control.
        Use Disable End-to-end TLS encryption for App Services. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-EndToEndTLSForAppServices.

        .OUTPUTS
        None. Reset-EndToEndTLSForAppServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-EndToEndTLSForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EndToEndTLSForAppServices\RemediatedForAppServices.csv

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

    Write-Host "*** To Disable End-to-end TLS encryption for App Services in a Subscription, Contributor or higher privileges on the App Services are required.***" -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all App Services..."
    Write-Host $([Constants]::SingleDashLine)

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all App Services from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $AppServicesDetails = Import-Csv -LiteralPath $FilePath

    $validAppServicesDetails = $AppServicesDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalAppServies = $(($validAppServicesDetails|Measure-Object).Count)

    if ($totalAppServies -eq 0)
    {
        Write-Host "No App Services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($totalAppServies|Measure-Object).Count)] App Services." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.EndToEndEncryptionEnabled};Label="EndToEndEncryptionEnabled";Width=50;Alignment="left"}                   
                    @{Expression={$_.PreviousEndToEndTLSEncryption};Label="PreviousEndToEndTLSEncryption";Width=50;Alignment="left"},
                    @{Expression={$_.isEndToEndTLSEncryptionSetPostRemediation};Label="isEndToEndTLSEncryptionSetPostRemediation";Width=50;Alignment="left"}
    $validAppServicesDetails | Format-Table -Property $colsProperty -Wrap

     # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RollbackEndToEndTLSOnAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Rolling back TLS Versions for all App Services in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {        
        Write-Host "Do you want to continue roll back operation?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "End-to-end TLS encryption will not be rolled back for any App Services in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
    }
    else
    {
        Write-Host "'Force' flag is provided. Disabling End-to-end TLS encryption on App Services in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    # List for storing rolled back App Services resource.
    $AppServicesRolledBack = @()

    # List for storing skipped rolled back App Services resource.
    $AppServicesSkipped = @()    

    Write-Host "Starting Roll back operation..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $validAppServicesDetails | ForEach-Object {
        $AppService = $_
        $AppService | Add-Member -NotePropertyName isEndToEndTLSEncryptionRolledback -NotePropertyValue $false
        try
        {
            Write-Host "Rolling back End-to-TLS Versions on App Service - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Info)
            $setAppServicesUri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$($_.ResourceGroupName)/providers/Microsoft.Web/sites/$($_.ResourceName)?api-version=2024-04-01"
                   
       $appServiceBody = @{
                location   = $_.Location
                properties = @{
                    endToEndEncryptionEnabled = $_.PreviousEndToEndTLSEncryption
                }
            }

            $AppServiceResource = Fetch-API -Method "PUT" -Uri $setAppServicesUri -Body $appServiceBody

            if(([string]$AppServiceResource.Properties.EndToEndEncryptionEnabled) -eq ($_.PreviousEndToEndTLSEncryption))
            {
               Write-Host "Succesfully rolled back End-to-end TLS on App Services - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Update)
               Write-Host $([Constants]::SingleDashLine)
               $AppService.PreviousEndToEndTLSEncryption = $AppService.EndToEndEncryptionEnabled
               $AppService.EndToEndEncryptionEnabled = $AppServiceResource.Properties.EndToEndEncryptionEnabled
               $AppService.isEndToEndTLSEncryptionSetPostRemediation = $false
               $AppService.isEndToEndTLSEncryptionRolledback = $true
               $AppServicesRolledBack += $AppService    
            }
            else
            {
                $AppService.isEndToEndTLSEncryptionRolledback = $false
                $AppServicesSkipped += $AppService
            }
        }
        catch
        {
            $AppServicesSkipped += $AppService
        }
    }

    $colsPropertyRollBack = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.EndToEndEncryptionEnabled};Label="EndToEndEncryptionEnabled";Width=50;Alignment="left"},
                    @{Expression={$_.PreviousEndToEndTLSEncryption};Label="PreviousEndToEndTLSEncryption";Width=50;Alignment="left"},
                    @{Expression={$_.isEndToEndTLSEncryptionRolledback};Label="isEndToEndTLSEncryptionRolledback";Width=50;Alignment="left"}

     if ($($AppServicesRolledBack | Measure-Object).Count -gt 0 -or $($AppServicesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($AppServicesRolledBack| Measure-Object).Count -gt 0)
        {
            Write-Host "End-to-end TLS is rolled back successfully on following App Services in the Subscription: " -ForegroundColor $([Constants]::MessageType.Update)
            $AppServicesRolledBack | Format-Table -Property $colsPropertyRollBack -Wrap

            # Write this to a file.
            $AppServiceRolledBackFile = "$($backupFolderPath)\RolledBackAppServices.csv"
            $AppServicesRolledBack | Export-CSV -Path $AppServiceRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($AppServiceRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($AppServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error configuring End-to-end TLS on following App Services in the Subscription: " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $AppServicesSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $AppServiceSkippedFile = "$($backupFolderPath)\RollbackSkippedAppService.csv"
            $AppServicesSkipped | Export-CSV -Path $AppServiceSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($AppServiceSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)                        
            
        }
    }

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
    $accessTokenSecure = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl -AsSecureString
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