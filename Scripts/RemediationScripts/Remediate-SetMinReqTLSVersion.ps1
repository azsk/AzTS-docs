<###
# Overview:
    This script is used to set required TLS version for App Services in a Subscription.

# Control ID:
    Azure_AppService_DP_Use_Secure_TLS_Version

# Display Name:
    Use Approved TLS Version in App Service.

# Prerequisites:
    1. Contributor and higher privileges on the App Services in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription that do not use the required TLS version for the production slot or for any of the non-production slots.
        3. Back up details of App Services that are to be remediated.
        4. Set the required TLS version on the production slot and all non-production slots in all App Services in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the previous TLS versions on the production slot and all non-production slots in all App Services in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the required TLS version on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the previous TLS versions on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the App Services in a Subscription that will be remediated:
           Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To set minimum required TLS version on the production slot and all non-production slots of all App Services in a Subscription:
           Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To set minimum required TLS version on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\AppServicesWithoutMinReqTLSVersion.csv

        4. To set minimum required TLS version on the production slot and all non-production slots of all App Services in a Subscription without taking back up before actual remediation:
           Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Set-AppServiceRequiredTLSVersion -Detailed

    To roll back:
        1. To reset minimum required TLS version on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Reset-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\RemediatedAppServices.csv
        
        2. To reset minimum required TLS version on the production slot of all App Services in a Subscription, from a previously taken snapshot:
           Reset-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -ExcludeNonProductionSlots -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\RemediatedAppServices.csv

        To know more about the options supported by the roll back command, execute:
        Get-Help Reset-AppServiceRequiredTLSVersion -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Websites", "Az.Resources", "Azure")

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..." 

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
        }
        else
        {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host "**Note:**  Az.Websites Module is required to be at the 2.11.0 version."
}

function Set-AppServiceRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Remediates 'Azure_AppService_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Remediates 'Azure_AppService_DP_Use_Secure_TLS_Version' Control.
        Sets the required TLS version on the production slot and all non-production slots in all App Services in the Subscription. 
        
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

        .INPUTS
        None. You cannot pipe objects to Set-AppServiceRequiredTLSVersion.

        .OUTPUTS
        None. Set-AppServiceRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\AppServicesWithoutMinReqTLSVersion.csv

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
    $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Preparing to set required TLS version for App Services in Subscription: $($SubscriptionId)"
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
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
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host "Subscription Name: $($context.Subscription.Name)"
    Write-Host "Subscription ID: $($context.Subscription.SubscriptionId)"
    Write-Host "Account Name: $($context.Account.Id)"
    Write-Host "Account Type: $($context.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "*** To Set Minimum TLS version for App Services in a Subscription, Contributor and higher privileges on the App Services are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all App Services..."
    Write-Host $([Constants]::SingleDashLine)

    $appServicesResourceType = "Microsoft.Web/sites"
    $appServicesSlotsResourceType = "Microsoft.Web/sites/slots"
    $appServiceResources = @()
    $appServiceSlotsResources = @()

    # No file path provided as input to the script. Fetch all App Services in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all App Services and their respective deployments slots in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Default)

        # Get all App Services in a Subscription
        $appServiceResources = Get-AzResource -ResourceType $appServicesResourceType -ErrorAction Stop
        $appServiceSlotsResources = Get-AzResource -ResourceType $appServicesSlotsResourceType -ErrorAction Stop
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all App Services from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Default)

        $appServiceDetails = Import-Csv -LiteralPath $FilePath
        $validAppServiceDetails = $appServiceDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }
        
        $validAppServiceDetails | ForEach-Object {
            $resourceId = $_.ResourceId
            $resourceName = $_.ResourceName
            try
            {
                Write-Host "Fetching App Service resource: Resource Name - $($ResourceName)"
                $appServiceResource = Get-AzResource -ResourceName $ResourceName -ErrorAction SilentlyContinue
                if($appServiceResource.ResourceType -eq $appServicesResourceType)
                {
                    $appServiceResources += $appServiceResource    
                }
                else
                {
                    $appServiceSlotsResources += $appServiceResource
                }
            }
            catch
            {
                Write-Host "Error fetching App Service resource: Resource Name - $($ResourceName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this App Service resource..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetMinTLSVersionForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
    
    $totalAppServices = ($appServiceResources | Measure-Object).Count
    $totalAppServicesSlots = ($appServiceSlotsResources | Measure-Object).Count

    if ($totalAppServices -eq 0)
    {
        Write-Host "No App Services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }
  
    Write-Host "Found $($totalAppServices) App Service(s) and $($totalAppServicesSlots) non-production slot(s)." -ForegroundColor $([Constants]::MessageType.Info)

    $requiredMinTLSVersion = 1.2

    if ($DryRun)
    {
        $appServicesWithMinTLSVersion = @()
        $appServicesWithoutMinTLSVersion = @()
        $appServicesSkipped = @()
        
        Write-Host "Fetching App Service(s) Configurations..."

        $appServiceResources | ForEach-Object {
            $appServiceResource = $_
            $resourceId = $_.ResourceId
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName

            try
            {
                #Write-Host "Fetching App Service configuration: Resource Name - $($resourceName), Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName)"
            
                $MinTLSVersionSetOnProductionSlot = $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $appServiceResource.Name -ErrorAction SilentlyContinue).SiteConfig.MinTLSVersion

                if($MinTLSVersionSetOnProductionSlot -ge $requiredMinTLSVersion)
                {
                    $appServicesWithMinTLSVersion += $appServiceResource | Select-Object @{N='ResourceName';E={$resourceName}},
                                                                                       @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                       @{N='CurrentMinTLSVersionSet';E={$MinTLSVersionSetOnProductionSlot}},
                                                                                       @{N='ResourceID';E={$resourceId}}
                }
                else
                {
                    $appServicesWithoutMinTLSVersion += $appServiceResource | Select-Object @{N='ResourceName';E={$resourceName}},
                                                                                       @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                       @{N='CurrentMinTLSVersionSet';E={$MinTLSVersionSetOnProductionSlot}},
                                                                                       @{N='ResourceID';E={$resourceId}}
                }
            }
            catch
            {
                $appServicesSkipped += $appServiceResource
                Write-Host "Error fetching App Service configuration: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
    
        $appServiceSlotsResources | ForEach-Object {
            $appServiceResource = $_
            $resourceId = $_.ResourceId
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName.Split("/")[0] 
            $slotName = $_.ResourceName.Split("/")[1]

            try
            {
                # Get all non-production slots for this App Service. 
        
                $MinTLSVersionSetOnNonProductionSlot = $(Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName).SiteConfig.MinTLSVersion

                if($MinTLSVersionSetOnNonProductionSlot -ge $requiredMinTLSVersion)
                {
                    $appServicesWithMinTLSVersion += $appServiceResource | Select-Object @{N='ResourceName';E={$_.ResourceName}},
                                                                                    @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                    @{N='CurrentMinTLSVersionSet';E={$MinTLSVersionSetOnNonProductionSlot}},
                                                                                    @{N='ResourceID';E={$resourceId}}
                }
                else
                {
                    $appServicesWithoutMinTLSVersion += $appServiceResource | Select-Object @{N='ResourceName';E={$_.ResourceName}},
                                                                                    @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                    @{N='CurrentMinTLSVersionSet';E={$MinTLSVersionSetOnNonProductionSlot}},
                                                                                    @{N='ResourceID';E={$resourceId}}
                }
        
            }
            catch
            {
                $appServicesSkipped += $appServiceResource      
                Write-Host "Error fetching App Service configuration: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }
        }

        Write-Host "Following $(($appServicesWithMinTLSVersion | Measure-Object).Count) App Service(s)/Non-production slot(s) are on required minimum TLS Version:" -ForegroundColor $([Constants]::MessageType.Info)
        $appServicesWithMinTLSVersion | Format-table
    
        $totalAppServicesWithoutMinTLSVersion = ($appServicesWithoutMinTLSVersion | Measure-Object).Count

        if ($totalAppServicesWithoutMinTLSVersion -eq 0)
        {
            Write-Host "No App Services found with TLS version not set to the required minimum. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }

        Write-Host "Following $(($appServicesWithoutMinTLSVersion | Measure-Object).Count) App Service(s)/Non-production slot(s) are not on required minimum TLS Version." -ForegroundColor $([Constants]::MessageType.Info)
        $appServicesWithoutMinTLSVersion | Format-table

        
        Write-Host $([Constants]::DoubleDashLine)
        
        if(-not $SkipBackup)
        {
            Write-Host "[Step 3 of 4] Backing up App Services details..."
            Write-Host $([Constants]::SingleDashLine)
        
            # Backing up App Services details.
            $backupFile = "$($backupFolderPath)\AppServicesWithoutMinReqTLSVersion.csv"

            $appServicesWithoutMinTLSVersion | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "App Services details have been backed up to: $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)

            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "[Step 4 of 4] Setting Minimum TLS Version for App Services..." -ForegroundColor $([Constants]::MessageType.Default)
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Remediation for the control has been skipped here since -DryRun flag is used. Please review non-compliant resources before remediating them." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "**Next Steps:**  Run the same command to remediate with -FilePath $($backupFile) and without -DryRun, to set minimum TLS Version for all App Services (across the production slot and all non-production slots) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        }
    }
    else
    {
        # Remediation

        Write-Host "Minimum TLS Version will be set on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Default)

        if (-not $Force)
        {
            Write-Host "Do you want to set Minimum TLS Version on the production slot and all non-production slots for all App Services? " -ForegroundColor $([Constants]::MessageType.Info) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Minimum TLS Version will not be set for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Minimum TLS Version will be set on the production slot and all non-production slots for all App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Setting Minimum TLS Version for App Services..." -ForegroundColor $([Constants]::MessageType.Default)
        Write-Host $([Constants]::SingleDashLine)
                
        # To hold results from the remediation.
        $appServicesRemediated = @()
        $appServicesSkipped = @()
        $appServicesWithoutMinTLSVersion = $validAppServiceDetails

        $totalAppServicesWithoutMinTLSVersion = ($appServicesWithoutMinTLSVersion | Measure-Object).Count

        if ($totalAppServicesWithoutMinTLSVersion -eq 0)
        {
            Write-Host "No App Services found with TLS version not set to the required minimum. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }

        $appServicesWithoutMinTLSVersion  | ForEach-Object {
            $appService = $_
            $resourceId = $_.ResourceID
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName
            $CurrentMinTLSVersionSet = $_.CurrentMinTLSVersionSet

            
            if(-not ($resourceName.Contains("/")))
            {
                #App Service
                try
                {
                    Write-Host "Setting minimum TLS Version for App Service: Resource ID - [$($resourceId)], Resource Group Name - [$($resourceGroupName)], Resource Name - [$($resourceName)]" -ForegroundColor $([Constants]::MessageType.Default)

                    $appService | Add-Member -NotePropertyName PreviousMinTLSVersion -NotePropertyValue $CurrentMinTLSVersionSet
                    
                    $UpdatedMinTLSVersion = $(Set-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName -MinTLSVersion $requiredMinTLSVersion).Siteconfig.MinTLSVersion

                    if($UpdatedMinTLSVersion -ge $requiredMinTLSVersion)
                    {
                        Write-Host "Successfully set minimum TLS version on the production slot." -ForegroundColor $([Constants]::MessageType.Update)
                        $appService.CurrentMinTLSVersionSet = $requiredMinTLSVersion
                        $appServicesRemediated += $appService
                    }
                    else
                    {
                        $appServicesSkipped += $appService
                        Write-Host "Error setting minimum TLS version on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "Skipping this App Service." -ForegroundColor $([Constants]::MessageType.Error)
                        return;
                    }
                }
                catch
                {
                    $appServicesSkipped += $appService
                    Write-Host "Error setting minimum TLS version on the production slot. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service." -ForegroundColor $([Constants]::MessageType.Error)
                    return
                }
            }
            else
            {
            # Appservice Slots
                try
                {

                    $appService | Add-Member -NotePropertyName PreviousMinTLSVersion -NotePropertyValue $CurrentMinTLSVersionSet

                    $slotResourceName = $resourceName.Split('/')[0]
                    $slotName = $resourceName.Split('/')[1]
                    Write-Host "Setting minimum TLS Version for non-production slot: Resource ID - [$($resourceId)], Resource Group Name - [$($resourceGroupName)], Resource Name - [$($slotResourceName)], Slot Name - [$($slotName)]" -ForegroundColor $([Constants]::MessageType.Default)
                    $UpdatedMinTLSVersion = $(Set-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $slotResourceName -Slot $slotName -MinTLSVersion $requiredMinTLSVersion).Siteconfig.MinTLSVersion

                    if($UpdatedMinTLSVersion -ge $requiredMinTLSVersion)
                    {
                        Write-Host "Successfully set minimum TLS version on the non-production slot." -ForegroundColor $([Constants]::MessageType.Update)
                        $appService.CurrentMinTLSVersionSet = $requiredMinTLSVersion
                        $appServicesRemediated += $appService
                    }
                    else
                    {
                        $appServicesSkipped += $appService
                        Write-Host "Error setting minimum TLS version on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "Skipping this App Service." -ForegroundColor $([Constants]::MessageType.Error)
                        return;
                    }
                }
                catch
                {
                    $appServicesSkipped += $appService
                    Write-Host "Error setting minimum TLS version on the non-production slot. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service." -ForegroundColor $([Constants]::MessageType.Error)
                    return
                }
            }
        }

        Write-Host $([Constants]::SingleDashLine)
        
        if (($appServicesRemediated | Measure-Object).Count -eq $totalAppServicesWithoutMinTLSVersion)
        {
            Write-Host "Minimum TLS Version successfully set on all $($totalAppServicesWithoutMinTLSVersion) App Service(s)/Non-production slot(s)." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "Minimum TLS Version successfully set on $($($appServicesRemediated | Measure-Object).Count) out of $($totalAppServicesWithoutMinTLSVersion) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
        }

        $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                        @{Expression={$_.PreviousMinTLSVersion};Label="Previous TLS Version Set";Width=20;Alignment="left"},
                        @{Expression={$_.CurrentMinTLSVersionSet};Label="Current TLS Version Set";Width=20;Alignment="left"}


        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

        if ($($appServicesRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Minimum TLS Version successfully set on the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Default)
            $appServicesRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $appServicesRemediatedFile = "$($backupFolderPath)\RemediatedAppServices.csv"
            $appServicesRemediated | Export-CSV -Path $appServicesRemediatedFile -NoTypeInformation
            Write-Host "**Note:** This information has been saved to $($appServicesRemediatedFile)" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($appServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError setting minimum TLS version on the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $appServicesSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $appServicesSkippedFile = "$($backupFolderPath)\SkippedAppServices.csv"
            $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($appServicesSkippedFile)" -ForegroundColor $([Constants]::MessageType.Info)
        }

    }

}

function Reset-AppServiceRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_AppService_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_AppService_DP_Use_Secure_TLS_Version' Control.
        Resets Minimum TLS Version on the production slot and all non-production slots in all App Services in the Subscription. 
        
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
        None. You cannot pipe objects to Reset-AppServiceRequiredTLSVersion.

        .OUTPUTS
        None. Reset-AppServiceRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\RemediatedAppServices.csv

        .EXAMPLE
        PS> Reset-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -ExcludeNonProductionSlots -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\RemediatedAppServices.csv

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

        [Switch]
        [Parameter(HelpMessage="Specifies exclusion of non-production slots from roll back")]
        $ExcludeNonProductionSlots,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the path to the file to be used as input for the roll back")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 3] Preparing to reset minimum TLS version on App Services in Subscription: $($SubscriptionId)"

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
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
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: $($context.Subscription.Name)"
    Write-Host "Subscription ID: $($context.Subscription.SubscriptionId)"
    Write-Host "Account Name: $($context.Account.Id)"
    Write-Host "Account Type: $($context.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "*** To Reset Minimum TLS version for for App Services in a Subscription, Contributor and higher privileges on the App Services are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all App Services..."
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all App Services from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

    $appServiceDetails = Import-Csv -LiteralPath $FilePath
    $validAppServiceDetails = $appServiceDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalAppServices = $($validAppServiceDetails.Count)

    if ($totalAppServices -eq 0)
    {
        Write-Host "No App Services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalAppServices) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetMinTLSVersionForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "Minimum TLS Version will be reset on the production slot for the following App Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
    $validAppServiceDetails | Format-Table

    $slotsBeingRolledBackMessage = "production slot"

    if ($ExcludeNonProductionSlots)
    {
        Write-Host "'ExcludeNonProductionSlots' flag is provided. Non-production slots will be excluded from the rollback." -ForegroundColor $([Constants]::MessageType.Warning)
    }
    else
    {
        $slotsBeingRolledBackMessage += " and all non-production slots"
        Write-Host "'ExcludeNonProductionSlots' flag is not provided. Minimum TLS Version will be reset on ALL non-production slots in addition to the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $Force)
    {
        Write-Host "Do you want to reset minimum TLS Version on the $($slotsBeingRolledBackMessage) for all App Services?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Minimum TLS Version will not be reset for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Minimum TLS Version will be set on the $($slotsBeingRolledBackMessage) for all App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Resetting Minimum TLS Version for App Service..." -ForegroundColor $([Constants]::MessageType.Warning)

    # Includes App Services, to which, previously made changes were successfully rolled back.
    $appServicesRolledBack = @()

    # Includes App Services that were skipped during roll back. There were errors rolling back the changes made previously.
    $appServicesSkipped = @()

    $validAppServiceDetails | ForEach-Object {
        $appService = $_
        $resourceId = $_.ResourceId
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.ResourceName
        $CurrentMinTLSVersionSet = $_.CurrentMinTLSVersionSet
        $PreviousMinTLSVersion = $_.PreviousMinTLSVersion

        try
        {
            Write-Host "Fetching App Service configuration: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName)"
            if(-not ($resourceName.Contains("/")))
            {
                #Appservice
                $CurrentMinTLSVersion = $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName -ErrorAction SilentlyContinue).SiteConfig.MinTLSVersion
                
                if($CurrentMinTLSVersion -eq $PreviousMinTLSVersion)
                {
                    $appServicesSkipped += $appService | Select-Object @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='ResourceName';E={$resourceName}},
                                                                        @{N='CurrentMinTLSVersionSet';E={$CurrentMinTLSVersion}},
                                                                        @{N='ResourceID';E={$resourceId}}
                    Write-Host "Minimum TLS Version is already reset to the previous set version on the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host "Skipping this App Service. If required, manually set the minimum TLS version on the production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    return
                }
                
                $UpdatedMinTLSVersion = $(Set-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName -MinTLSVersion $PreviousMinTLSVersion).Siteconfig.MinTLSVersion
                
                if($UpdatedMinTLSVersion -ne $PreviousMinTLSVersion)
                {
                    $appServicesSkipped += $appService | Select-Object @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='ResourceName';E={$resourceName}},
                                                                        @{N='CurrentMinTLSVersionSet';E={$UpdatedMinTLSVersion}},
                                                                        @{N='ResourceID';E={$resourceId}}
                    Write-Host "Error resetting minimum TLS version on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service. If required, manually set the minimum TLS version on the production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    return
                }

                Write-Host "Successfully resetted minimum TLS version on the production slot." -ForegroundColor $([Constants]::MessageType.Update)
                $appServicesRolledBack += $appService | Select-Object @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='ResourceName';E={$resourceName}},
                                                                        @{N='CurrentMinTLSVersionSet';E={$UpdatedMinTLSVersion}},
                                                                        @{N='ResourceID';E={$resourceId}}
            }
            elseif(-not $ExcludeNonProductionSlots)
            {
                #Appservice slot
                $slotResourceName = $resourceName.Split('/')[0]
                $slotName = $resourceName.Split('/')[1]
                $CurrentMinTLSVersion = $(Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $slotResourceName -Slot $slotName).SiteConfig.MinTLSVersion
            
                if($CurrentMinTLSVersion -eq $PreviousMinTLSVersion)
                {
                    $appServicesSkipped += $appService | Select-Object @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='ResourceName';E={$resourceName}},
                                                                        @{N='CurrentMinTLSVersionSet';E={$CurrentMinTLSVersion}},
                                                                        @{N='ResourceID';E={$resourceId}}
                    Write-Host "Minimum TLS Version is already reset to the previous set version on the non-production slot." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host "Skipping this App Service. If required, manually set the minimum TLS version on the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    return
                }
                
                $UpdatedMinTLSVersion = $(Set-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $slotResourceName -Slot $slotName -MinTLSVersion $PreviousMinTLSVersion).Siteconfig.MinTLSVersion

                if($UpdatedMinTLSVersion -ne $PreviousMinTLSVersion)
                {
                    $appServicesSkipped += $appService | Select-Object @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='ResourceName';E={$resourceName}},
                                                                        @{N='CurrentMinTLSVersionSet';E={$UpdatedMinTLSVersion}},
                                                                        @{N='ResourceID';E={$resourceId}}
                    Write-Host "Error resetting minimum TLS version on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service. If required, manually reset the minimum TLS Version on the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    return
                }

                Write-Host "Successfully resetted minimum TLS version on the non-production slot." -ForegroundColor $([Constants]::MessageType.Update)
                $appServicesRolledBack += $appService | Select-Object @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='ResourceName';E={$resourceName}},
                                                                        @{N='CurrentMinTLSVersionSet';E={$UpdatedMinTLSVersion}},
                                                                        @{N='ResourceID';E={$resourceId}}
            

            }

        }
        catch
        {
            $appServicesSkipped += $appService
            Write-Host "Error resetting minimum TLS version for the App Service. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

    if (($appServicesSkipped | Measure-Object).Count -eq 0)
    {
        Write-Host "Minimum TLS Version successfully set on the $($slotsBeingRolledBackMessage) for all $($totalAppServices) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Minimum TLS Version successfully set on the $($slotsBeingRolledBackMessage) for $($($appServicesRolledBack | Measure-Object).Count) out of $($totalAppServices) App Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                    @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                    @{Expression={$_.CurrentMinTLSVersionSet};Label="Current TLS Version Set";Width=20;Alignment="left"}

    if ($($appServicesRolledBack | Measure-Object).Count -gt 0 -or $($appServicesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($appServicesRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Minimum TLS Version successfully set on the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $appServicesRolledBack | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $appServicesRolledBackFile = "$($backupFolderPath)\RolledBackAppServices.csv"
            $appServicesRolledBack | Export-CSV -Path $appServicesRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to $($appServicesRolledBackFile)"
        }

        if ($($appServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError setting minimum TLS Version for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $appServicesSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $appServicesSkippedFile = "$($backupFolderPath)\RollbackSkippedAppServices.csv"
            $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($appServicesSkippedFile)"
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
