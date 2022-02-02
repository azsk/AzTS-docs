<###
# Overview:
    This script is used to enable HTTPS for App Services in a Subscription.

# Control ID:
    Azure_AppService_DP_Dont_Allow_HTTP_Access

# Display Name:
    Use HTTPS for App Services.

# Prerequisites:
    1. Contributor or higher privileges on the App Services in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription that do not have HTTPS enabled for the production slot or for any of the non-production slots.
        3. Back up details of App Services that are to be remediated.
        4. Enable HTTPS on the production slot and all non-production slots in all App Services in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable HTTPS on the production slot and all non-production slots in all App Services in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable HTTPS on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable HTTPS on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the App Services in a Subscription that will be remediated:
           Enable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To enable HTTPS on the production slot and all non-production slots of all App Services in a Subscription:
           Enable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To enable HTTPS on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Enable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSForAppServices\AppServicesWithoutHTTPSEnabled.csv

        4. To enable HTTPS only on the production slot and all non-production slots of all App Services in a Subscription without taking back up before actual remediation:
           Enable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Enable-HttpsForAppServices -Detailed

    To roll back:
        1. To disable HTTPS on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Disable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSForAppServices\RemediatedAppServices.csv
        
        2. To disable HTTPS on the production slot of all App Services in a Subscription, from a previously taken snapshot:
           Disable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -ExcludeNonProductionSlots -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSForAppServices\RemediatedAppServices.csv

        To know more about the options supported by the roll back command, execute:
        Get-Help Disable-HttpsForAppServices -Detailed        
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
}


function Enable-HttpsForAppServices
{
    <#
        .SYNOPSIS
        Remediates 'Azure_AppService_DP_Dont_Allow_HTTP_Access' Control.

        .DESCRIPTION
        Remediates 'Azure_AppService_DP_Dont_Allow_HTTP_Access' Control.
        Enables HTTPS on the production slot and all non-production slots in all App Services in the Subscription. 
        
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
        None. You cannot pipe objects to Enable-HttpsForAppServices.

        .OUTPUTS
        None. Enable-HttpsForAppServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSForAppServices\AppServicesWithoutHTTPSEnabled.csv

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
    Write-Host "[Step 1 of 3] Preparing to enable HTTPS for App Services in Subscription: $($SubscriptionId)"

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

    Write-Host "*** To enable HTTPS for App Services in a Subscription, Contributor or higher privileges on the App Services are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all App Services..."

    $appServicesResourceType = "Microsoft.Web/sites"
    $appServiceResources = @()

    # No file path provided as input to the script. Fetch all App Services in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all App Services in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all App Services in a Subscription
        $appServiceResources = Get-AzResource -ResourceType $appServicesResourceType -ErrorAction Stop
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all App Services from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

        $appServiceDetails = Import-Csv -LiteralPath $FilePath
        $validAppServiceDetails = $appServiceDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
        
        $validAppServiceDetails | ForEach-Object {
            $resourceId = $_.ResourceId

            try
            {
                Write-Host "Fetching App Service resource: Resource ID - $($resourceId)"
                $appServiceResource = Get-AzResource -ResourceId $resourceId -ErrorAction SilentlyContinue
                $appServiceResources += $appServiceResource
            }
            catch
            {
                Write-Host "Error fetching App Service resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this App Service resource..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
    }

    $totalAppServices = ($appServiceResources | Measure-Object).Count

    if ($totalAppServices -eq 0)
    {
        Write-Host "No App Services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }
  
    Write-Host "Found $($totalAppServices) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)

    # Includes App Services where HTTPS is enabled on all slots - production slot and all non-production slots.
    $appServicesWithHttpsEnabled = @()

    # Includes App Services where HTTPS is not enabled on all slots - production slot or one or more non-production slots.
    $appServicesWithoutHttpsEnabled = @()

    # Includes App Services that were skipped during remediation. There were errors remediating them.
    $appServicesSkipped = @()

    $appServiceResources | ForEach-Object {
        $appServiceResource = $_
        $resourceId = $_.ResourceId
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.ResourceName

        try
        {
            Write-Host "Fetching App Service configuration: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName)"
            
            $isHttpsEnabledOnProductionSlot = $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $appServiceResource.Name -ErrorAction SilentlyContinue).HttpsOnly

            Write-Host "Fetching non-production slot configurations for App Service: Resource ID - $($resourceId)"

            # Get all non-production slots for this App Service.
            $nonProductionSlotConfigurations = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName

            $isHttpsEnabledOnAllNonProductionSlots = -not $($nonProductionSlotConfigurations.HttpsOnly -contains $false)

            if ($isHttpsEnabledOnProductionSlot -and $isHttpsEnabledOnAllNonProductionSlots)
            {
                $appServicesWithHttpsEnabled += $appServiceResource
                Write-Host "HTTPS is enabled on the production slot and all non-production slots in the App Service." -ForegroundColor $([Constants]::MessageType.Update)
                return
            }

            if (-not $isHttpsEnabledOnProductionSlot)
            {
                Write-Host "HTTPS is not enabled on the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
            }

            # Holds the list of non-production slots without HTTPS enabled
            $nonProductionSlotsWithoutHttpsEnabled = @()
            $nonProductionSlotsWithoutHttpsEnabledStr = [String]::Empty

            if (-not $isHttpsEnabledOnAllNonProductionSlots)
            {
                $nonProductionSlotsWithoutHttpsEnabled = $($nonProductionSlotConfigurations | Where-Object { $_.HttpsOnly -eq $false }).Name
                $nonProductionSlotsWithoutHttpsEnabledStr = $($nonProductionSlotsWithoutHttpsEnabled -join ', ')
                Write-Host "HTTPS is not enabled on these non-production slots: $($nonProductionSlotsWithoutHttpsEnabledStr)" -ForegroundColor $([Constants]::MessageType.Warning)
            }

            $appServicesWithoutHttpsEnabled += $appServiceResource | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                                   @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                   @{N='ResourceName';E={$resourceName}},
                                                                                   @{N='IsHTTPSEnabledOnProductionSlot';E={$isHttpsEnabledOnProductionSlot}},
                                                                                   @{N='IsHTTPSEnabledOnAllNonProductionSlots';E={$isHttpsEnabledOnAllNonProductionSlots}},
                                                                                   @{N='NonProductionSlotsWithoutHTTPSEnabled';E={$nonProductionSlotsWithoutHttpsEnabledStr}}
        }
        catch
        {
            $appServicesSkipped += $appServiceResource
            Write-Host "Error fetching App Service configuration: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

    $totalAppServicesWithoutHttpsEnabled = ($appServicesWithoutHttpsEnabled | Measure-Object).Count

    if ($totalAppServicesWithoutHttpsEnabled -eq 0)
    {
        Write-Host "No App Services found with HTTPS not enabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalAppServicesWithoutHttpsEnabled) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableHttpsForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host $([Constants]::DoubleDashLine)

    if (-not $DryRun)
    {
        if (-not $SkipBackup)
        {
            Write-Host "Backing up App Services details to $($backupFolderPath)"
            $backupFile = "$($backupFolderPath)\AppServicesWithoutHTTPSEnabled.csv"
            $appServicesWithoutHttpsEnabled | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "App Services details have been backed up to $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)
        }

        Write-Host "HTTPS will be enabled on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Warning)

        if (-not $Force)
        {
            Write-Host "Do you want to enable HTTPS on the production slot and all non-production slots for all App Services? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "HTTPS will not be enabled for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. HTTPS will be enabled on the production slot and all non-production slots for all App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 3 of 3] Enabling HTTPS for App Services..." -ForegroundColor $([Constants]::MessageType.Warning)

        # To hold results from the remediation.
        $appServicesRemediated = @()
        $appServicesSkipped = @()

        $appServicesWithoutHttpsEnabled | ForEach-Object {
            $appService = $_
            $resourceId = $_.ResourceID
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName
            $isHttpsEnabledOnProductionSlot = $_.IsHTTPSEnabledOnProductionSlot
            $isHttpsEnabledOnAllNonProductionSlots = $_.IsHTTPSEnabledOnAllNonProductionSlots
            $nonProductionSlotsWithoutHttpsEnabled = $_.NonProductionSlotsWithoutHTTPSEnabled

            Write-Host "Enabling HTTPS for App Service: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName)" -ForegroundColor $([Constants]::MessageType.Warning)

            $nonProductionSlotsWithoutHttpsEnabledStr = $nonProductionSlotsWithoutHttpsEnabled -join ', '

            # Reset the status further down, as appropriate.
            $appService | Add-Member -NotePropertyName NonProductionSlotsSkipped -NotePropertyValue $nonProductionSlotsWithoutHttpsEnabledStr

            # If HTTPS is not enabled on the production slot
            if (-not [System.Convert]::ToBoolean($isHttpsEnabledOnProductionSlot))
            {
                try
                {
                    Write-Host "Enabling HTTPS on the production slot..." -ForegroundColor $([Constants]::MessageType.Warning)

                    $isHttpsEnabledOnProductionSlot = $(Set-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName -HttpsOnly $true).HttpsOnly

                    if ($isHttpsEnabledOnProductionSlot)
                    {
                        $isProductionSlotRemediated = $true
                        $appService.IsHTTPSEnabledOnProductionSlot = $true
                        Write-Host "Successfully enabled HTTPS on the production slot." -ForegroundColor $([Constants]::MessageType.Update)
                    }
                    else
                    {
                        $appServicesSkipped += $appService
                        Write-Host "Error enabling HTTPS on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "Skipping this App Service. HTTPS will not be enabled for any of the non-production slots." -ForegroundColor $([Constants]::MessageType.Error)
                        return;
                    }
                }
                catch
                {
                    $appServicesSkipped += $appService
                    Write-Host "Error enabling HTTPS on the production slot. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service. HTTPS will not be enabled for any of the non-production slots." -ForegroundColor $([Constants]::MessageType.Error)
                    return
                }
            }

            # Holds the list of non-production slots without HTTPS enabled
            $nonProductionSlotsSkipped = @()
            $nonProductionSlotsSkippedStr = [String]::Empty

            if (-not [System.Convert]::ToBoolean($isHttpsEnabledOnAllNonProductionSlots))
            {
                foreach ($slot in $nonProductionSlotsWithoutHttpsEnabled.Split(','))
                {
                    # Slot names are of the form: app-service-name/slot-name
                    $slotName = $slot.Split('/')[1]

                    try
                    {
                        Write-Host "Enabling HTTPS on the non-production slot: $($slot)" -ForegroundColor $([Constants]::MessageType.Warning)
                        
                        $isHttpsEnabledOnNonProductionSlot = $(Set-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName -HttpsOnly $true).HttpsOnly

                        if ($isHttpsEnabledOnNonProductionSlot)
                        {
                            Write-Host "Successfully enabled HTTPS on the non-production slot." -ForegroundColor $([Constants]::MessageType.Update)
                        }
                        else
                        {
                            $nonProductionSlotsSkipped += $slot
                            Write-Host "Error enabling HTTPS on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        }
                    }
                    catch
                    {
                        $nonProductionSlotsSkipped += $slot
                        Write-Host "Error enabling HTTPS on the non-production slot. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    }
                }
            }
            
            $nonProductionSlotsSkippedStr = $nonProductionSlotsSkipped -join ', '
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr

            # Remediation of an App Service is successful only if HTTPS is enabled on the production slot and all non-production slots.
            if ($($nonProductionSlotsSkipped | Measure-Object).Count -eq 0)
            {
                $appService.IsHTTPSEnabledOnAllNonProductionSlots = $true
                $appServicesRemediated += $appService
                Write-Host "Successfully enabled HTTPS on the production slot and all non-production slots for the App Service." -ForegroundColor $([Constants]::MessageType.Update)
            }
            else
            {
                $appServicesSkipped += $appService
                Write-Host "Error enabling HTTPS for these non-production slots: $($nonProductionSlotsSkippedStr)" -ForegroundColor $([Constants]::MessageType.Error)
            }
        }

        Write-Host $([Constants]::SingleDashLine)

        if (($appServicesRemediated | Measure-Object).Count -eq $totalAppServicesWithoutHttpsEnabled)
        {
            Write-Host "HTTPS successfully enabled on the production slot and all non-production slots for all $($totalAppServicesWithoutHttpsEnabled) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "HTTPS successfully enabled on the production slot and all non-production slots for $($($appServicesRemediated | Measure-Object).Count) out of $($totalAppServicesWithoutHttpsEnabled) App Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                        @{Expression={$_.IsHttpsEnabledOnProductionSlot};Label="Is HTTPS enabled on the production slot?";Width=20;Alignment="left"},
                        @{Expression={$_.IsHttpsEnabledOnAllNonProductionSlots};Label="Is HTTPS enabled on all the non-production slots?";Width=20;Alignment="left"},
                        @{Expression={$_.NonProductionSlotsWithoutHttpsEnabled};Label="Non-production slots without HTTPS enabled - Prior to remediation";Width=40;Alignment="left"},
                        @{Expression={$_.NonProductionSlotsSkipped};Label="Non-production slots without HTTPS enabled - Post remediation";Width=40;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($appServicesRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "HTTPS successfully enabled for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $appServicesRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $appServicesRemediatedFile = "$($backupFolderPath)\RemediatedAppServices.csv"
            $appServicesRemediated | Export-CSV -Path $appServicesRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to $($appServicesRemediatedFile)"
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($appServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError enabling HTTPS for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $appServicesSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $appServicesSkippedFile = "$($backupFolderPath)\SkippedAppServices.csv"
            $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($appServicesSkippedFile)"
        }
    }
    else
    {
        Write-Host "[Step 3 of 4] Backing up App Services details to $($backupFolderPath)"
        # Backing up App Services details.
        $backupFile = "$($backupFolderPath)\AppServicesWithoutHTTPSEnabled.csv"
        $appServicesWithoutHttpsEnabled | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] App Services details have been backed up to $($backupFile). Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to enable HTTPS for all App Services (across the production slot and all non-production slots) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
    }
}

function Disable-HttpsForAppServices
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_AppService_DP_Dont_Allow_HTTP_Access' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_AppService_DP_Dont_Allow_HTTP_Access' Control.
        Disables HTTPS on the production slot and all non-production slots in all App Services in the Subscription. 
        
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
        None. You cannot pipe objects to Disable-HttpsForAppServices.

        .OUTPUTS
        None. Disable-HttpsForAppServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSForAppServices\RemediatedAppServices.csv

        .EXAMPLE
        PS> Disable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -ExcludeNonProductionSlots -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSForAppServices\RemediatedAppServices.csv

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
    Write-Host "[Step 1 of 3] Preparing to disable HTTPS for App Services in Subscription: $($SubscriptionId)"

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

    Write-Host "*** To disable HTTPS for App Services in a Subscription, Contributor or higher privileges on the App Services are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
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
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableHttpsForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "HTTPS will be disabled on the production slot for all App Services." -ForegroundColor $([Constants]::MessageType.Warning)

    $slotsBeingRolledBackMessage = "production slot"

    if ($ExcludeNonProductionSlots)
    {
        Write-Host "'ExcludeNonProductionSlots' flag is provided. Non-production slots will be excluded from the rollback." -ForegroundColor $([Constants]::MessageType.Warning)
    }
    else
    {
        $slotsBeingRolledBackMessage += " and all non-production slots"
        Write-Host "'ExcludeNonProductionSlots' flag is not provided. HTTPS will be disabled on ALL non-production slots in addition to the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
    }
    
    if (-not $Force)
    {
        Write-Host "Do you want to disable HTTPS on the $($slotsBeingRolledBackMessage) for all App Services?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "HTTPS will not be disabled for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. HTTPS will be disabled on the $($slotsBeingRolledBackMessage) for all App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Disabling HTTPS for App Services..." -ForegroundColor $([Constants]::MessageType.Warning)

    # Includes App Services, to which, previously made changes were successfully rolled back.
    $appServicesRolledBack = @()

    # Includes App Services that were skipped during roll back. There were errors rolling back the changes made previously.
    $appServicesSkipped = @()

    $validAppServiceDetails | ForEach-Object {
        $appService = $_
        $resourceId = $_.ResourceId
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.ResourceName

        try
        {
            Write-Host "Fetching App Service configuration: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName)"
            
            $isHttpsEnabledOnProductionSlot = $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName -ErrorAction SilentlyContinue).HttpsOnly

            if (-not $isHttpsEnabledOnProductionSlot)
            {
                Write-Host "HTTPS is already disabled on the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Skipping this App Service. If required, manually disable HTTPS on the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                return
            }

            $isHttpsEnabledOnProductionSlot = $(Set-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName -HttpsOnly $false).HttpsOnly

            if ($isHttpsEnabledOnProductionSlot)
            {
                $appServicesSkipped += $appService
                Write-Host "Error disabling HTTPS on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this App Service. If required, manually disable HTTPS on the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                return
            }

            Write-Host "Successfully disabled HTTPS on the production slot." -ForegroundColor $([Constants]::MessageType.Update)

            $appService.IsHttpsEnabledOnProductionSlot = $false

            if ($ExcludeNonProductionSlots)
            {
                $appServicesRolledBack += $appService
                Write-Host "Changes previously made to the non-production slots will not be rolled back." -ForegroundColor $([Constants]::MessageType.Info)
                return
            }

            # Reset the states further below, as appropriate.
            $appService | Add-Member -NotePropertyName IsHttpsEnabledOnAnyNonProductionSlot -NotePropertyValue $false
            $appService | Add-Member -NotePropertyName NonProductionSlotsWithHttpsEnabled -NotePropertyValue ([String]::Empty)

            # Disable HTTPS on all non-production slots.
            Write-Host "Fetching non-production slot configurations for App Service: Resource ID - $($resourceId)"

            # Get all non-production slots for this App Service.
            $nonProductionSlotConfigurations = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName

            $isHttpsEnabledOnAnyNonProductionSlot = $($nonProductionSlotConfigurations.HttpsOnly -contains $true)

            # All non-production slots have HTTPS disabled.
            if (-not $isHttpsEnabledOnAnyNonProductionSlot)
            {
                $appServicesRolledBack += $appService
                Write-Host "HTTPS is not enabled on any of the non-production slots in the App Service." -ForegroundColor $([Constants]::MessageType.Update)
                return
            }

            $appService.IsHttpsEnabledOnAnyNonProductionSlot = $true

            # Holds the list of non-production slots with HTTPS enabled
            $nonProductionSlotsWithHttpsEnabled = @()
            $nonProductionSlotsWithHttpsEnabled = $($nonProductionSlotConfigurations | Where-Object { $_.HttpsOnly -eq $true }).Name
            $nonProductionSlotsWithHttpsEnabledStr = $($nonProductionSlotsWithHttpsEnabled -join ', ')

            $appService.NonProductionSlotsWithHttpsEnabled = $nonProductionSlotsWithHttpsEnabledStr

            # Holds the running list of non-production slots with HTTPS enabled. Remove slots from this list as HTTPS is being disabled on them.
            $nonProductionSlotsSkipped = $nonProductionSlotsWithHttpsEnabled
            $nonProductionSlotsSkippedStr = $nonProductionSlotsWithHttpsEnabledStr

            $appService.NonProductionSlotsSkipped = $nonProductionSlotsWithHttpsEnabledStr

            Write-Host "HTTPS is enabled on these non-production slots: $($nonProductionSlotsWithHttpsEnabledStr)" -ForegroundColor $([Constants]::MessageType.Warning)

            foreach ($slot in $nonProductionSlotsWithHttpsEnabled)
            {
                # Slot names are of the form: app-service-name/slot-name
                $slotName = $slot.Split('/')[1]

                Write-Host "Disabling HTTPS on the non-production slot: $($slot)" -ForegroundColor $([Constants]::MessageType.Warning)
                        
                $isHttpsEnabledOnNonProductionSlot = $(Set-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName -HttpsOnly $false).HttpsOnly

                if ($isHttpsEnabledOnNonProductionSlot)
                {
                    Write-Host "Error enabling HTTPS on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                }
                else
                {
                    # Remove this slot from the list of non-production slots with HTTPS enabled
                    $nonProductionSlotsSkipped = $nonProductionSlotsSkipped | Where-Object { $_ -ne $slot }
                    $nonProductionSlotsSkippedStr = $nonProductionSlotsSkipped -join ', '
                    $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr

                    Write-Host "Successfully disabled HTTPS on the non-production slot." -ForegroundColor $([Constants]::MessageType.Update)
                }
            }

            # Rollback of the changes previously made to an App Service is successful only if HTTPS is disabled on the production slot and all non-production slots.
            if ($($nonProductionSlotsSkipped | Measure-Object).Count -eq 0)
            {
                $appService.IsHttpsEnabledOnAnyNonProductionSlot = $false
                $appServicesRolledBack += $appService
                Write-Host "Successfully disabled HTTPS on the production slot and all non-production slots for the App Service." -ForegroundColor $([Constants]::MessageType.Update)
            }
            else
            {
                $appServicesSkipped += $appService
                Write-Host "Error disabling HTTPS for these non-production slots: $($nonProductionSlotsSkippedStr)" -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
        catch
        {
            $appServicesSkipped += $appService
            Write-Host "Error disabling HTTPS for the App Service. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

    if (($appServicesSkipped | Measure-Object).Count -eq 0)
    {
        Write-Host "HTTPS successfully disabled on the $($slotsBeingRolledBackMessage) for all $($totalAppServices) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "HTTPS successfully disabled on the $($slotsBeingRolledBackMessage) for $($($appServicesRolledBack | Measure-Object).Count) out of $($totalAppServices) App Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                    @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                    @{Expression={$_.IsHttpsEnabledOnProductionSlot};Label="Is HTTPS enabled on the production slot?";Width=20;Alignment="left"},
                    @{Expression={$_.IsHttpsEnabledOnAnyNonProductionSlot};Label="Is HTTPS enabled on any non-production slot?";Width=20;Alignment="left"},
                    @{Expression={$_.NonProductionSlotsWithHttpsEnabled};Label="Non-production slots with HTTPS enabled - Prior to rollback";Width=40;Alignment="left"},
                    @{Expression={$_.NonProductionSlotsSkipped};Label="Non-production slots with HTTPS enabled - Post rollback";Width=40;Alignment="left"}

    if ($($appServicesRolledBack | Measure-Object).Count -gt 0 -or $($appServicesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($appServicesRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "HTTPS successfully disabled for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $appServicesRolledBack | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $appServicesRolledBackFile = "$($backupFolderPath)\RolledBackAppServices.csv"
            $appServicesRolledBack | Export-CSV -Path $appServicesRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to $($appServicesRolledBackFile)"
        }

        if ($($appServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError disabling HTTPS for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
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
