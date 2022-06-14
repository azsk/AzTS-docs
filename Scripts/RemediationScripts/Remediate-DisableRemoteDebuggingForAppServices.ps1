<###
# Overview:
    This script is used to disable Remote Debugging for App Services in a Subscription.

# Control ID:
    Azure_AppService_Config_Disable_Remote_Debugging

# Display Name:
    Remote debugging should be turned off for Web Applications.

# Prerequisites:
    1. Contributor or higher privileges on the App Services in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription that do not have remote debugging disabled for the production slot or for any of the non-production slots.
        3. Back up details of App Services that are to be remediated.
        4. Disable remote debugging on the production slot and all non-production slots in all App Services in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription, the changes made to which previously, are to be rolled back.
        3. Enable remote debugging on the production slot and all non-production slots in all App Services in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable remote debugging on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable remote debugging on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the App Services in a Subscription that will be remediated:
           Disable-RemoteDebuggingForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To disable Remote Debugging on the production slot and all non-production slots of all App Services in a Subscription:
           Disable-RemoteDebuggingForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To disable Remote Debugging on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Disable-RemoteDebuggingForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableRemoteDebuggingForAppServices\AppServicesWithoutRemoteDebuggingDisabled.csv

        To know more about the options supported by the remediation command, execute:
        Get-Help Disable-RemoteDebuggingForAppServices -Detailed

    To roll back:
        1. To enable Remote Debugging on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Enable-RemoteDebuggingForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableRemoteDebuggingForAppServices\RemediatedAppServices.csv
        
        To know more about the options supported by the roll back command, execute:
        Get-Help Enable-RemoteDebuggingForAppServices -Detailed        
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

function Disable-RemoteDebuggingForAppServices
{
    <#
        .SYNOPSIS
        Remediates 'Azure_AppService_Config_Disable_Remote_Debugging' Control.

        .DESCRIPTION
        Remediates 'Azure_AppService_Config_Disable_Remote_Debugging' Control.
        Remote debugging must be turned off for App Service.
        
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
        None. You cannot pipe objects to Disable-RemoteDebuggingForAppServices.

        .OUTPUTS
        None. Disable-RemoteDebuggingForAppServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-RemoteDebuggingForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Disable-RemoteDebuggingForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Disable-RemoteDebuggingForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202201011212\DisableRemoteDebuggingForAppServices\AppServicesWithoutRemoteDebuggingDisabled.csv

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
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "`n[Step 1 of 5] Preparing to disable Remote Debugging for App Services in Subscription: $($SubscriptionId)"

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

    Write-Host "*** To disable Remote Debugging for App Services in a Subscription, Contributor or higher privileges on the App Services are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "`n[Step 2 of 5] Preparing to fetch all App Services..."

    $appServicesResourceType = "Microsoft.Web/sites"
    $appServiceResources = @()

    # No file path provided as input to the script. Fetch all App Services in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "`nFetching all App Services in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

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

    # Includes App Services where Remote Debugging is disabled on all slots - production slot and all non-production slots.
    $appServicesWithRemoteDebuggingDisabled = @()

    # Includes App Services where Remote Debugging is not disabled on all slots - production slot or one or more non-production slots.
    $appServicesWithoutRemoteDebuggingDisabled = @()

    # Includes App Services that were skipped during remediation. There were errors remediating them.
    $appServicesSkipped = @()

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "`n[Step 3 of 5] Fetching all App Service configurations..."
    Write-Host "This process may take some time..."  -ForegroundColor $([Constants]::MessageType.Warning)
    $i = 0

    $appServiceResources | ForEach-Object {
        $appServiceResource = $_
        $resourceId = $_.ResourceId
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.ResourceName
        $i++
        $progress = [math]::Round($($i*100/$totalAppServices), 2)
        Write-Progress -Activity 'Fetching configurations...' -Status "Progress status: $progress%" -PercentComplete (($i/$totalAppServices)*100)

        try
        {
            $nonCompliant = @()
            $nonProductionSlots = @()

            # Using GetAzWebApp to fetch site config for each of the App Service resource.
            $isRemoteDebuggingDisabledOnProductionSlot = -not $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $appServiceResource.Name -ErrorAction SilentlyContinue).SiteConfig.RemoteDebuggingEnabled
        
            # Get all non-production slots for this App Service.
            $nonProductionSlots = (Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName) | select -Property Name | ForEach {$_.Name}
            $nonProductionSlotsWithoutRemoteDebuggingDisabledStr = [String]::Empty
            $list = @()
            $IsRemoteDebuggingDisabledOnAllNonProductionSlots = $true
            $nonProductionSlots | ForEach-Object{
                $nonProdSlotName = $_
                $nonProdSlotName = $nonProdSlotName.Split('/')[1]
                $nonProductionSlotConfigurations = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $nonProdSlotName

                $isRemoteDebuggingDisabledOnNonProductionSlots = -not $($nonProductionSlotConfigurations.SiteConfig.RemoteDebuggingEnabled -eq $true)

                if (-not $isRemoteDebuggingDisabledOnNonProductionSlots)
                {
                    $list += $nonProdSlotName
                    $nonProductionSlotsWithoutRemoteDebuggingDisabledStr = $list -join ',' 
                    $IsRemoteDebuggingDisabledOnAllNonProductionSlots = $false
                }
            }

            if ($isRemoteDebuggingDisabledOnProductionSlot -and $IsRemoteDebuggingDisabledOnAllNonProductionSlots)
            {
                $appServicesWithRemoteDebuggingDisabled += $appServiceResource
                return
            }

            $appServicesWithoutRemoteDebuggingDisabled += $appServiceResource | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                                   @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                   @{N='ResourceName';E={$resourceName}},
                                                                                   @{N='IsRemoteDebuggingDisabledOnProductionSlot';E={$isRemoteDebuggingDisabledOnProductionSlot}},
                                                                                   @{N='IsRemoteDebuggingDisabledOnAllNonProductionSlots';E={$isRemoteDebuggingDisabledOnAllNonProductionSlots}},
                                                                                   @{N='NonProductionSlotsWithoutRemoteDebuggingDisabled';E={$nonProductionSlotsWithoutRemoteDebuggingDisabledStr}}
        }
        catch
        {
            $appServicesSkipped += $appServiceResource
            Write-Host "Error fetching App Service configuration: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

    $totalAppServicesWithoutRemoteDebuggingDisabled = ($appServicesWithoutRemoteDebuggingDisabled | Measure-Object).Count

    if ($totalAppServicesWithoutRemoteDebuggingDisabled -eq 0)
    {
        Write-Host "No App Services found with Remote Debugging enabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalAppServicesWithoutRemoteDebuggingDisabled) out of $($totalAppServices) App Service(s) with Remote Debugging enabled." -ForegroundColor $([Constants]::MessageType.Update)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DisableRemoteDebuggingForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "`n[Step 4 of 5] Backing up App Services details..."

    # Backing up App Services details.
    $backupFile = "$($backupFolderPath)\AppServicesWithoutRemoteDebuggingDisabled.csv"
    $appServicesWithoutRemoteDebuggingDisabled | Export-CSV -Path $backupFile -NoTypeInformation
    Write-Host "App Services details have been successful backed up to $($backupFolderPath)" -ForegroundColor $([Constants]::MessageType.Update)

    if (-not $DryRun)
    {
        Write-Host "`nFollowing App Service(s) are having Remote Debugging enabled:" -ForegroundColor $([Constants]::MessageType.Info)
        $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                        @{Expression={$_.isRemoteDebuggingDisabledOnProductionSlot};Label="Is Remote Debugging disabled on the production slot?";Width=20;Alignment="left"},
                        @{Expression={$_.isRemoteDebuggingDisabledOnAllNonProductionSlots};Label="Is Remote Debugging disabled on all the non-production slots?";Width=20;Alignment="left"},
                        @{Expression={$_.NonProductionSlotsWithoutRemoteDebuggingDisabled};Label="Non-production slots having Remote Debugging enabled";Width=20;Alignment="left"}

        $appServicesWithoutRemoteDebuggingDisabled | Format-Table -Property $colsProperty -Wrap

        Write-Host "Remote Debugging will be disabled on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Warning)

        if (-not $Force)
        {
            Write-Host "Do you want to disable Remote Debugging on the production slot and all non-production slots for all App Services? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Remote Debugging will not be disabled for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Remote Debugging will be disabled on the production slot and all non-production slots for all App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "`n[Step 5 of 5] Disabling Remote Debugging for App Services..."

        # To hold results from the remediation.
        $appServicesRemediated = @()
        $appServicesSkipped = @()

        $appServicesWithoutRemoteDebuggingDisabled | ForEach-Object {
            $appService = $_
            $resourceId = $_.ResourceID
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName
            $isRemoteDebuggingDisabledOnProductionSlot = $_.isRemoteDebuggingDisabledOnProductionSlot
            $isRemoteDebuggingDisabledOnAllNonProductionSlots = $_.isRemoteDebuggingDisabledOnAllNonProductionSlots
            $nonProductionSlotsWithoutRemoteDebuggingDisabled = $_.NonProductionSlotsWithoutRemoteDebuggingDisabled

            $nonProductionSlotsWithoutRemoteDebuggingDisabledStr = $nonProductionSlotsWithoutRemoteDebuggingDisabled -join ','
            $isRemoteDebuggingDisabledOnProdSlotPostRemediation = $isRemoteDebuggingDisabledOnProductionSlot
            
            # Reset the status further down, as appropriate.
            $appService | Add-Member -NotePropertyName NonProductionSlotsSkipped -NotePropertyValue $nonProductionSlotsWithoutRemoteDebuggingDisabledStr
            $appService | Add-Member -NotePropertyName IsRemoteDebuggingDisabledOnProductionSlotPostRemediation -NotePropertyValue $isRemoteDebuggingDisabledOnProdSlotPostRemediation

            # If Remote Debugging is not disabled on the production slot
            if (-not [System.Convert]::ToBoolean($isRemoteDebuggingDisabledOnProductionSlot))
            {
                try
                {
                    $resource = Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName
                    $resource.SiteConfig.RemoteDebuggingEnabled = $false

                    # Holding output of set command to avoid unnecessary logs.
                    $temp = $resource | Set-AzWebApp -ErrorAction SilentlyContinue
                    $isRemoteDebuggingDisabledOnProductionSlot = -not $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName).SiteConfig.RemoteDebuggingEnabled

                    if ($isRemoteDebuggingDisabledOnProductionSlot)
                    {
                        $isProductionSlotRemediated = $true
                        $appService.IsRemoteDebuggingDisabledOnProductionSlotPostRemediation = $true
                    }
                    else
                    {
                        $appServicesSkipped += $appService
                        return;
                    }
                }
                catch
                {
                    $appServicesSkipped += $appService
                    return
                }
            }

            # Holds the list of non-production slots without Remote Debugging disabled.
            $nonProductionSlotsSkipped = @()
            $nonProductionSlotsSkippedStr = [String]::Empty

            if (-not [System.Convert]::ToBoolean($isRemoteDebuggingDisabledOnAllNonProductionSlots))
            {
                foreach ($slot in $nonProductionSlotsWithoutRemoteDebuggingDisabled.Split(','))
                {
                    try
                    {
                        $resource = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slot
                        $resource.SiteConfig.RemoteDebuggingEnabled = $false
                        
                        # Holding output of set command to avoid unnecessary logs.
                        $temp = $resource | Set-AzWebAppSlot -ErrorAction SilentlyContinue

                        $isRemoteDebuggingDisabledOnProductionSlot = -not $(Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slot).SiteConfig.RemoteDebuggingEnabled
                        
                        if (-not $isRemoteDebuggingDisabledOnProductionSlot)
                        {
                            $nonProductionSlotsSkipped += $slot
                        }
                    }
                    catch
                    {
                        $nonProductionSlotsSkipped += $slot
                    }
                }
            }
            
            $nonProductionSlotsSkippedStr = $nonProductionSlotsSkipped -join ','
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr

            if ($($nonProductionSlotsSkipped | Measure-Object).Count -eq 0)
            {
                $appService.isRemoteDebuggingDisabledOnAllNonProductionSlots = $true
                $appServicesRemediated += $appService
            }
            else
            {
                $appServicesSkipped += $appService
            }
        }

        Write-Host $([Constants]::SingleDashLine)

        if (($appServicesRemediated | Measure-Object).Count -eq $totalAppServicesWithoutRemoteDebuggingDisabled)
        {
            Write-Host "Remote Debugging successfully disabled on the production slot and all non-production slots for all $($totalAppServicesWithoutRemoteDebuggingDisabled) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "Remote Debugging successfully disabled on the production slot and all non-production slots for $($($appServicesRemediated | Measure-Object).Count) out of $($totalAppServicesWithoutRemoteDebuggingDisabled) App Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                        @{Expression={$_.isRemoteDebuggingDisabledOnProductionSlot};Label="Is Remote Debugging disabled on the production slot - Prior to remediation?";Width=20;Alignment="left"},
                        @{Expression={$_.IsRemoteDebuggingDisabledOnProductionSlotPostRemediation};Label="Is Remote Debugging disabled on the production slot - Post remediation?";Width=20;Alignment="left"},
                        @{Expression={$_.isRemoteDebuggingDisabledOnAllNonProductionSlots};Label="Is Remote Debugging disabled on all the non-production slots?";Width=20;Alignment="left"},
                        @{Expression={$_.NonProductionSlotsWithoutRemoteDebuggingDisabled};Label="Non-production slots without Remote Debugging disabled - Prior to remediation";Width=40;Alignment="left"},
                        @{Expression={$_.NonProductionSlotsSkipped};Label="Non-production slots without Remote Debugging disabled - Post remediation";Width=40;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "`nRemediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($appServicesRemediated | Measure-Object).Count -gt 0)
        {
            $appServicesRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $appServicesRemediatedFile = "$($backupFolderPath)\RemediatedAppServices.csv"
            $appServicesRemediated | Export-CSV -Path $appServicesRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to $($appServicesRemediatedFile)"
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($appServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError disabling Remote Debugging for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $appServicesSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $appServicesSkippedFile = "$($backupFolderPath)\SkippedAppServices.csv"
            $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($appServicesSkippedFile)"
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "`n[Step 5 of 5] Disabling Remote Debugging for App Services..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "`n**Next steps:**" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to disable Remote Debugging for all App Services (across the production slot and all non-production slots) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
    }   
}

function Enable-RemoteDebuggingForAppServices
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_AppService_Config_Disable_Remote_Debugging' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_AppService_Config_Disable_Remote_Debugging' Control.
        Enables Remote Debugging on the production slot and all non-production slots in all App Services in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Enable-RemoteDebuggingForAppServices.

        .OUTPUTS
        None. Enable-RemoteDebuggingForAppServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-RemoteDebuggingForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\DisableRemoteDebuggingForAppServices\RemediatedAppServices.csv

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
    Write-Host "`n[Step 1 of 3] Preparing to enable Remote Debugging for App Services in Subscription: $($SubscriptionId)"

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

    Write-Host "*** To enable Remote Debugging for App Services in a Subscription, Contributor or higher privileges on the App Services are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "`n[Step 2 of 3] Preparing to fetch all App Services..."
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all App Services from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

    $appServiceDetails = Import-Csv -LiteralPath $FilePath
    $validAppServiceDetails = $appServiceDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalAppServices = ($validAppServiceDetails | Measure-Object).Count

    if ($totalAppServices -eq 0)
    {
        Write-Host "No App Services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalAppServices) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableRemoteDebuggingForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
    
    if (-not $Force)
    {
        Write-Host "Do you want to enable Remote Debugging on the production slot and all non-production slots for all App Services?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Remote Debugging will not be enabled for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Remote Debugging will be enabled on the production slot and all non-production slots for all App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "`n[Step 3 of 3] Enabling Remote Debugging for App Services..."

    # Includes App Services, to which, previously made changes were successfully rolled back.
    $appServicesRolledBack = @()

    # Includes App Services that were skipped during roll back. There were errors rolling back the changes made previously.
    $appServicesSkipped = @()

    $validAppServiceDetails | ForEach-Object {
        $appService = $_
        $resourceId = $appService.ResourceId
        $resourceGroupName = $appService.ResourceGroupName
        $resourceName = $appService.ResourceName
        $nonProdSlots = $appService.NonProductionSlotsWithoutRemoteDebuggingDisabled
        $isRemoteDebuggingDisabled = $appService.isRemoteDebuggingDisabledOnProductionSlot

        try
        {
            if ($isRemoteDebuggingDisabled -eq $false)
            {
                $resource = Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName
                $resource.SiteConfig.RemoteDebuggingEnabled = $true
            
                # Holding output of set command to avoid unnecessary logs.
                $temp = $resource | Set-AzWebApp -ErrorAction SilentlyContinue
                $isRemoteDebuggingDisabledOnProductionSlot = -not $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName).SiteConfig.RemoteDebuggingEnabled
                
                if ($isRemoteDebuggingDisabledOnProductionSlot)
                {
                    $appServicesSkipped += $appService
                    Write-Host "Error enabling Remote Debugging on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service. If required, manually enable Remote Debugging on the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    return
                }
            }

            # Reset the states further below, as appropriate.
            $appService | Add-Member -NotePropertyName IsRemoteDebuggingDisabledOnAnyNonProductionSlot -NotePropertyValue $false
            $appService | Add-Member -NotePropertyName NonProductionSlotsWithRemoteDebuggingDisabled -NotePropertyValue ([String]::Empty)

            $nonProductionSlotConfigurations = @()

            if ([String]::IsNullOrWhiteSpace($nonProdSlots))
            {
                $isNonProdSlotAvailable = $false
            }
            else
            {
                foreach ($slot in $nonProdSlots.Split(','))
                {
                    $nonProductionSlotConfigurations += Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slot
                }

                $isRemoteDebuggingDisabledOnAllNonProductionSlots = -not $($nonProductionSlotConfigurations.SiteConfig.RemoteDebuggingEnabled -eq $true)
            }

            # All non-production slots have Remote Debugging enabled.
            if (-not $isRemoteDebuggingDisabledOnAllNonProductionSlots -or -not $isNonProdSlotAvailable)
            {
                $appServicesRolledBack += $appService
                Write-Host "Remote Debugging is enabled on all non-production slots in the App Service." -ForegroundColor $([Constants]::MessageType.Update)
                return
            }

            $appService.IsRemoteDebuggingDisabledOnAnyNonProductionSlot = $true

            # Holds the list of non-production slots with Remote Debugging disabled.
            $nonProductionSlotsWithRemoteDebuggingDisabled = @()
            
            $nonProductionSlotsWithRemoteDebuggingDisabledStr = [string]::Empty
            $list = @()

            $nonProductionSlotConfigurations | ForEach-Object{
                $nonProductionSlotConfig = $_
                $nonProdSlotName = $nonProductionSlotConfig.Name.Split('/')[1]

                $nonProdSlotConfig = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $nonProdSlotName

                $isRemoteDebuggingDisabledOnNonProductionSlots = -not $($nonProdSlotConfig.SiteConfig.RemoteDebuggingEnabled -eq $true)

                if ($isRemoteDebuggingDisabledOnNonProductionSlots)
                {
                    $list += $nonProdSlotName
                    $nonProductionSlotsWithRemoteDebuggingDisabledStr = $list -join ',' 
                    $IsRemoteDebuggingEnabledOnAllNonProductionSlots = $false
                }
            }

            $appService.NonProductionSlotsWithRemoteDebuggingDisabled = $nonProductionSlotsWithRemoteDebuggingDisabledStr

            $nonProductionSlotsRolledBack = @()

            foreach ($slot in $nonProductionSlotsWithRemoteDebuggingDisabledStr.Split(','))
            {
                $resource = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slot
                $resource.SiteConfig.RemoteDebuggingEnabled = $true
                
                # Holding output of set command to avoid unnecessary logs.
                $temp = $resource | Set-AzWebAppSlot -ErrorAction SilentlyContinue   
                $isRemoteDebuggingDisabledOnNonProductionSlot = -not $(Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slot).SiteConfig.RemoteDebuggingEnabled

                if ($isRemoteDebuggingDisabledOnNonProductionSlot)
                {
                    $nonProductionSlotsSkipped += $slot
                    $nonProductionSlotsSkippedStr = $nonProductionSlotsRolledBack -join ','
                }
                else
                {
                    $nonProductionSlotsRolledBack += $slot
                    $nonProductionSlotsRolledBackStr = $nonProductionSlotsRolledBack -join ','
                }
            }

            $isRemoteDebuggingDisabledOnProductionSlot = -not $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName).SiteConfig.RemoteDebuggingEnabled
            $appService.IsRemoteDebuggingDisabledOnProductionSlot = $isRemoteDebuggingDisabledOnProductionSlot

            $appService.NonProductionSlotsWithoutRemoteDebuggingDisabled = $nonProductionSlotsRolledBackStr
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr

            # Rollback of the changes previously made to an App Service is successful only if Remote Debugging is enabled on the production slot and all non-production slots.
            if ($($nonProductionSlotsSkipped | Measure-Object).Count -eq 0)
            {
                $appService.IsRemoteDebuggingDisabledOnAnyNonProductionSlot = $false
                $appServicesRolledBack += $appService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                        @{N='IsRemoteDebuggingDisabledOnProductionSlot';E={$_.IsRemoteDebuggingDisabledOnProductionSlot}},
                                                                        @{N='IsRemoteDebuggingDisabledOnAnyNonProductionSlot';E={$_.IsRemoteDebuggingDisabledOnAnyNonProductionSlot}},
                                                                        @{N='NonProductionSlotsWithoutRemoteDebuggingDisabled';E={$_.NonProductionSlotsWithoutRemoteDebuggingDisabled}},
                                                                        @{N='NonProductionSlotsSkipped';E={$_.NonProductionSlotsSkipped}}
            }
            else
            {
                $appServicesSkipped += $appService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                        @{N='IsRemoteDebuggingDisabledOnProductionSlot';E={$_.IsRemoteDebuggingDisabledOnProductionSlot}},
                                                                        @{N='IsRemoteDebuggingDisabledOnAnyNonProductionSlot';E={$_.IsRemoteDebuggingDisabledOnAnyNonProductionSlot}},
                                                                        @{N='NonProductionSlotsWithoutRemoteDebuggingDisabled';E={$_.NonProductionSlotsWithoutRemoteDebuggingDisabled}},
                                                                        @{N='NonProductionSlotsSkipped';E={$_.NonProductionSlotsSkipped}}
            }
        }
        catch
        {
            $appServicesSkipped += $appService | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                @{N='ResourceName';E={$resourceName}},
                                                                @{N='IsRemoteDebuggingDisabledOnProductionSlot';E={$isRemoteDebuggingDisabledOnProductionSlot}},
                                                                @{N='IsRemoteDebuggingDisabledOnAnyNonProductionSlot';E={$isRemoteDebuggingDisabledOnAnyNonProductionSlot}},
                                                                @{N='NonProductionSlotsWithoutRemoteDebuggingDisabled';E={$nonProductionSlotsWithoutRemoteDebuggingDisabled}},
                                                                @{N='NonProductionSlotsSkipped';E={$nonProductionSlotsSkipped}}
        }
    }

    if (($appServicesSkipped | Measure-Object).Count -eq 0)
    {
        Write-Host "Remote Debugging successfully enabled on the production slot and all non-production slots for all $($totalAppServices) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Remote Debugging successfully enabled on the production slot and all non-production slots for $($($appServicesRolledBack | Measure-Object).Count) out of $($totalAppServices) App Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                    @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                    @{Expression={$_.IsRemoteDebuggingDisabledOnProductionSlot};Label="Is Remote Debugging disabled on the production slot?";Width=20;Alignment="left"},
                    @{Expression={$_.IsRemoteDebuggingDisabledOnAnyNonProductionSlot};Label="Is Remote Debugging disabled on any non-production slot?";Width=20;Alignment="left"},
                    @{Expression={$_.NonProductionSlotsWithoutRemoteDebuggingDisabled};Label="Non-production slots with Remote Debugging disabled - Prior to rollback";Width=40;Alignment="left"},
                    @{Expression={$_.NonProductionSlotsSkipped};Label="Non-production slots with Remote Debugging disabled - Post rollback";Width=40;Alignment="left"}

    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "`nRollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
    
    if ($($appServicesRolledBack | Measure-Object).Count -gt 0)
    {
        $appServicesRolledBack | Format-Table -Property $colsProperty -Wrap

        # Write this to a file.
        $appServicesRolledBackFile = "$($backupFolderPath)\RolledBackAppServices.csv"
        $appServicesRolledBack | Export-CSV -Path $appServicesRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to $($appServicesRolledBackFile)"
    }

    if ($($appServicesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "`nError enabling Remote Debugging for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $appServicesSkipped | Format-Table -Property $colsProperty -Wrap
            
        # Write this to a file.
        $appServicesSkippedFile = "$($backupFolderPath)\RollbackSkippedAppServices.csv"
        $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to $($appServicesSkippedFile)"
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