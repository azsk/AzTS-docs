<###
# Overview:
    This script is used to set required TLS version for App Services in a Subscription.

# Control ID:
    Azure_AppService_DP_Use_Secure_TLS_Version

# Display Name:
    Use Approved TLS Version in App Service.

# Prerequisites:
    Contributor and higher privileges on the App Services in a Subscription.

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
    
           Enable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To enable HTTPS on the production slot and all non-production slots of all App Services in a Subscription:
       
           Enable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To enable HTTPS on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
       
           Enable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSForAppServices\AppServicesWithoutHTTPSEnabled.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-HttpsForAppServices -Detailed

    To roll back:
        1. To disable HTTPS on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Disable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableHTTPSForAppServices\RemediatedAppServices.csv
        
        2. To disable HTTPS on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
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

function Set-RequiredTLSVersion
{
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
    Write-Host "[Step 1 of 4] Preparing to set required TLS version for App Services in Subscription: $($SubscriptionId)"

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
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: $($context.Subscription.Name)"
    Write-Host "Subscription ID: $($context.Subscription.SubscriptionId)"
    Write-Host "Account Name: $($context.Account.Id)"
    Write-Host "Account Type: $($context.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if $($context.Account.Id) is allowed to run this script..."

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of $($context.Account.Id) is: $($context.Account.Type)" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "*** To enable HTTPS for App Services in a Subscription, Contributor and higher privileges on the App Services are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all App Services..."

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

        Write-Host "1 Fetching all App Services from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

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

    $appServicesWithMinTLSVersion = @()

    $appServicesWithoutMinTLSVersion = @()

    $appServicesSkipped = @()

    $minTLSVersion = 1.2

    $appServiceResources | ForEach-Object {
        $appServiceResource = $_
        $resourceId = $_.ResourceId
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.ResourceName

        try
        {
            Write-Host "Fetching App Service configuration: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName)"
            
            $isMinTLSVersionSetOnProductionSlot = $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $appServiceResource.Name -ErrorAction SilentlyContinue).SiteConfig.MinTlsVersion -eq $minTLSVersion

            Write-Host "Fetching non-production slot configurations for App Service: Resource ID - $($resourceId)"

            # Get all non-production slots for this App Service.
            $nonProductionSlotConfigurations = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName
            
            Write-Host "Non-prod list: $($nonProductionSlotConfigurations.SiteConfig.MinTlsVersion)"

            $isMinTLSVersionSetOnAllNonProductionSlots = -not $($nonProductionSlotConfigurations.SiteConfig.MinTlsVersion -le $minTLSVersion)
            
            if ($isMinTLSVersionSetOnProductionSlot -and $isMinTLSVersionSetOnAllNonProductionSlots)
            {
                $appServicesWithMinTLSVersion += $appServiceResource
                Write-Host "Minimum required TLS is set on the production slot and all non-production slots in the App Service." -ForegroundColor $([Constants]::MessageType.Update)
                return
            }

            if (-not $isMinTLSVersionSetOnProductionSlot)
            {
                Write-Host "Minimum required TLS is not set on the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
            }

            # Holds the list of non-production slots without HTTPS enabled
            $nonProductionSlotsWithoutReqMinTLSVersion = @()
            $nonProductionSlotsWithoutReqMinTLSVersionStr = [String]::Empty

            if (-not $isMinTLSVersionSetOnAllNonProductionSlots)
            {
                $nonProductionSlotsWithoutReqMinTLSVersion = $($nonProductionSlotConfigurations | Where-Object { $_.SiteConfig.MinTlsVersion -le $minTLSVersion }).Name
                $nonProductionSlotsWithoutReqMinTLSVersionStr = $($nonProductionSlotsWithoutReqMinTLSVersion -join ', ')
                Write-Host "Minimum required TLS is not set on these non-production slots: $($nonProductionSlotsWithoutReqMinTLSVersionStr)" -ForegroundColor $([Constants]::MessageType.Warning)
            }

            $appServicesWithoutMinTLSVersion += $appServiceResource | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                                   @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                   @{N='ResourceName';E={$resourceName}},
                                                                                   @{N='CurrentMinTLSVersionSetOnProductionSlot';E={$isMinTLSVersionSetOnProductionSlot}},
                                                                                   @{N='CurrentMinTLSVersionSetOnAllNonProductionSlots';E={$isMinTLSVersionSetOnAllNonProductionSlots}},
                                                                                   @{N='nonProductionSlotsWithoutReqMinTLSVersion';E={$nonProductionSlotsWithoutReqMinTLSVersionStr}}
        
        }
        catch
        {
            $appServicesSkipped += $appServiceResource
            Write-Host "Error fetching App Service configuration: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

    Write-Host "Found $($appServicesWithMinTLSVersion) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    $totalAppServicesWithoutMinTLSVersion = ($appServicesWithoutMinTLSVersion | Measure-Object).Count

    if ($totalAppServicesWithoutMinTLSVersion -eq 0)
    {
        Write-Host "No App Services found with TLS version not set to the required minimum. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalAppServicesWithoutMinTLSVersion) App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetMinTLSVersionForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
       
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up App Services details to $($backupFolderPath)"
    
    # Backing up App Services details.
    $backupFile = "$($backupFolderPath)\AppServicesWithoutMinReqTLSVersion.csv"

    $appServicesWithoutMinTLSVersion | Export-CSV -Path $backupFile -NoTypeInformation
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
