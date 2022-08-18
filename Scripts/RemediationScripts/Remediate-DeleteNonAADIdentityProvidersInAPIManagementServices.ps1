<###
# Overview:
    This script is used to delete all non-Azure Active Directory (AAD) identity providers from all API Management services in a Subscription.
    Basic authentication - Username/Password - is also disabled.
    Only Azure Active Directory (AAD) is allowed to be configured as the identity provider.

    NOTE: Managed Identity (MI) based remediation is not supported for this script.

# Control ID:
    Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN

# Display Name:
    Enterprise applications using APIM must authenticate developers/applications using Azure Active Directory backed credentials.

# Prerequisites:
    1. Contributor and higher privileges on the API Management services in a Subscription.
    2. Connected to Azure using: Connect-AzAccount -Tenant 00000000-xxxx-0000-xxxx-000000000000 -Subscription 00000000-xxxx-0000-xxxx-000000000000

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Identify the API Management services in a Subscription that have non-Azure Active Directory (AAD) identity providers (and basic authentication) configured.
        3. Back up details of API Management services that are to be remediated.
        4. Delete all non-Azure Active Directory (AAD) identity providers (and basic authentication) from the API Management services in the Subscription.

    To roll back:
        Rollback is not supported as "secrets" of the various identity provider applications need to be available for the identity providers to be reconfigured in the API Management services.
        This is not recommended for security reasons.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to delete all non-Azure Active Directory (AAD) identity providers (and basic authentication) from the API Management services in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the API Management services in a Subscription that will be remediated:

           Delete-NonAadIdentityProvidersInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To delete all non-Azure Active Directory (AAD) identity providers (including basic authentication) in all API Management services in a Subscription:

           Delete-NonAadIdentityProvidersInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To delete all non-Azure Active Directory (AAD) identity providers (including basic authentication) in all API Management services in a Subscription, from a previously taken snapshot:

           Delete-NonAadIdentityProvidersInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205180800\DeleteNonAADIdentityProvidersInAPIManagementServices\APIManagementServicesWithNonAADIdentityProviders.csv

        To know more about the options supported by the remediation command, execute:

        Get-Help Delete-NonAadIdentityProvidersInApiManagementServices -Detailed
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

    # List of required modules.
    $requiredModules = @("Az.Accounts", "Az.ApiManagement")

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


function Delete-NonAadIdentityProvidersInApiManagementServices
{
    <#
        .SYNOPSIS
        Remediates 'Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN' Control.

        .DESCRIPTION
        Remediates 'Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN' Control.
        Deletes all non-Azure Active Directory (AAD) identity providers (and basic authentication) from the API Management services in the Subscription.

        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Delete-NonAadIdentityProvidersInApiManagementServices.

        .OUTPUTS
        None. Delete-NonAadIdentityProvidersInApiManagementServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Delete-NonAadIdentityProvidersInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Delete-NonAadIdentityProvidersInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Delete-NonAadIdentityProvidersInApiManagementServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205180800\DeleteNonAADIdentityProvidersInAPIManagementServices\APIManagementServicesWithNonAADIdentityProviders.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

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

    # List of allowed identity providers.
    $allowedIdentityProviders = @("Aad")

    # List of tiers/SKUs for which this Control and identity providers are not applicable.
    $nonApplicableSkus = @("Consumption")

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Prepare to delete all non-AAD identity providers (and basic authentication) from the API Management services in Subscription: [$($SubscriptionId)]"
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

    # Connect to Azure account.
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop

    if(-not $AutoRemediation)
    {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "This script can only be run by `User` Account Type. Account Type of [$($context.Account.Id)] is [$($context.Account.Type)]." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        return
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run this script." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 2 of 4] Fetch all API Management services"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Notes:" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host "1. To delete all non-AAD identity providers (and basic authentication) from the API Management services in a Subscription, Contributor and higher privileges on the API Management services are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host "2. Following identity providers are ALLOWED to be configured for the API Management services: [$($allowedIdentityProviders -join ', ')]. These will NOT be deleted." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host "3. API Management services of the following tiers / SKUs will NOT be considered for the remediation: [$($nonApplicableSkus -join ', ')]" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    $apiManagementServices = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    $controlIds = "Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "Error: File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "Fetching all API Management services failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No API Management service(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            try
            {
                $apiManagementService = Get-AzApiManagement -ResourceId $_.ResourceID -ErrorAction SilentlyContinue
                $apiManagementServices += $apiManagementService
            }
            catch
            {
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Valid resource id(s) not found in input json file.")    
                $logSkippedResources += $logResource
                return
            }
        }
    }
    else 
    {
        # No file path provided as input to the script. Fetch all API Management services in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all API Management services in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all API Management services in a Subscription.
            $apiManagementServices = Get-AzApiManagement -ErrorAction Stop

            # Filter out those tiers/SKUs for which this Control and identity providers are not applicable.
            $apiManagementServices = $apiManagementServices | Where-Object { $_.Sku -notin $nonApplicableSkus }
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                return
            }

            Write-Host "Fetching all API Management services from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            $apiManagementServicesDetails = Import-Csv -LiteralPath $FilePath | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

            $apiManagementServicesDetails | ForEach-Object {
                $resourceId = $_.ResourceId

                try
                {
                    $apiManagementService = Get-AzApiManagement -ResourceId $resourceId -ErrorAction SilentlyContinue

                    # This will have only those tiers/SKUs for which this Control is applicable.
                    $apiManagementServices += $apiManagementService
                }
                catch
                {
                    Write-Host "Error fetching API Management service: Resource ID: [$($resourceId)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this API Management service..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
        }
    }

    $totalApiManagementServices = ($apiManagementServices | Measure-Object).Count

    if ($totalApiManagementServices -eq 0)
    {
        Write-Host "No API Management services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        return
    }

    Write-Host "Found [$($totalApiManagementServices)] API Management service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Includes API Management services where non-AAD identity providers (and/or basic authentication) are enabled.
    $apiManagementServicesWithNonAadIdentityProvidersEnabled = @()

    # Includes API Management services where no non-AAD identity providers (including basic authentication) are enabled.
    # These API Management services may or may not have AAD identity provider enabled.
    $apiManagementServicesWithoutNonAadIdentityProvidersEnabled = @()

    # Includes API Management services that were skipped during remediation. There were errors remediating them.
    $apiManagementServicesSkipped = @()

    # Instantiate an instance of `APIManagementService`. This has utility methods to handle API Management service related configurations.
    try
    {
        [APIManagementService] $apiManagementServiceObj = [APIManagementService]::new([Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context)
    }
    catch{
        Write-Host "Skipping remediation. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        return
    }

    Write-Host "Fetching identity provider details for the API Management services..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $apiManagementServices | ForEach-Object {
        $apiManagementService = $_
        $resourceId = $_.Id
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.Name

        try
        {
            # Check if basic authentication - Username / Password is enabled.
            # Get sign-up settings of the API Management service.
            $signUpSettings = $apiManagementServiceObj.GetSignUpSettingsByAPIManagementService($SubscriptionId, $resourceGroupName, $resourceName)
            $basicAuthenticationStatus = $apiManagementServiceObj.CheckBasicAuthenticationStatusForAPIManagementService($signUpSettings)

            if (-not $basicAuthenticationStatus.isSuccessful)
            {
                $apiManagementServicesSkipped += $apiManagementService
                Write-Host "Error fetching API Management service basic authentication settings: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "This API Management service will not be remediated." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Error fetching API Management service basic authentication settings: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]")    
                $logSkippedResources += $logResource
                return
            }

            $isBasicAuthenticationEnabled = $basicAuthenticationStatus.isEnabled

            # Prepare API Management service context.
            $apiManagementServiceContext = New-AzApiManagementContext -ResourceGroupName $resourceGroupName -ServiceName $resourceName

            # Get all configured identity providers.
            $identityProviders = Get-AzApiManagementIdentityProvider -Context $apiManagementServiceContext -ErrorVariable identityProviderErrors

            # This check is required to differentiate between an error executing the above command to get the list of configured identity providers and no identity providers configured on the API Management service.
            # $identityProviders can be $null in both the cases, hence, relying on ErrorVariable.
            if ($identityProviderErrors.Count -gt 0)
            {
                $apiManagementServicesSkipped += $apiManagementService
                Write-Host "Error fetching API Management service identity providers: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($identityProviderErrors)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Error fetching API Management service identity providers: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($identityProviderErrors)]")    
                $logSkippedResources += $logResource
                return
            }

            # Check if the API Management service contains one or more non-AAD identity providers.
            $nonAadIdentityProviders = $identityProviders | Where-Object { $_.Type -notin $allowedIdentityProviders }
            $isNonAadIdentityProviderEnabled = $nonAadIdentityProviders.Count -gt 0

            if (-not ($isBasicAuthenticationEnabled -or $isNonAadIdentityProviderEnabled))
            {
                $apiManagementServicesWithoutNonAadIdentityProvidersEnabled += $apiManagementService
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","API Management service doesnot have any non-AAD Identity Provider enabled.")    
                $logSkippedResources += $logResource
                return
            }

            # Add this API Management service to the list of resources to be remediated.
            $apiManagementServicesWithNonAadIdentityProvidersEnabled += $apiManagementService | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                                                              @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                                              @{N='ResourceName';E={$resourceName}},
                                                                                                              @{N='IsBasicAuthenticationEnabled';E={$isBasicAuthenticationEnabled}},
                                                                                                              @{N='SignUpSettings';E={$signUpSettings}},
                                                                                                              @{N='IsNonAADIdentityProviderEnabled';E={$isNonAadIdentityProviderEnabled}},
                                                                                                              @{N='NonAADIdentityProviders';E={$($nonAadIdentityProviders.Type -join ', ')}},
                                                                                                              @{N='NonAADIdentityProvidersConfiguration';E={$nonAadIdentityProviders | ConvertTo-Json}}
        }
        catch
        {
            $apiManagementServicesSkipped += $apiManagementService
            Write-Host "Error fetching API Management service identity providers: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason","Error fetching API Management service identity providers: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($identityProviderErrors)]")    
            $logSkippedResources += $logResource
        }
    }

    $totalApiManagementServicesWithNonAadIdentityProvidersEnabled = ($apiManagementServicesWithNonAadIdentityProvidersEnabled | Measure-Object).Count

    if ($totalApiManagementServicesWithNonAadIdentityProvidersEnabled -eq 0)
    {
        Write-Host "No API Management services found with non-AAD identity providers (including basic authentication) configured. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        if($AutoRemediation -and ($apiManagementServicesWithoutNonAadIdentityProvidersEnabled|Measure-Object).Count -gt 0)
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

    Write-Host "Found [$($totalApiManagementServicesWithNonAadIdentityProvidersEnabled)] API Management service(s) with non-AAD identity providers (and basic authentication) configured." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                    @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                    @{Expression={$_.IsBasicAuthenticationEnabled};Label="Is basic authentication (Username/Password) enabled?";Width=20;Alignment="left"},
                    @{Expression={$_.IsNonAADIdentityProviderEnabled};Label="Is any non-AAD identity provider enabled?";Width=20;Alignment="left"},
                    @{Expression={$_.NonAADIdentityProviders};Label="Non-AAD Identity Providers";Width=40;Alignment="left"}

    if (-not $AutoRemediation -and $($apiManagementServicesWithNonAadIdentityProvidersEnabled | Measure-Object).Count -gt 0)
    {
        Write-Host "Summary of API Management services with one or more non-AAD identity providers (and/or basic authentication) configured:"
        $apiManagementServicesWithNonAadIdentityProvidersEnabled | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 3 of 4] Back up API Management services details"
    Write-Host $([Constants]::SingleDashLine)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DeleteNonAADIdentityProvidersInAPIManagementServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    # Backing up API Management services details.
    $backupFile = "$($backupFolderPath)\APIManagementServicesWithNonAADIdentityProviders.csv"

    $apiManagementServicesWithNonAadIdentityProvidersEnabled | Export-CSV -Path $backupFile -NoTypeInformation

    Write-Host "API Management services details have been backed up to [$($backupFile)]." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 4 of 4] Delete Non-AAD identity providers (and basic authentication) from API Management services"
    Write-Host $([Constants]::SingleDashLine)

    if (-not $DryRun)
    {
        Write-Host "Since, DryRun switch is not specified, Non-AAD identity providers will be 'deleted' from all API Management services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "CAUTION!!!" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "1. Deleting the identity providers can impact users accessing the API Management services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "2. ALL non-Azure Active Directory (AAD) identity providers (and basic authentication) will be deleted from all eligible API Management services in the Subscription." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "3. This script does not support rolling back and reconfiguring the non-AAD identity providers and other authentication options once deleted. It is advised to use this file to reconfigure them manually." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)

        if(-not $AutoRemediation)
        {
            Write-Host "Do you want to delete the non-AAD identity providers (and basic authentication) from all API Management services? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            $userInput = Read-Host -Prompt "(Y|N)"
            Write-Host $([Constants]::SingleDashLine)

            if($userInput -ne "Y")
            {
                Write-Host "Non-AAD identity providers (and basic authentication) will not be deleted from any API Management service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                return
            }
            Write-Host "User has provided consent to deleted Non-AAD identity providers (and basic authentication) from API Management service." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }

        # To hold results from the remediation.
        $apiManagementServicesRemediated = @()
        $apiManagementServicesSkipped = @()

        $apiManagementServicesWithNonAadIdentityProvidersEnabled | ForEach-Object {
            $apiManagementService = $_
            $resourceId = $_.ResourceID
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName
            $isBasicAuthenticationEnabled = $_.IsBasicAuthenticationEnabled
            $signUpSettings = $_.SignUpSettings
            $isNonAADIdentityProviderEnabled = $_.IsNonAADIdentityProviderEnabled
            $nonAadIdentityProviders = $_.NonAADIdentityProviders -split (", ")

            # Reset the status further down, as appropriate.
            $apiManagementService | Add-Member -NotePropertyName NonAADIdentityProvidersSkipped -NotePropertyValue $nonAadIdentityProviders

            # Check if basic authentication (Username/Password) is enabled on the API Management service.
            if ([System.Convert]::ToBoolean($isBasicAuthenticationEnabled))
            {
                try
                {
                    # Disable basic authentication and validate status.
                    $basicAuthenticationStatus = $apiManagementServiceObj.DisableAndCheckBasicAuthenticationStatusForAPIManagementService($SubscriptionId, $resourceGroupName, $resourceName, $signUpSettings)

                    # The update operation failed, or did not update the setting as required.
                    if (-not $basicAuthenticationStatus.isSuccessful -or $basicAuthenticationStatus.isEnabled)
                    {
                        $apiManagementServicesSkipped += $apiManagementService
                        Write-Host "Error disabling basic authentication on the API Management service: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "This API Management service will NOT be remediated. Non-AAD identity providers will not be deleted." -ForegroundColor $([Constants]::MessageType.Error)
                        $logResource = @{}
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        $logResource.Add("ResourceName",($_.ResourceName))
                        $logResource.Add("Reason","Error disabling basic authentication on the API Management service: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]")    
                        $logSkippedResources += $logResource
                        Write-Host $([Constants]::SingleDashLine)
                        return
                    }

                    $apiManagementService.IsBasicAuthenticationEnabled = $false
                }
                catch
                {
                    $apiManagementServicesSkipped += $apiManagementService
                    Write-Host "Error disabling basic authentication on the API Management service: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this API Management service. It is recommended to manually validate/remediate this resource." -ForegroundColor $([Constants]::MessageType.Error)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason","Error disabling basic authentication on the API Management service: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)].")    
                    $logSkippedResources += $logResource
                    return
                }
            }

            if ([System.Convert]::ToBoolean($isNonAADIdentityProviderEnabled))
            {
                # Prepare API Management service context.
                $apiManagementServiceContext = New-AzApiManagementContext -ResourceGroupName $resourceGroupName -ServiceName $resourceName

                foreach ($identityProvider in $nonAadIdentityProviders)
                {
                    try
                    {
                        # This method does not return any output.
                        # Validate if the operation was successful for all non-AAD identity providers at the end in a single call.
                        Remove-AzApiManagementIdentityProvider -Context $apiManagementServiceContext -Type $identityProvider
                    }
                    catch
                    {
                        $apiManagementServicesSkipped += $apiManagementService
                        $apiManagementService.NonAADIdentityProvidersSkipped = $nonAadIdentityProviders -join ", "
                        Write-Host "Error deleting non-AAD identity provider: [$($identityProvider)]" -ForegroundColor $([Constants]::MessageType.Error)
                        $logResource = @{}
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        $logResource.Add("ResourceName",($_.ResourceName))
                        $logResource.Add("Reason","Error deleting non-AAD identity provider: [$($identityProvider)]")    
                        $logSkippedResources += $logResource
                        Write-Host $([Constants]::SingleDashLine)
                        return
                    }
                }

                # Get all configured identity providers.
                $identityProviders = Get-AzApiManagementIdentityProvider -Context $apiManagementServiceContext -ErrorVariable identityProviderErrors

                # This check is required to differentiate between an error executing the above command to get the list of configured identity providers and no identity providers configured on the API Management service.
                # $identityProviders can be $null in both the cases, hence, relying on ErrorVariable.
                if ($identityProviderErrors.Count -gt 0)
                {
                    $apiManagementServicesSkipped += $apiManagementService
                    Write-Host "Error fetching API Management service identity providers: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($identityProviderErrors)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "This API Management service will not be evaluated as successfully remediated. It is recommended to manually validate/remediate this resource." -ForegroundColor $([Constants]::MessageType.Error)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason","Error fetching API Management service identity providers: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($identityProviderErrors)]")    
                    $logSkippedResources += $logResource
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }

                # Check if all the non-AAD identity providers identified previously have now been removed from the API Management service.
                $updatedNonAadIdentityProviders = $identityProviders.Type | Where-Object { $_ -notin $allowedIdentityProviders } | Where-Object { $_ -in $nonAadIdentityProviders }

                if ($updatedNonAadIdentityProviders.Count -gt 0)
                {
                    $apiManagementServicesSkipped += $apiManagementService
                    $apiManagementService.NonAADIdentityProvidersSkipped = $updatedNonAadIdentityProviders -join ", "
                    Write-Host "Error deleting the following non-AAD identity provider(s): [$($updatedNonAadIdentityProviders -split ', ')]" -ForegroundColor $([Constants]::MessageType.Error)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason","Error deleting the following non-AAD identity provider(s): [$($updatedNonAadIdentityProviders -split ', ')]")    
                    $logSkippedResources += $logResource
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
            }

            # API Management service is successfully remediated.
            $apiManagementServicesRemediated += $apiManagementService
            $apiManagementService.IsNonAADIdentityProviderEnabled = $false
            $apiManagementService.NonAADIdentityProvidersSkipped = 'NA'
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logRemediatedResources += $logResource
        }

        if (($apiManagementServicesRemediated | Measure-Object).Count -eq $totalApiManagementServicesWithNonAadIdentityProvidersEnabled)
        {
            Write-Host "Non-AAD identity providers (including basic authentication) successfully deleted from all [$($totalApiManagementServicesWithNonAadIdentityProvidersEnabled)] API Management service(s)." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "Non-AAD identity providers (including basic authentication) deleted on [$($($apiManagementServicesRemediated | Measure-Object).Count)] out of [$($totalApiManagementServicesWithNonAadIdentityProvidersEnabled)] API Management service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                        @{Expression={$_.IsBasicAuthenticationEnabled};Label="Is basic authentication (Username/Password) enabled?";Width=20;Alignment="left"},
                        @{Expression={$_.IsNonAADIdentityProviderEnabled};Label="Is any non-AAD identity provider enabled?";Width=20;Alignment="left"},
                        @{Expression={$_.NonAADIdentityProviders};Label="Non-AAD Identity Providers (Originally enabled)";Width=40;Alignment="left"},
                        @{Expression={$_.NonAADIdentityProvidersSkipped};Label="Non-AAD Identity Providers (Skipped)";Width=40;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation)
        {
            if ($($apiManagementServicesRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $apiManagementServicesRemediatedFile = "$($backupFolderPath)\RemediatedAPIManagementServices.csv"
                $apiManagementServicesRemediated | Export-CSV -Path $apiManagementServicesRemediatedFile -NoTypeInformation
                Write-Host "The information related to API Management Services where Non-AAD identity providers (including basic authentication) successfully deleted, has been saved to [$($apiManagementServicesRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($apiManagementServicesSkipped | Measure-Object).Count -gt 0)
            {
                 # Write this to a file.
                $apiManagementServicesSkippedFile = "$($backupFolderPath)\SkippedAPIManagementServices.csv"
                $apiManagementServicesSkipped | Export-CSV -Path $apiManagementServicesSkippedFile -NoTypeInformation
                Write-Host "This information related to API Management Services where Non-AAD identity providers (including basic authentication) not deleted, has been saved to [$($apiManagementServicesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

            if ($($apiManagementServicesRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Non-AAD identity providers (including basic authentication) successfully deleted from the following API Management service(s):" -ForegroundColor $([Constants]::MessageType.Update)
                $apiManagementServicesRemediated | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $apiManagementServicesRemediatedFile = "$($backupFolderPath)\RemediatedAPIManagementServices.csv"
                $apiManagementServicesRemediated | Export-CSV -Path $apiManagementServicesRemediatedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($apiManagementServicesRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($apiManagementServicesSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error deleting non-AAD identity providers (including basic authentication) from the following API Management service(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $apiManagementServicesSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $apiManagementServicesSkippedFile = "$($backupFolderPath)\SkippedAPIManagementServices.csv"
                $apiManagementServicesSkipped | Export-CSV -Path $apiManagementServicesSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($apiManagementServicesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
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
                    $logControl.RollbackFile = $apiManagementServicesRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "Since, DryRun switch specified. Non-AAD identity providers will not be deleted from any API Management services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "1.Run the same command with: -FilePath $($backupFile) and without -DryRun, to delete all non-AAD identity providers (and basic authentication) for all API Management services listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "`nNotes:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "1. Rollback is not supported. It is recommended to refer this file to manually reconfigure the identity providers, if required post the remediation." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
}

# Defines standard methods to manage REST authentication to Azure.
class AuthenticationHelper
{
    # Members of the class.
    [Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context

    # Constructor.
    AuthenticationHelper([Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context)
    {
        $this.context = $context
    }

    # Gets the access token for the scope denoted by $scope.
    [String] GetAccessToken([String] $scope)
    {
        [String] $accessToken = [String]::Empty

        try
        {
            $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                $this.context.Account,
                $this.context.Environment,
                $this.context.Tenant,
                [System.Security.SecureString] $null,
                "Never",
                $null,
                $scope)

            if ([String]::IsNullOrWhiteSpace($authResult))
            {
                Write-Host "Access token is NULL or empty. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                return $null
            }

            $accessToken = "Bearer " + $authResult.AccessToken
        }
        catch
        {
            Write-Host "Error occurred while fetching access token. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return $null
        }

        return $accessToken
    }
}

# Defines standard methods to handle API Management service related configurations.
class APIManagementService
{
    # Members of the class.
    [Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context
    [AuthenticationHelper] $authHelper

    # Constructor.
    APIManagementService([Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context)
    {
        $this.context = $context
        $this.authHelper = [AuthenticationHelper]::new([Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $this.context)
    }

    # Gets the sign-up settings for the API Management service denoted by the parameters.
    # This setting is used to determine if basic authentication is enabled on the API Management service or not.
    [String] GetSignUpSettingsByAPIManagementService([String] $subscriptionId, [String] $resourceGroupName, [String] $apiManagementServiceName)
    {
        $scope = "https://management.azure.com/"
        $accessToken = $this.authHelper.GetAccessToken($scope)

        [PSObject] $signUpSettings = New-Object PSObject

        try
        {
            $getSignUpSettingsUri = "$($scope)/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.ApiManagement/service/$($apiManagementServiceName)/portalsettings/signup?api-version=2021-08-01"
            $headers = @{"Authorization"=$($accessToken)}
            $response = Invoke-WebRequest -Method Get -Uri $getSignUpSettingsUri -Headers $headers -UseBasicParsing -ContentType "application/json" -ErrorAction Stop
            $signUpSettings = $response.Content
        }
        catch
        {
            Write-Host "Error occurred while fetching sign-up settings. SubscriptionID: [$($subscriptionId)], ResourceGroupName: [$($resourceGroupName)], APIManagementServiceName: [$($apiManagementServiceName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        }

        return $signUpSettings
    }

    # Checks if basic authentication (Username/Password) is enabled for the API Management service denoted by the parameters.
    [PSObject] CheckBasicAuthenticationStatusForAPIManagementService([String] $signUpSettings)
    {
        if ($null -ne $signUpSettings)
        {
            # This setting tells if username/password authentication is enabled for the API Management service.
            $isBasicAuthenticationEnabled =($signUpSettings | ConvertFrom-Json).properties.enabled
            return @{isSuccessful = $true; isEnabled = $isBasicAuthenticationEnabled}
        }

        return @{isSuccessful = $false; isEnabled = $null}
    }

    # Disable and validate the basic authentication (Username/Password) settings for the API Management service denoted by the parameters.
    [PSObject] DisableAndCheckBasicAuthenticationStatusForAPIManagementService([String] $subscriptionId, [String] $resourceGroupName, [String] $apiManagementServiceName, [String] $signUpSettings)
    {
        $scope = "https://management.azure.com/"
        $accessToken = $this.authHelper.GetAccessToken($scope)

        # Disable basic authentication.
        $signUpSettingsObj = $signUpSettings | ConvertFrom-Json
        $signUpSettingsObj.properties.enabled = $false
        $signUpSettings = $signUpSettingsObj | ConvertTo-Json

        try
        {
            $updateSignUpSettingsUri = "$($scope)/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.ApiManagement/service/$($apiManagementServiceName)/portalsettings/signup?api-version=2021-08-01"
            $headers = @{"Authorization"=$($accessToken)}
            $response = Invoke-WebRequest -Method Put -Uri $updateSignUpSettingsUri -Headers $headers -Body $signUpSettings -UseBasicParsing -ContentType "application/json" -ErrorAction Stop
        }
        catch
        {
            Write-Host "Error occurred while updating sign-up settings. SubscriptionID: [$($subscriptionId)], ResourceGroupName: [$($resourceGroupName)], APIManagementServiceName: [$($apiManagementServiceName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return @{isSuccessful = $false; isEnabled = $null}
        }

        return $this.CheckBasicAuthenticationStatusForAPIManagementService($response.Content)
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