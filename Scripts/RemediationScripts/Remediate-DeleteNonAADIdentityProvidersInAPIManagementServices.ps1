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

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Update)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
        }
        else
        {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Info)
        }
    }
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
        $FilePath
    )

    # List of allowed identity providers.
    $allowedIdentityProviders = @("Aad")

    # List of tiers/SKUs for which this Control and identity providers are not applicable.
    $nonApplicableSkus = @("Consumption")

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Preparing to delete all non-AAD identity providers (and basic authentication) from the API Management services in Subscription: $($SubscriptionId)"

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

    # Connect to Azure account.
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

    # Checking if the current account type is "User".
    if ($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of $($context.Account.Id) is: $($context.Account.Type)" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "$($context.Account.Id) is allowed to run this script." -ForegroundColor $([Constants]::MessageType.Update)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all API Management services..."
    Write-Host "*** Notes: ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "1. To delete all non-AAD identity providers (and basic authentication) from the API Management services in a Subscription, Contributor and higher privileges on the API Management services are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "2. Following identity providers are ALLOWED to be configured for the API Management services: $($allowedIdentityProviders -join ', '). These will NOT be deleted." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "3. API Management services of the following tiers / SKUs will NOT be considered for the remediation: $($nonApplicableSkus -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)

    $apiManagementServices = @()

    # No file path provided as input to the script. Fetch all API Management services in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all API Management services in Subscription: $($context.Subscription.SubscriptionId)"

        # Get all API Management services in a Subscription.
        $apiManagementServices = Get-AzApiManagement -ErrorAction Stop

        # Filter out those tiers/SKUs for which this Control and identity providers are not applicable.
        $apiManagementServices = $apiManagementServices | Where-Object { $_.Sku -notin $nonApplicableSkus }
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all API Management services from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

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
                Write-Host "Error fetching API Management service: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this API Management service..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
    }

    $totalApiManagementServices = ($apiManagementServices | Measure-Object).Count

    if ($totalApiManagementServices -eq 0)
    {
        Write-Host "No API Management services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalApiManagementServices) API Management service(s)." -ForegroundColor $([Constants]::MessageType.Update)

    # Includes API Management services where non-AAD identity providers (and/or basic authentication) are enabled.
    $apiManagementServicesWithNonAadIdentityProvidersEnabled = @()

    # Includes API Management services where no non-AAD identity providers (including basic authentication) are enabled.
    # These API Management services may or may not have AAD identity provider enabled.
    $apiManagementServicesWithoutNonAadIdentityProvidersEnabled = @()

    # Includes API Management services that were skipped during remediation. There were errors remediating them.
    $apiManagementServicesSkipped = @()

    # Instantiate an instance of `APIManagementService`. This has utility methods to handle API Management service related configurations.
    [APIManagementService] $apiManagementServiceObj = [APIManagementService]::new([Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $context)

    Write-Host "Fetching identity provider details for the API Management services..."

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
                Write-Host "Error fetching API Management service basic authentication settings: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName)." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "This API Management service will not be remediated." -ForegroundColor $([Constants]::MessageType.Error)
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
                Write-Host "Error fetching API Management service identity providers: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName). Error: $($identityProviderErrors)" -ForegroundColor $([Constants]::MessageType.Error)
                return
            }

            # Check if the API Management service contains one or more non-AAD identity providers.
            $nonAadIdentityProviders = $identityProviders | Where-Object { $_.Type -notin $allowedIdentityProviders }
            $isNonAadIdentityProviderEnabled = $nonAadIdentityProviders.Count -gt 0

            if (-not ($isBasicAuthenticationEnabled -or $isNonAadIdentityProviderEnabled))
            {
                $apiManagementServicesWithoutNonAadIdentityProvidersEnabled += $apiManagementService
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
            Write-Host "Error fetching API Management service identity providers: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

    $totalApiManagementServicesWithNonAadIdentityProvidersEnabled = ($apiManagementServicesWithNonAadIdentityProvidersEnabled | Measure-Object).Count

    if ($totalApiManagementServicesWithNonAadIdentityProvidersEnabled -eq 0)
    {
        Write-Host "No API Management services found with non-AAD identity providers (including basic authentication) configured. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalApiManagementServicesWithNonAadIdentityProvidersEnabled) API Management service(s) with non-AAD identity providers (and basic authentication) configured." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                    @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                    @{Expression={$_.IsBasicAuthenticationEnabled};Label="Is basic authentication (Username/Password) enabled?";Width=20;Alignment="left"},
                    @{Expression={$_.IsNonAADIdentityProviderEnabled};Label="Is any non-AAD identity provider enabled?";Width=20;Alignment="left"},
                    @{Expression={$_.NonAADIdentityProviders};Label="Non-AAD Identity Providers";Width=40;Alignment="left"}

    Write-Host "`nSummary of API Management services with one or more non-AAD identity providers (and/or basic authentication) configured:" -ForegroundColor $([Constants]::MessageType.Info)

    if ($($apiManagementServicesWithNonAadIdentityProvidersEnabled | Measure-Object).Count -gt 0)
    {
        $apiManagementServicesWithNonAadIdentityProvidersEnabled | Format-Table -Property $colsProperty -Wrap
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up API Management services details..."

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DeleteNonAADIdentityProvidersInAPIManagementServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    # Backing up API Management services details.
    $backupFile = "$($backupFolderPath)\APIManagementServicesWithNonAADIdentityProviders.csv"

    $apiManagementServicesWithNonAadIdentityProvidersEnabled | Export-CSV -Path $backupFile -NoTypeInformation

    Write-Host "API Management services details have been backed up to $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 4 of 4] Deleting Non-AAD identity providers (and basic authentication) from API Management services..."

    if (-not $DryRun)
    {
        Write-Host "-DryRun NOT specified. Non-AAD identity providers will be DELETED from all API Management services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "`n*** CAUTION!!! ***" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "1. Deleting the identity providers CAN impact users accessing the API Management services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "2. ALL non-Azure Active Directory (AAD) identity providers (and basic authentication) WILL be DELETED from all eligible API Management services in the Subscription." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "3. This script DOES NOT support rolling back and reconfiguring the non-AAD identity providers and other authentication options once deleted. It is ADVISED to use this file to reconfigure them manually." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "`nDo you REALLY want to DELETE the non-AAD identity providers (and basic authentication) from all API Management services? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Non-AAD identity providers (and basic authentication) will not be deleted from any API Management service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
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
                        Write-Host "Error disabling basic authentication on the API Management service: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName)." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "This API Management service will NOT be remediated. Non-AAD identity providers will NOT be deleted." -ForegroundColor $([Constants]::MessageType.Error)
                        return
                    }

                    $apiManagementService.IsBasicAuthenticationEnabled = $false
                }
                catch
                {
                    $apiManagementServicesSkipped += $apiManagementService
                    Write-Host "Error disabling basic authentication on the API Management service: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName)." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this API Management service. It is recommended to manually validate/remediate this resource." -ForegroundColor $([Constants]::MessageType.Error)
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
                        Write-Host "Error deleting non-AAD identity provider: $($identityProvider)." -ForegroundColor $([Constants]::MessageType.Error)
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
                    Write-Host "Error fetching API Management service identity providers: Resource ID - $($resourceId), Resource Group Name - $($resourceGroupName), Resource Name - $($resourceName). Error: $($identityProviderErrors)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "This API Management service will not be evaluated as successfully remediated. It is recommended to manually validate/remediate this resource." -ForegroundColor $([Constants]::MessageType.Error)
                    return
                }

                # Check if all the non-AAD identity providers identified previously have now been removed from the API Management service.
                $updatedNonAadIdentityProviders = $identityProviders.Type | Where-Object { $_ -notin $allowedIdentityProviders } | Where-Object { $_ -in $nonAadIdentityProviders }

                if ($updatedNonAadIdentityProviders.Count -gt 0)
                {
                    $apiManagementServicesSkipped += $apiManagementService
                    $apiManagementService.NonAADIdentityProvidersSkipped = $updatedNonAadIdentityProviders -join ", "
                    Write-Host "Error deleting the following non-AAD identity provider(s): $($updatedNonAadIdentityProviders -split ', ')" -ForegroundColor $([Constants]::MessageType.Error)
                    return
                }
            }

            # API Management service is successfully remediated.
            $apiManagementServicesRemediated += $apiManagementService
            $apiManagementService.IsNonAADIdentityProviderEnabled = $false
            $apiManagementService.NonAADIdentityProvidersSkipped = 'NA'
        }

        Write-Host $([Constants]::SingleDashLine)

        if (($apiManagementServicesRemediated | Measure-Object).Count -eq $totalApiManagementServicesWithNonAadIdentityProvidersEnabled)
        {
            Write-Host "Non-AAD identity providers (including basic authentication) successfully deleted from all $($totalApiManagementServicesWithNonAadIdentityProvidersEnabled) API Management service(s)." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "Non-AAD identity providers (including basic authentication) deleted on $($($apiManagementServicesRemediated | Measure-Object).Count) out of $($totalApiManagementServicesWithNonAadIdentityProvidersEnabled) API Management service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                        @{Expression={$_.IsBasicAuthenticationEnabled};Label="Is basic authentication (Username/Password) enabled?";Width=20;Alignment="left"},
                        @{Expression={$_.IsNonAADIdentityProviderEnabled};Label="Is any non-AAD identity provider enabled?";Width=20;Alignment="left"},
                        @{Expression={$_.NonAADIdentityProviders};Label="Non-AAD Identity Providers (Originally enabled)";Width=40;Alignment="left"},
                        @{Expression={$_.NonAADIdentityProvidersSkipped};Label="Non-AAD Identity Providers (Skipped)";Width=40;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

        if ($($apiManagementServicesRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Non-AAD identity providers (including basic authentication) successfully deleted from the following API Management service(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $apiManagementServicesRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $apiManagementServicesRemediatedFile = "$($backupFolderPath)\RemediatedAPIManagementServices.csv"
            $apiManagementServicesRemediated | Export-CSV -Path $apiManagementServicesRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to $($apiManagementServicesRemediatedFile)"
        }

        if ($($apiManagementServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError deleting non-AAD identity providers (including basic authentication) from the following API Management service(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $apiManagementServicesSkipped | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $apiManagementServicesSkippedFile = "$($backupFolderPath)\SkippedAPIManagementServices.csv"
            $apiManagementServicesSkipped | Export-CSV -Path $apiManagementServicesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($apiManagementServicesSkippedFile)"
        }
    }
    else
    {
        Write-Host "-DryRun specified. Non-AAD identity providers will NOT be deleted from any API Management services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "`n*** Next steps: ***" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "1.Run the same command with: -FilePath $($backupFile) and without -DryRun, to delete all non-AAD identity providers (and basic authentication) for all API Management services listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`n*** Notes: ***" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "1. Rollback is NOT supported. It is RECOMMENDED to refer this file to manually reconfigure the identity providers, if required post the remediation." -ForegroundColor $([Constants]::MessageType.Info)
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
                break
            }

            $accessToken = "Bearer " + $authResult.AccessToken
        }
        catch
        {
            Write-Host "Error occurred while fetching access token. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
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
            Write-Host "Error occurred while fetching sign-up settings. SubscriptionID: $($subscriptionId) ResourceGroupName: $($resourceGroupName), APIManagementServiceName: $($apiManagementServiceName) Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }

        return $signUpSettings
    }

    # Checks if basic authentication (Username/Password) is enabled for the API Management service denoted by the parameters.
    [PSObject] CheckBasicAuthenticationStatusForAPIManagementService([String] $signUpSettings)
    {
        if ($signUpSettings -ne $null)
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
            Write-Host "Error occurred while updating sign-up settings. SubscriptionID: $($subscriptionId) ResourceGroupName: $($resourceGroupName), APIManagementServiceName: $($apiManagementServiceName) Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
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