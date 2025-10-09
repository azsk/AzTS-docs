<##########################################

# Overview:
    This script is used to configure Microsoft Defender on subscription.

# ControlId: 
    Azure_Subscription_Config_Enable_MicrosoftDefender_Databases
    Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager
    Azure_Subscription_Config_Enable_MicrosoftDefender_AppService
    Azure_Subscription_Config_Enable_MicrosoftDefender_Storage
    Azure_Subscription_Config_Enable_MicrosoftDefender_Container
    Azure_Subscription_Config_Enable_MicrosoftDefender_Servers
    Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault
    Azure_Subscription_Config_Enable_MicrosoftDefender_CSPM

# Pre-requisites:
    1. You will need Owner role on subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Install and validate pre-requisites to run the script for subscription.
        2. Get the list of resource types that do not have Microsoft Defender plan enabled, from subscription.
        3. Take a backup of these non-compliant resource types.
        4. Register 'Microsoft.Security' provider and enable Microsoft Defender plan for all non-compliant resource types for subscription.
    
    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of resource type in a Subscription, the changes made to which previously, are to be rolled back.
        3. Roll back resource type in the Subscription.

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
        1. Run below command to configure Microsoft Defender for subscription with all the resource type. 
           
            Enable-MicrosoftDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAllRequiredResourceTypes
        
        2. Run below command to configure Microsoft Defender for subscription with selected resource type (App service). 

            Enable-MicrosoftDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAppService
        
        3. Run below command to configure Microsoft Defender for subscription with selected resource type (App service,Storage). 

            Enable-MicrosoftDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAppService - EnableStorage
        
        To know more about parameter execute:
            Get-Help Enable-MicrosoftDefender -Detailed
            
        To roll back:
        1. Run below command to roll back Microsoft Defender for subscription with all the resource type. 
           
            Remove-ConfigMicrosoftDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath  C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\MicrosoftDefender\RemediatedResourceType.csv
        
        To know more about parameter execute:
   
            Get-Help Remove-ConfigMicrosoftDefender -Detailed

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

    $requiredModules = @("Az.Resources", "Az.Security", "Az.Accounts")
    
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
    $accessToken = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl
    $authHeader = "Bearer " + $accessToken.Token
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

function Remediate-VirtualMachines {
    param (
        [string]$subscriptionId,          # Subscription ID
        [string]$reqMDCTier,              # Required MDC Tier (e.g., Standard, Free)
        [string]$vulnerabilityAssessmentEnabled, # Current server vulnerability assessment setting (e.g., MdeTvm)
        [string]$requiredVulnerabilityAssessmentProvider, # Current server vulnerability assessment setting (e.g., MdeTvm)
        [bool]$endpointProtectionEnabled,             # Whether WDATP is already enabled
        [bool]$Force
    )
    try {
        $virtualMachinePricing = Set-AzSecurityPricing -Name "VirtualMachines" -PricingTier $reqMDCTier
    }
    catch {
        Write-Host "Failed to set pricing tier for VirtualMachines" -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $_.Exception.Message -ForegroundColor $([Constants]::MessageType.Error)
    }

    if ($vulnerabilityAssessmentEnabled -ne $requiredVulnerabilityAssessmentProvider) {
        $proceedWithUpdate = $Force

        if (-not $Force) {
            # Inform user and get confirmation only if Force is not set
            $confirmation = Read-Host "The current vulnerability setting is $vulnerabilityAssessmentEnabled. Once changed to $requiredVulnerabilityAssessmentProvider, you cannot roll back to the previous setting. Do you still want to remediate? (Y/N)"
            $proceedWithUpdate = $confirmation -eq "Y"
        }

        if ($proceedWithUpdate) {
            $assessmentUri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/AzureServersSetting?api-version=2022-01-01-preview"
            $assessmentBody = @{
                kind = "AzureServersSetting"
                properties = @{
                    selectedProvider = $requiredVulnerabilityAssessmentProvider
                }
            }

            try {
                $res = Fetch-API -Method "PUT" -Uri $assessmentUri -Body $assessmentBody
                Write-Host "Server vulnerability assessment settings updated to $($res.properties.selectedProvider)." -ForegroundColor $([Constants]::MessageType.Update)
            }
            catch {
                Write-Host "Failed to update server vulnerability assessment settings"
                Write-Host $_.Exception.Message -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
        else {
            Write-Host "User chose not to remediate the vulnerability setting. Skipping update."
        }
    }

    if (-not $endpointProtectionEnabled) {
        $wdAtpUri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Security/settings/WDATP?api-version=2021-06-01"
        $wdAtpBody = @{
            id = "/subscriptions/$subscriptionId/providers/Microsoft.Security/settings/WDATP"
            name = "WDATP"
            type = "Microsoft.Security/settings"
            kind = "DataExportSettings"
            properties = @{
                enabled = "true"
            }
        }

        try {
            $res = Fetch-API -Method "PUT" -Uri $wdAtpUri -Body $wdAtpBody
            $wdAtpStatus = if ($res.properties.enabled) { "enabled" } else { "disabled" }
            Write-Host "Endpoint Protection (WDATP) setting is $wdAtpStatus." -ForegroundColor $([Constants]::MessageType.Update)
        }
        catch {
            Write-Host "Failed to update WDATP settings"
            Write-Host $_.Exception.Message -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

    return $virtualMachinePricing
}



function Check-VirtualMachineCompliance {
    param (
        [Parameter(Mandatory=$true)]
        [pscustomobject]$resource,
        [Parameter(Mandatory=$true)]
        [string]$subscriptionId,
        [Parameter(Mandatory=$true)]
        [string]$reqMDCTier,
        [Parameter(Mandatory=$true)]
        [string]$requiredVulnerabilityAssessmentProvider
    )

    $isNonCompliant = $false
    $wdAtpEnabled = $null
    $assessmentProvider = $null
    $securityEndpointProtectionSettingAPI = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Security/settings/WDATP?api-version=2022-05-01"
    $securityVulnerabilityAssessmentSettingAPI = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings?api-version=2023-05-01"

    if ($resource.PricingTier -ne $reqMDCTier) {
        $isNonCompliant = $true
    }

    try {
        $wdAtpResponse = Fetch-API -Method Get -Uri $securityEndpointProtectionSettingAPI -ErrorAction Stop
        $wdAtpEnabled = $wdAtpResponse.properties.enabled
        if ($wdAtpEnabled -eq $false) {
            $isNonCompliant = $true
        }
    }
    catch {
        Write-Warning "Failed to fetch WDATP settings: $_"
        $isNonCompliant = $true
    }

    try {
        $assessmentResponse = Fetch-API -Method Get -Uri $securityVulnerabilityAssessmentSettingAPI -ErrorAction Stop
        $assessmentProvider = $assessmentResponse.value[0].properties.selectedProvider
        if ($assessmentProvider -ne $requiredVulnerabilityAssessmentProvider) {
            $isNonCompliant = $true
        }
    }
    catch {
        Write-Warning "Failed to fetch server vulnerability assessment settings: $_"
        $isNonCompliant = $true
    }

    $complianceModel = [pscustomobject]@{
        IsCompliant        = -not $isNonCompliant
        Name               = $resource.Name
        PricingTier        = $resource.PricingTier
        Id                 = $resource.Id
        SubPlan            = $resource.SubPlan
        Extensions         = $resource.Extensions
        endpointProtectionEnabled       = $wdAtpEnabled
        vulnerabilityAssessmentEnabled  = $assessmentProvider
    }

    return $complianceModel
}


function Enable-MicrosoftDefender
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Subscription_Config_Enable_MicrosoftDefender_Databases', 'Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_AppService',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Storage',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Container',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Servers',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault'.
    'Azure_Subscription_Config_Enable_MicrosoftDefender_CSPM' control.
    
    .DESCRIPTION
    This command would help in remediating 'Azure_Subscription_Config_Enable_MicrosoftDefender_Databases',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_AppService',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Storage',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Container',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Servers',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_CSPM'  control.
    
    .PARAMETER SubscriptionId
    Enter subscription id on which remediation needs to be performed.

    .PARAMETER Force
    Specifies a forceful remediation without any prompts.
    
    .PARAMETER PerformPreReqCheck
    Perform pre requisites check to ensure all required modules to perform remediation operation are available.

    .PARAMETER EnableDatabases
    Specifies that databases resource type pricing tier is set to standard.

    .PARAMETER EnableResourceManager
    Specifies that resource manager resource type pricing tier is set to standard.

    .PARAMETER EnableAppService
    Specifies that app service resource type pricing tier is set to standard.

    .PARAMETER EnableStorage
    Specifies that storage resource type pricing tier is set to standard and subplan set to DefenderForStorageV2 .

    .PARAMETER EnableContainer
    Specifies that container resource type pricing tier is set to standard.

    .PARAMETER EnableServers
    Specifies that servers resource type pricing tier is set to standard.

    .PARAMETER EnableKeyVault
    Specifies that key vault resource type pricing tier is set to standard.

    .PARAMETER EnableAllRequiredResourceTypes
    Specifies that all resource type pricing tier is set to standard and for storage subplan is set to DefenderForStorageV2.

    .PARAMETER EnableAI
    Specifies that AI workload resource type pricing tier is set to standard.
    
    .INPUTS
    None. You cannot pipe objects to  Enable-MicrosoftDefender.

    .OUTPUTS
    None. Enable-MicrosoftDefender does not return anything that can be piped and used as an input to another command.

    .EXAMPLE
    PS> Enable-MicrosoftDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAllRequiredResourceTypes

    .EXAMPLE
    PS> Enable-MicrosoftDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAppService

    .EXAMPLE
    PS> Enable-MicrosoftDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAppService - EnableStorage
    #>

    param (
        [string]
        [Parameter(ParameterSetName = "EnableSelected",Mandatory = $true, HelpMessage = "Enter subscription id for remediation")]
        [Parameter(ParameterSetName = "EnableAll", Mandatory = $true, HelpMessage = "Enter subscription id for remediation")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "EnableAll", HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies a forceful remediation without any prompts")]
        [Parameter(ParameterSetName = "EnableAll", HelpMessage = "Specifies validation of prerequisites for the command")]
        $Force,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected",  HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableDatabases,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableResourceManager,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableAppService,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableStorage,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableContainer,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableServers,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableKeyVault,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableCSPM,        

        [Switch]
        [Parameter(ParameterSetName = "EnableAll", Mandatory = $true, HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableAllRequiredResourceTypes,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableAI
    )
   
    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }
    else {
        Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -PerformPreReqCheck switch is not provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context)) {
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


    Write-Host "Validating whether the current user [$($context.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."

    # Safe Check: Checking whether the current account is of type User
    if($context.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    # Safe Check: Current user needs to be either or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)";
    $roles = $currentLoginRoleAssignments | Where { ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Security Admin" ) -and !($_.Scope -like "/subscriptions/$($SubscriptionId)/resourceGroups")}

    if(($roles | Measure-Object).Count -le 0)
    {
        Write-Host "Warning: This script can only be run by an Owner of subscription [$($SubscriptionId)] " -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }
    
    # Declaring required resource types and pricing tier    
    $reqMDCTierResourceTypes = "VirtualMachines", "SqlServers", "AppServices", "StorageAccounts", "Containers", "KeyVaults", "SqlServerVirtualMachines", "Arm", "OpenSourceRelationalDatabases", "CosmosDbs","CloudPosture", "AI";
    $reqMDCTier = "Standard";
    $requiredVulnerabilityAssessmentProvider = "MdeTvm"
    $reqProviderName = "Microsoft.Security"
    $isProviderRegister = $true
    $previousProviderRegistrationState = $false

    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4]: Checking [$($reqMDCTier)] pricing tier for required resource types..."
    Write-Host $([Constants]::SingleDashLine)

    # Checking IsProviderRegister with 'Microsoft.Security' provider
    $registeredProvider =  Get-AzResourceProvider -ProviderNamespace $reqProviderName | Where-Object { $_.RegistrationState -eq "Registered" }

    if($null -eq $registeredProvider)
    {
        # capture provider registration state
        $isProviderRegister = $false
        Write-Host "Found [$($reqProviderName)] provider is not registered."  -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "$reqProviderName registering [It takes 2-3 min to get registered]..." -ForegroundColor $([Constants]::MessageType.Info)
        # Registering provider with required provider name, it will take 1-2 min for registration
        try 
        {
            $provider = Register-AzResourceProvider -ProviderNamespace $reqProviderName
            Write-Host "[$reqProviderName] registering..." -ForegroundColor $([Constants]::MessageType.Info)
            while((((Get-AzResourceProvider -ProviderNamespace $reqProviderName).RegistrationState -ne "Registered") | Measure-Object).Count -gt 0)
            {
                # Checking threshold time limit to avoid getting into infinite loop
                if($thresholdTimeLimit -ge 300)
                {
                    Write-Host "Error occurred while registering [$($reqProviderName)] provider. It is taking more time than expected, Aborting process..." -ForegroundColor $([Constants]::MessageType.Error)
                    throw [System.ArgumentException] ($_)
                }
                
                Start-Sleep -Seconds 30
               
                # Incrementing threshold time limit by 30 sec in every iteration
                $thresholdTimeLimit = $thresholdTimeLimit + 30
            }
            $isProviderRegister = $true
        }
        catch 
        {
            Write-Host "Error occurred while registering $reqProviderName provider. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
        Write-Host "$reqProviderName provider successfully registered." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else {
        $previousProviderRegistrationState = $true
    }

    $nonCompliantMDCTierResourcetype = @()
    $nonCompliantResourceType = @()
    
    $resourceType= Get-AzSecurityPricing  
    
    if($EnableAllRequiredResourceTypes -eq $true)
    {
         $resourceType | ForEach-Object {
        if ( $_.Name -eq "StorageAccounts" -and $_.SubPlan -ne "DefenderForStorageV2" )
        {
            $nonCompliantMDCTierResourcetype += $_ | select "Name", "PricingTier", "Id", "SubPlan", "Extensions"
        }
        elseif ($_.Name -eq "VirtualMachines") {
            $resource = $_ | Select-Object Name, PricingTier, Id, SubPlan, Extensions
            Write-Host "resource pricing tier $($resource.PricingTier)"
            $vm = Check-VirtualMachineCompliance -resource $resource -subscriptionId $subscriptionId -reqMDCTier $reqMDCTier -requiredVulnerabilityAssessmentProvider $requiredVulnerabilityAssessmentProvider

            if (!$vm.IsCompliant) {
                $nonCompliantMDCTierResourcetype += $vm
            }
        }
        elseif( $_.PricingTier -ne $reqMDCTier -and $reqMDCTierResourceTypes.Contains($_.Name) -and  $_.Name -ne "StorageAccounts")
        {
            $nonCompliantMDCTierResourcetype += $_ | select "Name", "PricingTier", "Id","SubPlan", "Extensions"
        }

        elseif ($_.Name -eq "CloudPosture") 
        {
                    
             if($_.PricingTier -ne $reqMDCTier)
             {
                $nonCompliantMDCTierResourcetype += $_ | select "Name", "PricingTier", "Id","SubPlan", "Extensions"
             }
             else
             {                
                # Define the array of Extension names to compare
                $ExtensionArray = @("SensitiveDataDiscovery", "ContainerRegistriesVulnerabilityAssessments", "AgentlessDiscoveryForKubernetes", "AgentlessVmScanning", "EntraPermissionsManagement", "ApiPosture")

                # Convert the JSON string to a PowerShell object
                try {
                    $jsonArray = $_.Extensions | ConvertFrom-Json
                } catch {
                    Write-Error "Failed to convert JSON string: $_"
                    return
                }
                
                # Filter by isEnabled value and select the names of enabled extensions
                $enabledNames = $jsonArray | Where-Object { $_.isEnabled -eq "True" } | Select-Object -ExpandProperty name
                
                # Compare the enabled names with the given array of Extension names and return the result as a boolean value indicating if no enabled Extension names are present in the given array
                $comparisonResult = -not ($enabledNames | Where-Object { $ExtensionArray -contains $_ })
                
                # Convert the JSON string to a PowerShell object
                #$jsonArray = $_.Extensions | ConvertFrom-Json
                if(!$comparisonResult)
                {
                   $nonCompliantMDCTierResourcetype += $_ | select "Name", "PricingTier", "Id","SubPlan", "Extensions" 
                }             
             }

            }
         } 

    }
    else
    {
        $resourceType | ForEach-Object {
                $resource = $_
                    if ( $EnableDatabases -eq $true -and  $_.PricingTier -ne $reqMDCTier -and ($_.Name -eq "CosmosDbs" -or $_.Name -eq "OpenSourceRelationalDatabases" -or $_.Name -eq "SqlServers" -or $_.Name -eq "SqlServerVirtualMachines")) {
                        $nonCompliantMDCTierResourcetype += $resource 
                    }

                    if ($EnableResourceManager -eq $true -and $_.Name -eq "Arm" -and  $_.PricingTier -ne $reqMDCTier) {
                        $nonCompliantMDCTierResourcetype += $resource  
                    }

                    if ($EnableAppService -eq $true -and $_.Name -eq "AppServices" -and  $_.PricingTier -ne $reqMDCTier) {
                        $nonCompliantMDCTierResourcetype += $resource 
                    }

                    if ($EnableStorage -eq $true -and $_.Name -eq "StorageAccounts" -and  $_.PricingTier -ne $reqMDCTier) {
                        $nonCompliantMDCTierResourcetype += $resource 
                    }

                    if ($EnableContainer -eq $true -and $_.Name -eq "Containers" -and  $_.PricingTier -ne $reqMDCTier) {
                        $nonCompliantMDCTierResourcetype += $resource  
                    }

                    if ($EnableServers -eq $true -and $_.Name -eq "VirtualMachines") {
                        $resource = $_ | Select-Object Name, PricingTier, Id, SubPlan, Extensions
                        $vm = Check-VirtualMachineCompliance -resource $resource -subscriptionId $subscriptionId -reqMDCTier $reqMDCTier -requiredVulnerabilityAssessmentProvider $requiredVulnerabilityAssessmentProvider

                        if (!$vm.IsCompliant) {
                            $nonCompliantMDCTierResourcetype += $vm
                        }
                    }

                    if ($EnableKeyVault -eq $true -and $_.Name -eq "KeyVaults" -and  $_.PricingTier -ne $reqMDCTier) {
                        $nonCompliantMDCTierResourcetype += $resource 
                    }

                    if ($EnableCSPM -eq $true -and $_.Name -eq "CloudPosture") 
                    {
                    
                     if($_.PricingTier -ne $reqMDCTier)
                     {
                        $nonCompliantMDCTierResourcetype += $resource
                     }
                     else
                     {                       
                        # Define the array of Extension names to compare
                        $ExtensionArray = @("SensitiveDataDiscovery", "ContainerRegistriesVulnerabilityAssessments", "AgentlessDiscoveryForKubernetes", "AgentlessVmScanning", "EntraPermissionsManagement", "ApiPosture")

                        # Convert the JSON string to a PowerShell object
                        try {
                            $jsonArray = $_.Extensions | ConvertFrom-Json
                        } catch {
                            Write-Error "Failed to convert JSON string: $_"
                            return
                        }
                        
                        # Filter by isEnabled value and select the names of enabled extensions
                        $enabledExtensionsNames = $jsonArray | Where-Object { $_.isEnabled -eq "True" } | Select-Object -ExpandProperty name
                        
                        # Compare the enabled names with the given array of Extension names and return the result as a boolean value indicating if no enabled Extension names are present in the given array
                        $comparisonResult = -not ($enabledExtensionsNames | Where-Object { $ExtensionArray -contains $_ })
                        
                        # Convert the JSON string to a PowerShell object
                        #$jsonArray = $_.Extensions | ConvertFrom-Json
                        if(!$comparisonResult)
                        {
                           $nonCompliantMDCTierResourcetype += $resource 
                        }             
                      }
                    if ($EnableAI -eq $true -and $_.Name -eq "AI" -and  $_.PricingTier -ne $reqMDCTier) {
                        $nonCompliantMDCTierResourcetype += $resource 

                    }
            }
        }
    }
   
    $nonCompliantMDCTypeCount = ($nonCompliantMDCTierResourcetype | Measure-Object).Count

    # If control is already in Passed state (i.e. 'Microsoft.Security' provider is already registered and no non-compliant resource types are found) then no need to execute below steps.
    if($isProviderRegister -and ($nonCompliantMDCTypeCount -eq 0))
    {
        Write-Host "[$($reqProviderName)] provider is already registered and there are no non-compliant resource types. In this case, remediation is not required."  -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($nonCompliantMDCTypeCount)] resource types non-compliant."

    $colsProperty =  @{Expression = { $_.Name }; Label = "Name"; Width = 40; Alignment = "left" },
            @{Expression = { $_.PricingTier }; Label = "PricingTier"; Width = 40; Alignment = "left" },
             @{Expression = { $_.Id }; Label = "Id"; Width = 80; Alignment = "left" }

    $nonCompliantMDCTierResourcetype | Format-Table -Property $colsProperty -Wrap
    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up resource type details..."
    Write-Host $([Constants]::SingleDashLine)
   
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\MicrosoftDefender"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    # Backing up resource type details.
    $backupFile = "$($backupFolderPath)\NonCompliantResourceTypes.csv"
    $nonCompliantMDCTierResourcetype | Export-CSV -Path $backupFile -NoTypeInformation

    Write-Host "Resource type details have been backed up to" -NoNewline
    Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)

    # Performing remediation
    if($nonCompliantMDCTypeCount -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4]  Remediating non-compliant resource type..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)

        if (-not $Force)
        {
            Write-Host "This step will remediate non-compliant resource type for subscription [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "NOTE: Pricing tier for storage accounts resource type will be set to [$($reqMDCTier)] with sub plan DefenderForStorageV2 " -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Do you want to continue? " -ForegroundColor $([Constants]::MessageType.Warning)
        
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Non-compliant resource type in the Subscription will not be remediated. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Non-compliant resource type in the Subscription will be remediated in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host "Starting remediation of non-compliant resource types."
        
        $remediatedResources = @()
        $skippedResources = @()

        if ($EnableAllRequiredResourceTypes -eq $true)
        {        
            Write-Host "Setting [$($reqMDCTier)] pricing tier..."
            $nonCompliantMDCTierResourcetype | ForEach-Object {
                $resource = $_
                try {

                    if ($_.Name -eq "StorageAccounts") {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier  -SubPlan DefenderForStorageV2 -Extension '[{"name":"OnUploadMalwareScanning","isEnabled":"false","additionalExtensionProperties": null},{"name":"SensitiveDataDiscovery","isEnabled":"false","additionalExtensionProperties":null}]'
                    } elseif ($_.Name -eq "VirtualMachines") {
                        $remediatedResource = Remediate-VirtualMachines -subscriptionId $SubscriptionId -reqMDCTier $reqMDCTier -vulnerabilityAssessmentEnabled $_.vulnerabilityAssessmentEnabled -endpointProtectionEnabled $_.endpointProtectionEnabled -requiredVulnerabilityAssessmentProvider $requiredVulnerabilityAssessmentProvider -Force $Force
                    }
                     elseif ($_.Name -eq "CloudPosture") 
                    {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier -Extension '[{"name":"SensitiveDataDiscovery","isEnabled":"True","additionalExtensionProperties":null,"operationStatus":null},{"name":"ContainerRegistriesVulnerabilityAssessments","isEnabled":"True","additionalExtensionProperties":null,"operationStatus":null},{"name":"AgentlessDiscoveryForKubernetes","isEnabled":"True","additionalExtensionProperties":null,"operationStatus":null},{"name":"AgentlessVmScanning","isEnabled":"True","additionalExtensionProperties":{"ExclusionTags":"[]"},"operationStatus":null},{"name":"EntraPermissionsManagement","isEnabled":"True","additionalExtensionProperties":null,"operationStatus":null},{"name":"ApiPosture","isEnabled":"True","additionalExtensionProperties":null,"operationStatus":null}]'
                     }
                    else {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier
                    }
                   
                   
                    if (($remediatedResource | Measure-Object).Count -gt 0) {
                        $resourceInfo = @{
                            Id                               = $resource.Id
                            Name                             = $resource.Name
                            CurrentPricingTier               = $reqMDCTier
                            PreviousPricingTier              = $resource.PricingTier
                            IsPreviousProvisioningStateRegistered = $previousProviderRegistrationState
                            SubPlan                          = $resource.SubPlan
                            CurrentExtensions=$remediatedResource.Extensions
                            PreviousExtensions=$resource.Extensions
                        }
        
                        # Check if the current resource is VirtualMachines to add extra properties
                        if ($_.Name -eq "VirtualMachines") {
                            $resourceInfo.previousVulnerabilityAssessmentEnabled = $_.vulnerabilityAssessmentEnabled
                            $resourceInfo.previousEndpointProtectionEnabled = $_.endpointProtectionEnabled
                        }
        
                        $remediatedResources += [PSCustomObject]$resourceInfo
                    }
                }
                catch {
                    Write-Host "Error occurred while setting $reqMDCTier pricing tier on resource [$($_.Name)]. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    $skippedResources += $resource | Select-Object  @{N = 'Id'; E = { $resource.Id }},
                        @{N='Name';E={$resource.Name}},
                        @{N='CurrentPricingTier';E={$resource.PricingTier}},
                        @{N='PreviousPricingTier';E={$resource.PricingTier}},
                        @{N='IsPreviousProvisioningStateRegistered';E={$previousProviderRegistrationState}},
                         @{N = 'SubPlan'; E = { $resource.SubPlan } },
                        @{N='CurrentExtensions';E={$remediatedResource.Extensions}},
                        @{N='PreviousExtensions';E={$resource.Extensions}}
                    return
                }
            }
        }
        else {
          
            $nonCompliantMDCTierResourcetype | ForEach-Object {
                $resource = $_
                try {

                    if ( $EnableDatabases -eq $true -and ($_.Name -eq "CosmosDbs" -or $_.Name -eq "OpenSourceRelationalDatabases" -or $_.Name -eq "SqlServers" -or $_.Name -eq "SqlServerVirtualMachines")) {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier 
                    }

                    if ($EnableResourceManager -eq $true -and $_.Name -eq "Arm") {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier 
                    }

                    if ($EnableAppService -eq $true -and $_.Name -eq "AppServices") {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier 
                    }

                    if ($EnableStorage -eq $true -and $_.Name -eq "StorageAccounts") {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier  -SubPlan DefenderForStorageV2 -Extension '[{"name":"OnUploadMalwareScanning","isEnabled":"false","additionalExtensionProperties": null},{"name":"SensitiveDataDiscovery","isEnabled":"false","additionalExtensionProperties":null}]'
                    }

                    if ($EnableContainer -eq $true -and $_.Name -eq "Containers") {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier 
                    }

                    if ($EnableServers -eq $true -and $_.Name -eq "VirtualMachines") {
                        $remediatedResource = Remediate-VirtualMachines -subscriptionId $SubscriptionId -reqMDCTier $reqMDCTier -vulnerabilityAssessmentEnabled $_.vulnerabilityAssessmentEnabled  -endpointProtectionEnabled $_.endpointProtectionEnabled -requiredVulnerabilityAssessmentProvider $requiredVulnerabilityAssessmentProvider -Force $Force
                    }

                    if ($EnableKeyVault -eq $true -and $_.Name -eq "KeyVaults") {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier 
                    }
                    if ($EnableCSPM -eq $true -and $_.Name -eq "CloudPosture") 
                    {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier -Extension '[{"name":"SensitiveDataDiscovery","isEnabled":"True","additionalExtensionProperties":null,"operationStatus":null},{"name":"ContainerRegistriesVulnerabilityAssessments","isEnabled":"True","additionalExtensionProperties":null,"operationStatus":null},{"name":"AgentlessDiscoveryForKubernetes","isEnabled":"True","additionalExtensionProperties":null,"operationStatus":null},{"name":"AgentlessVmScanning","isEnabled":"True","additionalExtensionProperties":{"ExclusionTags":"[]"},"operationStatus":null},{"name":"EntraPermissionsManagement","isEnabled":"True","additionalExtensionProperties":null,"operationStatus":null},{"name":"ApiPosture","isEnabled":"True","additionalExtensionProperties":null,"operationStatus":null}]'
                     }
                    if ($EnableAI -eq $true -and $_.Name -eq "AI") {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier 
                    }
                    

                    if (($remediatedResource | Measure-Object).Count -gt 0)
                    {
                        $resourceInfo = @{
                            Id                               = $resource.Id
                            Name                             = $resource.Name
                            CurrentPricingTier               = $reqMDCTier
                            PreviousPricingTier              = $resource.PricingTier
                            IsPreviousProvisioningStateRegistered = $previousProviderRegistrationState
                            SubPlan                          = $resource.SubPlan
                            CurrentExtensions=$remediatedResource.Extensions
                            PreviousExtensions=$resource.Extensions
                        }
        
                        # Check if the current resource is VirtualMachines to add extra properties
                        if ($_.Name -eq "VirtualMachines") {
                            $resourceInfo.previousVulnerabilityAssessmentEnabled = $_.vulnerabilityAssessmentEnabled
                            $resourceInfo.previousEndpointProtectionEnabled = $_.endpointProtectionEnabled
                        }
        
                        $remediatedResources += [PSCustomObject]$resourceInfo
                    }
                }
                catch {
                    Write-Host "Error occurred while setting $reqMDCTier pricing tier on resource [$($_.Name)]. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    $skippedResources += $resource | Select-Object  @{N = 'Id'; E = { $resource.Id }},
                        @{N='Name';E={$resource.Name}},
                        @{N='CurrentPricingTier';E={$resource.PricingTier}},
                        @{N='PreviousPricingTier';E={$resource.PricingTier}},
                        @{N='IsPreviousProvisioningStateRegistered';E={$previousProviderRegistrationState}},
                        @{N = 'SubPlan'; E = { $resource.SubPlan } },
                        @{N='CurrentExtensions';E={$remediatedResource.Extensions}},
                        @{N='PreviousExtensions';E={$resource.Extensions}}
                    return
                }
            }
        }

        
        $colsPropertyRemediated =  @{Expression = { $_.Name }; Label = "Name"; Width = 40; Alignment = "left" },
            @{Expression = { $_.CurrentPricingTier }; Label = "PricingTier"; Width = 40; Alignment = "left" },
            @{Expression = { $_.Id }; Label = "Id"; Width = 80; Alignment = "left" }

        $colsPropertySkipped =  @{Expression = { $_.Name }; Label = "Name"; Width = 40; Alignment = "left" },
            @{Expression = { $_.PreviousPricingTier }; Label = "PricingTier"; Width = 40; Alignment = "left" },
            @{Expression = { $_.Id }; Label = "Id"; Width = 80; Alignment = "left" }
       
       

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)


        if ($($remediatedResources | Measure-Object).Count -gt 0) {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Pricing tier/Extension is successfully configured for following resource types in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            $remediatedResources | Format-Table -Property $colsPropertyRemediated -Wrap

            # Write this to a file.
            $RemediatedFile = "$($backupFolderPath)\RemediatedResourceType.csv"
            $remediatedResources | Export-CSV -Path $RemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($RemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($skippedResources | Measure-Object).Count -gt 0) {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Error occured while setting Pricing tier to $reqMDCTier for following resource types in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            $skippedResources | Format-Table -Property $colsPropertySkipped -Wrap

            # Write this to a file.
            $SkippedFile = "$($backupFolderPath)\SkippedResourceType.csv"
            $skippedResources | Export-CSV -Path $SkippedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($SkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
}


function Remove-ConfigMicrosoftDefender
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Subscription_Config_Enable_MicrosoftDefender_Databases',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_AppService',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Storage',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Container',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Servers',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault'
    'Azure_Subscription_Config_Enable_MicrosoftDefender_CSPM' control.
    
    .DESCRIPTION
    This command would help in remediating 'Azure_Subscription_Config_Enable_MicrosoftDefender_Databases',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_AppService',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Storage',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Container',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Servers',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault'
    'Azure_Subscription_Config_Enable_MicrosoftDefender_CSPM' control.
    
    .PARAMETER SubscriptionId
    Specifies the ID of the Subscription that was previously remediated.

    .PARAMETER Force
    Specifies a forceful remediation without any prompts.
    
    .Parameter PerformPreReqCheck
    Specifies validation of prerequisites for the command.
    
    .PARAMETER FilePath
    Specifies the path to the file to be used as input for the roll back.

    .EXAMPLE
    PS> Remove-ConfigMicrosoftDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath  C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\MicrosoftDefender\RemediatedResourceType.csv
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id to perform rollback operation")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage="File path which contain logs generated by remediation script to rollback remediation changes")]
        $FilePath,

        [Switch]
        [Parameter(HelpMessage = "Specifies a forceful roll back without any prompts")]
        $Force,

        [Switch]
        [Parameter(HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck
    )

    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }
    else {
        Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -PerformPreReqCheck switch is not provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context)) {
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


    Write-Host "Validating whether the current user [$($context.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."

    # Safe Check: Checking whether the current account is of type User
    if ($context.Account.Type -ne "User") {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    # Safe Check: Current user needs to be either  or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    if (($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -eq "Owner"  -or $_.RoleDefinitionName -eq "Security Admin" -and !($_.Scope -like "/subscriptions/$($SubscriptionId)/resourceGroups") } | Measure-Object).Count -le 0) {
        Write-Host "Warning: This script can only be run by an Owner of subscription [$($SubscriptionId)] " -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3]: Fetching remediation log to perform rollback operation to configure Microsoft Defender for subscription [$($SubscriptionId)]..."
    Write-Host $([Constants]::SingleDashLine)

    # Array to store resource context
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Warning: Rollback file is not found. Please check if the initial Remediation script has been run from the same machine. Exiting the process" -ForegroundColor $([Constants]::MessageType.Warning)
        break;        
    }

    # Declaring required resource types and pricing tier
    $reqProviderName = "Microsoft.Security"
    $providerPreviousProvisioningState = $true
    $providerErrorState = $false
    $initialRemediatedResources = Import-Csv -LiteralPath $FilePath

    $remediatedResourceTypes = $initialRemediatedResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.Id) -and ![String]::IsNullOrWhiteSpace($_.Name) -and ![String]::IsNullOrWhiteSpace($_.PreviousPricingTier) }

    $remediatedResourceTypeCount = ($remediatedResourceTypes | Measure-Object).Count

    # If control is already in Passed state (i.e. 'Microsoft.Security' provider is already registered and no non-compliant resource types are found) then no need to execute below steps.
    if ($remediatedResourceTypeCount -eq 0) {
        Write-Host "There are no resource types to be rolled back. Exiting..."  -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($remediatedResourceTypeCount)] resource types to be rolled back"
   
    $colsProperty =  @{Expression = { $_.Name }; Label = "Name"; Width = 40; Alignment = "left" },
            @{Expression = { $_.CurrentPricingTier }; Label = "PricingTier"; Width = 40; Alignment = "left" },
            @{Expression = { $_.Id }; Label = "Id"; Width = 80; Alignment = "left" }

    $remediatedResourceTypes | Format-Table -Property $colsProperty -Wrap

    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\MicrosoftDefender"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3]: Performing rollback operation for mentioned resource type of the subscription [$($SubscriptionId)]..."
    Write-Host $([Constants]::SingleDashLine)
    
    # Performing rollback operation
    if(($remediatedResourceTypes | Measure-Object).Count -gt 0)
    {
        if (-not $Force)
        {
            Write-Host "This step will rollback following resource type for subscription [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Do you want to continue? " -ForegroundColor $([Constants]::MessageType.Warning)
        
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Compliant resource type in the Subscription will be rolled back. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. compliant resource type in the Subscription will be rolled back in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $rolledBackResources = @()
        $skippedResources = @()

        $remediatedResourceTypes | ForEach-Object {
                if($_.IsPreviousProvisioningStateRegistered -eq "false")
                {
                    $providerPreviousProvisioningState = $false
                }
                return
                }

        $isProviderRegister = (((Get-AzResourceProvider -ProviderNamespace $reqProviderName).RegistrationState -eq "Registered") | Measure-Object).Count -gt 0
        if ($providerPreviousProvisioningState -eq $isProviderRegister)
        {
            Write-Host "[$($reqProviderName)] provider registration state is same as before executing remediation script." -ForegroundColor $([Constants]::MessageType.Update)

            $remediatedResourceTypes | ForEach-Object {
                $resource = $_
                try {
                if($resource.Name -eq "CloudPosture")
                {
                    if($resource.PreviousPricingTier -eq "Free")
                    {
                        $rolledBackResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $resource.PreviousPricingTier 
                    }
                    elseif($resource.PreviousPricingTier -eq "Standard")
                    {
                        if($resource.PreviousExtensions -ne "")
                        {
                          $rolledBackResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $resource.PreviousPricingTier -Extension $resource.PreviousExtensions
                        }
                    }
                }
                elseif($resource.Name -eq "StorageAccounts")
                {
                    if($resource.PreviousPricingTier -eq "Free")
                    {
                        $rolledBackResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $resource.PreviousPricingTier 
                    }
                    elseif($resource.PreviousPricingTier -eq "Standard" -and $resource.SubPlan -ne "")
                    {
                        $rolledBackResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $resource.PreviousPricingTier -SubPlan $resource.SubPlan
                    }
                }
                else
                {
                    $rolledBackResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $resource.PreviousPricingTier 
                }
                
                    if (($rolledBackResource | Measure-Object).Count -gt 0) {
                        $rolledBackResources += $rolledBackResource | Select-Object  @{N = 'Id'; E = { $resource.Id } },
                        @{N = 'Name'; E = { $resource.Name } },
                        @{N = 'CurrentPricingTier'; E = { $resource.PreviousPricingTier } },
                        @{N = 'PreviousPricingTier'; E = { $resource.PreviousPricingTier } },
                         @{N = 'SubPlan'; E = { $resource.SubPlan } },
                        @{N = 'CurrentExtensions'; E = { $resource.CurrentExtensions } },
                        @{N = 'PreviousExtensions'; E = { $resource.PreviousExtensions } }
                    }
                }
                catch {
                    Write-Host "Error occurred while setting $reqMDCTier pricing tier on resource [$($_.Name)]. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error) 
                    $skippedResources += $resource | Select-Object  @{N = 'Id'; E = { $resource.Id } },
                    @{N = 'Name'; E = { $resource.Name } },
                    @{N = 'CurrentPricingTier'; E = { $resource.CurrentPricingTier } },
                    @{N = 'PreviousPricingTier'; E = { $resource.PreviousPricingTier } }
                    @{N = 'SubPlan'; E = { $resource.SubPlan } },
                    @{N = 'CurrentExtensions'; E = { $resource.CurrentExtensions } },
                    @{N = 'PreviousExtensions'; E = { $resource.PreviousExtensions } }
                    return
                }
            }

            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "Rollback Summary: " -ForegroundColor $([Constants]::MessageType.Info)

            $colsPropertyRolledback =  @{Expression = { $_.Name }; Label = "Name"; Width = 40; Alignment = "left" },
             @{Expression = { $_.PreviousPricingTier }; Label = "PricingTier"; Width = 40; Alignment = "left" },
            @{Expression = { $_.Id }; Label = "Id"; Width = 80; Alignment = "left" }

            $colsPropertySkipped =  @{Expression = { $_.Name }; Label = "Name"; Width = 40; Alignment = "left" },
            @{Expression = { $_.CurrentPricingTier }; Label = "PricingTier"; Width = 40; Alignment = "left" },
            @{Expression =  { $_.Id }; Label = "Id"; Width = 80; Alignment = "left" }

            if ($($rolledBackResources | Measure-Object).Count -gt 0) {
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Successfully rolled back for following resource types in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                $rolledBackResources | Format-Table -Property $colsPropertyRolledback -Wrap

                # Write this to a file.
                $RolledBackFile = "$($backupFolderPath)\RolledBackResourceType.csv"
                $rolledBackResources | Export-CSV -Path $RolledBackFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($RolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            }

            if ($($skippedResources | Measure-Object).Count -gt 0) {
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Error occured while rolling back for following resource types in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                $skippedResources | Format-Table -Property $colsPropertySkipped -Wrap

                # Write this to a file.
                $SkippedFile = "$($backupFolderPath)\SkippedResourceType.csv"
                $skippedResources | Export-CSV -Path $SkippedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($SkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            }
        }
        else 
        {
            # when current provider registration state and before executing remediation script is not same.
            # That means while doing remediation it got registered, to perform rollback we need to unregister it
            Write-Host "$[reqProviderName] provider name was registered before executing remediation script, performing rollback." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host "$[reqProviderName] un-registering.It takes 2-3 min to get unregistered" -ForegroundColor $([Constants]::MessageType.Info)
            try 
            {
                $provider = Unregister-AzResourceProvider -ProviderNamespace $reqProviderName
                Write-Host "$reqProviderName un-registering..." -ForegroundColor $([Constants]::MessageType.Warning)
                while((((Get-AzResourceProvider -ProviderNamespace $reqProviderName).RegistrationState -ne "Unregistered") | Measure-Object).Count -gt 0)
                {
                    # Checking threshold time limit to avoid getting into infinite loop
                    if($thresholdTimeLimit -ge 300)
                    {
                        Write-Host "Error occurred while un-registering [$($reqProviderName)] provider. It is taking more time than expected, Aborting process..." -ForegroundColor $([Constants]::MessageType.Error)
                        throw [System.ArgumentException] ($_)
                    }
                    Start-Sleep -Seconds 30

                    # Incrementing threshold time limit by 30 sec in every iteration
                    $thresholdTimeLimit = $thresholdTimeLimit + 30
                }

                if (-not $providerErrorState) {
                    Write-Host "Successfully rolled back provisiong state of the provider [$($reqProviderName)]" -ForegroundColor $([Constants]::MessageType.Update)
                }
            }
            catch 
            {
                Write-Host "Error occured while  rolling back provisiong state of the provider [$($reqProviderName)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                $providerErrorState = true
            }
        }
    }
}

class Constants {
    # Defines commonly used colour codes, corresponding to the severity of the log.
    static [Hashtable] $MessageType = @{
        Error   = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info    = [System.ConsoleColor]::Cyan
        Update  = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}