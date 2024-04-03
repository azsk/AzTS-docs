<##########################################

# Overview:
    This script is used to configure Azure Defender on subscription.

# ControlId: 
    Azure_Subscription_Config_Enable_MicrosoftDefender_Databases_Trial
    Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager_Trial
    Azure_Subscription_Config_Enable_MicrosoftDefender_AppService_Trial
    Azure_Subscription_Config_Enable_MicrosoftDefender_Storage_Trial
    Azure_Subscription_Config_Enable_MicrosoftDefender_Container_Trial
    Azure_Subscription_Config_Enable_MicrosoftDefender_Servers_Trial
    Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault_Trial

# Pre-requisites:
    1. You will need Owner or Contributor role on subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Install and validate pre-requisites to run the script for subscription.
        2. Get the list of resource types that do not have Azure Defender plan enabled, from subscription.
        3. Take a backup of these non-compliant resource types.
        4. Register 'Microsoft.Security' provider and enable Azure Defender plan for all non-compliant resource types for subscription.
    
    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of resource type in a Subscription, the changes made to which previously, are to be rolled back.
        3. Roll back resource type in the Subscription.

# Step to execute script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remediate on AVD Host pool(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to rollback on all AVD Host pool(s) in the Subscription. Refer `Examples`, below.

# Command to execute:
    To remediate:
        1. Run below command to configure Azure Defender for subscription with all the resource type. 
           
            Enable-AzureDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAllResourceType
        
        2. Run below command to configure Azure Defender for subscription with selected resource type (App service). 

            Enable-AzureDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAppService
        
        3. Run below command to configure Azure Defender for subscription with selected resource type (App service,Storage). 

            Enable-AzureDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAppService - EnableStorage
        
        To know more about parameter execute:
            Get-Help Enable-AzureDefender -Detailed
            
        To roll back:
        1. Run below command to roll back Azure Defender for subscription with all the resource type. 
           
            Remove-ConfigAzureDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath  C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\AzureDefender\RemediatedResourceType.csv
        
        To know more about parameter execute:
   
            Get-Help Remove-ConfigAzureDefender -Detailed

########################################
#>
function Pre_requisites
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

function Enable-AzureDefender
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Subscription_Config_Enable_MicrosoftDefender_Databases_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_AppService_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Storage_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Container_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Servers_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault_Trial' control.
    
    .DESCRIPTION
    This command would help in remediating 'Azure_Subscription_Config_Enable_MicrosoftDefender_Databases_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_AppService_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Storage_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Container_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Servers_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault_Trial'  control.
    
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
    Specifies that storage resource type pricing tier is set to standard.

    .PARAMETER EnableContainer
    Specifies that container resource type pricing tier is set to standard.

    .PARAMETER EnableServers
    Specifies that servers resource type pricing tier is set to standard.

    .PARAMETER EnableKeyVault
    Specifies that key vault resource type pricing tier is set to standard.

    .PARAMETER EnableAllResourceType
    Specifies that all resource type pricing tier is set to standard.
    
    .INPUTS
    None. You cannot pipe objects to  Enable-AzureDefender.

    .OUTPUTS
    None. Enable-AzureDefender does not return anything that can be piped and used as an input to another command.

    .EXAMPLE
    PS> Enable-AzureDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAllResourceType

    .EXAMPLE
    PS> Enable-AzureDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAppService

    .EXAMPLE
    PS> Enable-AzureDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -EnableAppService - EnableStorage
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
        [Parameter(ParameterSetName = "EnableSelected", Mandatory = $true, HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableServers,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", Mandatory = $true, HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableKeyVault,

        [Switch]
        [Parameter(ParameterSetName = "EnableAll", Mandatory = $true, Default = $true, HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableAllResourceType
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

    # Safe Check: Current user needs to be either Contributor or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -eq "Owner"  -or $_.RoleDefinitionName -eq 'Contributor' -or $_.RoleDefinitionName -eq "Security Admin" } | Measure-Object).Count -le 0)
    {
        Write-Host "Warning: This script can only be run by an Owner or Contributor of subscription [$($SubscriptionId)] " -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4]: Checking [$($reqMDCTier)] pricing tier for required resource types..."
    Write-Host $([Constants]::SingleDashLine)
    
    # Declaring required resource types and pricing tier
    $reqMDCTierResourceTypes = "VirtualMachines", "SqlServers", "AppServices", "StorageAccounts", "Containers", "KeyVaults", "SqlServerVirtualMachines", "Arm", "OpenSourceRelationalDatabases", "CosmosDbs";
    $reqMDCTier = "Standard";
    $reqProviderName = "Microsoft.Security"
    $isProviderRegister = $true
    $previousProviderRegistrationState = $false

    # Checking IsProviderRegister with 'Microsoft.Security' provider
    $registeredProvider =  Get-AzResourceProvider -ProviderNamespace $reqProviderName | Where-Object { $_.RegistrationState -eq "Registered" }

    if($null -eq $registeredProvider)
    {
        # capture provider registration state
        $isProviderRegister = $false
        Write-Host "Found [$($reqProviderName)] provider is not registered."
        Write-Host "$reqProviderName registering [It takes 2-3 min to get registered]..."
        # Registering provider with required provider name, it will take 1-2 min for registration
        try 
        {
            Register-AzResourceProvider -ProviderNamespace $reqProviderName
            while((((Get-AzResourceProvider -ProviderNamespace $reqProviderName).RegistrationState -ne "Registered") | Measure-Object).Count -gt 0)
            {
                # Checking threshold time limit to avoid getting into infinite loop
                if($thresholdTimeLimit -ge 300)
                {
                    Write-Host "Error occurred while registering [$($reqProviderName)] provider. It is taking more time than expected, Aborting process..." -ForegroundColor $([Constants]::MessageType.Error)
                    throw [System.ArgumentException] ($_)
                }
                Start-Sleep -Seconds 30
                Write-Host "$reqProviderName registering..." -ForegroundColor $([Constants]::MessageType.Warning)

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
    $nonCompliantMDCTierResourcetype = Get-AzSecurityPricing | Where-Object { $_.PricingTier -ne $reqMDCTier -and $reqMDCTierResourceTypes.Contains($_.Name) } | select "Name", "PricingTier", "Id"

    $nonCompliantMDCTypeCount = ($nonCompliantMDCTierResourcetype | Measure-Object).Count

    # If control is already in Passed state (i.e. 'Microsoft.Security' provider is already registered and no non-compliant resource types are found) then no need to execute below steps.
    if($isProviderRegister -and ($nonCompliantMDCTypeCount -eq 0))
    {
        Write-Host "[$($reqProviderName)] provider is already registered and there are no non-compliant resource types. In this case, remediation is not required."  -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($nonCompliantMDCTypeCount)] resource types without [$($reqMDCTier)]"

    $colsPropertyRemediated = @{Expression = { $_.Id }; Label = "Id"; Width = 60; Alignment = "left" },
        @{Expression = { $_.Name }; Label = "Name"; Width = 30; Alignment = "left" },
        @{Expression = { $_.PricingTier }; Label = "PricingTier"; Width = 30; Alignment = "left" }

    $nonCompliantMDCTierResourcetype | Format-Table -Property $colsPropertyRemediated -Wrap
    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up resource type details..."
    Write-Host $([Constants]::SingleDashLine)
   
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\AzureDefender"

    # Backing up resource type details.
    $backupFile = "$($backupFolderPath)\NonCompliantResourceTypes.csv"
    $nonCompliantMDCResource | Export-CSV -Path $backupFile -NoTypeInformation

    Write-Host "Resource type details have been backed up to" -NoNewline
    Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)

    # Performing remediation
    if($nonCompliantMDCTypeCount -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4]  Remediating non compliant resource type..."
        Write-Host $([Constants]::SingleDashLine)

        if (-not $Force)
        {
            Write-Host "This step will remediate non compliant resource type for subscription [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Do you want to continue? " -ForegroundColor $([Constants]::MessageType.Warning)
        
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Non compliant resource type in the Subscription will not be remediated. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Non compliant resource type in the Subscription will be remediated in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }
        
        $remediatedResources = @()
        $skippedResources = @()

        if ($EnableAllResourceType -eq $true)
        {        
            Write-Host "Setting [$($reqMDCTier)] pricing tier..."
            $nonCompliantMDCTierResourcetype | ForEach-Object {
                $resource = $_
                try {
                    $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier
                   
                    if (($remediatedResource | Measure-Object).Count -gt 0) {
                        $remediatedResources += $remediatedResource | Select-Object  @{N = 'Id'; E = { $resource.Id } },
                        @{N = 'Name'; E = { $resource.Name } },
                        @{N = 'CurrentPricingTier'; E = { $reqMDCTier } },
                        @{N = 'PreviousPricingTier'; E = { $resource.PricingTier } },
                        @{N = 'IsPreviousProvisioningStateRegistered'; E = { $previousProviderRegistrationState } }
                    }
                }
                catch {
                    Write-Host "Error occurred while setting $reqMDCTier pricing tier on resource [$($_.Name)]. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    $skippedResources += $resource | Select-Object  @{N = 'Id'; E = { $resource.Id }},
                        @{N='Name';E={$resource.Name}},
                        @{N='CurrentPricingTier';E={$resource.PricingTier}},
                        @{N='PreviousPricingTier';E={$resource.PricingTier}},
                        @{N='IsPreviousProvisioningStateRegistered';E={$previousProviderRegistrationState}}
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
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier  -SubPlan DefenderForStorageV2 
                    }

                    if ($EnableContainer -eq $true -and $_.Name -eq "Containers") {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier 
                    }

                    if ($EnableServers -eq $true -and $_.Name -eq "VirtualMachines") {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier 
                    }

                    if ($EnableKeyVault -eq $true -and $_.Name -eq "KeyVaults") {
                        $remediatedResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier 
                    }
                    
                    if (($remediatedResource | Measure-Object).Count -gt 0)
                    {
                        $remediatedResources += $remediatedResource | Select-Object  @{N = 'Id'; E = { $resource.Id }},
                        @{N='Name';E={$resource.Name}},
                        @{N='CurrentPricingTier';E={$reqMDCTier}},
                        @{N='PreviousPricingTier';E={$resource.PricingTier}},
                        @{N='IsPreviousProvisioningStateRegistered';E={$previousProviderRegistrationState}}
                    }
                    
                }
                catch {
                    Write-Host "Error occurred while setting $reqMDCTier pricing tier on resource [$($_.Name)]. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    $skippedResources += $resource | Select-Object  @{N = 'Id'; E = { $resource.Id }},
                        @{N='Name';E={$resource.Name}},
                        @{N='CurrentPricingTier';E={$resource.PricingTier}},
                        @{N='PreviousPricingTier';E={$resource.PricingTier}},
                        @{N='IsPreviousProvisioningStateRegistered';E={$previousProviderRegistrationState}}
                    return
                }
            }
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)


        if ($($remediatedResources | Measure-Object).Count -gt 0) {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Pricing tier is successfully configured to $reqMDCTier for following resource types in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
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
            $skippedResources | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $SkippedFile = "$($backupFolderPath)\SkippedResourceType.csv"
            $skippedResources | Export-CSV -Path $SkippedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($SkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
}


function Remove-ConfigAzureDefender
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Subscription_Config_Enable_MicrosoftDefender_Databases_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_AppService_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Storage_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Container_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Servers_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault_Trial' control.
    
    .DESCRIPTION
    This command would help in remediating 'Azure_Subscription_Config_Enable_MicrosoftDefender_Databases_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_ResourceManager_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_AppService_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Storage_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Container_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_Servers_Trial',
    'Azure_Subscription_Config_Enable_MicrosoftDefender_KeyVault_Trial' control.
    
    .PARAMETER SubscriptionId
    Specifies the ID of the Subscription that was previously remediated.

    .PARAMETER Force
    Specifies a forceful remediation without any prompts.
    
    .Parameter PerformPreReqCheck
    Specifies validation of prerequisites for the command.
    
    .PARAMETER FilePath
    Specifies the path to the file to be used as input for the roll back.

    .EXAMPLE
    PS> Remove-ConfigAzureDefender -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath  C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\AzureDefender\RemediatedResourceType.csv
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id to perform rollback operation")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage="File path which contain logs generated by remediation script to rollback remediation changes")]
        $Path,

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
    if ($context.Account.Type -ne "User") {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    # Safe Check: Current user needs to be either Contributor or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    if (($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq 'Contributor' -or $_.RoleDefinitionName -eq "Security Admin" } | Measure-Object).Count -le 0) {
        Write-Host "Warning: This script can only be run by an Owner or Contributor of subscription [$($SubscriptionId)] " -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3]: Fetching remediation log to perform rollback operation to configure Azure Defender for subscription [$($SubscriptionId)]..."
    Write-Host $([Constants]::SingleDashLine)

    # Array to store resource context
    if (-not (Test-Path -Path $Path))
    {
        Write-Host "Warning: Rollback file is not found. Please check if the initial Remediation script has been run from the same machine. Exiting the process" -ForegroundColor $([Constants]::MessageType.Warning)
        break;        
    }

    # Declaring required resource types and pricing tier
    $reqProviderName = "Microsoft.Security"
    $providerPreviousProvisioningState = $true
    $providerErrorState = $false
    $initialRemediatedResources = Import-Csv -LiteralPath $FilePath

    $remediatedResourceTypes = $initialRemediatedResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.Id) -and ![String]::IsNullOrWhiteSpace($_.Name) -and ![String]::IsNullOrWhiteSpace($_.PricingTier) }

    $remediatedResourceTypeCount = ($remediatedResourceTypes | Measure-Object).Count

    # If control is already in Passed state (i.e. 'Microsoft.Security' provider is already registered and no non-compliant resource types are found) then no need to execute below steps.
    if ($remediatedResourceTypeCount -eq 0) {
        Write-Host "There are no resource types to be rolled back. Exiting..."  -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($nonCompliantMDCTypeCount)] resource types to be rolled back"
    
    $colsPropertyRemediated = @{Expression = { $_.Id }; Label = "Id"; Width = 60; Alignment = "left" },
    @{Expression = { $_.Name }; Label = "Name"; Width = 30; Alignment = "left" },
    @{Expression = { $_.PricingTier }; Label = "PricingTier"; Width = 30; Alignment = "left" }

    $remediatedResourceTypes | Format-Table -Property $colsPropertyRemediated -Wrap

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
                Write-Host " compliant resource type in the Subscription will be rolled back. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. compliant resource type in the Subscription will be rolled back in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $rolledBackResources = @()
        $skippedResources = @()

        $isProviderRegister = (((Get-AzResourceProvider -ProviderNamespace $reqProviderName).RegistrationState -eq "Registered") | Measure-Object).Count -gt 0
        if ($providerPreviousProvisioningState -eq $isProviderRegister)
        {
            Write-Host "[$($reqProviderName)] provider registration state is same as before executing remediation script." -ForegroundColor $([Constants]::MessageType.Update)

            $remediatedResourceTypes | ForEach-Object {
                $resource = $_
                $providerPreviousProvisioningState = [System.Convert]::ToBoolean($_.IsPreviousProvisioningStateRegistered)
                try {
                    $rolledBackResource = Set-AzSecurityPricing -Name $_.Name -PricingTier $resource.PreviousPricingTier
                
                    if (($rolledBackResource | Measure-Object).Count -gt 0) {
                        $rolledBackResources += $rolledBackResource | Select-Object  @{N = 'Id'; E = { $resource.Id } },
                        @{N = 'Name'; E = { $resource.Name } },
                        @{N = 'CurrentPricingTier'; E = { $resource.PreviousPricingTier } },
                        @{N = 'PreviousPricingTier'; E = { $resource.PreviousPricingTier } }
                    }
                }
                catch {
                    Write-Host "Error occurred while setting $reqMDCTier pricing tier on resource [$($_.Name)]. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error) 
                    $skippedResources += $resource | Select-Object  @{N = 'Id'; E = { $resource.Id } },
                    @{N = 'Name'; E = { $resource.Name } },
                    @{N = 'CurrentPricingTier'; E = { $resource.PricingTier } },
                    @{N = 'PreviousPricingTier'; E = { $resource.PreviousPricingTier } }
                    return
                }
            }

            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "Rollback Summary: " -ForegroundColor $([Constants]::MessageType.Info)


            if ($($rolledBackResources | Measure-Object).Count -gt 0) {
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Successfully rolled back for following resource types in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                $rolledBackResources | Format-Table -Property $colsPropertyRemediated -Wrap

                # Write this to a file.
                $RolledBackFile = "$($backupFolderPath)\RolledBackResourceType.csv"
                $rolledBackResources | Export-CSV -Path $RolledBackFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($RemediatRolledBackFileedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            }

            if ($($skippedResources | Measure-Object).Count -gt 0) {
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Error occured while rolling back for following resource types in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                $skippedResources | Format-Table -Property $colsProperty -Wrap

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
            Write-Host "$reqProviderName provider name was registered before executing remediation script, performing rollback."
            Write-Host "$reqProviderName unregistering...[It takes 2-3 min to get unregistered]..."
            try 
            {
                Unregister-AzResourceProvider -ProviderNamespace $reqProviderName
                while((((Get-AzResourceProvider -ProviderNamespace $reqProviderName).RegistrationState -ne "Unregistered") | Measure-Object).Count -gt 0)
                {
                    # Checking threshold time limit to avoid getting into infinite loop
                    if($thresholdTimeLimit -ge 300)
                    {
                        Write-Host "Error occurred while unregistering [$($reqProviderName)] provider. It is taking more time than expected, Aborting process..." -ForegroundColor $([Constants]::MessageType.Error)
                        throw [System.ArgumentException] ($_)
                    }
                    Start-Sleep -Seconds 30
                    Write-Host "$reqProviderName unregistering..." -ForegroundColor $([Constants]::MessageType.Warning)

                    # Incrementing threshold time limit by 30 sec in every iteration
                    $thresholdTimeLimit = $thresholdTimeLimit + 30
                }

                if (-not $providerErrorState) {
                    Write-Host "Successfully rolled back provisiong state of the provider [$($reqProviderName)]" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            catch 
            {
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