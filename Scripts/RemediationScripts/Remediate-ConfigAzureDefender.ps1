<##########################################

# Overview:
    This script is used to configure Azure Defender on subscription.

# ControlId:
    Azure_Subscription_Config_MDC_Defender

# Pre-requisites:
    You will need Owner or Contributor role on subscription.

# Steps performed by the script:
    1. Install and validate pre-requisites to run the script for subscription.

    2. Get the list of resource types that do not have Azure Defender plan enabled, from subscription.

    3. Take a backup of these non-compliant resource types.

    4. Register 'Microsoft.Security' provider and enable Azure Defender plan for all non-compliant resource types for subscription.

# Step to execute script:
    Download and load remediation script in PowerShell session and execute below command.
    To know how to load script in PowerShell session refer link: https://aka.ms/AzTS-docs/RemediationscriptExcSteps.

# Command to execute:
    Examples:
        1. Run below command to configure Azure Defender for subscription

        Set-ConfigAzureDefender -SubscriptionId '<Sub_Id>' -PerformPreReqCheck: $true

    Note: 
        To rollback changes made by remediation script, execute below command
        Remove-ConfigAzureDefender -SubscriptionId '<Sub_Id>' -Path '<Json file path containing Remediated log>' -PerformPreReqCheck: $true

To know more about parameter execute:
    a. Get-Help Set-ConfigAzureDefender -Detailed
    b. Get-Help Remove-ConfigAzureDefender -Detailed

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

    Write-Host "Required modules are: Az.Resources, Az.Security, Az.Accounts" -ForegroundColor Cyan
    Write-Host "Checking for required modules..."
    $availableModules = $(Get-Module -ListAvailable Az.Resources, Az.Security, Az.Accounts)
    
    # Checking if 'Az.Accounts' module is available or not.
    if($availableModules.Name -notcontains 'Az.Accounts')
    {
        Write-Host "Installing module Az.Accounts..." -ForegroundColor Yellow
        Install-Module -Name Az.Accounts -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "Az.Accounts module is available." -ForegroundColor Green
    }

    # Checking if 'Az.Resources' module is available or not.
    if($availableModules.Name -notcontains 'Az.Resources')
    {
        Write-Host "Installing module Az.Resources..." -ForegroundColor Yellow
        Install-Module -Name Az.Resources -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "Az.Resources module is available." -ForegroundColor Green
    }

    # Checking if 'Az.Security' module is available or not.
    if($availableModules.Name -notcontains 'Az.Security')
    {
        Write-Host "Installing module Az.Security..." -ForegroundColor Yellow
        Install-Module -Name Az.Security -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "Az.Security module is available." -ForegroundColor Green
    }
}

function Set-ConfigAzureDefender
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Subscription_Config_MDC_Defender' control.
    .DESCRIPTION
    This command would help in remediating 'Azure_Subscription_Config_MDC_Defender' control.
    .PARAMETER SubscriptionId
        Enter subscription id on which remediation needs to be performed.
    .PARAMETER PerformPreReqCheck
        Perform pre requisites check to ensure all required modules to perform remediation operation are available.
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id for remediation")]
        $SubscriptionId,

        [switch]
        $PerformPreReqCheck
    )

    Write-Host "======================================================"
    Write-Host "Starting to configure Azure Defender for subscription [$($SubscriptionId)]..."
    Write-Host "------------------------------------------------------"

    if($PerformPreReqCheck)
    {
        try 
        {
            Write-Host "Checking for pre-requisites..."
            Pre_requisites
            Write-Host "------------------------------------------------------"     
        }
        catch 
        {
            Write-Host "Error occurred while checking pre-requisites. ErrorMessage [$($_)]" -ForegroundColor Red    
            break
        }
    }

    # Connect to AzAccount
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet))
    {       
        Write-Host "Connecting to AzAccount..."
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to AzAccount" -ForegroundColor Green
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force

    Write-Host "Metadata Details: `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host "------------------------------------------------------"
    Write-Host "Starting with Subscription [$($SubscriptionId)]..."


    Write-Host "Step 1 of 3: Validating whether the current user [$($currentSub.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."

    # Safe Check: Checking whether the current account is of type User
    if($currentSub.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor Yellow
        return;
    }

    # Safe Check: Current user needs to be either Contributor or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $currentSub.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -eq "Owner"  -or $_.RoleDefinitionName -eq 'Contributor' -or $_.RoleDefinitionName -eq "Security Admin" } | Measure-Object).Count -le 0)
    {
        Write-Host "Warning: This script can only be run by an Owner or Contributor of subscription [$($SubscriptionId)] " -ForegroundColor Yellow
        return;
    }

    # Declaring required resource types and pricing tier
    $reqMDCTierResourceTypes = "VirtualMachines","SqlServers","AppServices","StorageAccounts","Containers","KeyVaults","SqlServerVirtualMachines","Dns","Arm";
    $reqMDCTier = "Standard";
    $reqProviderName = "Microsoft.Security"
    $isProviderRegister = $true

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
                    Write-Host "Error occurred while registering [$($reqProviderName)] provider. It is taking more time than expected, Aborting process..." -ForegroundColor Red
                    throw [System.ArgumentException] ($_)
                }
                Start-Sleep -Seconds 30
                Write-Host "$reqProviderName registering..." -ForegroundColor Yellow

                # Incrementing threshold time limit by 30 sec in every iteration
                $thresholdTimeLimit = $thresholdTimeLimit + 30
            }
        }
        catch 
        {
            Write-Host "Error occurred while registering $reqProviderName provider. ErrorMessage [$($_)]" -ForegroundColor Red
            return
        }
        Write-Host "$reqProviderName provider successfully registered." -ForegroundColor Green
    }

    Write-Host "Step 2 of 3: Checking [$($reqMDCTier)] pricing tier for [$($reqMDCTierResourceTypes -join ", ")] resource types..."
    $nonCompliantMDCTierResourcetype = @()
    $nonCompliantMDCTierResourcetype = Get-AzSecurityPricing | Where-Object { $_.PricingTier -ne $reqMDCTier -and $reqMDCTierResourceTypes.Contains($_.Name) } | select "Name", "PricingTier", "Id"

    $nonCompliantMDCTypeCount = ($nonCompliantMDCTierResourcetype | Measure-Object).Count

    Write-Host "Found [$($nonCompliantMDCTypeCount)] resource types without [$($reqMDCTier)]"
    Write-Host "[NonCompliantMDCType]: [$($nonCompliantMDCTierResourcetype.Name -join ", ")]"

    # If control is already in Passed state (i.e. 'Microsoft.Security' provider is already registered and no non-compliant resource types are found) then no need to execute below steps.
    if($isProviderRegister -and ($nonCompliantMDCTypeCount -eq 0))
    {
        Write-Host "[$($reqProviderName)] provider is already registered and there are no non-compliant resource types. In this case, remediation is not required." -ForegroundColor Green
        Write-Host "======================================================"
        return
    }

    # Creating data object for resource types without 'Standard' pricing tier to export into json, it will help while doing rollback operation. 
    $nonCompliantMDCResource =  New-Object psobject -Property @{
            SubscriptionId = $SubscriptionId 
            IsProviderRegister = $isProviderRegister
        }
    $nonCompliantMDCResource | Add-Member -Name 'NonCompliantMDCType' -Type NoteProperty -Value $nonCompliantMDCTierResourcetype

    # Creating the log file
    $folderPath = [Environment]::GetFolderPath("MyDocuments") 
    if (Test-Path -Path $folderPath)
    {
        $folderPath += "\AzTS\Remediation\Subscriptions\$($subscriptionid.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\ConfigAzureDefender"
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }

    Write-Host "Step 3 of 3: Taking backup of resource types without [$($reqMDCTier)] tier and [$($reqProviderName)] provider registration status. Please do not delete this file. Without this file you won't be able to rollback any changes done through Remediation script." -ForegroundColor Cyan
    $nonCompliantMDCResource | ConvertTo-json | out-file "$($folderpath)\NonCompliantMDCType.json"  
    Write-Host "Path: $($folderpath)\NonCompliantMDCType.json"     
    Write-Host "`n"

    # Performing remediation
    if($nonCompliantMDCTypeCount -gt 0)
    {
        try 
        {
            Write-Host "Setting [$($reqMDCTier)] pricing tier..."
            $nonCompliantMDCTierResourcetype | ForEach-Object {
                (Set-AzSecurityPricing -Name $_.Name -PricingTier $reqMDCTier -ErrorAction SilentlyContinue) | Select-Object -Property Id, Name, PricingTier
            }
        }
        catch 
        {
            Write-Host "Error occurred while setting $reqMDCTier pricing tier. ErrorMessage [$($_)]" -ForegroundColor Red 
            return
        }
        Write-Host "Successfully set [$($reqMDCTier)] pricing tier for non-compliant resource types." -ForegroundColor Green
        Write-Host "======================================================"
    }
    else
    {
        Write-Host "Required resource types compliant with [$($reqMDCTier)] pricing tier." -ForegroundColor Green
        Write-Host "======================================================"
        return   
    }
}


function Remove-ConfigAzureDefender
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Subscription_Config_MDC_Defender' control.
    .DESCRIPTION
    This command would help in remediating 'Azure_Subscription_Config_MDC_Defender' control.
    .PARAMETER SubscriptionId
        Enter subscription id on which remediation needs to be performed.
    .PARAMETER PerformPreReqCheck
        Perform pre requisites check to ensure all required modules to perform rollback operation are available.
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id to perform rollback operation")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage="Json file path which contain logs generated by remediation script to rollback remediation changes")]
        $Path,

        [switch]
        $PerformPreReqCheck
    )

    Write-Host "======================================================"
    Write-Host "Starting to rollback operation to configure Azure Defender for subscription [$($SubscriptionId)]..."
    Write-Host "------------------------------------------------------"

    if($PerformPreReqCheck)
    {
        try 
        {
            Write-Host "Checking for pre-requisites..."
            Pre_requisites
            Write-Host "------------------------------------------------------"     
        }
        catch 
        {
            Write-Host "Error occurred while checking pre-requisites. ErrorMessage [$($_)]" -ForegroundColor Red    
            break
        }
    }

    # Connect to AzAccount
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet))
    {       
        Write-Host "Connecting to AzAccount..."
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to AzAccount" -ForegroundColor Green
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force

    

    Write-Host "Metadata Details: `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host "------------------------------------------------------"
    Write-Host "Starting with subscription [$($SubscriptionId)]..."


    Write-Host "Step 1 of 3: Validating whether the current user [$($currentSub.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."

    # Safe Check: Checking whether the current account is of type User
    if($currentSub.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor Yellow
        break;
    }

    # Safe Check: Current user need to be either Contributor or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $currentSub.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -eq "Owner"  -or $_.RoleDefinitionName -eq 'Contributor' } | Measure-Object).Count -le 0)
    {
        Write-Host "Warning: This script can only be run by an Owner or Contributor of subscription [$($SubscriptionId)] " -ForegroundColor Yellow
        break;
    }
    Write-Host "Step 2 of 3: Fetching remediation log to perform rollback operation to configure Azure Defender for subscription [$($SubscriptionId)]..."
 
    # Array to store resource context
    if (-not (Test-Path -Path $Path))
    {
        Write-Host "Warning: Rollback file is not found. Please check if the initial Remediation script has been run from the same machine. Exiting the process" -ForegroundColor Yellow
        break;        
    }

    # Declaring required resource types and pricing tier
    $reqMDCTier = "Standard";
    $reqProviderName = "Microsoft.Security"
    $remediatedLog = Get-Content -Raw -Path $Path | ConvertFrom-Json

    Write-Host "Step 3 of 3: Performing rollback operation to configure Azure Defender for subscription [$($SubscriptionId)]..."
        
    # Performing rollback operation
    try
    {
        if(($remediatedLog | Measure-Object).Count -gt 0)
        {
            Write-Host "Configuring Azure Defender as per remediation log on subscription [$($SubscriptionId)]..."
            
            if($null -ne $remediatedLog.NonCompliantMDCType -and ($remediatedLog.NonCompliantMDCType | Measure-Object).Count -gt 0)
            {
                try 
                {
                    $remediatedLog.NonCompliantMDCType | ForEach-Object {
                        (Set-AzSecurityPricing -Name $_.Name -PricingTier $_.PricingTier) | Select-Object -Property Id, Name, PricingTier
                    }
                }
                catch 
                {
                    Write-Host "Error occurred while performing rollback operation to configure Azure Defender. ErrorMessage [$($_)]" -ForegroundColor Red 
                    break      
                }
            }
            else 
            {
                Write-Host "No non-compliant resource types found to perform rollback operation." -ForegroundColor Green                
            }

            Write-Host "`n"
            # Checking current registration state of provider i.e. 'Microsoft.Security' on subscription.
            $isProviderRegister = (((Get-AzResourceProvider -ProviderNamespace $reqProviderName).RegistrationState -eq "Registered") | Measure-Object).Count -gt 0
            if([System.Convert]::ToBoolean($remediatedLog.IsProviderRegister) -eq $isProviderRegister)
            {
                Write-Host "[$($reqProviderName)] provider registration state is same as before executing remediation script." -ForegroundColor Green
                Write-Host "Rollback operation successfully performed." -ForegroundColor Green
                Write-Host "======================================================"
                break;
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
                            Write-Host "Error occurred while unregistering [$($reqProviderName)] provider. It is taking more time than expected, Aborting process..." -ForegroundColor Red
                            throw [System.ArgumentException] ($_)
                        }
                        Start-Sleep -Seconds 30
                        Write-Host "$reqProviderName unregistering..." -ForegroundColor Yellow

                        # Incrementing threshold time limit by 30 sec in every iteration
                        $thresholdTimeLimit = $thresholdTimeLimit + 30
                    }
                }
                catch 
                {
                    Write-Host "Error occurred while unregistering $reqProviderName provider. ErrorMessage [$($_)]" -ForegroundColor Red
                    break;
                }
                Write-Host "$reqProviderName provider successfully unregistered." -ForegroundColor Green
                Write-Host "Rollback operation successfully performed." -ForegroundColor Green
                Write-Host "======================================================"
            }
        }
        else 
        {
            Write-Host "Azure Defender details not found to perform rollback operation."
            Write-Host "======================================================"
            break
        }
    }
    catch
    {
        Write-Host "Error occurred while performing rollback operation to configure Azure Defender. ErrorMessage [$($_)]" -ForegroundColor Red 
        break
    }
}

<#
# ***************************************************** #
# Function calling with parameters for remediation.
Set-ConfigAzureDefender -SubscriptionId '<Sub_Id>' -PerformPreReqCheck: $true

# Function calling with parameters to rollback remediation changes.
Remove-ConfigAzureDefender -SubscriptionId '<Sub_Id>' -Path '<Json file path containing Remediated log>' -PerformPreReqCheck: $true
#>
