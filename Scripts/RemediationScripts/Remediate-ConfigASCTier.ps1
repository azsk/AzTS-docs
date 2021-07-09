<##########################################

# Overivew:
    This script is used to config ASC tier on subscription.

ControlId: 
    Azure_Subscription_Config_ASC_Tier

# Pre-requesites:
    You will need owner or contributor role on subscription.

# Steps performed by the script
    1. Install and validate pre-requesites to run the script for subscription.

    2. Get list non-compliant ASC type from subscription.

    3. Taking backup of non-compliant ASC type.

    4. Register 'Microsoft.Security' provider and enable required tier for all non-compliant ASC type for subscription.

# Step to execute script:
    Download and load remediation script in PowerShell session and execute below command.
    To know how to load script in PowerShell session refer link: https://aka.ms/AzTS-docs/RemediationscriptExcSteps.

# Command to execute:
    Examples:
        1. Run below command to config ASC tier for subscription

        Set-ConfigASCTier -SubscriptionId '<Sub_Id>' -PerformPreReqCheck: $true

    Note: 
        To rollback changes made by remediation script, execute below command
        Remove-ConfigASCTier -SubscriptionId '<Sub_Id>' -Path '<Json file path containing Remediated log>' -PerformPreReqCheck: $true

To know more about parameter execute:
    a. Get-Help Set-ConfigASCTier -Detailed
    b. Get-Help Remove-ConfigASCTier -Detailed

########################################
#>
function Pre_requisites
{
    <#
    .SYNOPSIS
    This command would check pre requisities modules.
    .DESCRIPTION
    This command would check pre requisities modules to perform remediation.
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

function Set-ConfigASCTier
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Subscription_Config_ASC_Tier' control.
    .DESCRIPTION
    This command would help in remediating 'Azure_Subscription_Config_ASC_Tier' control.
    .PARAMETER SubscriptionId
        Enter subscription id on which remediation need to perform.
    .PARAMETER PerformPreReqCheck
        Perform pre requisities check to ensure all required module to perform rollback operation is available.
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id for remediation")]
        $SubscriptionId,

        [switch]
        $PerformPreReqCheck
    )

    Write-Host "======================================================"
    Write-Host "Starting to remediate config ASC tier for subscription [$($SubscriptionId)]..."
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
            Write-Host "Error occured while checking pre-requisites. ErrorMessage [$($_)]" -ForegroundColor Red    
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

    # Safe Check: Current user need to be either Contributor or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $currentSub.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -eq "Owner"  -or $_.RoleDefinitionName -eq 'Contributor' -or $_.RoleDefinitionName -eq "Security Admin" } | Measure-Object).Count -le 0)
    {
        Write-Host "Warning: This script can only be run by an Owner or Contributor of subscription [$($SubscriptionId)] " -ForegroundColor Yellow
        return;
    }

    # Declaring required ASC type and pricing tier
    $reqASCTierResourceTypes = "VirtualMachines","SqlServers","AppServices","StorageAccounts","KubernetesService","ContainerRegistry","KeyVaults","SqlServerVirtualMachines","Dns","Arm";
    $reqASCTier = "Standard";
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
                    Write-Host "Error occurred while registering [$($reqProviderName)] provider. It is taking more time then expected, Aborting process..." -ForegroundColor Red
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
            Write-Host "Error Occured while registering $reqProviderName provider. ErrorMessage [$($_)]" -ForegroundColor Red
            return
        }
        Write-Host "$reqProviderName provider successfully registered." -ForegroundColor Green
    }

    Write-Host "Step 2 of 3: Checking [$($reqASCTier)] pricing tier for [$($reqASCTierResourceTypes -join ", ")] ASC type..."
    $nonCompliantASCTierResourcetype = @()
    $nonCompliantASCTierResourcetype = Get-AzSecurityPricing | Where-Object { $_.PricingTier -ne $reqASCTier -and $reqASCTierResourceTypes.Contains($_.Name) } | select "Name", "PricingTier", "Id"

    $nonCompliantASCTypeCount = ($nonCompliantASCTierResourcetype | Measure-Object).Count

    Write-Host "Found [$($nonCompliantASCTypeCount)] ASC type without [$($reqASCTier)]"
    Write-Host "[NonCompliantASCType]: [$($nonCompliantASCTierResourcetype.Name -join ", ")]"

    # If control is already in Passed state (i.e. 'Microsoft.Security' provider is already registered and no non-compliant ASC type found) then no need to execute below steps.
    if($isProviderRegister -and ($nonCompliantASCTypeCount -eq 0))
    {
        Write-Host "[$($reqProviderName)] provider is already registered and there is no non-compliant ASC type. In this case remediation not required." -ForegroundColor Green
        Write-Host "======================================================"
        return
    }

    # Creating data object for ASC type without 'Standard' pricing tier to export into json, it will help while doing rollback opeartion. 
    $nonCompliantASCResource =  New-Object psobject -Property @{
            SubscriptionId = $SubscriptionId 
            IsProviderRegister = $isProviderRegister
        }
    $nonCompliantASCResource | Add-Member -Name 'NonCompliantASCType' -Type NoteProperty -Value $nonCompliantASCTierResourcetype

    # Creating the log file
    $folderPath = [Environment]::GetFolderPath("MyDocuments") 
    if (Test-Path -Path $folderPath)
    {
        $folderPath += "\AzTS\Remediation\Subscriptions\$($subscriptionid.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\ConfigASCTier"
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }

    Write-Host "Step 3 of 3: Taking backup of ASC type without [Standard] tier and [$($reqProviderName)] provider registration status. Please do not delete this file. Without this file you wont be able to rollback any changes done through Remediation script." -ForegroundColor Cyan
    $nonCompliantASCResource | ConvertTo-json | out-file "$($folderpath)\NonCompliantASCType.json"  
    Write-Host "Path: $($folderpath)\NonCompliantASCType.json"     
    Write-Host "`n"

    # Performing remediation
    if($nonCompliantASCTypeCount -gt 0)
    {
        try 
        {
            Write-Host "Setting [$($reqASCTier)] pricing tier..."
            $nonCompliantASCTierResourcetype | ForEach-Object {
                (Set-AzSecurityPricing -Name $_.Name -PricingTier $reqASCTier -ErrorAction SilentlyContinue) | Select-Object -Property Id, Name, PricingTier
            }
        }
        catch 
        {
            Write-Host "Error occurred while setting $reqASCTier pricing tier. ErrorMessage [$($_)]" -ForegroundColor Red 
            return
        }
        Write-Host "Successfuly set [$($reqASCTier)] pricing tier for non-compliant ASC type." -ForegroundColor Green
        Write-Host "======================================================"
    }
    else
    {
        Write-Host "Required ASC type compliant with [$($reqASCTier)] pricing tier." -ForegroundColor Green
        Write-Host "======================================================"
        return   
    }
}


function Remove-ConfigASCTier
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Subscription_Config_ASC_Tier' control.
    .DESCRIPTION
    This command would help in remediating 'Azure_Subscription_Config_ASC_Tier' control.
    .PARAMETER SubscriptionId
        Enter subscription id on which remediation need to perform.
    .PARAMETER PerformPreReqCheck
        Perform pre requisities check to ensure all required module to perform rollback operation is available.
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
    Write-Host "Starting to rollback operation to config ASC tier for subscription [$($SubscriptionId)]..."
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
            Write-Host "Error occured while checking pre-requisites. ErrorMessage [$($_)]" -ForegroundColor Red    
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
    Write-Host "Step 2 of 3: Fetching remediation log to perform rollback operation to config ASC tier for subscription [$($SubscriptionId)]..."
 
    # Array to store resource context
    if (-not (Test-Path -Path $Path))
    {
        Write-Host "Warning: Rollback file is not found. Please check if the initial Remediation script has been run from the same machine. Exiting the process" -ForegroundColor Yellow
        break;        
    }

    # Declaring required ASC type and pricing tier
    $reqASCTier = "Standard";
    $reqProviderName = "Microsoft.Security"
    $remediatedLog = Get-Content -Raw -Path $Path | ConvertFrom-Json

    Write-Host "Step 3 of 3: Performing rollback operation to config ASC tier for subscription [$($SubscriptionId)]..."
        
    # Performing rollback operation
    try
    {
        if(($remediatedLog | Measure-Object).Count -gt 0)
        {
            Write-Host "Configuring ASC tier as per remediation log on subscription [$($SubscriptionId)]..."
            
            if($null -ne $remediatedLog.NonCompliantASCType -and ($remediatedLog.NonCompliantASCType | Measure-Object).Count -gt 0)
            {
                try 
                {
                    $remediatedLog.NonCompliantASCType | ForEach-Object {
                        (Set-AzSecurityPricing -Name $_.Name -PricingTier $_.PricingTier) | Select-Object -Property Id, Name, PricingTier
                    }
                }
                catch 
                {
                    Write-Host "Error occurred while performing rollback operation to configure ASC tier. ErrorMessage [$($_)]" -ForegroundColor Red 
                    break      
                }
            }
            else 
            {
                Write-Host "No non-compliant ASC type found to perform rollback operation." -ForegroundColor Green                
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
                            Write-Host "Error occurred while unregistering [$($reqProviderName)] provider. It is taking more time then expected, Aborting process..." -ForegroundColor Red
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
                    Write-Host "Error Occured while unregistering $reqProviderName provider. ErrorMessage [$($_)]" -ForegroundColor Red
                    break;
                }
                Write-Host "$reqProviderName provider successfully unregistered." -ForegroundColor Green
                Write-Host "Rollback operation successfully performed." -ForegroundColor Green
                Write-Host "======================================================"
            }
        }
        else 
        {
            Write-Host "ASC tier details not found to perform rollback operation."
            Write-Host "======================================================"
            break
        }
    }
    catch
    {
        Write-Host "Error occurred while performing rollback operation to configure ASC tier. ErrorMessage [$($_)]" -ForegroundColor Red 
        break
    }
}

<#
# ***************************************************** #
# Function calling with parameters for remediation.
Set-ConfigASCTier -SubscriptionId '<Sub_Id>' -PerformPreReqCheck: $true

# Function calling with parameters to rollback remediation changes.
Remove-ConfigASCTier -SubscriptionId '<Sub_Id>' -Path '<Json file path containing Remediated log>' -PerformPreReqCheck: $true
#>


