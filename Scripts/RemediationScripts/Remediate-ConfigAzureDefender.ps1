<##########################################

# Overview:
    This script is used to configure Microsoft Defender for Cloud on subscription.

# ControlId:
    Azure_Subscription_Config_MDC_Defender_Plans

# Pre-requisites:
    You will need Owner or Contributor role on subscription.

# Steps performed by the script:
    1. Install and validate pre-requisites to run the script for subscription.
    2. Get the list of disabled Microsoft Defender for Cloud plans from subscription.
    3. Take a backup of these non-compliant plans.
    4. Register 'Microsoft.Security' provider and enable all disabled Microsoft Defender for Cloud plans for subscription.
    5. Verify Azure Policy assignments for MDC features that requires DINE policy in place.

# Step to execute script:
    Download and load remediation script in PowerShell session and execute below command.
    To know how to load script in PowerShell session refer link: https://aka.ms/AzTS-docs/RemediationscriptExcSteps.

# Command to execute:
    Examples:
        1. Run below command to configure Microsoft Defender for Cloud for subscription

        Set-ConfigAzureDefender -Environment 'AzureCloud' -SubscriptionId '<Sub_Id>' -PerformPreReqCheck: $true

    Note: 
        To rollback changes made by remediation script, execute below command
        Remove-ConfigAzureDefender -Environment 'AzureCloud' -SubscriptionId '<Sub_Id>' -Path '<Json file path containing Remediated log>' -PerformPreReqCheck: $true

To know more about parameter execute:
    a. Get-Help Set-ConfigAzureDefender -Detailed
    b. Get-Help Remove-ConfigAzureDefender -Detailed

    
# Known issues
    1. This script does not support plan extension-level, meaning:
        a. It is possible that some plan was already enabled but with some specific extension being disabled - no change will be made in this case.
        b. There is no extension-level log and the revert capability is limited.
    2. There is no SubPlan feature support for plans that supports it in the API level
    3. Plans 'Servers', 'Databases' are partially supported - it seems like enabling the plan does not enables all extensions within it.
    4. Plan 'API' throws exception when trying to enable, because of (2) above.
    5. Revert does not support Azure Policy definition assigned during the enablement script.
    6. Enable-MdcPlans: need to better manage errors on speicific plan enablement, so issues like (4) will be easier to be found.

########################################
#>

function Install-Az-Module
{
    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Module name")]
        $Name
    )
    
    if ($null -eq (Get-Module -Name $Name))
    {
        Write-Host "Installing module $Name..." -ForegroundColor Yellow
        Install-Module -Name $Name -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "$Name module is available." -ForegroundColor Green
    }
}

function Register-ResourceProvider
{
    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Resource Provider name")]
        $Name
    )
    
    # Checking IsProviderRegister with relevant provider
    $registeredProvider =  Get-AzResourceProvider -ProviderNamespace $Name | Where-Object { $_.RegistrationState -eq "Registered" }
    $isProviderRegister = $true

    if($null -eq $registeredProvider)
    {
        # capture provider registration state
        $isProviderRegister = $false
        Write-Host "Found [$($Name)] provider is not registered."
        Write-Host "$Name registering [It takes 2-3 min to get registered]..."
        # Registering provider with required provider name, it will take 1-2 min for registration
        try 
        {
            Register-AzResourceProvider -ProviderNamespace $Name
            while((((Get-AzResourceProvider -ProviderNamespace $Name).RegistrationState -ne "Registered") | Measure-Object).Count -gt 0)
            {
                # Checking threshold time limit to avoid getting into infinite loop
                if($thresholdTimeLimit -ge 300)
                {
                    Write-Host "Error occurred while registering [$($Name)] provider. It is taking more time than expected, Aborting process..." -ForegroundColor Red
                    throw [System.ArgumentException] ($_)
                }
                Start-Sleep -Seconds 30
                Write-Host "$Name registering..." -ForegroundColor Yellow

                # Incrementing threshold time limit by 30 sec in every iteration
                $thresholdTimeLimit = $thresholdTimeLimit + 30
            }
            
            $isProviderRegister = $true
        }
        catch 
        {
            Write-Host "Error occurred while registering $Name provider. ErrorMessage [$($_)]" -ForegroundColor Red
        }
        Write-Host "$Name provider successfully registered." -ForegroundColor Green
    }
    else
    {
        Write-Host "Found [$($Name)] provider is already registered."
    }
    
    return $isProviderRegister
}

function Pre_requisites
{
    <#
    .SYNOPSIS
    This command would check pre requisites modules.
    .DESCRIPTION
    This command would check pre requisites modules to perform remediation.
    #>

    try
    {
        Write-Host "Checking for pre-requisites..."
        Write-Host "Required modules are: Az.Resources, Az.Security, Az.Accounts" -ForegroundColor Cyan
        Write-Host "Checking for required modules..."
        Install-Az-Module -Name 'Az.Accounts'
        Install-Az-Module -Name 'Az.Resources'
        Install-Az-Module -Name 'Az.Security'
        Write-Host "------------------------------------------------------"     
        return $true
    }
    catch 
    {
        Write-Host "Error occurred while checking pre-requisites. ErrorMessage [$($_)]" -ForegroundColor Red    
        return $false
    }
}

function Connect-Subscription
{
    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Subscription Id")]
        $SubscriptionId,
        
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Environment")]
        $Environment
    )
    
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet))
    {
        Write-Host "Connecting to AzAccount..."
        Connect-AzAccount -Environment $Environment -ErrorAction Stop
        Write-Host "Connected to AzAccount" -ForegroundColor Green
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force

    Write-Host "Metadata Details: `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host "------------------------------------------------------"
    Write-Host "Starting with Subscription [$($SubscriptionId)]..."

    return $currentSub
}

function Validate-Permissions
{
    param (
        [object]
        [Parameter(Mandatory = $true, HelpMessage="Subscription object")]
        $Subscription
    )
    
    # Safe Check: Checking whether the current account is of type User
    if($Subscription.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor Yellow
        return;
    }

    # Safe Check: Current user needs to be either Contributor or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $Subscription.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -eq "Owner"  -or $_.RoleDefinitionName -eq 'Contributor' -or $_.RoleDefinitionName -eq "Security Admin" } | Measure-Object).Count -le 0)
    {
        Write-Host "Warning: This script can only be run by an Owner or Contributor of subscription [$($SubscriptionId)] " -ForegroundColor Yellow
        return;
    }
}

function Get-NonCompliantPlans
{
    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Expected tier name")]
        $ExpectedTierName
    )
    
    $reqMdcPlans = "VirtualMachines", "SqlServers", "AppServices", "StorageAccounts", "SqlServerVirtualMachines", "KeyVaults", "Arm", "CosmosDbs", "Containers", "CloudPosture", "Api"; #TODO: list it from API instead.
    Write-Host "Checking [$($reqMDCTier)] pricing tier for [$($ExpectedTierName -join ", ")] plans..."
    $nonCompliantPlans = @()    
    $nonCompliantPlans = Get-AzSecurityPricing | Where-Object { $_.PricingTier -ne $ExpectedTierName -and $reqMdcPlans.Contains($_.Name) } | select "Name", "PricingTier", "Id"
    
    return $nonCompliantPlans
}

function Create-LogFolder
{
    $folderPath = [Environment]::GetFolderPath("MyDocuments") 
    if (Test-Path -Path $folderPath)
    {
        $folderPath += "\AzTS\Remediation\Subscriptions\$($subscriptionid.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\ConfigAzureDefender"
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }
    
    return $folderPath
}

function Log-MdcPlanCompliance
{
    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Log folder path")]
        $FolderPath,
        
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Subscription Id")]
        $SubscriptionId,
        
        [object]
        [Parameter(Mandatory = $true, HelpMessage="Non compliant plans")]
        $NonCompliantPlans
    )
    
    # Creating data object for resource types without 'Standard' pricing tier to export into json, it will help while doing rollback operation. 
    $nonCompliantMDCResource =  New-Object psobject -Property @{
            SubscriptionId = $SubscriptionId 
            IsProviderRegister = $true
        }
    $nonCompliantMDCResource | Add-Member -Name 'NonCompliantMDCType' -Type NoteProperty -Value $NonCompliantPlans

    Write-Host "Step 3: Taking backup of resource types without [$($reqMDCTier)] tier and [$($mdcResourceProviderName)] provider registration status. Please do not delete this file. Without this file you won't be able to rollback any changes done through Remediation script." -ForegroundColor Cyan
    $nonCompliantMDCResource | ConvertTo-json | out-file "$($folderpath)\NonCompliantMDCType.json"  
    Write-Host "Path: $($folderpath)\NonCompliantMDCType.json"
}

function Enable-MdcPlans
{
    param (
        [object]
        [Parameter(Mandatory = $true, HelpMessage="Plans to enable")]
        $PlansToEnable,
        
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Required Pricing tier")]
        $PricingTier
    )
    
    try 
    {
        Write-Host "Setting [$($PricingTier)] pricing tier..."
        
        # TODO: current implementation hide failed operations with 'SilentlyContinue'. Better to change it.
        $PlansToEnable | ForEach-Object {
            (Set-AzSecurityPricing -Name $_.Name -PricingTier $PricingTier -ErrorAction SilentlyContinue) | Select-Object -Property Id, Name, PricingTier
        }
    }
    catch 
    {
        Write-Host "Error occurred while setting $PricingTier pricing tier. ErrorMessage [$($_)]" -ForegroundColor Red 
        return
    }
    Write-Host "Successfully set [$($PricingTier)] pricing tier for non-compliant resource types." -ForegroundColor Green
    
}

function Get-PolicySubscriptionScope
{
    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Subscription Id")]
        $SubscriptionId
    )

    return "/subscriptions/$SubscriptionId"
}

function Get-NonCompliantPolicies
{
    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Subscription Id")]
        $SubscriptionId
    )
    
    # build expected policies list
    $expectedPoliciesIds = New-Object System.Collections.ArrayList

    if ('Standard' -eq (Get-AzSecurityPricing -Name 'Containers').PricingTier)
    {
        $expectedPoliciesIds.Add('64def556-fbad-4622-930e-72d1d5589bf5') # defender sensor for AKS
        $expectedPoliciesIds.Add('708b60a6-d253-4fe0-9114-4be4c00f012c') # defender sensor for Arc
        $expectedPoliciesIds.Add('a8eff44f-8c92-45c3-a3fb-9880802d67a7') # policy add-on for AKS
        $expectedPoliciesIds.Add('0adc5395-9169-4b9b-8687-af838d69410a') # policy add-on for Arc
    }
    
    # query all policies
    $nonCompliantPoliciesIds = New-Object System.Collections.ArrayList
    $scope = Get-PolicySubscriptionScope -SubscriptionId $SubscriptionId
    
    $expectedPoliciesIds | ForEach-Object {
                            $fullId = "/providers/Microsoft.Authorization/policyDefinitions/$_"
                            $foundPolicy = (Get-AzPolicyAssignment -Scope $scope -PolicyDefinitionId $fullId)
                            if ($foundPolicy -eq $null)
                            {
                                Write-Host "assignment not found for $fullId"
                                $nonCompliantPoliciesIds.Add($_)
                            }
                            else
                            {
                                Write-Host "assignment found for $fullId"
                            }
                        }
    
    Write-Host "non compliant policies (if any): $nonCompliantPoliciesIds"
    return $nonCompliantPoliciesIds
}

function Assign-Policies
{
    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Subscription Id")]
        $SubscriptionId,
        
        [object]
        [Parameter(Mandatory = $true, HelpMessage="Subscription Id")]
        $Policies
    )
    $scope = Get-PolicySubscriptionScope -SubscriptionId $SubscriptionId
    
    $location = (Get-AzLocation)[0].Location
    
    $Policies | ForEach-Object {
                    if (($_.Length) -eq 36) # Weird bug of working with arrays in PS, will be solved later
                    {
                        $definition = Get-AzPolicyDefinition -SubscriptionId $SubscriptionId -Name $_
                        $assignment = New-AzPolicyAssignment -Name $_ -Scope $scope -PolicyDefinition $definition -IdentityType 'SystemAssigned' -Location $location
                        $remediation = Start-AzPolicyRemediation -Name "creation-$(New-Guid)" -PolicyAssignmentId ($assignment.Id) -ResourceDiscoveryMode ReEvaluateCompliance
                        Write-Host "Policy assigned and remediation task created for $_"
                    }
                }
}

function Set-ConfigAzureDefender # didn't changed this one as I'm not sure how it is being called, but better to align with 'Defender for Cloud' naming
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Subscription_Config_MDC_Defender_Plans' control.
    .DESCRIPTION
    This command would help in remediating 'Azure_Subscription_Config_MDC_Defender_Plans' control.
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
        $PerformPreReqCheck,
        
        [string]
        [Parameter(Mandatory = $false, HelpMessage="Environment")]
        $Environment = 'AzureCloud'
    )

    Write-Host "======================================================"
    Write-Host "Starting to configure Microsoft Defender for Cloud for subscription [$($SubscriptionId)]..."
    Write-Host "------------------------------------------------------"

    if($PerformPreReqCheck)
    {
        if ($false -eq (Pre_requisites))
        {
            return
        }
    }

    # Setting context for current subscription.
    $currentSub = Connect-Subscription -Environment $Environment -SubscriptionId $SubscriptionId

    Write-Host "Step 1: Validating whether the current user [$($currentSub.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."
    
    if ($false -eq (Validate-Permissions -Subscription $currentSub))
    {
        return;
    }

    # Declaring required resource types and pricing tier
    $mdcResourceProviderName = "Microsoft.Security"
    $isProviderRegister = Register-ResourceProvider -Name $mdcResourceProviderName
    $isProviderRegister = $isProviderRegister && Register-ResourceProvider -Name 'Microsoft.PolicyInsights'
    
    if ($false -eq $isProviderRegister)
    {
        return;
    }

    $reqMDCTier = "Standard";
    $nonCompliantMDCTierResourcetype = Get-NonCompliantPlans -ExpectedTierName $reqMDCTier

    # If control is already in Passed state (i.e. 'Microsoft.Security' provider is already registered and no non-compliant resource types are found) then no need to execute below steps.
    $nonCompliantMDCTypeCount = ($nonCompliantMDCTierResourcetype | Measure-Object).Count
    
    if($nonCompliantMDCTypeCount -eq 0)
    {
        Write-Host "[$($mdcResourceProviderName)] provider is already registered and there are no non-compliant resource types. In this case, remediation is not required." -ForegroundColor Green
        Write-Host "======================================================"
        return
    }
    
    Write-Host "Found [$($nonCompliantMDCTypeCount)] resource types without [$($reqMDCTier)]"
    Write-Host "[NonCompliantMDCType]: [$($nonCompliantMDCTierResourcetype.Name -join ", ")]"
    
    # Creating the log folder
    $folderPath = Create-LogFolder
    
    # Create log file
    Log-MdcPlanCompliance -FolderPath $folderPath -SubscriptionId $SubscriptionId -NonCompliantPlans $nonCompliantMDCTierResourcetype
    
    # Performing remediation
    Enable-MdcPlans -PlansToEnable $nonCompliantMDCTierResourcetype -PricingTier $reqMDCTier
    
    ## Handle MDC capabilities enabled by Azure policy
    
    # Get non-assigned policies
    $policies = Get-NonCompliantPolicies -SubscriptionId $SubscriptionId
    
    # Assign the policies
    Assign-Policies -SubscriptionId $SubscriptionId -Policies $policies
    
    Write-Host "======================================================"
}


function Remove-ConfigAzureDefender
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Subscription_Config_MDC_Defender_Plans' control.
    .DESCRIPTION
    This command would help in remediating 'Azure_Subscription_Config_MDC_Defender_Plans' control.
    .PARAMETER SubscriptionId
        Enter subscription id on which remediation needs to be performed.
    .PARAMETER PerformPreReqCheck
        Perform pre requisites check to ensure all required modules to perform rollback operation are available.
    #>

    param (
        [string]
        [Parameter(Mandatory = $false, HelpMessage="Environment")]
        $Environment = 'AzureCloud',
    
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
    Write-Host "Starting to rollback operation to configure Microsoft Defender for Cloud for subscription [$($SubscriptionId)]..."
    Write-Host "------------------------------------------------------"

    if($PerformPreReqCheck)
    {
        if ($false -eq (Pre_requisites))
        {
            return
        }
    }

    # Connect to AzAccount
    $currentSub = Connect-Subscription -Environment $Environment -SubscriptionId $SubscriptionId

    Write-Host "Step 1: Validating whether the current user [$($currentSub.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."
    
    if ($false -eq (Validate-Permissions -Subscription $currentSub))
    {
        return;
    }

    Write-Host "Step 2 of 3: Fetching remediation log to perform rollback operation to configure Microsoft Defender for Cloud for subscription [$($SubscriptionId)]..."
 
    # Array to store resource context
    if (-not (Test-Path -Path $Path))
    {
        Write-Host "Warning: Rollback file is not found. Please check if the initial Remediation script has been run from the same machine. Exiting the process" -ForegroundColor Yellow
        break;        
    }

    # Declaring required resource types and pricing tier
    $reqMDCTier = "Standard";
    $mdcResourceProviderName = "Microsoft.Security"
    $remediatedLog = Get-Content -Raw -Path $Path | ConvertFrom-Json

    Write-Host "Step 3 of 3: Performing rollback operation to configure Microsoft Defender for Cloud for subscription [$($SubscriptionId)]..."
        
    # Performing rollback operation
    try
    {
        if(($remediatedLog | Measure-Object).Count -gt 0)
        {
            Write-Host "Configuring Microsoft Defender for Cloud as per remediation log on subscription [$($SubscriptionId)]..."
            
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
                    Write-Host "Error occurred while performing rollback operation to configure Microsoft Defender for Cloud. ErrorMessage [$($_)]" -ForegroundColor Red 
                    break      
                }
            }
            else 
            {
                Write-Host "No non-compliant resource types found to perform rollback operation." -ForegroundColor Green                
            }

            Write-Host "`n"
            # Checking current registration state of provider i.e. 'Microsoft.Security' on subscription.
            $isProviderRegister = (((Get-AzResourceProvider -ProviderNamespace $mdcResourceProviderName).RegistrationState -eq "Registered") | Measure-Object).Count -gt 0
            if([System.Convert]::ToBoolean($remediatedLog.IsProviderRegister) -eq $isProviderRegister)
            {
                Write-Host "[$($mdcResourceProviderName)] provider registration state is same as before executing remediation script." -ForegroundColor Green
                Write-Host "Rollback operation successfully performed." -ForegroundColor Green
                Write-Host "======================================================"
                break;
            }
            else 
            {
                # when current provider registration state and before executing remediation script is not same.
                # That means while doing remediation it got registered, to perform rollback we need to unregister it
                Write-Host "$mdcResourceProviderName provider name was registered before executing remediation script, performing rollback."
                Write-Host "$mdcResourceProviderName unregistering...[It takes 2-3 min to get unregistered]..."
                try 
                {
                    Unregister-AzResourceProvider -ProviderNamespace $mdcResourceProviderName
                    while((((Get-AzResourceProvider -ProviderNamespace $mdcResourceProviderName).RegistrationState -ne "Unregistered") | Measure-Object).Count -gt 0)
                    {
                        # Checking threshold time limit to avoid getting into infinite loop
                        if($thresholdTimeLimit -ge 300)
                        {
                            Write-Host "Error occurred while unregistering [$($mdcResourceProviderName)] provider. It is taking more time than expected, Aborting process..." -ForegroundColor Red
                            throw [System.ArgumentException] ($_)
                        }
                        Start-Sleep -Seconds 30
                        Write-Host "$mdcResourceProviderName unregistering..." -ForegroundColor Yellow

                        # Incrementing threshold time limit by 30 sec in every iteration
                        $thresholdTimeLimit = $thresholdTimeLimit + 30
                    }
                }
                catch 
                {
                    Write-Host "Error occurred while unregistering $mdcResourceProviderName provider. ErrorMessage [$($_)]" -ForegroundColor Red
                    break;
                }
                Write-Host "$mdcResourceProviderName provider successfully unregistered." -ForegroundColor Green
                Write-Host "Rollback operation successfully performed." -ForegroundColor Green
                Write-Host "======================================================"
            }
        }
        else 
        {
            Write-Host "Microsoft Defender for Cloud details not found to perform rollback operation."
            Write-Host "======================================================"
            break
        }
    }
    catch
    {
        Write-Host "Error occurred while performing rollback operation to configure Microsoft Defender for Cloud. ErrorMessage [$($_)]" -ForegroundColor Red 
        break
    }
}

<#
# ***************************************************** #
# Function calling with parameters for remediation.
Set-ConfigAzureDefender -Environment 'AzureCloud' -SubscriptionId '<Sub_Id>' -PerformPreReqCheck: $true

# Function calling with parameters to rollback remediation changes.
Remove-ConfigAzureDefender -Environment 'AzureCloud' -SubscriptionId '<Sub_Id>' -Path '<Json file path containing Remediated log>' -PerformPreReqCheck: $true
#>
