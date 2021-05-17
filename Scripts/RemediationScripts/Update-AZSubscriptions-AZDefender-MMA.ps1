<##########################################

# Overivew:
    This script is used to update azure subscriptions to enable azure defender and MMA on subscriptions.

# Pre-requesites:
    You will need owner or Contributor role at subscription level.

# Steps performed by the script
    1. Install and validate pre-requesites to run the script for subscription.

    2. Update azure subscriptions to enable azure defender and MMA.

# Step to execute script:
    Download and load remediation script in PowerShell session and execute below command.
    To know how to load script in PowerShell session refer link: https://aka.ms/AzTS-docs/RemediationscriptExcSteps.

# Command to execute:
    Examples:
        1. Run below command to update azure subscriptions to enable azure defender and MMA on subscription

         Update-AZDefenderMMA -SubscriptionId '<Sub_Id>' -PerformPreReqCheck: $true -interactiveMode Yes

To know more about parameter execute below command:
    a. Get-Help Update-AZDefenderMMA -Detailed

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

function Update-AZDefenderMMA
{
    <#
    .SYNOPSIS
    Updates an Azure Subscription for Azure Defender and MMA.
    .DESCRIPTION
    This script should be used to update Azure Subscriptions to enable Azure Defender and MMA.
    .PARAMETER SubscriptionId
        Enter subscription id on which update need to perform.
    .PARAMETER PerformPreReqCheck
        Perform pre requisities check to ensure all required module to perform update operation is available.
    .PARAMETER interactiveMode
        Specifies whether this should be executed in interactive mode.
        Accepted vaules are: 1, true, yes, on, enabled.
        If not provided, it will executes in unattended mode.
    #>
    Param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id for remediation")]
        $SubscriptionId,

        [switch]
        $PerformPreReqCheck,
        
        [parameter(position=0)] [string]$interactiveMode
    )

    Write-Host "======================================================"
    Write-Host "Starting to update azure subscriptions to enable azure defender and MMA for subscription [$($SubscriptionId)]..."
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

    # Check for valid regex patterns in a string and cast it into a boolean.
    switch -regex ($interactiveMode.Trim())
    {
        "^(1|true|yes|on|enabled)$" { [bool]$interactiveMode = $true }
        default { [bool]$interactiveMode = $false }
    }

    if(($SubscriptionId | Measure-Object).Count -gt 0)
    {
        Write-Host "============================================="; 
        if($interactiveMode)
        {
            $response = Read-Host "Do you want to continue with the Sub: [$($SubscriptionId)] ? (Y/N)"
            if($response -eq "N")
            {
                break;                
            }
        }        
        Write-Host "Starting with updating defender plans to Standard" -ForegroundColor Cyan
        
        # Get current pricing tier 
        $ascpricing = Get-AzSecurityPricing 
        if(($ascpricing | Measure-Object).Count -gt 0)
        {                        
            $ascpricing | Where-Object { $_.PricingTier -ne "Standard" } | ForEach-Object { Set-AzSecurityPricing -Name $_.Name -PricingTier Standard }
            Write-Host "Completed updating defender plans to Standard" -ForegroundColor Green
        }
        else
        {
            Write-Host "Not able to fetch the ASC Pricing details" -ForegroundColor Red
        }
        Write-Host "--------------------------------------------"; 
        # 2)  Set auto provisioning for extensions in Azure Security Center. This script will set a single subscription for the current context
        Write-Host "Starting to update auto-provision settings to On" -ForegroundColor Cyan
        Set-AzSecurityAutoProvisioningSetting -Name "default" -EnableAutoProvision | Out-Null
        Write-Host "Completed updating auto-provision settings to On" -ForegroundColor Green

        Write-Host "Completed updating for SubscriptionId [$($SubscriptionId)]" -ForegroundColor Green

        
        Write-Host "============================================="; 
    }
    else
    {
        Write-Host "No subscription(s) found." -ForegroundColor Red
    }
}