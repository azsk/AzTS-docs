<###
# Overview:
    This script is used to congigure WAF Policy on All endpoints of Front Doors in a Subscription.

# Control ID:
    Azure_FrontDoor_NetSec_Enable_WAF_Configuration_Trial

# Display Name:
    WAF Policy should be configured on for Endpoints in Front Door.

# Prerequisites:
    1. Contributor or higher privileges on the Front Doors in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of all Front Doors Endpoints in a Subscription that do not have WAF Configured
        3. Back up details of Front Door Endpoint(s) that are to be remediated.
        4. Configure the WAF Policy for all endpoints in the Frontdoors.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Frontdoors' Endpoint(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Remove Configured WAF Policy from all endpoints in all the Frontdoors.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to configure WAF Policy on All endpoints of Front Doors in a Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remove configured WAF Policy on All endpoints of Front Doors in a Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Front Doors in a Subscription that will be remediated:
           Configure-WAFPolicyForFrontDoorEndPoints -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To Configure WAF Policy for FrontEndpoint(s) of all Front Doors in a Subscription:
           Configure-WAFPolicyForFrontDoorEndPoints -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3.  To Configure WAF Policy for all Front Door FrontEndpoint(s) in a Subscription, from a previously taken snapshot:
           Configure-WAFPolicyForFrontDoorEndPoints -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ConfigureFrontDoorWAFPolicy\frontdoorEndpointsWithoutWAFPolicyConfigured.csv

        To know more about the options supported by the remediation command, execute:
        Get-Help Configure-WAFPolicyForFrontDoorEndPoints -Detailed

    To roll back:
        1. To remove configured WAF Policy for all Front Door  FrontEndpoint(s) in a Subscription, from a previously taken snapshot:
           Remove-WAFPolicyForFrontDoorEndPoints -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ConfigureFrontDoorWAFPolicy\RemediatedfrontDoorFrontEndpointsForConfigureWAFPolicy.csv
        
        To know more about the options supported by the roll back command, execute:
        Get-Help Remove-WAFPolicyForFrontDoorEndPoints -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.FrontDoor", "Az.Resources")

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

function Configure-WAFPolicyForFrontDoorEndPoints
{
    <#
        .SYNOPSIS
        Remediates 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration_Trial' Control.

        .DESCRIPTION
        Remediates 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration_Trial' Control.
        WAF Policy Mode must be configured for Front Door Endpoint(s).
        
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

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Enable-WAFPolicyForFrontDoors.

        .OUTPUTS
        None. Configure-WAFPolicyForFrontDoorEndPoints does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Configure-WAFPolicyForFrontDoorEndPoints -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Configure-WAFPolicyForFrontDoorEndPoints -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Configure-WAFPolicyForFrontDoorEndPoints -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202201011212\ConfigureFrontDoorWAFPolicy\frontdoorEndpointsWithoutWAFPolicyConfigured.csv

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

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "`n[Step 1 of 5] Preparing to configure WAF Policy for Front Door Frontendpoint(s) in Subscription: $($SubscriptionId)"
    Write-Host $([Constants]::SingleDashLine)
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..."
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
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
        Write-Host $([Constants]::DoubleDashLine)
        break
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    if(-not($AutoRemediation))
    {
        Write-Host "Subscription Name: $($context.Subscription.Name)"
        Write-Host "Subscription ID: $($context.Subscription.SubscriptionId)"
        Write-Host "Account Name: $($context.Account.Id)"
        Write-Host "Account Type: $($context.Account.Type)"
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "*** To configure WAF Policy for Front Door Endpoint(s) in a Subscription, Contributor or higher privileges on the Front Doors are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "`n[Step 2 of 5] Preparing to fetch all Front Doors..."
    Write-Host $([Constants]::SingleDashLine)

    $frontDoors = @()
    $frontDoorsCDN = @()
    $frontDoorFrontendPoints = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    # Control Id
    $controlIds = "Azure_FrontDoor_NetSec_Enable_WAF_Configuration_Trial"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
        Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
        }
        Write-Host "Fetching all Front Doors failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}

        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Front Door(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }  
        
        $validResources | ForEach-Object { 
            try
            {
                $name = $_.ResourceName
                $resourceGroupName = $_.ResourceGroupName
                # Get all Frontendpoint(s) for this Front Door.
                $frontendpoints = ( Get-AzFrontDoorFrontendEndpoint -ResourceGroupName $resourceGroupName -FrontDoorName $name -ErrorAction SilentlyContinue) 
                $frontDoorFrontendPoints += $frontendpoints  | Select-Object @{N='EndpointId';E={$_.Id}},
                                                                        @{N='FrontDoorName';E={$frontDoorName}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='EndPointName';E={$_.Name}},
                                                                        @{N='WAFPolicyName';E={$_.WebApplicationFirewallPolicyLink.Split('/')[8]}},
                                                                        @{N='WAFPolicyResourceGroup';E={$_.WebApplicationFirewallPolicyLink.Split('/')[4]}},
                                                                        @{N='IsWAFConfigured';E={
                                                                        if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                        { 
                                                                            $false
                                                                        }
                                                                        else
                                                                        {
                                                                            $true
                                                                        }
                                                                        }},
                                                                        @{N='IsPreventionMode';E={
                                                                        if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                        { 
                                                                            $false
                                                                        }
                                                                        else
                                                                        {
                                                                            $WAFPolicy = Get-AzFrontDoorWafPolicy -Name $_.WebApplicationFirewallPolicyLink.Split('/')[8]  -ResourceGroupName  $_.WebApplicationFirewallPolicyLink.Split('/')[4]  
                                                                            if($WAFPolicy.PolicyMode -eq 'Prevention')
                                                                            { 
                                                                                $true
                                                                            }
                                                                            else
                                                                            {
                                                                                $false
                                                                                
                                                                            }
                                                                        }
                                                                        }},
                                                                        @{N='IsWAFEnabled';E={
                                                                            if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                            { 
                                                                                $false
                                                                            }
                                                                            else
                                                                            {
                                                                                $WAFPolicy = Get-AzFrontDoorWafPolicy -Name $_.WebApplicationFirewallPolicyLink.Split('/')[8]  -ResourceGroupName  $_.WebApplicationFirewallPolicyLink.Split('/')[4]  
                                                                                
                                                                                if($WAFPolicy.PolicyEnabledState -eq 'Enabled')
                                                                                { 
                                                                                    $true
                                                                                }
                                                                                else
                                                                                {
                                                                                    $false
                                                                                }
                                                                            }
                                                                        }}
            }
            catch
            {
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Valid resource id(s) not found in input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }
    else
    { 
        # No file path provided as input to the script. Fetch all Front Doors in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "`nFetching all Front Doors in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            # Get all Front Doors in the Subscription
            $frontDoors = Get-AzFrontDoor  -ErrorAction Stop
            $totalfrontDoors = ($frontDoors | Measure-Object).Count
            
            if($totalfrontDoors -gt 0)
            {
                $frontDoors | ForEach-Object {
                    $frontDoor = $_
                    $frontDoorId = $_.Id
                    $resourceGroupName = $_.Id.Split('/')[4]
                    $frontDoorName = $_.Name

                    # Get all Frontendpoint(s) for this Front Door.
                    $frontendpoints = ( Get-AzFrontDoorFrontendEndpoint -ResourceGroupName $resourceGroupName -FrontDoorName $frontDoorName -ErrorAction SilentlyContinue) 
                    $frontDoorFrontendPoints += $frontendpoints  | Select-Object @{N='EndpointId';E={$_.Id}},
                                                                            @{N='FrontDoorName';E={$frontDoorName}},
                                                                            @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                            @{N='EndPointName';E={$_.Name}},
                                                                            @{N='WAFPolicyName';E={$_.WebApplicationFirewallPolicyLink.Split('/')[8]}},
                                                                            @{N='WAFPolicyResourceGroup';E={$_.WebApplicationFirewallPolicyLink.Split('/')[4]}},
                                                                            @{N='IsWAFConfigured';E={
                                                                            if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                            { 
                                                                                $false
                                                                            }
                                                                            else
                                                                            {
                                                                                $true
                                                                            }
                                                                            }},
                                                                            @{N='IsPreventionMode';E={
                                                                            if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                            { 
                                                                                $false
                                                                            }
                                                                            else
                                                                            {
                                                                                $WAFPolicy = Get-AzFrontDoorWafPolicy -Name $_.WebApplicationFirewallPolicyLink.Split('/')[8]  -ResourceGroupName  $_.WebApplicationFirewallPolicyLink.Split('/')[4]  
                                                                                if($WAFPolicy.PolicyMode -eq 'Prevention')
                                                                                { 
                                                                                    $true
                                                                                }
                                                                                else
                                                                                {
                                                                                    $false
                                                                                    
                                                                                }
                                                                            }
                                                                            }},
                                                                            @{N='IsWAFEnabled';E={
                                                                                if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                                { 
                                                                                    $false
                                                                                }
                                                                                else
                                                                                {
                                                                                    $WAFPolicy = Get-AzFrontDoorWafPolicy -Name $_.WebApplicationFirewallPolicyLink.Split('/')[8]  -ResourceGroupName  $_.WebApplicationFirewallPolicyLink.Split('/')[4]  
                                                                                    
                                                                                    if($WAFPolicy.PolicyEnabledState -eq 'Enabled')
                                                                                    { 
                                                                                        $true
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                        $false
                                                                                    }
                                                                                }
                                                                            }}
            
                }
            }
            
            
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                break
            }

            Write-Host "Fetching all Front Door Frontendpoint(s) from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $frontDoorFrontEndpointsDetails = Import-Csv -LiteralPath $FilePath
            $validfrontDoorEndpointsDetails = $frontDoorFrontEndpointsDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.EndPointName) }
            
            $validfrontDoorEndpointsDetails | ForEach-Object {
                $frontdoorFrontEndpointId = $_.EndpointId
                $resourceGroupName = $_.ResourceGroupName
                $frontDoorName = $_.FrontDoorName

                try
                {
                    $frontendpoints = ( Get-AzFrontDoorFrontendEndpoint -ResourceId $frontdoorFrontEndpointId -ErrorAction SilentlyContinue) 
                    $frontDoorFrontendPoints += $frontendpoints  | Select-Object @{N='EndpointId';E={$frontdoorFrontEndpointId}},
                                                                            @{N='FrontDoorName';E={$frontDoorName}},
                                                                            @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                            @{N='EndPointName';E={$_.Name}},
                                                                            @{N='WAFPolicyName';E={$_.WebApplicationFirewallPolicyLink.Split('/')[8]}},
                                                                            @{N='WAFPolicyResourceGroup';E={$_.WebApplicationFirewallPolicyLink.Split('/')[4]}},

                                                                            @{N='IsWAFConfigured';E={
                                                                            if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                            { 
                                                                                $false
                                                                            }
                                                                            else
                                                                            {
                                                                                $true
                                                                            }
                                                                            }},
                                                                            @{N='IsPreventionMode';E={
                                                                            if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                            { 
                                                                                $false
                                                                            }
                                                                            else
                                                                            {
                                                                                $WAFPolicy = Get-AzFrontDoorWafPolicy -Name $_.WebApplicationFirewallPolicyLink.Split('/')[8]  -ResourceGroupName  $_.WebApplicationFirewallPolicyLink.Split('/')[4]  
                                                                                if($WAFPolicy.PolicyMode -eq 'Prevention')
                                                                                { 
                                                                                    $true
                                                                                }
                                                                                else
                                                                                {
                                                                                    $false
                                                                                    
                                                                                }
                                                                            }
                                                                            }},
                                                                            @{N='IsWAFEnabled';E={
                                                                                if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                                { 
                                                                                    $false
                                                                                }
                                                                                else
                                                                                {
                                                                                    $WAFPolicy = Get-AzFrontDoorWafPolicy -Name $_.WebApplicationFirewallPolicyLink.Split('/')[8]  -ResourceGroupName  $_.WebApplicationFirewallPolicyLink.Split('/')[4]  
                                                                                    
                                                                                    if($WAFPolicy.PolicyEnabledState -eq 'Enabled')
                                                                                    { 
                                                                                        $true
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                        $false
                                                                                    }
                                                                                }
                                                                            }}
                }
                catch
                {
                    Write-Host "Error fetching Front Door FrontEndpoint:  ID - $($frontdoorFrontEndpointId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host $([Constants]::SingleDashLine)
                    Write-Host "Skipping this Front Door FrontEndpoint..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
        }
    }

    if(-not($AutoRemediation))
    {
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            $totalfrontDoors = ($frontDoors | Measure-Object).Count

            if ($totalfrontDoors -eq 0)
            {
                Write-Host "No Front Doors found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::DoubleDashLine)
                break
            }

            Write-Host "Found $($totalfrontDoors) Front Door(s)." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
  
   
    $totalfrontDoorFrontendPoints = ($frontDoorFrontendPoints | Measure-Object).Count

    if ($totalfrontDoorFrontendPoints -eq 0)
    {
        Write-Host "No Front Door Endpoint(s) found with WAF not Configured. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        break
    }
    
    Write-Host "Found $($totalfrontDoorFrontendPoints) Front Door Frontendpoint(s)" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Includes Front Door Endpoint(s) where WAF Policy is not configured
    $frontDoorEndpointsWithWAFPolicyNotConfigured = @()

    # Includes Front Door Endpoint(s) that were skipped during remediation. There were errors remediating them.
    $frontDoorEndpointsSkipped = @()
      
    Write-Host "`n[Step 3 of 5] Fetching Frontendpoint(s)..."
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Front Door Endpoint(s) for which WAF Policy is not  Configured..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $frontDoorFrontendPoints | ForEach-Object {
        $frontEndPoint = $_        
            if($_.IsWAFConfigured -eq $false)
            {
                $frontDoorEndpointsWithWAFPolicyNotConfigured += $frontEndPoint
            }
    }

    $totalfrontDoorEndpointsWithWAFPolicyNotConfigured = ($frontDoorEndpointsWithWAFPolicyNotConfigured | Measure-Object).Count
     
    if ($totalfrontDoorEndpointsWithWAFPolicyNotConfigured  -eq 0)
    {
        Write-Host "No Front Door Frontendpoints(s) found where WAF Policy is not configured.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	

        if($AutoRemediation -and ($frontDoorFrontendPoints |Measure-Object).Count -gt 0) 
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

    Write-Host "Found [$($totalfrontDoorEndpointsWithWAFPolicyNotConfigured)] Front Door Frontendpoints(s) found where WAF Policy is not configured ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    if(-not($AutoRemediation))
    { 
        Write-Host "`nFollowing Front Door Frontendpoints(s) are having wihtout WAF Policies configured:" -ForegroundColor $([Constants]::MessageType.Info)
        $colsProperty = @{Expression={$_.EndpointId};Label="Frontendpoint Id";Width=10;Alignment="left"},
                        @{Expression={$_.EndPointName};Label="Frontendpoint";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"},
                        @{Expression={$_.IsPreventionMode};Label="Is Prevention Mode on ";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFEnabled};Label="Is associated WAF Policy in Enabled State";Width=7;Alignment="left"}
        $frontDoorEndpointsWithWAFPolicyNotConfigured | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ConfigureFrontDoorWAFPolicy"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "`n[Step 4 of 5] Backing up Front Door Frontendpoint(s) details..."
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
    
        # Backing up Front Door Endpoints details.
        $backupFile = "$($backupFolderPath)\frontdoorEndpointsWithoutWAFPolicyConfigured.csv"
        $frontDoorEndpointsWithWAFPolicyNotConfigured | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Front Door Frontendpoint(s) details have been successful backed up to $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun)
    {
         # Here AutoRemediation switch is used as there is no need to take user input at BRS level if user has given consent to proceed with the remediation in AutoRemediation Script.
        if(-not $AutoRemediation)
        {
            Write-Host "WAF Policy will be configured for all Front Door Frontendpoint(s)." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            if (-not $Force)
            {
                Write-Host "Do you want to configure WAF Policy on Front Door Frontendpoint(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                $userInput = Read-Host -Prompt "(Y|N)"
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host " WAF Policy Mode will not Configured for any Front Door FrontEndpoint(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    break
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. WAF Policy will be configured for all Front Door Frontendoint(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
 
        Write-Host "`n[Step 5 of 5] Configuring WAF Policy for Front Door Endpoint(s)..."
        Write-Host $([Constants]::SingleDashLine)

        # To hold results from the remediation.
        $frontDoorFrontendpointsRemediated = @()

        Do
        {
             $wafPolicyName = Read-Host -Prompt "Enter WAF Policy Name"
             Write-Host $([Constants]::SingleDashLine)
             $policyResourceGroup = Read-Host -Prompt "Enter WAF Policy Resource Group"
             Write-Host $([Constants]::SingleDashLine)
             $policy = Get-AzFrontDoorWafPolicy -Name  $wafPolicyName  -ResourceGroupName $policyResourceGroup -ErrorAction SilentlyContinue

             if($policy -eq $null)
             {
                Write-Host "WAF Policy name or WAF Policy Resource Group Name is not correct. Please enter correct details."
                Write-Host $([Constants]::SingleDashLine)
             }

             if($policy -ne $null -and $policy.Sku -ne 'Classic_AzureFrontDoor')
             {
                Write-Host "WAF Policy is not of type Front door tier Classic . Please enter correct details."
                Write-Host $([Constants]::SingleDashLine)
             }
         }
         while($policy.Sku -ne 'Classic_AzureFrontDoor' -or $policy -eq $null)

   
        # Remidiate Controls by Configuring WAF Policy
        $frontDoorEndpointsWithWAFPolicyNotConfigured | ForEach-Object {
            $frontDoorEndPoint = $_
            $frontdoorName = $_.FrontDoorName;
            $resourceGroupName = $_.ResourceGroupName; 

            # Holds the list of Front Door Endpoints without WAF Policy Configure
            $frontendpointsSkipped = @()
            $frontendpointsSkippedStr = [String]::Empty
             
            try
            {   
                $wafpolicy = Update-AzFrontDoorWafPolicy -Name  $wafPolicyName  -ResourceGroupName $policyResourceGroup -Mode Prevention
                $frontDoor = Get-AzFrontDoor -ResourceGroupName $resourceGroupName ` -Name $frontdoorName
                 
                if ($frontDoor -eq $null)
                {
                    $frontendpointsSkipped += $frontDoorEndPoint

                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.FrontDoorName))
                    $logResource.Add("Reason", "Error while configuring WAF Policy for Frontdoor EndPoint")
                    $logSkippedResources += $logResource     
                }
                else
                {
                    $frontDoor[0].FrontendEndpoints[0].WebApplicationFirewallPolicyLink = $wafpolicy.Id
                    $setPolicy = Set-AzFrontDoor -InputObject $frontDoor[0]
                    $frontDoorFrontendpointsRemediated += $frontDoorEndPoint

                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.FrontDoorName))
                    $logRemediatedResources += $logResource
                }
            }
            catch
            {
                $frontendpointsSkipped += $frontDoorEndPoint
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.FrontDoorName))
                $logResource.Add("Reason", "Error while configuring WAF Policy for Frontdoor EndPoint")
                $logSkippedResources += $logResource     
            }
                 
            $frontendpointsSkippedStr = $frontendpointsSkipped -join ','
        }

        $totalRemediatedForWAFConfigured = ($frontDoorFrontendpointsRemediated | Measure-Object).Count
        Write-Host $([Constants]::SingleDashLine)

        if ($totalRemediatedForWAFConfigured -eq $totalfrontDoorEndpointsWithWAFPolicyNotConfigured)
        {
            Write-Host "WAF Policy Configured for all $($totalfrontDoorEndpointsWithWAFPolicyNotConfigured) Front Door Frontend Endpoint(s) ." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "WAF Policy Configured for  $totalRemediatedForWAFConfigured out of $($totalfrontDoorEndpointsWithWAFPolicyNotConfigured) Front Door Frontend Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        $colsProperty = @{Expression={$_.EndpointId};Label="Frontendpoint Id";Width=10;Alignment="left"},
                        @{Expression={$_.EndPointName};Label="Frontendpoint";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"},
                        @{Expression={$_.IsPreventionMode};Label="Is Prevention Mode on ";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFEnabled};Label="Is associated WAF Policy in Enabled State";Width=7;Alignment="left"}
                       
                       
        Write-Host "`nRemediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        
        if($AutoRemediation)
        {
            if ($($frontDoorFrontendpointsRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $frontDoorEndpointsRemediatedFile = "$($backupFolderPath)\RemediatedfrontDoorFrontEndpointsForConfigureWAFPolicy.csv"
                $frontDoorFrontendpointsRemediated | Export-CSV -Path $frontDoorEndpointsRemediatedFile -NoTypeInformation
                Write-Host "The information related to Front door Endpoints(s) where WAF Policy is successfully configured has been saved to [$($frontDoorEndpointsRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($frontendpointsSkipped | Measure-Object).Count -gt 0)
            {   
                # Write this to a file.
                $frontendpointsSkippedFile = "$($backupFolderPath)\SkippedfrontDoorFrontendpointsForConfigureWAFPolicy.csv"
                $frontendpointsSkipped | Export-CSV -Path $frontendpointsSkippedFile -NoTypeInformation
                Write-Host "The information related to Front door Endpoints(s) where WAF Policy is not configured has been saved to [$($frontendpointsSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            if ($($frontDoorFrontendpointsRemediated | Measure-Object).Count -gt 0)
            {
                $frontDoorFrontendpointsRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $frontDoorEndpointsRemediatedFile = "$($backupFolderPath)\v.csv"
                $frontDoorFrontendpointsRemediated | Export-CSV -Path $frontDoorEndpointsRemediatedFile -NoTypeInformation
                Write-Host "This information has been saved to $($frontDoorEndpointsRemediatedFile)"
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($frontendpointsSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "`nError performing remediation steps for the following Front Door Frontendpoint(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $frontendpointsSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                
                # Write this to a file.
                $frontendpointsSkippedFile = "$($backupFolderPath)\SkippedfrontDoorFrontendpointsForConfigureWAFPolicy.csv"
                $frontendpointsSkipped | Export-CSV -Path $frontendpointsSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to $($frontDoorsSkippedFile)"
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
                    $logControl.RollbackFile = $frontDoorEndpointsRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
         
        Write-Host "`n[Step 5 of 5] Configuring WAF Policy for Frontendpoint(s)..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "`n**Next steps:**" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to configure WAF Policy for all Front Door Endpoint(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Remove-WAFPolicyForFrontDoorEndPoints
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration_Trial' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration_Trial' Control.
        Removes Configured WAF Policies in all Front Doors in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-WAFPolicyForFrontDoors.

        .OUTPUTS
        None. Remove-WAFPolicyForFrontDoorEndPoints does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Remove-WAFPolicyForFrontDoorEndPoints -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ConfigureFrontDoorWAFPolicy\RemediatedfrontDoorFrontEndpointsForConfigureWAFPolicy.csv

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
    Write-Host "`n[Step 1 of 4] Preparing to switch Front Door Endpoint(s) in Subscription: $($SubscriptionId)"
    Write-Host $([Constants]::SingleDashLine)
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..."
            Write-Host $([Constants]::SingleDashLine)
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
        Write-Host $([Constants]::DoubleDashLine)
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

    Write-Host "*** To remove Configured WAF Policy for all Front Door Endpoint(s) in a Subscription, Contributor or higher privileges on the Front Doors are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "`n[Step 2 of 4] Preparing to fetch all Front Door Endpoints..."
    Write-Host $([Constants]::SingleDashLine)

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        break
    }

    Write-Host "Fetching all Front Door Endpoints from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

        $frontDoorFrontEndpointsDetails = Import-Csv -LiteralPath $FilePath
        $validfrontDoorEndpointsDetails = $frontDoorFrontEndpointsDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.EndPointName) }
        $frontDoorFrontendPoints = @()

        $validfrontDoorEndpointsDetails | ForEach-Object {
            $frontdoorFrontEndpointId = $_.EndpointId
            $resourceGroupName = $_.ResourceGroupName
            $frontDoorName = $_.FrontDoorName

            try
            {
                $frontendpoints = ( Get-AzFrontDoorFrontendEndpoint -ResourceId $frontdoorFrontEndpointId -ErrorAction SilentlyContinue) 
                $frontDoorFrontendPoints += $frontendpoints  | Select-Object @{N='EndpointId';E={$frontdoorFrontEndpointId}},
                                                                                @{N='FrontDoorName';E={$frontDoorName}},
                                                                                @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                @{N='EndPointName';E={$_.Name}},
                                                                                @{N='WAFPolicyName';E={$_.WebApplicationFirewallPolicyLink.Split('/')[8]}},
                                                                                @{N='WAFPolicyResourceGroup';E={$_.WebApplicationFirewallPolicyLink.Split('/')[4]}},

                                                                                @{N='IsWAFConfigured';E={
                                                                                if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                                { 
                                                                                    $false
                                                                                }
                                                                                else
                                                                                {
                                                                                    $true
                                                                                }
                                                                                }},
                                                                                @{N='IsPreventionMode';E={
                                                                                if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                                { 
                                                                                    $false
                                                                                }
                                                                                else
                                                                                {
                                                                                    $WAFPolicy = Get-AzFrontDoorWafPolicy -Name $_.WebApplicationFirewallPolicyLink.Split('/')[8]  -ResourceGroupName  $_.WebApplicationFirewallPolicyLink.Split('/')[4]  
                                                                                    if($WAFPolicy.PolicyMode -eq 'Prevention')
                                                                                    { 
                                                                                        $true
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                        $false
                                                                                        
                                                                                    }
                                                                                }
                                                                                }},
                                                                                @{N='IsWAFEnabled';E={
                                                                                    if($_.WebApplicationFirewallPolicyLink -eq $null)
                                                                                    { 
                                                                                        $false
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                        $WAFPolicy = Get-AzFrontDoorWafPolicy -Name $_.WebApplicationFirewallPolicyLink.Split('/')[8]  -ResourceGroupName  $_.WebApplicationFirewallPolicyLink.Split('/')[4]  
                                                                                        
                                                                                        if($WAFPolicy.PolicyEnabledState -eq 'Enabled')
                                                                                        { 
                                                                                            $true
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                            $false
                                                                                        }
                                                                                    }
                                                                                }}
            }
            catch
            {
                Write-Host "Error fetching Front Door FrontEndpoint:  ID - $($frontdoorFrontEndpointId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Skipping this Front Door FrontEndpoint..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        
    # Includes Front Door Endpoint(s) where WAF Policy is configured
    $frontDoorEndpointsWithWAFPolicyConfigured = @()
 
    Write-Host "`n[Step 3 of 4] Fetching Frontendpoint(s)..."
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Front Door Endpoint(s) for which WAF Policy is configured..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $frontDoorFrontendPoints | ForEach-Object {
        $frontEndPoint = $_        
            if($_.IsWAFConfigured -eq $true)
            {
                $frontDoorEndpointsWithWAFPolicyConfigured += $frontEndPoint
            }
    }

    $totalfrontDoorEndpointsWithWAFPolicyConfigured = ($frontDoorEndpointsWithWAFPolicyConfigured | Measure-Object).Count
     
    if ($totalfrontDoorEndpointsWithWAFPolicyConfigured  -eq 0)
    {
        Write-Host "No Front Door Frontendpoints(s) found where WAF Policy is configured.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    } 

    
    Write-Host "Found [$($totalfrontDoorEndpointsWithWAFPolicyConfigured)] Front Door Frontendpoints(s) found where WAF Policy is configured" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
    
     # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ConfigureFrontDoorWAFPolicy"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    } 
    
    if (-not $Force)
    {
        Write-Host "Do you want to remove configured WAF Policy for all Front Door Endpoint(s)?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "WAF Policy will not be removed for any Front Door Endpoint(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. WAF Policy will be removed for all the Front Door Endpoint(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

  
 
    Write-Host "`n[Step 3 of 4] Removing configured WAF Policy for Front Doors Frontendpoint(s) ..."
    Write-Host $([Constants]::SingleDashLine)

    # Includes Front Doors, to which, previously made changes were successfully rolled back.
    $frontDoorEndpointsRolledBack = @()

    # Includes Front Doors that were skipped during roll back. There were errors rolling back the changes made previously.
    $frontDoorEndpointsSkipped = @()

     # Roll back by removing configured WAF Policy
        $frontDoorEndpointsWithWAFPolicyConfigured | ForEach-Object {
            $frontDoorEndPoint = $_
            $wafPolicyName = $_.WAFPolicyName
            $wafPolicyRG = $_.WAFPolicyResourceGroup
            # Holds the list of Front Door Endpoints without WAF Policy 
            $frontendpointsSkippedStr = [String]::Empty
             
            try
            {  
                $frontendpointResource = Update-AzFrontDoorWafPolicy -Name  $wafPolicyName  -ResourceGroupName $wafPolicyRG -Mode Detection
                if ($frontendpointResource.PolicyMode -ne 'Detection')
                {
                    $frontDoorEndpointsSkipped += $frontDoorEndPoint
                }
                else
                {
                    $frontDoorEndPoint.IsPreventionMode = $false
                    $frontDoorEndpointsRolledBack += $frontDoorEndPoint
                }
            }
            catch
            {
                $frontDoorEndpointsSkipped += $frontDoorEndPoint
            }
       }

        $totalfrontDoorEndpointsRolledBack = ($frontDoorEndpointsRolledBack | Measure-Object).Count

        Write-Host $([Constants]::SingleDashLine)

        if ($totalfrontDoorEndpointsRolledBack -eq $totalfrontDoorEndpointsWithWAFPolicyConfigured)
        {
            Write-Host "WAF Policy removed for all $($totalfrontDoorEndpointsWithWAFPolicyConfigured) Front Door Frontend Endpoint(s) ." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "WAF Policy removed for  $totalfrontDoorEndpointsRolledBack out of $($totalfrontDoorEndpointsWithWAFPolicyConfigured) Front Door Frontend Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
     
        Write-Host "`nRollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $colsProperty = @{Expression={$_.EndpointId};Label="Endpoint Id";Width=10;Alignment="left"},
                        @{Expression={$_.EndPointName};Label="Endpoint";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"},
                        @{Expression={$_.IsPreventionMode};Label="Is Prevention Mode on ";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFEnabled};Label="Is associated WAF Policy in Enabled State";Width=7;Alignment="left"}
            

        if ($($frontDoorEndpointsRolledBack | Measure-Object).Count -gt 0)
        {
            $frontDoorEndpointsRolledBack | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $frontDoorEndpointsRolledBackFile = "$($backupFolderPath)\RolledBackfrontDoorEndpointsForWAFPolicyConfigured.csv"
            $frontDoorEndpointsRolledBack | Export-CSV -Path $frontDoorEndpointsRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to $($frontDoorEndpointsRolledBackFile)"
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($frontDoorEndpointsSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError removing configured WAF Policy for the following Front Door Endpoint(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $frontDoorEndpointsSkipped | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $frontDoorEndpointsSkippedFile = "$($backupFolderPath)\RollbackSkippedEndpointsForWAFPolicyConfigured.csv"
            $frontDoorEndpointsSkipped | Export-CSV -Path $frontDoorEndpointsSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($frontDoorEndpointsSkippedFile)"
            Write-Host $([Constants]::SingleDashLine)
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