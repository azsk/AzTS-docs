<###
# Overview:
    This script is used to enable state of WAF Policy configured on all endpoints of Front Doors in a Subscription.

# Control ID:
    Azure_FrontDoor_NetSec_Enable_WAF_Configuration

# Display Name:
     Front Door (Classic) should have Web Application Firewall configured

# Prerequisites:
    1. Contributor or higher privileges on the Front Doors in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of all Front Doors Endpoints in a Subscription that do not have WAF Policy Enabled
        3. Back up details of Front Door Endpoint(s) that are to be remediated.
        4. Set Policy State to enabled for all endpoints in the Front Doors.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Front Doors' Endpoint(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Revert Policy state to disabled for all endpoints in all the Front Doors.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable WAF Policy state on All endpoints of Front Doors in a Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable WAF Policy state on All endpoints of Front Doors in a Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Front Doors in a Subscription that will be remediated:
           Enable-WAFPolicyStateForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To set WAF Policy state to enabled for FrontEndpoint(s) of all Front Doors in a Subscription:
           Enable-WAFPolicyStateForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To Switch WAF Policy state to enabled for FrontEndpoint(s) of all Front Doors in a Subscription, from a previously taken snapshot:
           Enable-WAFPolicyStateForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetFrontDoorPolicyEnabled\frontdoorEndpointsWithoutPolicyInEnabledState.csv

        To know more about the options supported by the remediation command, execute:
        Get-Help Enable-WAFPolicyStateForFrontDoor -Detailed

    To roll back:
        1. To Switch WAF Policy state to disabled for FrontEndpoint(s) all Front Doors in a Subscription, from a previously taken snapshot:
           Disable-WAFPolicyStateForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetFrontDoorPolicyEnabled\RemediatedfrontDoors.csv
        
        To know more about the options supported by the roll back command, execute:
        Get-Help Disable-WAFPolicyStateForFrontDoor -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.FrontDoor")

    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)    
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "[$($_)] module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
}

function Enable-WAFPolicyStateForFrontDoor
{
    <#
        .SYNOPSIS
        Remediates 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration' Control.

        .DESCRIPTION
        Remediates 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration' Control.
        WAF Policy State must be Enabled for Front Door Endpoint(s).
        
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

        .INPUTS
        None. You cannot pipe objects to Enable-WAFPolicyStateForFrontDoor.

        .OUTPUTS
        None. Enable-WAFPolicyStateForFrontDoor does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-WAFPolicyStateForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-WAFPolicyStateForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-WAFPolicyStateForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202201011212\SetFrontDoorPolicyEnabled\frontdoorEndpointsWithoutPolicyInEnabledState.csv

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
        $FilePath
    )

   Write-Host $([Constants]::DoubleDashLine)
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 5] Validate and install the modules required to run the script and validate the user"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)            
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 5] Validate the user"
        Write-Host $([Constants]::SingleDashLine)
    }

    # Connect to Azure account
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

    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)
    

    Write-Host "To enable WAF Policy for Front Door Endpoint(s) in a Subscription, Contributor or higher privileges on the Front Doors are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 5] Preparing to fetch all Front Doors"
    Write-Host $([Constants]::SingleDashLine)


    $frontDoors = @()
    $frontDoorFrontendPoints = @()
 
    # Control Id
    $controlIds = "Azure_FrontDoor_NetSec_Enable_WAF_Configuration"

    # No file path provided as input to the script. Fetch all Front Doors in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Front Doors in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
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
                                                                        @{N='IsWAFPolicyStateEnabled';E={
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
            Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            break
        }

        Write-Host "Fetching all Front Door Frontendpoint(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
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
                                                                        @{N='IsWAFPolicyStateEnabled';E={
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
                Write-Host "Skipping this Front Door FrontEndpoint..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
    }
    
   
     
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        $totalfrontDoors = ($frontDoors | Measure-Object).Count

        if ($totalfrontDoors -eq 0)
        {
            Write-Host "No Front Doors found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            break
        }

        Write-Host "Found [$($totalfrontDoors)] Front Door(s)." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    
  
   
    $totalfrontDoorFrontendPoints = ($frontDoorFrontendPoints | Measure-Object).Count

    if ($totalfrontDoorFrontendPoints -eq 0)
    {
        Write-Host "No Front Door Endpoint(s) found with WAF Policy not in enabled state. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }
    
    Write-Host "Found [$($totalfrontDoorFrontendPoints)] Front Door Frontendpoint(s)" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Includes Front Door Endpoint(s) where WAF Policy is not in Enabled State
    $frontDoorEndpointsWithWAFPolicyNotInEnabledState = @()

    # Includes Front Door Endpoint(s) that were skipped during remediation. There were errors remediating them.
    $frontDoorEndpointsSkipped = @()
    
     
    Write-Host "[Step 3 of 5] Fetching Frontendpoint(s) where WAF Policy is not in Enabled State"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Front Door Endpoint(s) for which WAF Policy is not in Enabled State..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $frontDoorFrontendPoints | ForEach-Object {
        $frontEndPoint = $_        
            if(($_.IsWAFPolicyStateEnabled -eq $false) -and ($_.IsWAFConfigured -eq $true))
            {
                $frontDoorEndpointsWithWAFPolicyNotInEnabledState += $frontEndPoint
            }
    }

    $totalfrontDoorEndpointsWithWAFPolicyNotInEnabledState = ($frontDoorEndpointsWithWAFPolicyNotInEnabledState | Measure-Object).Count
     
    if ($frontDoorEndpointsWithWAFPolicyNotInEnabledState  -eq 0)
    {
        Write-Host "No Front Door Frontendpoints(s) found where WAF Policy is not in Enabled State.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalfrontDoorEndpointsWithWAFPolicyNotInEnabledState)] Front Door Frontendpoints(s) found where WAF Policy is not in Enabled State ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
     
    
    Write-Host "Following Front Door Frontendpoints(s) are having WAF Policies with Mode not in Enabled State:" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)	
    $colsProperty = @{Expression={$_.EndpointId};Label="Frontendpoint Id";Width=10;Alignment="left"},
                        @{Expression={$_.EndPointName};Label="Frontendpoint";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFPolicyStateEnabled};Label="Is WAF Policy in Enabled State?";Width=7;Alignment="left"}
    $frontDoorEndpointsWithWAFPolicyNotInEnabledState | Format-Table -Property $colsProperty -Wrap
    Write-Host $([Constants]::SingleDashLine)


    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetFrontDoorPolicyEnabled"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 4 of 5] Backing up Front Door Frontendpoint(s) details"
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
    
        # Backing up Front Door Endpoints details.
        $backupFile = "$($backupFolderPath)\frontdoorEndpointsWithoutPolicyInEnabledState.csv"
        $frontDoorEndpointsWithWAFPolicyNotInEnabledState | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Front Door Frontendpoint(s) details have been successful backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun)
    {
       
        Write-Host "WAF Policy state will be switched to Enabled for all Front Door Frontendpoint(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        if (-not $Force)
        {
            Write-Host "Do you want to switch state to Enabled for WAF Policies associated with Front Door Frontendpoint(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"
            Write-Host $([Constants]::SingleDashLine)
            if($userInput -ne "Y")
            {
                Write-Host "WAF Policy State will not be switched to Enabled for any Front Door FrontEndpoint(s). Exiting." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::DoubleDashLine)
                break
            }
            else
            {
                Write-Host "WAF Policy State will be switched to Enabled for all Front Door Frontend Endpoint(s)." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. WAF Policy State will be Enabled for all Front Door Frontendoint(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
         

        
        Write-Host "[Step 5 of 5] Switching WAF Policy State to Enabled for all Front Door Endpoint(s)"
        Write-Host $([Constants]::SingleDashLine)

        # To hold results from the remediation.
        $frontDoorFrontendpointsRemediated = @()
   

        # Remidiate Controls by Enabling WAF Policy State
        $frontDoorEndpointsWithWAFPolicyNotInEnabledState | ForEach-Object {
            $frontDoorEndPoint = $_
            $wafPolicyName = $_.WAFPolicyName
            $wafPolicyRG = $_.WAFPolicyResourceGroup
            # Holds the list of Front Door Endpoints without WAF Policy in Enabled State.
            $frontendpointsSkipped = @()
            $frontendpointsSkippedStr = [String]::Empty
             
            try
            {  
                $updatedPolicy = Update-AzFrontDoorWafPolicy -Name  $wafPolicyName  -ResourceGroupName $wafPolicyRG  -EnabledState Enabled

                if ($updatedPolicy.PolicyEnabledState -ne 'Enabled')
                {
                    $frontendpointsSkipped += $frontDoorEndPoint
                }
                else
                {
                    $frontDoorEndPoint.IsWAFPolicyStateEnabled = $true
                    $frontDoorFrontendpointsRemediated += $frontDoorEndPoint
                }
            }
            catch
            {
                $frontendpointsSkipped += $frontDoorEndPoint
            }
                 
            $frontendpointsSkippedStr = $frontendpointsSkipped -join ','
        }

        $totalRemediated = ($frontDoorFrontendpointsRemediated | Measure-Object).Count

        if ($totalRemediated -eq $totalfrontDoorEndpointsWithWAFPolicyNotInEnabledState)
        {
            Write-Host "WAF Policy State Enabled for all [$($totalfrontDoorEndpointsWithWAFPolicyNotInEnabledState)] Front Door Frontend Endpoint(s) ." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "WAF Policy State Enabled for [$totalRemediated] out of [$($totalfrontDoorEndpointsWithWAFPolicyNotInEnabledState)] Front Door Frontend Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        $colsProperty = @{Expression={$_.EndpointId};Label="Frontendpoint Id";Width=10;Alignment="left"},
                        @{Expression={$_.EndPointName};Label="Frontendpoint";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFPolicyStateEnabled};Label="Is WAF Policy in Enabled State?";Width=7;Alignment="left"}
                       
                      
        
        Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

    
        if($($frontDoorFrontendpointsRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Successfully Enabled WAF Policy on the following Frontdoor Frontend Endpoint(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            $frontDoorFrontendpointsRemediated | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $frontDoorEndpointsRemediatedFile = "$($backupFolderPath)\RemediatedfrontDoorFrontEndpointsForEnabledState.csv"
            $frontDoorFrontendpointsRemediated | Export-CSV -Path $frontDoorEndpointsRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to $($frontDoorEndpointsRemediatedFile)"
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($frontendpointsSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error performing remediation steps for the following Front Door Frontendpoint(s):" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            $frontendpointsSkipped | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $frontendpointsSkippedFile = "$($backupFolderPath)\SkippedfrontDoorFrontendpointsForEnabledState.csv"
            $frontendpointsSkipped | Export-CSV -Path $frontendpointsSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($frontendpointsSkippedFile)"
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
        
        Write-Host "[Step 5 of 5] Enabling WAF Policy State for Frontendpoint(s)"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to Enable WAF Policy State for all Front Door Endpoint(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Disable-WAFPolicyStateForFrontDoor
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration' Control.
        Enables all WAF Policies States in all Front Door Frontendpoint(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-WAFPolicyStateForFrontDoor.

        .OUTPUTS
        None. Disable-WAFPolicyStateForFrontDoor does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-WAFPolicyStateForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetFrontDoorPolicyEnabled\RemediatedfrontDoorFrontEndpointsForEnabledState.csv

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
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 4] Validate and install the modules required to run the script and validate the user"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites"	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)	
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 4] Validate the user" 
        Write-Host $([Constants]::SingleDashLine)
    }  

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        
        Write-Host "Connecting to Azure account..."
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        # Setting up context for the current Subscription.
        $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    }

    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    # Note about the required access required for remediation

    Write-Host "To set WAF Policy State to disabled for all Front Door Endpoint(s) in a Subscription, Contributor or higher privileges on the Front Doors are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Front Door Endpoints"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        break
    }

    Write-Host "Fetching all Front Door Endpoints from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
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
                                                                            @{N='IsWAFPolicyStateEnabled';E={
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
            Write-Host "Error fetching Front Door FrontEndpoint:  ID - [$($frontdoorFrontEndpointId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this Front Door FrontEndpoint..." -ForegroundColor $([Constants]::MessageType.Warning)
        }
    }


        
    # Includes Front Door Endpoint(s) where WAF Policy is in Enabled State
    $frontDoorEndpointsWithWAFPolicyInEnabledState = @()

    Write-Host "[Step 3 of 4] Fetching Frontendpoint(s)"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Front Door Endpoint(s) for which WAF Policy is in Enabled State..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $frontDoorFrontendPoints | ForEach-Object {
        $frontEndPoint = $_        
            if(($_.IsWAFPolicyStateEnabled -eq $true) -and ($_.IsWAFConfigured -eq $true))
            {
                $frontDoorEndpointsWithWAFPolicyInEnabledState += $frontEndPoint
            }
    }

    $totalfrontDoorEndpointsWithWAFPolicyInEnabledState = ($frontDoorEndpointsWithWAFPolicyInEnabledState | Measure-Object).Count
     
    if ($totalfrontDoorEndpointsWithWAFPolicyInEnabledState  -eq 0)
    {
        Write-Host "No Front Door Frontendpoints(s) found where WAF Policy is in Enabled State.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    } 

    
    Write-Host "Found [$($totalfrontDoorEndpointsWithWAFPolicyInEnabledState)] Front Door Frontendpoints(s) found where WAF Policy is in Enabled State in file to Rollback." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetFrontDoorPolicyEnabled"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    } 
    
    if (-not $Force)
    {
        Write-Host "Do you want to set WAF Policy State to be Disabled for all Front Door Endpoint(s)?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "WAF Policy State will not be Disabled for any Front Door Endpoint(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            break
        }
        else
        {
            Write-Host "WAF Policy State will be Disabled for all Front Door Endpoint(s)." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. WAF Policy State will be Disabled for all the Front Door Endpoint(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

  

    
 
    Write-Host "[Step 4 of 4] Disabling WAF Policy State for Front Doors Frontendpoint(s)"
    Write-Host $([Constants]::SingleDashLine)
    # Includes Front Doors, to which, previously made changes were successfully rolled back.
    $frontDoorEndpointsRolledBack = @()

    # Includes Front Doors that were skipped during roll back. There were errors rolling back the changes made previously.
    $frontDoorEndpointsSkipped = @()

   
    # Roll back by switching Policy State to Disabled
    $frontDoorEndpointsWithWAFPolicyInEnabledState | ForEach-Object {
        $frontDoorEndPoint = $_
        $wafPolicyName = $_.WAFPolicyName
        $wafPolicyRG = $_.WAFPolicyResourceGroup
        # Holds the list of Front Door Endpoints without WAF Policy in Enabled State.
        $frontendpointsSkippedStr = [String]::Empty
            
        try
        {  

            $frontendpointResource = Update-AzFrontDoorWafPolicy -Name  $wafPolicyName  -ResourceGroupName $wafPolicyRG -EnabledState Disabled
            if ($frontendpointResource.PolicyEnabledState -ne 'Disabled')
            {
                $frontDoorEndpointsSkipped += $frontDoorEndPoint     
            }
            else
            {
                $frontDoorEndPoint.IsWAFPolicyStateEnabled = $false
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

    if ($totalfrontDoorEndpointsRolledBack -eq $totalfrontDoorEndpointsWithWAFPolicyInEnabledState)
    {
        Write-Host "WAF Policy State Disabled for all [$($totalfrontDoorEndpointsWithWAFPolicyInEnabledState)] Front Door Frontend Endpoint(s) ." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "WAF Policy State Disabled for  [$totalfrontDoorEndpointsRolledBack] out of [$($totalfrontDoorEndpointsWithWAFPolicyInEnabledState)] Front Door Frontend Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
        
    Write-Host "Rollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $colsProperty = @{Expression={$_.EndpointId};Label="Frontendpoint Id";Width=10;Alignment="left"},
                    @{Expression={$_.EndPointName};Label="Frontendpoint";Width=10;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                    @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                    @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                    @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                    @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"},
                    @{Expression={$_.IsWAFPolicyStateEnabled};Label="Is WAF Policy in Enabled State?";Width=7;Alignment="left"}
        

    if ($($frontDoorEndpointsRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "Successfully disabled WAF Policy on the following Frontdoor Frontend Endpoint(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        $frontDoorEndpointsRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $frontDoorEndpointsRolledBackFile = "$($backupFolderPath)\RolledBackfrontDoorEndpointsForWAFPolicyState.csv"
        $frontDoorEndpointsRolledBack | Export-CSV -Path $frontDoorEndpointsRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to $($frontDoorEndpointsRolledBackFile)"
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($($frontDoorEndpointsSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error Disabling Frontdoor Endpoints for the following Front Door Endpoint(s):" -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::SingleDashLine)
        $frontDoorEndpointsSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
        
        # Write this to a file.
        $frontDoorEndpointsSkippedFile = "$($backupFolderPath)\RollbackSkippedEndpointsForWAFPolicyState.csv"
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