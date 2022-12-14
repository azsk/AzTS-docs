<###
# Overview:
    This script is used to enable WAF Policy Prevention Mode on all endpoints of Front Doors in a Subscription.

# Control ID:
    Azure_FrontDoor_NetSec_Enable_WAF_Configuration

# Display Name:
    WAF Policy should be turned on for Endpoints in Front Door.

# Prerequisites:
    1. Contributor or higher privileges on the Front Doors in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of all Front Doors Endpoints in a Subscription that do not have WAF Policy in Prevention Mode
        3. Back up details of Front Door Endpoint(s) that are to be remediated.
        4. Set Policy mode to Prevention for all endpoints in the Frontdoors.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Frontdoors' Endpoint(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Revert Policy mode to Detection all endpoints in all the Frontdoors.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable WAF Policy on All endpoints of Front Doors in a Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable WAF Policy on All endpoints of Front Doors in a Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Front Doors in a Subscription that will be remediated:
           Enable-WAFPolicyPreventionModeForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To Switch WAF Policy Mode to Prvention for FrontEndpoint(s) of all Front Doors in a Subscription:
           Enable-WAFPolicyPreventionModeForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To Switch WAF Policy Mode to  Prvention for FrontEndpoint(s) of all Front Doors in a Subscription, from a previously taken snapshot:
           Enable-WAFPolicyPreventionModeForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetFrontDoorPolicyModeToPrevention\frontdoorEndpointsWithoutPolicyInPreventionMode.csv

        To know more about the options supported by the remediation command, execute:
        Get-Help Enable-WAFPolicyPreventionModeForFrontDoor -Detailed

    To roll back:
        1. To Switch WAF Policy Mode to Prvention for FrontEndpoint(s) all Front Doors in a Subscription, from a previously taken snapshot:
           Disable-WAFPolicyPreventionModeForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetFrontDoorPolicyModeToPrevention\RemediatedfrontDoorFrontEndpointsForPreventionMode.csv
        
        To know more about the options supported by the roll back command, execute:
        Get-Help Disable-WAFPolicyPreventionModeForFrontDoor -Detailed        
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

function Enable-WAFPolicyPreventionModeForFrontDoor
{
    <#
        .SYNOPSIS
        Remediates 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration' Control.

        .DESCRIPTION
        Remediates 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration' Control.
        WAF Policy Mode must be in Prevention Mode for Front Door Endpoint(s).
        
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
        None. You cannot pipe objects to Enable-WAFPolicyForFrontDoors.

        .OUTPUTS
        None. Enable-WAFPolicyForFrontDoors does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-WAFPolicyForFrontDoors -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-WAFPolicyForFrontDoors -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-WAFPolicyForFrontDoors -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202201011212\SetFrontDoorPolicyModeToPrevention\frontdoorEndpointsWithoutPolicyInPreventionMode.csv

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
    Write-Host "[Step 2 of 5] Preparing to fetch all Front Doors..."
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
                                                                        }} 
            }
            catch
            {
                Write-Host "Error fetching Front Door FrontEndpoint: ID - [$($frontdoorFrontEndpointId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
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
        Write-Host "No Front Door Endpoint(s) found with WAF not Configured. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        break
    }
    
    Write-Host "Found [$($totalfrontDoorFrontendPoints)] Front Door Frontendpoint(s)" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Includes Front Door Endpoint(s) where WAF Policy is not in Prevention Mode
    $frontDoorEndpointsWithWAFPolicyNotInPrevention = @()

    # Includes Front Door Endpoint(s) that were skipped during remediation. There were errors remediating them.
    $frontDoorEndpointsSkipped = @()

    
    
   
    Write-Host "[Step 3 of 5] Fetching Frontendpoint(s)..."
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Front Door Endpoint(s) for which WAF Policy is not in Prevention Mode..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $frontDoorFrontendPoints | ForEach-Object {
        $frontEndPoint = $_        
            if(($_.IsPreventionMode -eq $false) -and ($_.IsWAFConfigured -eq $true))
            {
                $frontDoorEndpointsWithWAFPolicyNotInPrevention += $frontEndPoint
            }
    }

    $totalfrontDoorEndpointsWithWAFPolicyNotInPrevention = ($frontDoorEndpointsWithWAFPolicyNotInPrevention | Measure-Object).Count
     
    if ($totalfrontDoorEndpointsWithWAFPolicyNotInPrevention  -eq 0)
    {
        Write-Host "No Front Door Frontendpoints(s) found where WAF Policy is not in Prevention Mode.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalfrontDoorEndpointsWithWAFPolicyNotInPrevention)] Front Door Frontendpoints(s) found where WAF Policy is not in Prevention Mode ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
     
    
    Write-Host "Following Front Door Frontendpoints(s) are having WAF Policies with Mode not in Prevention:" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)	
    $colsProperty = @{Expression={$_.EndpointId};Label="Frontendpoint Id";Width=10;Alignment="left"},
                        @{Expression={$_.EndPointName};Label="Frontendpoint";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"},
                        @{Expression={$_.IsPreventionMode};Label="Is Prevention Mode on ";Width=7;Alignment="left"}
                        
    $frontDoorEndpointsWithWAFPolicyNotInPrevention | Format-Table -Property $colsProperty -Wrap
    Write-Host $([Constants]::SingleDashLine)
    

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetFrontDoorPolicyModeToPrevention"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

 
    Write-Host "[Step 4 of 5] Backing up Front Door Frontendpoint(s) details..."
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
    
        # Backing up Front Door Endpoints details.
        $backupFile= "$($backupFolderPath)\frontdoorEndpointsWithoutPolicyInPreventionMode.csv"
        $frontDoorEndpointsWithWAFPolicyNotInPrevention | Export-CSV -Path $backupFile -NoTypeInformation
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
         
        Write-Host "WAF Policy mode will be switched to Prevention for all Front Door Frontendpoint(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        if (-not $Force)
        {
            Write-Host "Do you want to switch WAF Policy Mode to Prevention from Detection associated with Front Door Frontendpoint(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"
            Write-Host $([Constants]::SingleDashLine)
            if($userInput -ne "Y")
            {
                Write-Host " WAF Policy Mode will not be switched to Prevention from Detection for any Front Door FrontEndpoint(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::DoubleDashLine)
                break
            }
            else
            {
                Write-Host "WAF Policy State will be switched to Prevention Mode for all Front Door Frontend Endpoint(s)." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. WAF Policy will be configured & Mode will be switched to Prevention from Detection on all Front Door Frontendoint(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
        

 
        Write-Host "[Step 5 of 5] Switching Mode to Prevention from Detection for Front Door Endpoint(s)..."
        Write-Host $([Constants]::SingleDashLine)
        # To hold results from the remediation.
        $frontDoorFrontendpointsRemediated = @()
   

        # Remidiate Controls by Switching Policy Mode from Detection to Prevention
        $frontDoorEndpointsWithWAFPolicyNotInPrevention | ForEach-Object {
            $frontDoorEndPoint = $_
            $wafPolicyName = $_.WAFPolicyName
            $wafPolicyRG = $_.WAFPolicyResourceGroup
            # Holds the list of Front Door Endpoints without WAF Policy in Prevention Mode.
            $frontendpointsSkipped = @()
            $frontendpointsSkippedStr = [String]::Empty
             
            try
            {  
                $updatedPolicy = Update-AzFrontDoorWafPolicy -Name  $wafPolicyName  -ResourceGroupName $wafPolicyRG -Mode Prevention

                if ($updatedPolicy.PolicyMode -ne 'Prevention')
                {
                    $frontendpointsSkipped += $frontDoorEndPoint
                       
                }
                else
                {
                    $frontDoorEndPoint.IsPreventionMode = $true
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

        Write-Host $([Constants]::SingleDashLine)

        if ($totalRemediated -eq $totalfrontDoorEndpointsWithWAFPolicyNotInPrevention)
        {
            Write-Host "WAF Policy Mode changed to Prevention for all [$($totalfrontDoorEndpointsWithWAFPolicyNotInPrevention)] Front Door Frontend Endpoint(s) ." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "WAF Policy Mode changed to Prevention for [$totalRemediated] out of [$($totalfrontDoorEndpointsWithWAFPolicyNotInPrevention)] Front Door Frontend Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        $colsProperty = @{Expression={$_.EndpointId};Label="Frontendpoint Id";Width=10;Alignment="left"},
                        @{Expression={$_.EndPointName};Label="Frontendpoint";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"},
                        @{Expression={$_.IsPreventionMode};Label="Is WAF Policy in Prevention Mode?";Width=7;Alignment="left"} 
                        
        Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        
          
        if ($($frontDoorFrontendpointsRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Successfully set WAF Policy Mode to Prevention on the following Frontdoor Frontend Endpoint(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            $frontDoorFrontendpointsRemediated | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $frontDoorEndpointsRemediatedFile = "$($backupFolderPath)\RemediatedfrontDoorFrontEndpointsForPreventionMode.csv"
            $frontDoorFrontendpointsRemediated | Export-CSV -Path $frontDoorEndpointsRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to $($frontDoorEndpointsRemediatedFile)"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($frontendpointsSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error performing remediation steps for the following Front Door Frontendpoint(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $frontendpointsSkipped | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            
            # Write this to a file.
            $frontendpointsSkippedFile = "$($backupFolderPath)\SkippedfrontDoorFrontendpointsForPreventionMode.csv"
            $frontendpointsSkipped | Export-CSV -Path $frontendpointsSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($frontendpointsSkippedFile)"
            Write-Host $([Constants]::SingleDashLine)
        }
         
    }
    else
    {
 
        Write-Host "[Step 5 of 5] Switching WAF Policy mode to Prevention for Frontendpoint(s)..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to switch WAF Policy Mode to Prvention for all Front Door Endpoint(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Disable-WAFPolicyPreventionModeForFrontDoor
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration' Control.
        Switches the Policy Mode to Detection from Prevention for all WAF Policies in all Front Doors in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-WAFPolicyPreventionModeForFrontDoor.

        .OUTPUTS
        None. Disable-WAFPolicyPreventionModeForFrontDoor does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-WAFPolicyPreventionModeForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetFrontDoorPolicyModeToPrevention\RemediatedfrontDoorFrontEndpointsForPreventionMode.csv

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


    Write-Host "To Switich WAF Policy Mode to Detection for all Front Door Endpoint(s) in a Subscription, Contributor or higher privileges on the Front Doors are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Front Door Endpoints..."
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
                                                                            }} 
            }
            catch
            {
                Write-Host "Error fetching Front Door FrontEndpoint: ID - [$($frontdoorFrontEndpointId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this Front Door FrontEndpoint..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }


        
    # Includes Front Door Endpoint(s) where WAF Policy is in Prevention Mode
    $frontDoorEndpointsWithWAFPolicyInPrevention = @()

    
 
    Write-Host "[Step 3 of 4] Fetching Frontendpoint(s) where WAF Policy is not in Prevention Mode..."
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Front Door Endpoint(s) for which WAF Policy is not in Prevention Mode..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $frontDoorFrontendPoints | ForEach-Object {
        $frontEndPoint = $_        
            if(($_.IsPreventionMode -eq $true) -and ($_.IsWAFConfigured -eq $true))
            {
                $frontDoorEndpointsWithWAFPolicyInPrevention += $frontEndPoint
            }
    }

    $totalfrontDoorEndpointsWithWAFPolicyInPrevention = ($frontDoorEndpointsWithWAFPolicyInPrevention | Measure-Object).Count
     
    if ($totalfrontDoorEndpointsWithWAFPolicyInPrevention  -eq 0)
    {
        Write-Host "No Front Door Frontendpoints(s) found where WAF Policy is in Prevention Mode.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    } 

    
    Write-Host "Found [$($totalfrontDoorEndpointsWithWAFPolicyInPrevention)] Front Door Frontendpoints(s) found where WAF Policy is in Prevention Mode in file to Rollback." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
    
     # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetFrontDoorPolicyModeToPrevention"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    } 
    
    if (-not $Force)
    {
        Write-Host "Do you want to switch WAF Policy Mode to Detection for all Front Door Endpoint(s)?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "WAF Policy Mode will not be switched to Detection for any Front Door Endpoint(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. WAF Policy Mode will be switched to Detection for all the Front Door Endpoint(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

    
    Write-Host "[Step 4 of 4] Switching WAF Policy mode to Detection for Front Doors Frontendpoint(s) ..."
    Write-Host $([Constants]::SingleDashLine)
    # Includes Front Doors, to which, previously made changes were successfully rolled back.
    $frontDoorEndpointsRolledBack = @()

    # Includes Front Doors that were skipped during roll back. There were errors rolling back the changes made previously.
    $frontDoorEndpointsSkipped = @()

   
    # Roll back by switching Policy Mode from to Detection from Prevention
    $frontDoorEndpointsWithWAFPolicyInPrevention | ForEach-Object {
        $frontDoorEndPoint = $_
        $wafPolicyName = $_.WAFPolicyName
        $wafPolicyRG = $_.WAFPolicyResourceGroup
        # Holds the list of Front Door Endpoints without WAF Policy in Prevention Mode.
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

        if ($totalfrontDoorEndpointsRolledBack -eq $totalfrontDoorEndpointsWithWAFPolicyInPrevention)
        {
            Write-Host "WAF Policy Mode changed to Prevention for all [$($totalfrontDoorEndpointsWithWAFPolicyInPrevention)] Front Door Frontend Endpoint(s) ." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "WAF Policy Mode changed to Detection for  [$totalfrontDoorEndpointsRolledBack] out of [$($totalfrontDoorEndpointsWithWAFPolicyInPrevention)] Front Door Frontend Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Warning)
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
                        @{Expression={$_.IsPreventionMode};Label="Is WAF Policy in Prevention Mode?";Width=7;Alignment="left"} 
            

        if ($($frontDoorEndpointsRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Successfully rolled back WAF Policy Mode to Detection on the following Frontdoor Frontend Endpoint(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            $frontDoorEndpointsRolledBack | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)

            # Write this to a file.
            $frontDoorEndpointsRolledBackFile = "$($backupFolderPath)\RolledBackfrontDoorEndpointsForWAFPolicyMode.csv"
            $frontDoorEndpointsRolledBack | Export-CSV -Path $frontDoorEndpointsRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to $($frontDoorEndpointsRolledBackFile)"
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($frontDoorEndpointsSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error Switching WAF Policy Mode to Detection from Prevention for the following Front Door Endpoint(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $frontDoorEndpointsSkipped | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            
            # Write this to a file.
            $frontDoorEndpointsSkippedFile = "$($backupFolderPath)\RollbackSkippedEndpointsForWAFPolicyMode.csv"
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