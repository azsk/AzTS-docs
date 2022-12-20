<###
# Overview:
    This script is used to congigure WAF Policy on all endpoints of Front Doors in a Subscription.

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
        2. Get the list of all Front Doors Endpoints in a Subscription that do not have WAF Configured
        3. Back up details of Front Door Endpoint(s) that are to be remediated.
        4. Configure the WAF Policy for all endpoints in the Frontdoors.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to configure WAF Policy on all endpoints of Front Doors in a Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Front Doors in a Subscription that will be remediated:
           Configure-WAFPolicyForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To Configure WAF Policy for FrontEndpoint(s) of all Front Doors in a Subscription:
           Configure-WAFPolicyForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3.  To Configure WAF Policy for all Front Door FrontEndpoint(s) in a Subscription, from a previously taken snapshot:
           Configure-WAFPolicyForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ConfigureFrontDoorWAFPolicy\frontdoorEndpointsWithoutWAFPolicyConfigured.csv

        To know more about the options supported by the remediation command, execute:
        Get-Help Configure-WAFPolicyForFrontDoor -Detailed

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
 
function Configure-WAFPolicyForFrontDoor
{
    <#
        .SYNOPSIS
        Remediates 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration' Control.

        .DESCRIPTION
        Remediates 'Azure_FrontDoor_NetSec_Enable_WAF_Configuration' Control.
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

        .INPUTS
        None. You cannot pipe objects to Enable-WAFPolicyForFrontDoors.

        .OUTPUTS
        None. Configure-WAFPolicyForFrontDoor does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Configure-WAFPolicyForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Configure-WAFPolicyForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Configure-WAFPolicyForFrontDoor -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202201011212\ConfigureFrontDoorWAFPolicy\frontdoorEndpointsWithoutWAFPolicyConfigured.csv

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
    

    Write-Host "To configure WAF Policy for Front Door Endpoint(s) in a Subscription, Contributor or higher privileges on the Front Doors are required." -ForegroundColor $([Constants]::MessageType.Info)
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

    # Includes Front Door Endpoint(s) where WAF Policy is not configured
    $frontDoorEndpointsWithWAFPolicyNotConfigured = @()

    # Includes Front Door Endpoint(s) that were skipped during remediation. There were errors remediating them.
    $frontDoorEndpointsSkipped = @()
      
    Write-Host "[Step 3 of 5] Fetching Frontendpoint(s) with WAF not Configured"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Front Door Endpoint(s) for which WAF Policy is not Configured..." -ForegroundColor $([Constants]::MessageType.Info)
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
        return
    }

    Write-Host "Found [$($totalfrontDoorEndpointsWithWAFPolicyNotConfigured)] Front Door Frontendpoints(s) found where WAF Policy is not configured ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	


    Write-Host "Following Front Door Frontendpoints(s) are having wihtout WAF Policies configured:" -ForegroundColor $([Constants]::MessageType.Info)
    $colsProperty = @{Expression={$_.EndpointId};Label="Frontendpoint Id";Width=10;Alignment="left"},
                    @{Expression={$_.EndPointName};Label="Frontendpoint";Width=10;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                    @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                    @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                    @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                    @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"}
    $frontDoorEndpointsWithWAFPolicyNotConfigured | Format-Table -Property $colsProperty -Wrap
    Write-Host $([Constants]::SingleDashLine)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ConfigureFrontDoorWAFPolicy"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "[Step 4 of 5] Backing up Front Door Frontendpoint(s) details"
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
    
        # Backing up Front Door Endpoints details.
        $backupFile = "$($backupFolderPath)\frontdoorEndpointsWithoutWAFPolicyConfigured.csv"
        $frontDoorEndpointsWithWAFPolicyNotConfigured | Export-CSV -Path $backupFile -NoTypeInformation
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
        Write-Host "WAF Policy will be enabled for all Front Door Frontendpoint(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        if (-not $Force)
        {
            Write-Host "Do you want to configure WAF Policy on Front Door Frontendpoint(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            $userInput = Read-Host -Prompt "(Y|N)"
            Write-Host $([Constants]::SingleDashLine)
            if($userInput -ne "Y")
            {
                Write-Host "WAF Policy Mode will not Configured for any Front Door FrontEndpoint(s). Exiting." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::DoubleDashLine)
                break
            }
            else
            {
                Write-Host "WAF Policy Mode will be Configured for all Front Door FrontEndpoint(s)" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. WAF Policy will be configured for all Front Door Frontendoint(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
    
 
        Write-Host "[Step 5 of 5] Configuring WAF Policy for Front Door Endpoint(s)"
        Write-Host $([Constants]::SingleDashLine)

        # To hold results from the remediation.
        $frontDoorFrontendpointsRemediated = @()

        Write-Host "Configuring WAF Policy on FrontDoor Frontend Endpoint(s)"
        Write-Host $([Constants]::SingleDashLine)

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
                Do
                {
                    $wafPolicyName = Read-Host -Prompt "Enter WAF Policy Name for Endpoint: [$($_.EndPointName)] of Frontdoor [$($frontdoorName)] " 
                    Write-Host $([Constants]::SingleDashLine)
                    $policyResourceGroup = Read-Host -Prompt "Enter WAF Policy Resource Group Name for Endpoint: [$($_.EndPointName)] of Frontdoor [$($frontdoorName)] "

                    $wafPolicyName = $wafPolicyName.Trim()
                    $policyResourceGroup = $policyResourceGroup.Trim()

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

                $wafpolicy = Update-AzFrontDoorWafPolicy -Name  $wafPolicyName  -ResourceGroupName $policyResourceGroup -Mode Prevention
                $frontDoor = Get-AzFrontDoor -ResourceGroupName $resourceGroupName ` -Name $frontdoorName
                 
                if ($frontDoor -eq $null)
                {
                    $frontendpointsSkipped += $frontDoorEndPoint
                }
                else
                {
                    $totalEndpoints = ($frontDoor[0].FrontendEndpoints | Measure-Object).Count 
                    for($k=0; $k -lt $totalEndpoints; $k++)
                    {
                        if($_.EndpointName -eq $frontDoor[0].FrontendEndpoints[$k].Name)
                        {
                            $frontDoor[0].FrontendEndpoints[$k].WebApplicationFirewallPolicyLink = $wafpolicy.Id
                            $setPolicy = Set-AzFrontDoor -InputObject $frontDoor[0]
                            $frontDoorFrontendpointsRemediated += $frontDoorEndPoint
                            $frontDoorEndPoint.IsWAFConfigured = $true;
                            $frontDoorEndPoint.WAFPolicyName = $wafPolicyName;
                            $frontDoorEndPoint.WAFPolicyResourceGroup = $policyResourceGroup;
                        }
                    }                                    
                }
            }
            catch
            {
                $frontendpointsSkipped += $frontDoorEndPoint
            }
                 
            $frontendpointsSkippedStr = $frontendpointsSkipped -join ','
        }

        $totalRemediatedForWAFConfigured = ($frontDoorFrontendpointsRemediated | Measure-Object).Count
        Write-Host $([Constants]::SingleDashLine)

        if ($totalRemediatedForWAFConfigured -eq $totalfrontDoorEndpointsWithWAFPolicyNotConfigured)
        {
            Write-Host "WAF Policy Configured for all [$($totalfrontDoorEndpointsWithWAFPolicyNotConfigured)] Front Door Frontend Endpoint(s) ." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "WAF Policy Configured for  [$totalRemediatedForWAFConfigured] out of [$($totalfrontDoorEndpointsWithWAFPolicyNotConfigured)] Front Door Frontend Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        $colsProperty = @{Expression={$_.EndpointId};Label="Frontendpoint Id";Width=10;Alignment="left"},
                        @{Expression={$_.EndPointName};Label="Frontendpoint";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"}
                       
                       
        Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        
        if ($($frontDoorFrontendpointsRemediated | Measure-Object).Count -gt 0)
        {
                Write-Host "Successfully configured WAF Policy on the following Frontdoor Frontend Endpoint(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            $frontDoorFrontendpointsRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $frontDoorEndpointsRemediatedFile = "$($backupFolderPath)\RemediatedfrontDoorFrontEndpointsForConfigureWAFPolicy.csv"
            $frontDoorFrontendpointsRemediated | Export-CSV -Path $frontDoorEndpointsRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to $($frontDoorEndpointsRemediatedFile)"
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($frontendpointsSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error performing remediation steps for the following Front Door Frontendpoint(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $frontendpointsSkipped | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            
            # Write this to a file.
            $frontendpointsSkippedFile = "$($backupFolderPath)\SkippedfrontDoorFrontendpointsForConfigureWAFPolicy.csv"
            $frontendpointsSkipped | Export-CSV -Path $frontendpointsSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($frontDoorsSkippedFile)"
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
         
        Write-Host "[Step 5 of 5] Configuring WAF Policy for Frontendpoint(s)"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to configure WAF Policy for all Front Door Endpoint(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
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