<###
# Overview:
    This script is used to enable the WAF Policy configured on Front Door CDN(s) in a Subscription.

# Control ID:
    Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration

# Display Name:
   Front Door CDN should have Web Application Firewall configured

# Prerequisites:
    1. Contributor or higher privileges on the Front Door CDNs in a Subscription.
    2. Must be connected to Azure with same authenticated account with which have required access over Front door CDNs.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of all Front Door CDNs in a Subscription that do not have WAF Policy in Enable state.
        3. Back up details of Front Door CDNs that are to be remediated.
        4. Change the WAF policy state configured on endpoints domain(s) in the Front Door CDNs.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Security Policy(s) of Front Door CDNs in a Subscription, the changes made to which previously, are to be rolled back.
        3. Revert by changing the WAF Policies state configured on the Front Door CDNs.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable WAF Policy state configured on all endpoint domain(s) of Front Door CDNs in a Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to roll back the WAF Policy state Configured on all endpoint domain(s) of Front Door CDNs in a Subscription- we previously remediated. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Front Door CDNs in a Subscription that will be remediated:
           EnableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To set WAF Policy mode configured on Endpoint domain(s) of all Front Door CDNs in a Subscription:
           EnableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To set WAF Policy mode configured on Endpoint domain(s) of all Front Door CDNs in a Subscription, from a previously taken snapshot:
           EnableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableFrontDoorCDNWAFPolicy\FrontdoorCDNPolicyNotInEnableState.csv

        To know more about the options supported by the remediation command, execute:
        Get-Help EnableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN -Detailed

    To roll back:
        1. To revert WAF Policy mode configured on Endpoint domain(s) of all Front Door CDNs in a Subscription, from a previously taken snapshot:
           DisableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableFrontDoorCDNWAFPolicy\RemediatedfrontDoorCDNSecurityPolicy.csv
        
        To know more about the options supported by the roll back command, execute:
        Get-Help DisableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.FrontDoor", "Az.Cdn")

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

function EnableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN
{
    <#
        .SYNOPSIS
        Remediates 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.

        .DESCRIPTION
        Remediates 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.
        Set WAF Policy state to Enabled configured on Endpoint domain(s) in Front Door CDNs(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that needs to be remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back with mandatory user input prompts only.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .INPUTS
        None. You cannot pipe objects to EnableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN

        .OUTPUTS
        None. EnableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> EnableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202211190719\EnableFrontDoorCDNWAFPolicy\FrontdoorCDNPolicyNotInEnableState.csv

        .LINK
        None
    #>

    param (

        [String]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies a dry run of the actual remediation")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies a dry run of the actual remediation")]
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

    Write-Host "To change WAF Policy state for all Front Door CDNs(s) in a Subscription, Contributor or higher privileges role on the Front Door CDNs are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Front Door CDNs(s)."
    Write-Host $([Constants]::SingleDashLine)

     # list to store Front Door CDNs End Points 
    $frontDoors = @()
    $frontDoorSecurityPolicies = @()
    
     # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources=@()	

    # Control Id	
    $controlIds = "Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration"

    if ([String]::IsNullOrWhiteSpace($FilePath))	
    {
        Write-Host "Fetch all Front Door CDNs(s) in Subscription: [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

         # Get all Front Door CDNs(s) in a Subscription
        $frontDoors =  Get-AzFrontDoorCdnProfile -ErrorAction Stop

        # Seperating required properties
        $totalfrontDoors = ($frontDoors | Measure-Object).Count
        
        if($totalfrontDoors -gt 0)
        {
            $frontDoors | ForEach-Object {
                $frontDoor = $_
                $frontDoorId = $_.Id
                $resourceGroupName = $_.ResourceGroupName
                $frontDoorName = $_.Name
                    # Get All Security Policies which are currently configured on Azure Front Door CDN(s)
                    $SecurityPolicies = ( Get-AzFrontDoorCdnSecurityPolicy -ResourceGroupName $resourceGroupName -ProfileName $frontDoorName -ErrorAction SilentlyContinue) 
                    If($SecurityPolicies -ne $null)
                    {
                    $frontDoorSecurityPolicies +=  $SecurityPolicies | Select-Object @{N='FrontDoorId';E={$frontDoorId}},
                                                                                        @{N='FrontDoorName';E={$frontDoorName}},
                                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                        @{N='SecurityPolicyName';E={$_.Name}},
                                                                                        @{N='WAFPolicyName';E={$_.Parameter.WafPolicyId.Split('/')[8]}},
                                                                                        @{N='WAFPolicyRgName';E={$_.Parameter.WafPolicyId.Split('/')[4]}},
                                                                                        @{N='IsWAFPolicyEnabled';E=
                                                                                        {
                                                                                                $wafPolicyId = $_.Parameter.WafPolicyId
                                                                                                $policyRgName = $wafPolicyId.Split('/')[4]
                                                                                                $policyName = $wafPolicyId.Split('/')[8]
                                                                                                $wafPolicy = Get-AzFrontDoorWafPolicy -ResourceGroupName $policyRgName -Name $policyName
                                                                                                if($wafPolicy.PolicyEnabledState -ne "Enabled")
                                                                                                {
                                                                                                    $false
                                                                                                }
                                                                                        }
                                                                                        }
                    }
                    else{
                        Write-Host "Error fetching Security Policies for Front Door CDN(s) resource. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    }           
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

    Write-Host "Fetch all Front Door CDNs from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $frontDoorSecurityPolicyDetails = Import-Csv -LiteralPath $FilePath
    $validfrontDoorSecurityPolicyDetails = $frontDoorSecurityPolicyDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.SecurityPolicyName) }
    $validfrontDoorSecurityPolicyDetails| ForEach-Object {
            $securityPolicy = $_
            try
            { 
                $frontDoorProfile = Get-AzFrontDoorCdnProfile -ResourceGroupName $_.ResourceGroupName -ProfileName $_.FrontDoorName -ErrorAction SilentlyContinue
                if($frontDoorProfile -ne $null)
                {
                    $SecurityPolicies = ( Get-AzFrontDoorCdnSecurityPolicy -ResourceGroupName $_.ResourceGroupName -ProfileName $_.FrontDoorName -Name $_.SecurityPolicyName -ErrorAction SilentlyContinue)
                    if($SecurityPolicies -ne $null)
                    {
                    $frontDoorSecurityPolicies +=  $SecurityPolicies | Select-Object @{N='FrontDoorId';E={$securityPolicy.FrontDoorId}},
                                                                                        @{N='FrontDoorName';E={$securityPolicy.FrontDoorName}},
                                                                                        @{N='ResourceGroupName';E={$securityPolicy.ResourceGroupName}},
                                                                                        @{N='SecurityPolicyName';E={$_.Name}},
                                                                                        @{N='WAFPolicyName';E={$_.Parameter.WafPolicyId.Split('/')[8]}},
                                                                                        @{N='WAFPolicyRgName';E={$_.Parameter.WafPolicyId.Split('/')[4]}},                                                                                         
                                                                                        @{N='IsWAFPolicyEnabled';E=
                                                                                        {
                                                                                                $wafPolicyId = $_.Parameter.WafPolicyId
                                                                                                $policyRgName = $wafPolicyId.Split('/')[4]
                                                                                                $policyName = $wafPolicyId.Split('/')[8]
                                                                                                $wafPolicy = Get-AzFrontDoorWafPolicy -ResourceGroupName $policyRgName -Name $policyName
                                                                                                if($wafPolicy.PolicyEnabledState -ne "Enabled")
                                                                                                {
                                                                                                    $false
                                                                                                }
                                                                                        }
                                                                                        }
                        
                    }
                    else
                    {
                        Write-Host "Error fetching Security Policies of Front Door CDNs(s) resource. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    }
                }
                else
                {
                    Write-Host "Error fetching Front Door CDNs(s) resource. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                }   
            }
            catch
            {
                Write-Host "Error fetching Front Door CDNs/ Security Policies of Front Door CDNs(s) resource: Resource ID:  [$($SecurityPolicyName)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }            
        }
    }    

    $totalFrontDoorSecurityPolicies = ($frontDoorSecurityPolicies| Measure-Object).Count

    if ($totalFrontDoorSecurityPolicies -eq 0)
    {
        Write-Host "No Front Door CDNs Security Policies(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalFrontDoorSecurityPolicies)] Front Door CDNs Security Policy(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Front Door CDNs EndPoint(s) for which WAF is not configured.
    $SecurityPolicyWithoutWAFInEnabledState = @()

    Write-Host "Separating Security Policy(s) for which WAF Policy state is not Enabled..." -ForegroundColor $([Constants]::MessageType.Info)

    $frontDoorSecurityPolicies | ForEach-Object {
        $policy = $_        
            if($_.IsWAFPolicyEnabled -eq $false)
            {
                $SecurityPolicyWithoutWAFInEnabledState += $policy
            }
    }
   
    $totalSecurityPolicyWithoutWAFInEnabledState  = ($SecurityPolicyWithoutWAFInEnabledState | Measure-Object).Count

    if ($totalSecurityPolicyWithoutWAFInEnabledState  -eq 0)
    {
        Write-Host "No Security Policy of Front Door CDN(s) found where WAF policy state is not Enabled..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalSecurityPolicyWithoutWAFInEnabledState)] Security Policy of Front Door CDN(s) found where WAF policy state is not Enabled ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression={$_.FrontDoorId};Label="FrontDoorId";Width=30;Alignment="left"},
                    @{Expression={$_.FrontDoorName};Label="FrontDoorName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=100;Alignment="left"},
                    @{Expression={$_.SecurityPolicyName};Label="SecurityPolicyName";Width=100;Alignment="left"},
                    @{Expression={$_.IsWAFPolicyEnabled};Label="IsWAFPolicyEnabled";Width=100;Alignment="left"},
                    @{Expression={$_.WAFPolicyName};Label="WAFPolicyName";Width=100;Alignment="left"},
                    @{Expression={$_.WAFPolicyRgName};Label="WAFPolicyRgName";Width=100;Alignment="left"}
                    

    Write-Host "Frond Door CDN(s) Security Policy where WAF policy state is not Enabled are as follows:"
    $SecurityPolicyWithoutWAFInEnabledState | Format-Table -Property $colsProperty -Wrap
    Write-Host $([Constants]::SingleDashLine)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetPolicyStateToEnabled"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 3 of 4] Back up Security Policy of Front Door CDN(s) details..."
    Write-Host $([Constants]::SingleDashLine)

     if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        # Backing up EndPoint(s) details.
        $backupFile = "$($backupFolderPath)\FrontDoorCDNSecurityPolicyDetailsBackUp.csv"
        $SecurityPolicyWithoutWAFInEnabledState | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Security Policy(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Change the Policy state configured on Front Door CDNs(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)

        if (-not $Force)
        {
            Write-Host "Do you want to change the Policy state to enabled configured on Front Door CDNs(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "we are not changing  the Policy state to enabled configured on Front Door CDNs(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
        }

        # List for storing remediated Policies(s)
        $FrontDoorSecurityPolicyRemediated = @()

        # List for storing skipped Security Policy(s)
        $FrontDoorSecurityPolicySkipped = @()

        Write-Host "Changing the policy state configured on Front Door CDN(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        # Loop through the list of Security Policy(s) which needs to be remediated.
        $SecurityPolicyWithoutWAFInEnabledState | ForEach-Object {
            $securityPolicy = $_
            try
            {
                $policy = Get-AzFrontDoorWafPolicy -ResourceGroupName $securityPolicy.WAFPolicyRgName -Name $securityPolicy.WAFPolicyName
                  if($policy -ne $null)
                    {
                        $updatedpolicy = Update-AzFrontDoorWafPolicy -Name $securityPolicy.WAFPolicyName -ResourceGroupName $securityPolicy.WAFPolicyRgName -EnabledState Enabled
                        if($updatedpolicy.PolicyEnabledState -eq "Enabled")
                            {
                            $securityPolicy.IsWAFPolicyEnabled = $true
                            $FrontDoorSecurityPolicyRemediated += $securityPolicy
                            $logResource = @{}	
                            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                            $logResource.Add("ResourceName",($_.FrontDoorName))	
                            $logRemediatedResources += $logResource	
                            }
                       
                        else
                            {
                            $FrontDoorSecurityPolicySkipped += $securityPolicy
                            $logResource = @{}	
                            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                            $logResource.Add("ResourceName",($_.FrontDoorName))
                            $logResource.Add("Reason", "Error updating WAF Policy on : [$($securityPolicy)]")      
                            $logSkippedResources += $logResource
                            }
                   }
                    else
                    {
                        $FrontDoorSecurityPolicySkipped += $securityPolicy
                        $logResource = @{}	
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                        $logResource.Add("ResourceName",($_.FrontDoorName))
                        $logResource.Add("Reason", "Error fetching waf policy on : [$($securityPolicy)]")      
                        $logSkippedResources += $logResource	
                    }
            }
            catch
            {
                $FrontDoorSecurityPolicySkipped += $securityPolicy
                $logResource = @{}	
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                $logResource.Add("ResourceName",($_.FrontDoorName))	
                $logResource.Add("Reason","Error while updating WAF Policy")    	
                $logSkippedResources += $logResource	
                Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host $([Constants]::SingleDashLine)
            }
         }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        if ($($FrontDoorSecurityPolicyRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Successfully changed the policy state to Enabled of Front Door CDNs(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            $FrontDoorSecurityPolicyRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $FrontDoorSecurityPolicyRemediatedFile = "$($backupFolderPath)\RemediatedFrontDoorCDNPolicy.csv"
            $FrontDoorSecurityPolicyRemediated | Export-CSV -Path $FrontDoorSecurityPolicyRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($FrontDoorSecurityPolicyRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }          
        
        if ($($FrontDoorSecurityPolicySkipped | Measure-Object).Count -gt 0)
        {

            Write-Host "Error while changing WAF policy state Front Door CDNs(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            $FrontDoorSecurityPolicySkipped | Format-Table -Property $colsProperty -Wrap            
            # Write this to a file.
            $FrontDoorSecurityPolicySkippedFile = "$($backupFolderPath)\SkippedFrontDoorCDNPolicy.csv"
            $FrontDoorSecurityPolicySkipped | Export-CSV -Path $FrontDoorSecurityPolicySkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($FrontDoorSecurityPolicySkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
        
       
    }
    
    }

function DisableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN
{
    <#
    .SYNOPSIS
    Rolls back remediation done for 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.

    .DESCRIPTION
    Rolls back remediation done for 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.
    Remove WAF configuration from the Security Policy(s) in the Subscription. 
        
    .PARAMETER SubscriptionId
    Specifies the ID of the Subscription that was previously remediated.
        
    .Parameter PerformPreReqCheck
    Specifies validation of prerequisites for the command.
      
    .PARAMETER FilePath
    Specifies the path to the file to be used as input for the roll back.

    .INPUTS
    None. You cannot pipe objects to DisableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN

    .OUTPUTS
    None. DisableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN does not return anything that can be piped and used as an input to another command.

    .EXAMPLE
    PS> DisableWAFPolicyState-ConfiguredOnAzureFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ChangePolicyState\RemediatedFrontDoorCDNPolicy.csv

    .LINK
    None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

        [Switch]
        [Parameter(HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the path to the file to be used as input for the roll back")]
        $FilePath
    )

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 3] Validate and install the modules required to run the script and validate the user..."
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
        Write-Host "[Step 1 of 3] Validate the user..." 
        Write-Host $([Constants]::SingleDashLine)
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        # Setting up context for the current Subscription.
        $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    }

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    # Note about the required access required for remediation

    Write-Host "To change the WAF Policy state to Disabled configured on Front Door CDN(s) in a Subscription, Contributor or higher privileged role assignment on the Front Door CDNs(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Front Door CDN(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file:  [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Fetch all Security Policy of Front Door CDN(s) from" -NoNewline
    Write-Host " [$($FilePath)\...]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $FrontDoorSecurityPolicyDetails = Import-Csv -LiteralPath $FilePath

    $validFrontDoorSecurityPolicyDetails = $FrontDoorSecurityPolicyDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.FrontDoorName) -and ![String]::IsNullOrWhiteSpace($_.SecurityPolicyName)}

    $totalFrontDoorSecurityPolicy = $(($validFrontDoorSecurityPolicyDetails|Measure-Object).Count)

    if ($totalFrontDoorSecurityPolicy -eq 0)
    {
        Write-Host "No Security Policy of Front Door CDNs found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$(($validFrontDoorSecurityPolicyDetails| Measure-Object).Count)] Security Policy(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.FrontDoorId};Label="FrontDoorId";Width=30;Alignment="left"},
                    @{Expression={$_.FrontDoorName};Label="FrontDoorName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=100;Alignment="left"},
                    @{Expression={$_.SecurityPolicyName};Label="SecurityPolicyName";Width=100;Alignment="left"},
                    @{Expression={$_.IsWAFPolicyEnabled};Label="IsWAFPolicyEnabled";Width=100;Alignment="left"},
                    @{Expression={$_.WAFPolicyName};Label="WAFPolicyName";Width=100;Alignment="left"},
                    @{Expression={$_.WAFPolicyRgName};Label="WAFPolicyRgName";Width=100;Alignment="left"}

    $validFrontDoorSecurityPolicyDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetPolicyStateToDisabled"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Change Policy state to Disabled of all remediated Security Policy(s) of Front Door CDN(s)in the Subscription"
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        
    Write-Host "Do you want to change WAF Policy state to Disabled of Security Policy(s) mentioned in the file?"  -ForegroundColor $([Constants]::MessageType.Warning)
    $userInput = Read-Host -Prompt "(Y|N)"

    if($userInput -ne "Y")
    {
        Write-Host "WAF policy state will not be rolled back on Security Policy(s) of Front Door CDN(s) mentioned in the file. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }
        Write-Host "WAF policy state will be rolled back on Security Policy(s) of Front Door CDN(s) mentioned in the file." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. WAF policy state will be rolled back on Security Policy(s) of Front Door CDN(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Security Policy resource.
    $SecurityPolicyRolledBack = @()

    # List for storing skipped rolled back Security Policy resource.
    $SecurityPolicySkipped = @()

    $validFrontDoorSecurityPolicyDetails | ForEach-Object {
        $securityPolicy = $_
        try
        {   
            $policy = Get-AzFrontDoorWafPolicy -ResourceGroupName $securityPolicy.WAFPolicyRgName -Name $securityPolicy.WAFPolicyName
            if($policy -ne $null)
            {
                $updatedpolicy = Update-AzFrontDoorWafPolicy -Name $securityPolicy.WAFPolicyName -ResourceGroupName $securityPolicy.WAFPolicyRgName -EnabledState Disabled
                if($updatedpolicy.PolicyEnabledState -ne "Enabled")
                {
                    $securityPolicy.IsWAFPolicyEnabled = $false
                    $SecurityPolicyRolledBack += $securityPolicy
                }
                else
                {
                    $SecurityPolicySkipped += $securityPolicy
                }  
            }
            else
            {
                $SecurityPolicySkipped += $securityPolicy
            }            
        }
        catch
        {
            $SecurityPolicySkipped += $securityPolicy
        }
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
    
    if ($($SecurityPolicyRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "WAF Policy state has been changed on the following Front Door CDN(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
        $SecurityPolicyRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $SecurityPolicyRolledBackFile = "$($backupFolderPath)\RolledBackFrontDoorPolicies.csv"
        $SecurityPolicyRolledBack | Export-CSV -Path $SecurityPolicyRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($SecurityPolicyRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }

    if ($($SecurityPolicySkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error while changing WAF Policy state of Front Door CDN(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
        $SecurityPolicySkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

            
        # Write this to a file.
        $SecurityPolicySkippedFile = "$($backupFolderPath)\RollbackSkippedFrontDoorPolicies.csv"
        $SecurityPolicySkipped | Export-CSV -Path $SecurityPolicySkippedFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($SecurityPolicySkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }
}

# Defines commonly used constants.
class Constants
{
    # Defines commonly used colour codes, corresponding to the severity of the log...
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

        