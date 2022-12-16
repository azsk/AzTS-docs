<###
# Overview:
    This script is used to configure WAF Policy on all endpoints of Front Door CDN(s) in a Subscription.

# Control ID:
    Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration

# Display Name:
    Front Door should have Web Application Firewall configured

# Prerequisites:
    1. Contributor or higher privileges on the Front Door CDNs in a Subscription.
    2. Must be connected to Azure with same authenticated account with which have required access over Front door CDNs.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of all Front Door CDNs Endpoints in a Subscription that do not have WAF Policy Configured
        3. Back up details of Front Door CDN Endpoint(s) that are to be remediated.
        4. Configure WAF for all endpoints in the Front Door.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Front Door' Endpoint(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Revert by removing WAF Policies from endpoints in all the Front Door.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to configure WAF Policy on all endpoints of Front Door CDNs in a Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to roll back the WAF Policy Configuration on all endpoints of Front Door CDNs in a Subscription- we previously remediated. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Front Door CDNs in a Subscription that will be remediated:
           Configure-WAFConfigurationOnFrontDoorEndpoint -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To configure WAF Policy for Endpoint(s) of all Front Door CDNs in a Subscription:
           Configure-WAFConfigurationOnFrontDoorEndpoint -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To configure WAF Policy for Endpoint(s) of all Front Door CDNs in a Subscription, from a previously taken snapshot:
           Configure-WAFConfigurationOnFrontDoorEndpoint -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ConfigureFrontDoorCDNWAFPolicy\frontdoorCDNEndpointsWithoutWAFPolicyConfigured.csv

        To know more about the options supported by the remediation command, execute:
        Get-Help Configure-WAFConfigurationOnFrontDoorEndpoint -Detailed

    To roll back:
        1. To remove configured WAF Policy Mode for Endpoint(s) all Front Door CDNs in a Subscription, from a previously taken snapshot:
           Remove-WAFConfigurationOnFrontDoorEndpoint -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ConfigureFrontDoorCDNWAFPolicy\RemediatedfrontDoorCDNEndpointsForConfigureWAFPolicy.csv
        
        To know more about the options supported by the roll back command, execute:
        Get-Help Remove-WAFConfigurationOnFrontDoorEndpoint -Detailed        
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

function Configure-WAFConfigurationOnFrontDoorEndpoint
{
    <#
        .SYNOPSIS
        Remediates 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.

        .DESCRIPTION
        Remediates 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.
        Configure WAF Policy for Endpoint(s) in Front Door(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that needs to be remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back with mandatory user input prompts only.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .INPUTS
        None. You cannot pipe objects to Configure-WAFConfigurationOnFrontDoorEndpoint.

        .OUTPUTS
        None. Configure-WAFConfigurationOnFrontDoorEndpoint does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Configure-WAFConfigurationOnFrontDoorEndpoint -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202211190719\ConfigureFrontDoorCDNWAFPolicy\FrontDoorEndpointWithWAFConfiguration.csv

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

    Write-Host "To Configured WAF Policy for all Front Door CDN Endpoint(s) in a Subscription, Contributor or higher privileges on the Front Door CDNs are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Front Door CDN Endpoints"
    Write-Host $([Constants]::SingleDashLine)

     # list to store Front Door End Points 
    $frontDoors = @()
    $frontDoorEndPoints = @()
    
     # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources=@()	

    # Control Id	
    $controlIds = "Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration"

    if ([String]::IsNullOrWhiteSpace($FilePath))	
    {
        Write-Host "Fetch all Front Door(s) in Subscription: [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

         # Get all Front Door(s) in a Subscription
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

                # Get all Frontendpoint(s) for this Front Door.
                $frontendpoints = ( Get-AzFrontDoorCdnEndpoint -ResourceGroupName $resourceGroupName -ProfileName $frontDoorName -ErrorAction SilentlyContinue) 
                if($frontendpoints -ne $null)
                {
                    $SecurityPolicies = ( Get-AzFrontDoorCdnSecurityPolicy -ResourceGroupName $resourceGroupName -ProfileName $frontDoorName -ErrorAction SilentlyContinue) 
                    if($SecurityPolicies -ne $null)
                    {
                        $frontDoorEndPoints += $frontendpoints  | Select-Object @{N='EndpointId';E={$_.Id}},
                                                                        @{N='FrontDoorName';E={$frontDoorName}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='EndPointName';E={$_.Name}},
                                                                        @{N='SecurityPolicyName';E="NA"},
                                                                        @{N='IsWAFConfigured';E={
                                                                        foreach($policy in $SecurityPolicies)
                                                                        {
                                                                        foreach($association in $policy.Parameter.Association)
                                                                        {
                                                                        if($association.Domain.Id.Split('/')[10] -eq $_.Name)
                                                                        {
                                                                        if($policy.Parameter.WafPolicyId -ne $null)
                                                                        {
                                                                            $true
                                                                        }
                                                                        else
                                                                        {
                                                                            $false
                                                                        }
                                                                        }    
                                                                        }
                                                                        }
                                                                        }
                                                                        }
                    }
                    else
                    {
                        Write-Host "Error fetching Security Policies of Front Door(s) resource. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    }
                    
                }
                else{
                    Write-Host "Error fetching End points of Front Door(s) resource. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                }
                                                                                    
        
            }
        }
    }
    else{

    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        break
    }

    Write-Host "Fetch all Front Door CDN Endpoints from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $frontDoorEndpointsDetails = Import-Csv -LiteralPath $FilePath
    $validfrontDoorEndpointsDetails = $frontDoorEndpointsDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.EndPointName) }

    $validfrontDoorEndpointsDetails| ForEach-Object {
            $resourceId = $_.EndpointId

            try
            {   
                $frontendpoints = ( Get-AzFrontDoorCdnEndpoint -ResourceGroupName $_.ResourceGroupName -ProfileName $_.FrontDoorName -ErrorAction SilentlyContinue) 
                $SecurityPolicies = ( Get-AzFrontDoorCdnSecurityPolicy -ResourceGroupName $_.ResourceGroupName -ProfileName $_.FrontDoorName -ErrorAction SilentlyContinue) 
                $frontDoorEndPoints += $frontendpoints  | Select-Object @{N='EndpointId';E={$_.Id}},
                                                                        @{N='FrontDoorName';E={$_.Id.Split('/')[8]}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='EndPointName';E={$_.Name}},
                                                                        @{N='SecurityPolicyName';E="NA"},
                                                                        @{N='IsWAFConfigured';E={
                                                                        foreach($policy in $SecurityPolicies)
                                                                        {
                                                                        foreach($association in $policy.Parameter.Association)
                                                                        {
                                                                        if($association.Domain.Id.Split('/')[10] -eq $_.Name )
                                                                        {
                                                                        if($policy.Parameter.WafPolicyId -ne $null)
                                                                        {
                                                                            $true
                                                                        }
                                                                        else
                                                                        {
                                                                            $false
                                                                        }
                                                                        }    
                                                                        }
                                                                        }
                                                                        }
                                                                        }  
            }
            catch
            {
                Write-Host "Error fetching End points of Front Door(s) resource: Resource ID:  [$($EndpointId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }            
        }
        }
    

    $totalFrontDoorEndPoints = ($frontDoorEndPoints| Measure-Object).Count

    if ($totalFrontDoorEndPoints -eq 0)
    {
        Write-Host "No Front Door EndPoint(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalFrontDoorEndPoints)] Front Door End Point(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Front Door EndPoint(s) for which WAF is not configured.
    $EndPointsWithoutWAFConfigured = @()

    Write-Host "Separating Endpoint(s) for which WAF is not configured..." -ForegroundColor $([Constants]::MessageType.Info)

    $frontDoorEndPoints | ForEach-Object {
        $EndPoint = $_        
            if($_.IsWAFConfigured -ne $true)
            {
                $_.IsWAFConfigured = $false
                $EndPointsWithoutWAFConfigured += $EndPoint
            }
    }
   
    $totalEndPointsWithoutWAFConfigured  = ($EndPointsWithoutWAFConfigured | Measure-Object).Count

    if ($totalEndPointsWithoutWAFConfigured  -eq 0)
    {
        Write-Host "No EndPoint(s) found with where WAF is not configured.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalEndPointsWithoutWAFConfigured)] EndPoint(s) for which WAF is not configured ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression={$_.EndpointId};Label="EndpointId";Width=30;Alignment="left"},
                    @{Expression={$_.FrontDoorName};Label="FrontDoorName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=100;Alignment="left"},
                    @{Expression={$_.EndPointName};Label="EndPointName";Width=100;Alignment="left"}
                    @{Expression={$_.SecurityPolicyName};Label="SecurityPolicyName";Width=100;Alignment="left"}
                    @{Expression={$_.IsWAFConfigured};Label="IsWAFConfigured";Width=100;Alignment="left"}

    Write-Host "Endpoint(s) without WAF configuration are as follows:"
    $EndPointsWithoutWAFConfigured | Format-Table -Property $colsProperty -Wrap
    Write-Host $([Constants]::SingleDashLine)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ConfiguredWAFOnEndPoint"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 3 of 4] Back up Endpoint(s) details..."
    Write-Host $([Constants]::SingleDashLine)

     if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        # Backing up EndPoint(s) details.
        $backupFile = "$($backupFolderPath)\FrontDoorEndPointDetailsBackUp.csv"
        $EndPointsWithoutWAFConfigured | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "EndPoint(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
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
        Write-Host "[Step 4 of 4] Configure the WAF on Endpoint(s) of Front Door(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)

        if (-not $Force)
        {
            Write-Host "Do you want to configure WAF on the Endpoint(s) of Front Door(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "we are starting the procedure to configure the WAF on the Endpoint(s) of Front Door(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
        }

        # List for storing remediated Endpoint(s)
        $EndpointRemediated = @()

        # List for storing skipped Subnet(s)
        $EndpointSkipped = @()

        Write-Host "Enabling the WAF on Endpoint(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of Endpoint(s) which needs to be remediated.
        $EndPointsWithoutWAFConfigured | ForEach-Object {
            $endpoint = $_
            try
            {                
              Write-Host "To Start configuring the WAF on the Endpoint(s), Please enter the WAF Policy Details for Front Door" + $_.FrontDoorName -ForegroundColor $([Constants]::MessageType.Info)
              $policyName = Read-Host -Prompt "Please enter name of Web Application Firewall Policy Name which is not assigned to any other end point of Front door " 
              $policyRGName = Read-Host -Prompt "Please enter Resource Group of Web Application Firewall Policy"
              if($policyName -ne $null -and $policyRGName -ne $null)
                {
                  $policy = $policy = Get-AzFrontDoorWafPolicy -ResourceGroupName $policyRGName -Name $policyName
                  if($policy -ne $null)
                    {
                        $securityPolicyName = $_.EndPointName + "SecurityPolicy"
                        $endpointDetails = Get-AzFrontDoorCdnEndpoint -ResourceGroupName $_.ResourceGroupName -ProfileName $_.FrontDoorName -EndpointName $_.EndPointName
                        $updateAssociation = New-AzFrontDoorCdnSecurityPolicyWebApplicationFirewallAssociationObject -PatternsToMatch @("/*") -Domain @(@{"Id"=$($endpointDetails.Id)})
                        $updateWafParameter = New-AzFrontDoorCdnSecurityPolicyWebApplicationFirewallParametersObject  -Association @($updateAssociation) -WafPolicyId $policy.Id
                        $securityPolicy = New-AzFrontDoorCdnSecurityPolicy -ProfileName $_.FrontDoorName -ResourceGroupName $_.ResourceGroupName -Name $securityPolicyName -Parameter $updateWafParameter
                       
                       if($securityPolicy.Parameter.WafPolicyId -ne $null)
                      {
                        $endpoint.IsWAFConfigured = $true
                        $endpoint.SecurityPolicyName = $securityPolicyName
                        $EndpointRemediated += $endpoint
                        $logResource = @{}	
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                        $logResource.Add("ResourceName",($_.EndPointName))	
                        $logRemediatedResources += $logResource	
                      }
                      else
                      {
                        $EndpointSkipped += $endpoint
                        $logResource = @{}	
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                        $logResource.Add("ResourceName",($_.EndPointName))
                        $logResource.Add("Reason", "Error Configuring NSG on : [$($endpoint)]")      
                        $logSkippedResources += $logResource
                      }
                     }
                    else
                    {
                      $EndpointSkipped += $endpoint
                      $logResource = @{}	
                      $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                      $logResource.Add("ResourceName",($_.EndPointName))
                      $logResource.Add("Reason", "Error Configuring NSG on : [$($endpoint)]")      
                      $logSkippedResources += $logResource	
                    }
                }
                else
                {
                    Write-Host "WAF Policy Name or Resource Group can not be empty..." -ForegroundColor $([Constants]::MessageType.Info)
                    $EndpointSkipped += $endpoint                                    
                    return;
                }
            }
            catch
            {
                $EndpointSkipped += $endpoint
                $logResource = @{}	
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                $logResource.Add("ResourceName",($_.EndPointName))	
                $logResource.Add("Reason","Encountered error Configuring WAF")    	
                $logSkippedResources += $logResource	
                Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host $([Constants]::SingleDashLine)
            }
         }

          Write-Host $([Constants]::DoubleDashLine)

          Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        if ($($EndpointRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Successfully configured the WAF on the Endpoint(s) of Front Door(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            $EndpointRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $EndpointRemediatedFile = "$($backupFolderPath)\RemediatedFrontDoorEndpoint.csv"
            $EndpointRemediated | Export-CSV -Path $EndpointRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($EndpointRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }          
        
        if ($($EndpointSkipped | Measure-Object).Count -gt 0)
        {

            Write-Host "Error while configuring WAF on the Endpoint(s) of Front Door(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            $EndpointSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $EndpointSkippedFile = "$($backupFolderPath)\SkippedSubnet.csv"
            $EndpointSkipped | Export-CSV -Path $EndpointSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($EndpointSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
        
       
    }
    
    }

function Remove-WAFConfigurationOnFrontDoorEndpoint
{
    <#
    .SYNOPSIS
    Rolls back remediation done for 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.

    .DESCRIPTION
    Rolls back remediation done for 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.
    Remove WAF configuration from the Endpoint(s) in the Subscription. 
        
    .PARAMETER SubscriptionId
    Specifies the ID of the Subscription that was previously remediated.
        
    .Parameter PerformPreReqCheck
    Specifies validation of prerequisites for the command.
      
    .PARAMETER FilePath
    Specifies the path to the file to be used as input for the roll back.

    .INPUTS
    None. You cannot pipe objects to Remove-WAFConfigurationOnFrontDoorEndpoint.

    .OUTPUTS
    None. Remove-WAFConfigurationOnFrontDoorEndpoint does not return anything that can be piped and used as an input to another command.

    .EXAMPLE
    PS> Remove-WAFConfigurationOnFrontDoorEndpoint -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemoveNSGConfiguration\RemediatedFrontDoorEndpoints.csv

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

    Write-Host "To remove WAF configuration from the Ebdpoints(s) of Front Door(s) in a Subscription, Contributor or higher privileged role assignment on the Front Door(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Front Door(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file:  [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Fetch all Endpoint(s) of Front Door from" -NoNewline
    Write-Host " [$($FilePath)\...]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $FrontDoorEndpointDetails = Import-Csv -LiteralPath $FilePath

    $validFrontDoorEndpointDetails = $FrontDoorEndpointDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.EndpointId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.FrontDoorName) -and ![String]::IsNullOrWhiteSpace($_.SecurityPolicyName) }

    $totalFrontDoorEndpoints = $(($validFrontDoorEndpointDetails|Measure-Object).Count)

    if ($totalFrontDoorEndpoints -eq 0)
    {
        Write-Host "No Endpoint of Front Door(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$(($validFrontDoorEndpointDetails|Measure-Object).Count)] Subnet(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.EndpointId};Label="EndpointId";Width=30;Alignment="left"},
                    @{Expression={$_.FrontDoorName};Label="FrontDoorName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=100;Alignment="left"},                    
                    @{Expression={$_.EndPointName};Label="EndPointName";Width=100;Alignment="left"}
                    @{Expression={$_.SecurityPolicyName};Label="SecurityPolicyName";Width=100;Alignment="left"}
                    @{Expression={$_.IsWAFConfigured};Label="IsWAFConfigured";Width=100;Alignment="left"}
                    

    $validFrontDoorEndpointDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RemoveWAFfromFrontDoorEndPoint"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Remove WAF Configuration from all remediated Endpoint(s) of Front Door(s) in the Subscription"
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        
    Write-Host "Do you want to remove WAF Configuration from Endpoint(s) mentioned in the file?"  -ForegroundColor $([Constants]::MessageType.Warning)
    $userInput = Read-Host -Prompt "(Y|N)"

    if($userInput -ne "Y")
    {
        Write-Host "WAF Configuration will not be rolled back on Endpoint(s) of Front Door(s) mentioned in the file. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }
        Write-Host "WAF Configuration will be rolled back on Endpoint(s) of Front Door(s) mentioned in the file." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. WAF Configuration will be rolled back on Endpoint(s) of Front Door(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Subnet resource.
    $EndpointsRolledBack = @()

    # List for storing skipped rolled back Subnet resource.
    $EndpointsSkipped = @()

    $validFrontDoorEndpointDetails | ForEach-Object {
        $Endpoint = $_
        try
        {   
            
             $remediatedEndpointDetails = Remove-AzFrontDoorCdnSecurityPolicy -ProfileName $_.FrontDoorName -ResourceGroupName $_.ResourceGroupName -Name $_.SecurityPolicyName
            if($remediatedEndpointDetails.Parameter.WafPolicyId -eq $null)
            {
                $Endpoint.IsWAFConfigured = $false
                $EndpointsRolledBack += $Endpoint
            }
            else
            {
                $EndpointsSkipped += $Endpoint
            }            
        }
        catch
        {
            $EndpointsSkipped += $Subnet
        }
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
    
    if ($($EndpointsRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "WAF configuration has been removed on the following Endpoint(s) of the Front Door(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
        $EndpointsRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $EndpointsRolledBackFile = "$($backupFolderPath)\RolledBackFrontDoorEndpoints.csv"
        $EndpointsRolledBack | Export-CSV -Path $$EndpointsRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($EndpointsRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }

    if ($($EndpointsSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error while removing WAF configuration on the Endpoint(s) of Front Door(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
        $EndpointsSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

            
        # Write this to a file.
        $EndpointsSkippedFile = "$($backupFolderPath)\RollbackSkippedFrontDoorEndpoints.csv"
        $EndpointsSkipped | Export-CSV -Path $EndpointsSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($EndpointsSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
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

        