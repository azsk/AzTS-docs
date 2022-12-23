<###
# Overview:
    This script is used to enable state of the WAF Policy configured on endpoints of Front Door CDNs in a Subscription.

# Control ID:
    Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration

# Display Name:
    Front Door should have Web Application Firewall configured

# Prerequisites:
    1. Contributor or higher privileges on the Front Door CDNs in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of all Front Door CDNs Endpoints in a Subscription that do not have WAF Policy Enabled
        3. Back up details of Front Door CDN Endpoint(s) that are to be remediated.
        4. Enable Policy for all endpoints in the Front Doors.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Front Doors' Endpoint(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Revert back Policy State to Disabled for all endpoints in all the Front Doors.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable WAF Policy on All endpoints of Front Door CDNs in a Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable WAF Policy on All endpoints of Front Door CDNs in a Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Front Door CDNs in a Subscription that will be remediated:
           Enable-WAFPolicyForFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To Enable WAF Policy for Endpoint(s) of all Front Door CDNs in a Subscription:
           Enable-WAFPolicyForFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To Enable WAF Policy for Endpoint(s) of all Front Door CDNs in a Subscription, from a previously taken snapshot:
           Enable-WAFPolicyForFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableFrontDoorCDNWAFPolicy\frontdoorCDNEndpointsWithoutPolicyEnabled.csv

        To know more about the options supported by the remediation command, execute:
        Get-Help Enable-WAFPolicyForFrontDoorCDN -Detailed

    To roll back:
        1. To Disable WAF Policy for Endpoint(s) all Front Door CDNs in a Subscription, from a previously taken snapshot:
           Disable-WAFPolicyForFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableFrontDoorCDNWAFPolicy\RemediatedfrontDoorCDNEndpointsForEnabledState.csv
        
        To know more about the options supported by the roll back command, execute:
        Get-Help Disable-WAFPolicyForFrontDoorCDN -Detailed        
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

function Enable-WAFPolicyForFrontDoorCDN
{
    <#
        .SYNOPSIS
        Remediates 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.

        .DESCRIPTION
        Remediates 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.
        WAF Policy must be Enabled for Front Door CDN Endpoint(s).
        
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
        None. Enable-WAFPolicyForFrontDoorCDN does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-WAFPolicyForFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-WAFPolicyForFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-WAFPolicyForFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202201011212\EnableFrontDoorCDNWAFPolicy\frontdoorCDNEndpointsWithoutPolicyEnabled.csv

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


    Write-Host "To enable WAF Policy for Front Door CDN Endpoint(s) in a Subscription, Contributor or higher privileges on the Front Door CDNs are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 5] Preparing to fetch all Front Door CDNs"
    Write-Host $([Constants]::SingleDashLine)
    $frontDoorCDNs = @()
    $frontDoorEndPoints = @()
    $resourceAppIdURI = "https://management.azure.com/"
    $apiResponse =@()
    $classicAccessToken= (Get-AzAccessToken -ResourceUrl $ResourceAppIdURI).Token
    $endPointPolicies = New-Object System.Collections.ArrayList

     # To keep track of remediated and skipped resources
     $logRemediatedResources = @()
     $logSkippedResources=@()
 
     # Control Id
     $controlIds = "Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration"
 
     
    # No file path provided as input to the script. Fetch all Front Door CDNs in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Front Door CDNs in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
    
        # Get all Front Door CDNs in the Subscription
        $frontDoorCDNs = Get-AzFrontDoorCdnProfile -ErrorAction SilentlyContinue
        $totalfrontDoors = ($frontDoorCDNs | Measure-Object).Count
        
        if($totalfrontDoors -gt 0)
        {
            $frontDoorCDNs | ForEach-Object {
                $frontDoor = $_
                $frontDoorId = $_.Id
                $resourceGroupName = $_.Id.Split('/')[4]
                $frontDoorName = $_.Name

            if($null -ne $classicAccessToken)
            {
                $header = "Bearer " + $classicAccessToken
                $headers = @{"Authorization"=$header;"Content-Type"="application/json"; "x-ms-version" ="2013-08-01"}
                $uri = [string]:: Format("{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Cdn/profiles/{3}/securityPolicies?api-version=2021-06-01",$resourceAppIdURI,$SubscriptionId,$resourceGroupName,$frontDoorName)
                $apiResponse = Invoke-WebRequest -Method GET -Uri $uri -Headers $headers -UseBasicParsing

                if($apiResponse.StatusCode -ge 200 -and $apiResponse.StatusCode -le 399)
                {
                    if($null -ne $apiResponse.Content)
                    {
                        $content = $apiResponse.Content | ConvertFrom-Json 
                        $value = $content.value
                        $totalValues = ($value | Measure-Object).Count
                        for($i=0; $i -lt $totalValues; $i++)
                        {
                            $wafPolicyId = $value[$i].properties.parameters.wafPolicy.id
                            $wafPolicyName = $wafPolicyId.Split('/')[8]
                            $wafPolicyResourceGroup = $wafPolicyId.Split('/')[4]
                            $associations = $value[$i].properties.parameters.associations
                            $totalAssociations = ($associations | Measure-Object).Count
                                for($j=0; $j -lt $totalAssociations; $j++)
                                {
                                    $association = $associations[$j]
                                    $domains = $association.domains
                                    $totalDomains = ($domains | Measure-Object).Count
                                    for($k=0; $k -lt $totalDomains; $k++)
                                    {
                                        $domain = $domains[$k]
                                        $id = $domain.id
                                        $endpointName = $id.Split('/')[10]
                                        $EndpointPolicy = New-Object System.Object
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "endpointName" -Value $endpointName
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "wafPolicyName" -Value $wafPolicyName
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "wafPolicyResourceGroup" -Value $wafPolicyResourceGroup
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "wafPolicyId" -Value $wafPolicyId 
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "frontdoorName" -Value $frontDoorName
                                        $endPointPolicies.Add($EndpointPolicy) | Out-Null
                                    }
                                }   
                        }
                    }        
                }
            }


            # Get all Endpoint(s) for this Front Door CDN.
            $endpoints = ( Get-AzFrontDoorCdnEndpoint -ResourceGroupName $resourceGroupName -ProfileName $frontDoorName -ErrorAction SilentlyContinue) 
            $frontDoorEndPoints += $endpoints  | Select-Object @{N='EndpointId';E={$_.Id}},
                                                                        @{N='FrontDoorName';E={$frontDoorName}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='EndPointName';E={$_.Name}},
                                                                        @{N='WAFPolicyName';E={ $endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName }},
                                                                        @{N='WAFPolicyResourceGroup';E={ $endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyResourceGroup}},
                                                                        @{N='IsWAFConfigured';E={
                                                                        if(($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName) -eq $null)
                                                                        { 
                                                                            $false
                                                                        }
                                                                        else
                                                                        {
                                                                            $true
                                                                        }
                                                                        }},
                                                                        @{N='IsPreventionMode';E={
                                                                        if(($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName) -eq $null)
                                                                        { 
                                                                            $false
                                                                        }
                                                                        else
                                                                        {
                                                                            $WAFPolicy = Get-AzFrontDoorWafPolicy -Name  ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName) -ResourceGroupName   ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyResourceGroup)
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
                                                                        @{N='IsWAFPolicyStateEnabled';E={
                                                                            if(($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName) -eq $null)
                                                                            { 
                                                                                $false
                                                                            }
                                                                            else
                                                                            {
                                                                                $WAFPolicy = Get-AzFrontDoorWafPolicy -Name  ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName) -ResourceGroupName   ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyResourceGroup)
                                                                                
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
            break
        }

        Write-Host "Fetching all Front Door CDN Endpoint(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)

        $frontDoorEndpointsDetails = Import-Csv -LiteralPath $FilePath
        $validfrontDoorEndpointsDetails = $frontDoorEndpointsDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.EndPointName) }
        
        $uniquefrontDoors = $validfrontDoorEndpointsDetails | Select-Object -Unique -Property FrontDoorName, ResourceGroupName

        foreach($frontdoor in $uniquefrontDoors)
        {
            $resourceGroupName = $frontdoor.ResourceGroupName
            $frontDoorName = $frontdoor.FrontDoorName
            if($null -ne $classicAccessToken)
            {
                $header = "Bearer " + $classicAccessToken
                $headers = @{"Authorization"=$header;"Content-Type"="application/json"; "x-ms-version" ="2013-08-01"}
                $uri = [string]:: Format("{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Cdn/profiles/{3}/securityPolicies?api-version=2021-06-01",$resourceAppIdURI,$SubscriptionId,$resourceGroupName,$frontDoorName)
                $apiResponse = Invoke-WebRequest -Method GET -Uri $uri -Headers $headers -UseBasicParsing

                if($apiResponse.StatusCode -ge 200 -and $apiResponse.StatusCode -le 399)
                {
                    if($null -ne $apiResponse.Content)
                    {
                        $content = $apiResponse.Content | ConvertFrom-Json 
                        $value = $content.value
                        $totalValues = ($value | Measure-Object).Count
                        for($i=0; $i -lt $totalValues; $i++)
                        {
                            $wafPolicyId = $value[$i].properties.parameters.wafPolicy.id
                            $wafPolicyName = $wafPolicyId.Split('/')[8]
                            $wafPolicyResourceGroup = $wafPolicyId.Split('/')[4]
                            $associations = $value[$i].properties.parameters.associations
                            $totalAssociations = ($associations | Measure-Object).Count
                                for($j=0; $j -lt $totalAssociations; $j++)
                                {
                                    $association = $associations[$j]
                                    $domains = $association.domains
                                    $totalDomains = ($domains | Measure-Object).Count
                                    for($k=0; $k -lt $totalDomains; $k++)
                                    {
                                        $domain = $domains[$k]
                                        $id = $domain.id
                                        $endpointName = $id.Split('/')[10]
                                        $EndpointPolicy = New-Object System.Object
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "endpointName" -Value $endpointName
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "wafPolicyName" -Value $wafPolicyName
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "wafPolicyResourceGroup" -Value $wafPolicyResourceGroup
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "wafPolicyId" -Value $wafPolicyId 
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "frontdoorName" -Value $frontDoorName
                                        $endPointPolicies.Add($EndpointPolicy) | Out-Null
                                    }
                                }   
                        }
                    }        
                }
            }

        }

        $validfrontDoorEndpointsDetails | ForEach-Object {
            $frontdoorEndpointName = $_.EndPointName
            $resourceGroupName = $_.ResourceGroupName
            $frontDoorName = $_.FrontDoorName

            try
            {
                

                $endpoints = ( Get-AzFrontDoorCdnEndpoint -EndpointName $frontdoorEndpointName -ProfileName $frontDoorName -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue) 
                $frontDoorEndPoints += $endpoints  | Select-Object @{N='EndpointId';E={$_.Id}},
                                                                        @{N='FrontDoorName';E={$frontDoorName}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='EndPointName';E={$_.Name}},
                                                                        @{N='WAFPolicyName';E={ $endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName }},
                                                                        @{N='WAFPolicyResourceGroup';E={ $endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyResourceGroup}},
                                                                        @{N='IsWAFConfigured';E={
                                                                        if(($endPointPolicies | where endpointName -eq $_.Name | select -ExpandProperty wafPolicyName) -eq $null)
                                                                        { 
                                                                            $false
                                                                        }
                                                                        else
                                                                        {
                                                                            $true
                                                                        }
                                                                        }},
                                                                        @{N='IsPreventionMode';E={
                                                                        if(($endPointPolicies | where endpointName -eq $_.Name | select -ExpandProperty wafPolicyName) -eq $null)
                                                                        { 
                                                                            $false
                                                                        }
                                                                        else
                                                                        {
                                                                            $WAFPolicy = Get-AzFrontDoorWafPolicy -Name  ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName) -ResourceGroupName   ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyResourceGroup)
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
                                                                        @{N='IsWAFPolicyStateEnabled';E={
                                                                            if(($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName) -eq $null)
                                                                            { 
                                                                                $false
                                                                            }
                                                                            else
                                                                            {
                                                                                $WAFPolicy = Get-AzFrontDoorWafPolicy -Name  ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName) -ResourceGroupName   ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyResourceGroup)
                                                                                
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
                Write-Host "Error fetching Front Door CDN Endpoint:  ID - [$($frontdoorEndpointId)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this Front Door CDN Endpoint..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
    }
    

     
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        $totalfrontDoors = ($frontDoorCDNs | Measure-Object).Count

        if ($totalfrontDoors -eq 0)
        {
            Write-Host "No Front Door CDNs found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }

        Write-Host "Found $($totalfrontDoors) Front Door CDN(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
     
  
   
    $totalfrontDoorEndPoints = ($frontDoorEndPoints | Measure-Object).Count

    if ($totalfrontDoorEndPoints -eq 0)
    {
        Write-Host "No Front Door CDN Endpoint(s) found having WAF Policy not Enabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }
    
    Write-Host "Found [$($totalfrontDoorEndPoints)] Front Door CDN Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Update)


    # Includes Front Door CDN Endpoint(s) where WAF Policy is in not Enabled
    $frontDoorEndpointsWithWAFPolicyNotEnabled = @()
    $totalfrontDoorEndpointsWithWAFPolicyNotConfigured = 0

    # Includes Front Door CDN Endpoint(s) that were skipped during remediation. There were errors remediating them.
    $frontDoorEndpointsSkipped = @()
     
 
    Write-Host "[Step 3 of 5] Fetching Endpoint(s) for which WAF Policy is not enabled"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Front Door CDN Endpoint(s) for which WAF Policy is not enabled..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $frontDoorEndPoints | ForEach-Object {
        $endPoint = $_        
        if($_.IsWAFConfigured -eq $false)
        {
            $totalfrontDoorEndpointsWithWAFPolicyNotConfigured = $totalfrontDoorEndpointsWithWAFPolicyNotConfigured + 1
        }
        if(($_.IsWAFPolicyStateEnabled -eq $false) -and ($_.IsWAFConfigured -eq $true))
        {
            $frontDoorEndpointsWithWAFPolicyNotEnabled += $endPoint
        }
        else
        {
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.FrontDoorName))
            $logResource.Add("EndPointName",($_.EndPointName))
            $logResource.Add("Reason","WAF Policy already enabled on endpoint")    
            $logSkippedResources += $logResource

        }
    }

    $totalfrontDoorEndpointsWithWAFPolicyNotEnabled = ($frontDoorEndpointsWithWAFPolicyNotEnabled | Measure-Object).Count
     
    if ($totalfrontDoorEndpointsWithWAFPolicyNotConfigured  -gt 0)
    {
         Write-Host "Found [$($totalfrontDoorEndpointsWithWAFPolicyNotConfigured)] Front Door Endpoints(s) found where WAF Policy is not configured. Use [Remediate-ConfigureWAFOnAzureFrontDoor.ps1] BRS to Configure WAF Policy on Front Door Endpoints without WAF Policy Configured." -ForegroundColor $([Constants]::MessageType.Update)
         Write-Host $([Constants]::SingleDashLine)	
    }

    if ($totalfrontDoorEndpointsWithWAFPolicyNotEnabled  -eq 0)
    {
        Write-Host "No Front Door CDN endpoints(s) found where WAF Policy is not Enabled.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalfrontDoorEndpointsWithWAFPolicyNotEnabled)] Front Door CDN Endpoints(s) found where WAF Policy is not Enabled ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
     
  
    Write-Host "Following Front Door CDN Endpoints(s) are having WAF Policies not Enabled:" -ForegroundColor $([Constants]::MessageType.Info)
    $colsProperty = @{Expression={$_.EndpointId};Label="Endpoint Id";Width=10;Alignment="left"},
                        @{Expression={$_.EndPointName};Label="Endpoint";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFPolicyStateEnabled};Label="Is associated WAF Policy in Enabled State";Width=7;Alignment="left"}
    $frontDoorEndpointsWithWAFPolicyNotEnabled | Format-Table -Property $colsProperty -Wrap


    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableFrontDoorCDNWAFPolicy"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    
    Write-Host "[Step 4 of 5] Backing up Front Door CDN Endpoint(s) details"
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
    
        # Backing up Front Door CDN Endpoints details.
        $backupFileForWAFNotEnabled = "$($backupFolderPath)\frontdoorCDNEndpointsWithoutPolicyEnabled.csv"
        $frontDoorEndpointsWithWAFPolicyNotEnabled | Export-CSV -Path $backupFileForWAFNotEnabled -NoTypeInformation
        Write-Host "Front Door Endpoint(s) details have been successful backed up to $($backupFolderPath)" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun)
    {
         
        Write-Host "WAF Policy will be Enabled for all Front Door CDN Endpoint(s)." -ForegroundColor $([Constants]::MessageType.Warning)

        if (-not $Force)
        {
            Write-Host "Do you want to Enable WAF Policies associated with Front Door CDN Endpoint(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host " WAF Policy will not be enabled for any Front Door CDN Endpoint(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }
            else
            {
                Write-Host "WAF Policy will be enabled for all Front Door CDN Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. WAF Policy will be enabled on all Front Door CDN Endoint(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }
         

        
        Write-Host "[Step 5 of 5] Enabling WAF Policy for Front Door CDN Endpoint(s)"
        Write-Host $([Constants]::SingleDashLine)

        # To hold results from the remediation.
        $frontDoorEndpointsRemediated = @()
   

        # Remidiate Controls by Eanbling WAF Policy
        $frontDoorEndpointsWithWAFPolicyNotEnabled | ForEach-Object {
            $frontDoorEndPoint = $_
            $wafPolicyName = $_.WAFPolicyName
            $wafPolicyRG = $_.WAFPolicyResourceGroup
            $endpointsSkipped = @()
            
             
            try
            {  
                $updatedPolicy = Update-AzFrontDoorWafPolicy -Name  $wafPolicyName  -ResourceGroupName $wafPolicyRG -EnabledState Enabled

                if ($updatedPolicy.PolicyEnabledState -ne 'Enabled')
                {
                    $endpointsSkipped += $frontDoorEndPoint
                       
                }
                else
                {
                    $frontDoorEndPoint.IsWAFPolicyStateEnabled = $true
                    $frontDoorEndpointsRemediated += $frontDoorEndPoint
                }
            }
            catch
            {
                $endpointsSkipped += $frontDoorEndPoint
            }
        }

        $totalRemediated = ($frontDoorEndpointsRemediated | Measure-Object).Count

        Write-Host $([Constants]::SingleDashLine)

        if ($totalRemediated -eq $totalfrontDoorEndpointsWithWAFPolicyNotEnabled)
        {
            Write-Host "WAF Policy Enabled for all [$($totalfrontDoorEndpointsWithWAFPolicyNotEnabled)] Front Door CDN Endpoint(s) ." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "WAF Policy Enabled for [$totalRemediated] out of [$($totalfrontDoorEndpointsWithWAFPolicyNotEnabled)] Front Door CDN Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsProperty = @{Expression={$_.EndpointId};Label="Endpoint Id";Width=10;Alignment="left"},
                        @{Expression={$_.EndPointName};Label="Endpoint";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFPolicyStateEnabled};Label="Is associated WAF Policy in Enabled State";Width=7;Alignment="left"}
                       
                      
       
        Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        
        
        
        if ($($frontDoorEndpointsRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Successfully enabled WAF Policy on the following Frontdoor CDN Endpoint(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            $frontDoorEndpointsRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $frontDoorEndpointsRemediatedFile = "$($backupFolderPath)\RemediatedfrontDoorCDNEndpointsForEnabledState.csv"
            $frontDoorEndpointsRemediated | Export-CSV -Path $frontDoorEndpointsRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($frontDoorEndpointsRemediatedFile)]"
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($endpointsSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error performing remediation steps for the following Front Door CDN Endpoint(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $endpointsSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $endpointsSkippedFile = "$($backupFolderPath)\SkippedfrontDoorCDNEndpointsForEnabledState.csv"
            $endpointsSkipped | Export-CSV -Path $endpointsSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($endpointsSkippedFile)]"
        }
        
    }
    else
    {
        
        Write-Host "[Step 5 of 5] Enabling WAF Policy for Endpoint(s)"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to Enable WAF Policy for all Front Door CDN Endpoint(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
    }   
}

function Disable-WAFPolicyForFrontDoorCDN
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_FrontDoor_CDNProfile_NetSec_Enable_WAF_Configuration' Control.
        Disables back all WAF Policies in all Front Door CDNs in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-WAFPolicyForFrontDoorCDN.

        .OUTPUTS
        None. Disable-WAFPolicyForFrontDoorCDN does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-WAFPolicyForFrontDoorCDN -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202211190719\EnableFrontDoorCDNWAFPolicy\RemediatedfrontDoorCDNEndpointsForEnabledState.csv

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

    Write-Host "To Disable WAF Policy for all Front Door CDN Endpoint(s) in a Subscription, Contributor or higher privileges on the Front Door CDNs are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Front Door CDN Endpoints"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Front Door CDN Endpoints from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)

        $frontDoorEndPoints = @()
        $resourceAppIdURI = "https://management.azure.com/"
        $apiResponse =@()
        $classicAccessToken= (Get-AzAccessToken -ResourceUrl $ResourceAppIdURI).Token
        $endPointPolicies = New-Object System.Collections.ArrayList

        $frontDoorEndpointsDetails = Import-Csv -LiteralPath $FilePath
        $validfrontDoorEndpointsDetails = $frontDoorEndpointsDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.EndPointName) }
        
        $uniquefrontDoors = $validfrontDoorEndpointsDetails | Select-Object -Unique -Property FrontDoorName, ResourceGroupName

        foreach($frontdoor in $uniquefrontDoors)
        {
            $resourceGroupName = $frontdoor.ResourceGroupName
            $frontDoorName = $frontdoor.FrontDoorName

            if($null -ne $classicAccessToken)
            {
                $header = "Bearer " + $classicAccessToken
                $headers = @{"Authorization"=$header;"Content-Type"="application/json"; "x-ms-version" ="2013-08-01"}
                $uri = [string]:: Format("{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Cdn/profiles/{3}/securityPolicies?api-version=2021-06-01",$resourceAppIdURI,$SubscriptionId,$resourceGroupName,$frontDoorName)
                $apiResponse = Invoke-WebRequest -Method GET -Uri $uri -Headers $headers -UseBasicParsing

                if($apiResponse.StatusCode -ge 200 -and $apiResponse.StatusCode -le 399)
                {
                    if($null -ne $apiResponse.Content)
                    {
                        $content = $apiResponse.Content | ConvertFrom-Json 
                        $value = $content.value
                        $totalValues = ($value | Measure-Object).Count
                        for($i=0; $i -lt $totalValues; $i++)
                        {
                            $wafPolicyId = $value[$i].properties.parameters.wafPolicy.id
                            $wafPolicyName = $wafPolicyId.Split('/')[8]
                            $wafPolicyResourceGroup = $wafPolicyId.Split('/')[4]
                            $associations = $value[$i].properties.parameters.associations
                            $totalAssociations = ($associations | Measure-Object).Count
                                for($j=0; $j -lt $totalAssociations; $j++)
                                {
                                    $association = $associations[$j]
                                    $domains = $association.domains
                                    $totalDomains = ($domains | Measure-Object).Count
                                    for($k=0; $k -lt $totalDomains; $k++)
                                    {
                                        $domain = $domains[$k]
                                        $id = $domain.id
                                        $endpointName = $id.Split('/')[10]
                                        $EndpointPolicy = New-Object System.Object
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "endpointName" -Value $endpointName
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "wafPolicyName" -Value $wafPolicyName
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "wafPolicyResourceGroup" -Value $wafPolicyResourceGroup
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "wafPolicyId" -Value $wafPolicyId 
                                        $EndpointPolicy | Add-Member -MemberType NoteProperty -Name "frontdoorName" -Value $frontDoorName
                                        $endPointPolicies.Add($EndpointPolicy) | Out-Null
                                    }
                                }   
                          }
                    }        
                }
            }
        }

        

        $validfrontDoorEndpointsDetails | ForEach-Object {
            $frontdoorEndpointName = $_.EndPointName
            $resourceGroupName = $_.ResourceGroupName
            $frontDoorName = $_.FrontDoorName

            try
            {

                $endpoints = ( Get-AzFrontDoorCdnEndpoint -EndpointName $frontdoorEndpointName -ProfileName $frontDoorName -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue) 
                $frontDoorEndPoints += $endpoints  | Select-Object @{N='EndpointId';E={$_.Id}},
                                                                        @{N='FrontDoorName';E={$frontDoorName}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='EndPointName';E={$_.Name}},
                                                                        @{N='WAFPolicyName';E={ $endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName }},
                                                                        @{N='WAFPolicyResourceGroup';E={ $endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyResourceGroup}},
                                                                        @{N='IsWAFConfigured';E={
                                                                        if(($endPointPolicies | where endpointName -eq $_.Name | select -ExpandProperty wafPolicyName) -eq $null)
                                                                        { 
                                                                             $false
                                                                        }
                                                                        else
                                                                        {
                                                                            $true
                                                                        }
                                                                        }},
                                                                        @{N='IsPreventionMode';E={
                                                                        if(($endPointPolicies | where endpointName -eq $_.Name | select -ExpandProperty wafPolicyName) -eq $null)
                                                                        { 
                                                                            $false
                                                                        }
                                                                        else
                                                                        {
                                                                            $WAFPolicy = Get-AzFrontDoorWafPolicy -Name  ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName) -ResourceGroupName   ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyResourceGroup)
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
                                                                        @{N='IsWAFPolicyStateEnabled';E={
                                                                            if(($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName) -eq $null)
                                                                            { 
                                                                                $false
                                                                            }
                                                                            else
                                                                            {
                                                                                $WAFPolicy = Get-AzFrontDoorWafPolicy -Name  ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyName) -ResourceGroupName   ($endPointPolicies | where endpointName -eq $_.Name |  select -ExpandProperty wafPolicyResourceGroup)
                                                                                
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
                Write-Host "Error fetching Front Door CDN Endpoint: ID - [$($frontdoorEndpointId)]... Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this Front Door CDN Endpoint..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }


        
    # Includes Front Door CDN Endpoint(s) where WAF Policy is in Enabled
    $frontDoorEndpointsWithWAFPolicyEnabled = @()

    
    
    Write-Host "[Step 3 of 4] Fetching Endpoint(s) for which WAF Policy is enabled"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Front Door CDN Endpoint(s) for which WAF Policy is enabled..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $frontDoorEndPoints | ForEach-Object {
        $endPoint = $_        
            if(($_.IsWAFPolicyStateEnabled -eq $true) -and ($_.IsWAFConfigured -eq $true))
            {
                $frontDoorEndpointsWithWAFPolicyEnabled += $endPoint
            }
    }

    $totalfrontDoorEndpointsWithWAFPolicyEnabled = ($frontDoorEndpointsWithWAFPolicyEnabled | Measure-Object).Count
     
    if ($totalfrontDoorEndpointsWithWAFPolicyEnabled  -eq 0)
    {
        Write-Host "No Front Door CDN  Endpoints(s) found where WAF Policy is Enabled.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    } 

    
    Write-Host "Found [$($totalfrontDoorEndpointsWithWAFPolicyEnabled)] Front Door CDN  Endpoints(s) found where WAF Policy is Enabled in file to Rollback." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
    
     # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableFrontDoorCDNWAFPolicy"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    } 
    
    if (-not $Force)
    {
        Write-Host "Do you want to Disable WAF Policy for all Front Door CDN Endpoint(s)?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "WAF Policy  will not be Disabled for any Front Door CDN Endpoint(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. WAF Policy will be Disabled for all the Front Door CDN Endpoint(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    
    
    Write-Host "[Step 4 of 4] Disabling WAF Policy for Front Door CDNs Endpoint(s)"
    Write-Host $([Constants]::SingleDashLine)

    # Includes Front Door CDN s, to which, previously made changes were successfully rolled back.
    $frontDoorEndpointsRolledBack = @()

    # Includes Front Door CDN s that were skipped during roll back. There were errors rolling back the changes made previously.
    $frontDoorEndpointsSkipped = @()

   
     # Roll back by disabling WAF Policy
        $frontDoorEndpointsWithWAFPolicyEnabled | ForEach-Object {
            $frontDoorEndPoint = $_
            $wafPolicyName = $_.WAFPolicyName
            $wafPolicyRG = $_.WAFPolicyResourceGroup
             
            try
            {  
                $endpointResource = Update-AzFrontDoorWafPolicy -Name  $wafPolicyName  -ResourceGroupName $wafPolicyRG -EnabledState Disabled

                if ($endpointResource.PolicyEnabledState -ne 'Disabled')
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

        if ($totalfrontDoorEndpointsRolledBack -eq $totalfrontDoorEndpointsWithWAFPolicyEnabled)
        {
            Write-Host "WAF Policy Disabled for all [$($totalfrontDoorEndpointsWithWAFPolicyEnabled)] Front Door CDN Endpoint(s) ." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "WAF Policy disabled for [$totalfrontDoorEndpointsRolledBack] out of [$($totalfrontDoorEndpointsWithWAFPolicyEnabled)] Front Door CDN Endpoint(s)" -ForegroundColor $([Constants]::MessageType.Warning)
        }
       
        Write-Host "Rollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
         Write-Host $([Constants]::SingleDashLine)
        
        $colsProperty = @{Expression={$_.EndpointId};Label="Endpoint Id";Width=10;Alignment="left"},
                        @{Expression={$_.EndPointName};Label="Endpoint";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.FrontDoorName};Label="Front Door";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyName};Label="WAF Policy Name";Width=7;Alignment="left"},
                        @{Expression={$_.WAFPolicyResourceGroup};Label="WAF Policy RG";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFConfigured};Label="Is WAF Policy Configured?";Width=7;Alignment="left"},
                        @{Expression={$_.IsWAFPolicyStateEnabled};Label="Is associated WAF Policy in Enabled State";Width=7;Alignment="left"}
            

        if ($($frontDoorEndpointsRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Successfully disabled WAF Policy on the following Frontdoor CDN Endpoint(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            $frontDoorEndpointsRolledBack | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $frontDoorEndpointsRolledBackFile = "$($backupFolderPath)\RolledBackfrontDoorCDNEndpointsForWAFPolicyState.csv"
            $frontDoorEndpointsRolledBack | Export-CSV -Path $frontDoorEndpointsRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to $($frontDoorEndpointsRolledBackFile)"
        }

        if ($($frontDoorEndpointsSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error Disabling WAF Policy for the following Front Door CDN  Endpoint(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $frontDoorEndpointsSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $frontDoorEndpointsSkippedFile = "$($backupFolderPath)\RolledBackSkippedfrontDoorCDNEndpointsForWAFPolicyState.csv"
            $frontDoorEndpointsSkipped | Export-CSV -Path $frontDoorEndpointsSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($frontDoorEndpointsSkippedFile)"
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