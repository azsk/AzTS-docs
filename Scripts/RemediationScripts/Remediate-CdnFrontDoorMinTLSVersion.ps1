<###
# Overview:
    This script is used to set required TLS version for Front Door CDN Profile in a Subscription.

# Control ID:
    Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version

# Display Name:
    Front Door should have approved minimum TLS version.

# Prerequisites:
    1. Contributor or higher privileges on the Front Doors in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of Front Door CDN Profile Domains in a Subscription that do not use the required TLS version.
        3. Back up details of Front Door CDN Profiles Domains that are required to be remediated.
        4. Set the required TLS version on the Domains in all Front Doors CDN Profiles in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Front Door CDN Profile Domains in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the previous TLS versions for all Front Door CDN Profile Domains in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the required TLS version on the Front Doors. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the previous TLS versions on the Domains configured in Front Door CDN Profiles. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Front Door CDN Profiles in a Subscription that will be remediated:
           Set-FrontDoorCDNProfileRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To set minimum required TLS version on all domains of Front Door CDN Profiles in a Subscription:
           Set-FrontDoorCDNProfileRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To set minimum required TLS version on all domains of Front Door CDN Profiles in a Subscription, from a previously taken snapshot:
           Set-FrontDoorCDNProfileRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForCdnFrontDoors\FrontDoorWithoutMinReqTLSVersion.csv

        To know more about the options supported by the remediation command, execute:
        Get-Help Set-FrontDoorCDNProfileRequiredTLSVersion -Detailed

    To roll back:
        1. To reset minimum required TLS version on all domains of Front Door CDN Profiles in a Subscription, from a previously taken snapshot:
           Reset-FrontDoorCDNProfileRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForCdnFrontDoors\RemediatedFrontDoors.csv
        
        To know more about the options supported by the roll back command, execute:
        Get-Help Reset-FrontDoorCDNProfileRequiredTLSVersion -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Cdn")
    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "$($_) module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host $([Constants]::SingleDashLine)

}

function Set-FrontDoorCDNProfileRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Remediates 'Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Remediates 'Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version' Control.
        Sets the required TLS version on all the domains in all Front Door CDN Profiles in the Subscription. 
        
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
        None. You cannot pipe objects to Set-FrontDoorCDNProfileRequiredTLSVersion.

        .OUTPUTS
        None. Set-FrontDoorCDNProfileRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-FrontDoorCDNProfileRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-FrontDoorCDNProfileRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-FrontDoorCDNProfileRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForCdnFrontDoors\FrontDoorWithoutMinReqTLSVersion.csv

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
    Write-Host "[Step 1 of 4] Prepare to set required TLS version for all Domain of Front Door CDN Profiles in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "To Set Minimum TLS version for front Door CDN Profiles in a Subscription, Contributor or higher privileges on the Front Door CDN Profiles are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Fetch all Front Door CDN Profiles"
    Write-Host $([Constants]::SingleDashLine)

    $FrontDoorResources = @()

    $FrontDoorDomainResources = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    $controlIds = "Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version"

    # Fetch all front doors in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Front Door CDN Profile Domain(s) in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        # Get all Front Doors in a Subscription
        $FrontDoorResources = Get-AzFrontDoorCdnProfile -SubscriptionId $SubscriptionId -ErrorAction Stop
        foreach($frontdoor in $FrontDoorResources)
        {
            try
            {
                $FrontDoorCustomDomains = @()

                $FrontDoorCustomDomains = Get-AzFrontDoorCdnCustomDomain -ProfileName $frontdoor.Name -ResourceGroupName $frontdoor.ResourceGroupName 
                
                if($FrontDoorCustomDomains)
                {
                    Write-Host "Domains Configurations successfully fetched for Front Door CDN Profile:" [$($frontdoor.Name)] -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }

                if($FrontDoorCustomDomains -ne $null)
                {
                    $FrontDoorDomainResources +=  $FrontDoorCustomDomains | Select-Object @{N='ResourceGroupName';E={$frontdoor.ResourceGroupName}},
                                                                                @{N='ProfileName';E={$frontdoor.Name}},
                                                                                @{N='DomainName';E={$_.Name}},
                                                                                @{N='HostName';E={$_.HostName}},
                                                                                @{N='DomainDeploymentStatus';E={$_.DeploymentStatus}},
                                                                                @{N='DomainValidationState';E={$_.DomainValidationState}},
                                                                                @{N='MinimumTlsVersion';E={$_.TlsSetting.MinimumTlsVersion}}        
                }
            }
            catch
            {
                Write-Host "Error while fetching Front Door CDN Profile Domain details. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)	
            return
        }

        Write-Host "Fetching all Front Door CDN Profiles from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $frontdoorDetails = Import-Csv -LiteralPath $FilePath
        $validFrontDoorDetails = $frontdoorDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.DomainName)
                                                                    ![String]::IsNullOrWhiteSpace($_.ResourceGroupName)
                                                                    ![String]::IsNullOrWhiteSpace($_.ProfileName) }

        $validFrontDoorDetails | ForEach-Object {
            $frontDoorResource = $_
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ProfileName
            try
            {
                Write-Host "Fetching Front Door CDN Profiles Domain configuration: Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
                $FrontDoorCustomDomains = @()

                $FrontDoorCustomDomains = Get-AzFrontDoorCdnCustomDomain -ProfileName $resourceName -ResourceGroupName $resourceGroupName -CustomDomainName $_.DomainName
                
                if($FrontDoorCustomDomains)
                {
                    Write-Host "Domains Configurations successfully fetched for Front Door CDN Profile:" [$($resourceName)] -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }

                if($FrontDoorCustomDomains -ne $null)
                {
                    $FrontDoorDomainResources +=  $FrontDoorCustomDomains | Select-Object @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                @{N='ProfileName';E={$resourceName}},
                                                                                @{N='DomainName';E={$_.Name}},
                                                                                @{N='HostName';E={$_.HostName}},
                                                                                @{N='DomainDeploymentStatus';E={$_.DeploymentStatus}},
                                                                                @{N='DomainValidationState';E={$_.DomainValidationState}},
                                                                                @{N='MinimumTlsVersion';E={$_.TlsSetting.MinimumTlsVersion}}
                            
                        
                }
            }
            catch
            {
                $frontDoorsDomainsSkipped += $frontDoorResource
                Write-Host "Error fetching Front Door CDN Profiles configuration: Resource Name: [$($resourceName)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("DomainName",($_.DomainName))
                $logResource.Add("ResourceName",($_.ProfileName))
                $logResource.Add("Reason","Encountered error while fetching Front Door configuration")    
                $logSkippedResources += $logResource
                Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
    }
                     
    }
    
    $totalFrontDoorDomains = ($FrontDoorDomainResources | Measure-Object).Count

    if ($totalFrontDoorDomains -eq 0)
    {
        Write-Host "No Front Door CDN Profile Domain(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }  
    
    Write-Host "Found [$($totalFrontDoorDomains)] Front Door CDN Profile Domain(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # Includes required version of TLS
    $requiredMinTLSVersion = "TLS12"

    $CompliantFrontDoorDomainPoints = @()

    # Includes Front Door CDN Profiles that were skipped during remediation. There were errors remediating them.
    $frontDoorsDomainsSkipped = @()

    $NonCompliantFrontDoorDomains = @()

     $FrontDoorDomainResources | ForEach-Object {
            $frontDoorDomainResource = $_
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.DomainName
           
            if($frontDoorDomainResource.MinimumTlsVersion -ne $requiredMinTLSVersion)
            {
                $NonCompliantFrontDoorDomains += $frontDoorDomainResource
            }            
     }     
    
    $totalNonCompliantFrontDoorDomains = ($NonCompliantFrontDoorDomains | Measure-Object).Count

    if ($totalNonCompliantFrontDoorDomains -eq 0)
    {
        Write-Host "No Front Door CDN Profiles Domain(s) found having minimum TLS version less than required minimum TLS version. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)        
        return
    }

    Write-Host "Found [$($totalNonCompliantFrontDoorDomains)] Front Door CDN Profiles Domain(s) having minimum TLS version less than required minimum TLS version." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetMinTLSVersionForCdnFrontDoors"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    if (-not $DryRun)
    {  
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "`[Step 4 of 4] Set minimum required TLS Version for FrontDoors"
        Write-Host $([Constants]::SingleDashLine)        
       
        if (-not $Force)
        {
            Write-Host "Do you want to set minimum required TLS Version for all Domains? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                
            $userInput = Read-Host -Prompt "(Y|N)"
            Write-Host $([Constants]::SingleDashLine)
            if($userInput -ne "Y")
            {
                Write-Host "Minimum required TLS Version will not be set for any Domain. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                return
            }
            Write-Host "User has provided consent to set minimum required TLS Version on Domains for all Front Doors." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
        }
        else
        {
            Write-Host "'Force' flag is provided. Minimum required TLS Version will be set on the for all Front Door CDN Profiles Domain(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }       

        
        # To hold results from the remediation.
        $frontDoorsDomainsRemediated = @()
        $frontDoorsDomainsSkipped = @()
        
        $NonCompliantFrontDoorDomains | ForEach-Object {
            $frontdoorEndpoint = $_
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ProfileName
            $DomainName = $_.DomainName
            $PrevMinimumTlsVersion = $_.MinimumTlsVersion
            $MinimumTlsVersion = $_.MinimumTlsVersion
            
            
            $frontdoorEndpoint | Add-Member -NotePropertyName PrevMinimumTlsVersion -NotePropertyValue $PrevMinimumTlsVersion

            Write-Host "Setting minimum required TLS Version for domains of Front Door CDN Profiles :  Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
           
            try
            {
                Write-Host "Setting minimum required TLS version on domain : [$DomainName]" -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
                    
                $customDomain = Get-AzFrontDoorCdnCustomDomain -CustomDomainName $DomainName  -ProfileName $resourceName -ResourceGroupName $resourceGroupName
                if($customDomain -ne $null)
                {
                    if($customDomain.DomainValidationState -eq "Approved" -and $customDomain.DeploymentStatus -eq "Succeeded")
                    {
                        $tlsSettings = $customDomain.TlsSetting
                        $tlsSettings.MinimumTlsVersion = $requiredMinTLSVersion
                        $updatedDomain = Update-AzFrontDoorCdnCustomDomain -CustomDomainName $DomainName  -ProfileName $resourceName -ResourceGroupName $resourceGroupName -TlsSetting $tlsSettings
                        if($updatedDomain -ne $null -and $updatedDomain.TlsSetting.MinimumTlsVersion -eq $requiredMinTLSVersion)
                        {
                            $frontdoorEndpoint.MinimumTlsVersion = $requiredMinTLSVersion
                            $frontDoorsDomainsRemediated += $frontdoorEndpoint
                            Write-Host "Minimum required TLS version for Front Door CDN Profiles has been set successfully for " [$DomainName]  -ForegroundColor $([Constants]::MessageType.Update)
                            Write-Host $([Constants]::SingleDashLine)
                            $logResource = @{}	
                            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                            $logResource.Add("ResourceName",($_.ProfileName))
                            $logResource.Add("DomainName",($_.DomainName))
                            $logRemediatedResources += $logResource
                        }
                    }                
                    else
                    {
                        $frontDoorsDomainsSkipped += $frontdoorEndpoint
                        $logResource = @{}
                        $logResource.Add("DomainName",($_.DomainName))
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        $logResource.Add("ResourceName",($_.ProfileName))
                        $logResource.Add("Reason", "Warning! Skipping this resource as Domain Deployment Status and Domain Validation State must be Succeeded and Approved, Skipping this Front Door domain.")
                        $logSkippedResources += $logResource
                        Write-Host "Warning! Skipping this resource as Domain Deployment Status and Domain Validation State must be Succeeded and Approved." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host "Skipping this Front Door Domain." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                    }                    
                }
                 else
                {
                    $frontDoorsDomainsSkipped += $frontdoorEndpoint
                    $logResource = @{}
                    $logResource.Add("DomainName",($_.DomainName))
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ProfileName))
                    $logResource.Add("Reason", "Error while retrieving the domain details to minimum required TLS version. Skipping this Front Door Domain.")
                    $logSkippedResources += $logResource
                    Write-Host "Error while setting the minimum required TLS version for this Front Door Domain." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Front Door Domain." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
            catch
            {
                $frontDoorsDomainsSkipped += $frontdoorEndpoint
                $logResource = @{}
                $logResource.Add("DomainName",($_.DomainName))
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ProfileName))
                $logResource.Add("Reason", "Error while setting the minimum required TLS version. Skipping this Front Door Domain.")
                $logSkippedResources += $logResource
                Write-Host "Error while setting the minimum required TLS version for this Front Door Domain." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this Front Door Domain." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                
            }
            
        }

        if (($frontDoorsDomainsRemediated | Measure-Object).Count -eq $totalNonCompliantFrontDoorDomains)
        {
            Write-Host "Successfully set the minimum required TLS version for all [$($totalNonCompliantFrontDoorDomains)] Front Door Domain(s)." -ForegroundColor $([Constants]::MessageType.Update)   
        }
        else
        {
            Write-Host "Minimum required TLS version is successfully set on the domains for [$($($frontDoorsDomainsRemediated | Measure-Object).Count)] out of [$($totalNonCompliantFrontDoorDomains)] Front Door Domain(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsProperty = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ProfileName};Label="Profile Name";Width=20;Alignment="left"},
                        @{Expression={$_.DomainName};Label="Domain Name";Width=20;Alignment="left"},
                        @{Expression={$_.HostName};Label="Host Name";Width=20;Alignment="left"},
                        @{Expression={$_.PrevMinimumTlsVersion};Label="Previous Min TLS Version";Width=20;Alignment="left"},
                        @{Expression={$_.MinimumTlsVersion};Label="Current Min TLS Version";Width=20;Alignment="left"},
                        @{Expression={$_.DomainDeploymentStatus};Label="DomainDeploymentStatus";Width=20;Alignment="left"},
                        @{Expression={$_.DomainValidationState};Label="DomainValidationState";Width=20;Alignment="left"}
                        
        Write-Host $([Constants]::DoubleDashLine)
        
        
       
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($frontDoorsDomainsRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Successfully set minimum required TLS version for the following Front Door Domain(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $frontDoorsDomainsRemediated | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $frontDoorsDomainsRemediatedFile = "$($backupFolderPath)\RemediatedCdnFrontDoorForMinReqTLSVersion.csv"
            $frontDoorsDomainsRemediated | Export-CSV -Path $frontDoorsDomainsRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($frontDoorsDomainsRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($frontDoorsDomainsSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error while setting the minimum required TLS Version for the following Front Door Domain(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $frontDoorsDomainsSkipped | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $frontDoorSkippedFile = "$($backupFolderPath)\SkippedFrontDoorsForMinReqTLSVersion.csv"
            $frontDoorsDomainsSkipped | Export-CSV -Path $frontDoorSkippedFile -NoTypeInformation 
            Write-Host "This information has been saved to [$($frontDoorSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
        Write-Host "[Step 4 of 4] Back up Front Doors details"
        Write-Host $([Constants]::SingleDashLine)
        # Backing up Front Doors details.
        $BackupFile = "$($backupFolderPath)\CdnFrontDoorsWithoutReqMinTLSVersion.csv"
        $NonCompliantFrontDoorDomains | Export-CSV -Path $BackupFile -NoTypeInformation
        Write-Host "Front Door details have been backed up to [$($BackupFile)]. Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath $($BackupFile) and without -DryRun, to set minimum required TLS Version for all domains of Front Doors listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
}

function Reset-FrontDoorCDNProfileRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version' Control.
        Resets Minimum TLS Version on the domain in Front Door CDN Profiles in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-FrontDoorCDNProfileRequiredTLSVersion.

        .OUTPUTS
        None. Reset-FrontDoorCDNProfileRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-FrontDoorCDNProfileRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForCdnFrontDoors\RemediatedCdnFrontDoorForMinReqTLSVersion.csv

        .EXAMPLE
        PS> Reset-FrontDoorCDNProfileRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck  -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForCdnFrontDoors\RemediatedCdnFrontDoorForMinReqTLSVersion.csv

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
    Write-Host "[Step 1 of 3] Prepare to reset minimum TLS version on Front Door CDN Profile Domain(s) in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "To Reset Minimum TLS version for domain of Front Door CDN Profiles in a Subscription, Contributor or higher privileges on the Front Doors are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Fetch all Front Doors"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }

    Write-Host "Fetching all Front Doors from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $frontdoorDetails = Import-Csv -LiteralPath $FilePath
    $validFrontDoorDomainDetails = $frontdoorDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceGroupName)
                                                                ![String]::IsNullOrWhiteSpace($_.ProfileName)
                                                                ![String]::IsNullOrWhiteSpace($_.DomainName)
                                                                ![String]::IsNullOrWhiteSpace($_.MinimumTlsVersion)
                                                            }

    $totalFrontDoorDomain = $(($validFrontDoorDomainDetails|Measure-Object).Count)

    if ($totalFrontDoorDomain -eq 0)
    {
        Write-Host "No Front door End points found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }

    Write-Host "Found [$($totalFrontDoorDomain)] Front Door End point(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetMinTLSVersionForCdnFrontDoors"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "Minimum TLS Version will be reset on the following Front Door Domain(s):"
    $validFrontDoorDomainDetails | Select-Object 
                    @{N="Resource Group Name"; E={$_.ResourceGroupName}},
                    @{N="Resource Name"; E={$_.ProfileName}}, 
                    @{N="Domain Name"; E={$_.DomainName}},
                    @{N="Host Name"; E={$_.HostName}},
                    @{N="Domain Deployment Status"; E={$_.DomainDeploymentStatus}},
                    @{N="Domain Validation State"; E={$_.DomainValidationState}},
                    @{N="MinimumTlsVersion"; E={$_.MinimumTlsVersion}} | Format-Table -AutoSize -Wrap
    Write-Host $([Constants]::SingleDashLine)

    if (-not $Force)
    {
        Write-Host "Do you want to reset minimum TLS Version for all Front Door CDN Profile Domain(s)? " -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "Minimum TLS Version will not be reset for any Front Door CDN Profile Domain(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "User has provided consent to reset minimum TLS Version on all Front Door CDN Profile Domain(s)." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. Minimum TLS Version will be reset on all Front Door CDN Profile Domain(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 3 of 3] Reset Minimum TLS Version for Front Door CDN Profile Domain(s)" 
    Write-Host $([Constants]::SingleDashLine)

    # Includes Front Door CDN Profile Domain(s), to which, previously made changes were successfully rolled back.
    $frontDoorDomainRolledBack = @()

    # Includes Front Door CDN Profile Domain(s) that were skipped during roll back. There were errors rolling back the changes made previously.
    $frontDoorsDomainsSkipped = @()



    $validFrontDoorDomainDetails | ForEach-Object {
        $frontdoorDomain = $_
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.ProfileName
        $DomainName = $_.DomainName
        $minimumTlsVersion = $_.MinimumTlsVersion
        $PrevMinimumTlsVersion = $_.PrevMinimumTlsVersion
        try
        {
            Write-Host "Fetching Front Front Door CDN Profiles configuration: Domain Name: [$($DomainName)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
                $customDomain = Get-AzFrontDoorCdnCustomDomain -CustomDomainName $DomainName  -ProfileName $resourceName -ResourceGroupName $resourceGroupName
                if($customDomain -ne $null)
                {
                    $tlsSettings = $customDomain.TlsSetting
                    $tlsSettings.MinimumTlsVersion = $PrevMinimumTlsVersion
                    $updatedDomain = Update-AzFrontDoorCdnCustomDomain -CustomDomainName $DomainName  -ProfileName $resourceName -ResourceGroupName $resourceGroupName -TlsSetting $tlsSettings
                    if($updatedDomain -ne $null -and $updatedDomain.TlsSetting.MinimumTlsVersion -eq $PrevMinimumTlsVersion)
                    {
                        $frontDoorDomainRolledBack += $frontdoorDomain
                        Write-Host "Minimum required TLS version for Front Door CDN Profiles Domain has been Rolled back successfully for FrontDoor" ($resourceName) "with Domain" ($DomainName) -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    else
                    {
                        $frontDoorsDomainsSkipped += $frontdoorDomain
                        $logResource = @{}
                        $logResource.Add("DomainName",($_.DomainName))
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        $logResource.Add("ResourceName",($_.ProfileName))
                        $logResource.Add("Reason", "Error while Rolling back the minimum required TLS version. Skipping this Front Door CDN Profiles Domain.")
                        $logSkippedResources += $logResource
                        Write-Host "Error while Rolling back the minimum required TLS version for this Front Door CDN Profiles Domain." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "Skipping this Front Door." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                        return
                    }
                 
                }
                else
                {
                    $frontDoorsDomainsSkipped += $frontdoorDomain
                    $logResource = @{}
                    $logResource.Add("DomainName",($_.DomainName))
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ProfileName))
                    $logResource.Add("Reason", "Error while Rolling back the minimum required TLS version. Skipping this Front Door CDN Profiles Domain.")
                    $logSkippedResources += $logResource
                    Write-Host "Error while Rolling back the minimum required TLS version for this Front Door CDN Profiles Domain." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Front Door." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }                    
            }
            catch
            {
                $frontDoorsDomainsSkipped += $frontdoorDomain
                $logResource = @{}
                $logResource.Add("DomainName",($_.DomainName))
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ProfileName))
                $logResource.Add("Reason", "Error while resetting the minimum required TLS version on the domain. Skipping this Front Door CDN Profiles Domain.")
                $logSkippedResources += $logResource
                Write-Host "Error while resetting the minimum required TLS version on the domain of Front Door CDN Profiles Domain." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                return
            }   
        }

        Write-Host "Successfully rolled back changes on the Front Door." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)

    if (($frontDoorsDomainsSkipped | Measure-Object).Count -eq 0)
    {
        Write-Host "Minimum TLS Version successfully reset on the for all [$($totalFrontDoorEndpoints)] Front Door Domain(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Minimum TLS Version successfully reset for [$($($frontDoorDomainRolledBack | Measure-Object).Count)] out of [$($totalFrontDoorEndpoints)] Front Door Domain(s)" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    $colsProperty =     @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ProfileName};Label="Profile Name";Width=20;Alignment="left"},
                        @{Expression={$_.DomainName};Label="Domain Name";Width=20;Alignment="left"},
                        @{Expression={$_.HostName};Label="Host Name";Width=20;Alignment="left"},
                        @{Expression={$_.DomainDeploymentStatus};Label="Domain Deployment Status";Width=20;Alignment="left"},
                        @{Expression={$_.DomainValidationState};Label="Domain Validation State";Width=20;Alignment="left"},
                        @{Expression={$_.MinimumTlsVersion};Label="Minimum Tls Version";Width=20;Alignment="left"}
                        
    if ($($frontDoorDomainRolledBack | Measure-Object).Count -gt 0 -or $($frontDoorsDomainsSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($frontDoorDomainRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Minimum TLS Version successfully reset on the following Front Door Domain(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $frontDoorDomainRolledBack | Format-Table -Property $colsProperty -Wrap -AutoSize
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $frontDoorDomainRolledBackFile = "$($backupFolderPath)\RolledBackCdnFrontDoors.csv"
            $frontDoorDomainRolledBack | Export-CSV -Path $frontDoorDomainRolledBackFile -NoTypeInformation
            Write-Host "Note: This information has been saved to [$($frontDoorDomainRolledBackFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($frontDoorsDomainsSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error resetting minimum TLS Version for the following Front Door CDN Profiles Domain(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $frontDoorsDomainsSkipped | Format-Table -Property $colsProperty -Wrap -AutoSize
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $frontDoorSkippedFile = "$($backupFolderPath)\RollbackSkippedCdnFrontDoors.csv"
            $frontDoorsDomainsSkipped | Export-CSV -Path $frontDoorSkippedFile -NoTypeInformation
            Write-Host "Note: This information has been saved to [$($frontDoorSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
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

class FrontendEndPointsClass
{
    [string] $MinTLSVersion
    [string] $TypeOfCertificate
    [string] $DomainName
    [string] $FrontDoorName
    [string] $ResourceGroup
}
