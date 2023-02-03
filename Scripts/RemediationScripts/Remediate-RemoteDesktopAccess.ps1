<##########################################

# Overview:
    This script is used to disable remote Desktop (RDP) access on cloud service(s).

ControlId: 
    Azure_CloudService_SI_Disable_RemoteDesktop_Access

DisplayName:
    Remote Desktop (RDP) access must be disabled on cloud service roles.    

# Pre-requisites:
    You will need atleast contributor role on cloud service(s) of subscription.

# Steps performed by the script
    1. Install and validate pre-requisites to run the script.

    2. Get cloud service(s) with enabled remote desktop (RDP) access.
        a. For given cloud service(s) present in input json file.
                          ----OR----
        b. For all cloud service(s) present in subscription.

    3. Taking backup of config of cloud service(s) with enabled remote desktop access that are going to be remediated using remediation script.

    4. Disabling remote desktop access from cloud service(s).

# Step to execute script:
    Download and load remediation script in PowerShell session and execute below command.
    To know how to load script in PowerShell session refer link: https://aka.ms/AzTS-docs/RemediationscriptExcSteps.

# Command to execute:
    Examples:
        1. Run below command to disable remote desktop access from all cloud service(s) of subscription
        Disable-RemoteDesktopAccess -SubscriptionId '<Sub_Id>' -Force

        2. Run below command to disable remote desktop access from given cloud service(s)
        Disable-RemoteDesktopAccess -SubscriptionId '<Sub_Id>' -Path '<Json file path containing cloud service(s) detail>' -Force

        Note: [Recommended] Use -DryRun switch to get details of Cloud service(s) in CSV for pre-check.

To know more about parameter execute:
    a. Get-Help Disable-RemoteDesktopAccess -Detailed

########################################
#>

function Setup-Prerequisites
{
    <#
        .SYNOPSIS
        This command would check pre requisites modules.
        .DESCRIPTION
        This command would check pre requisites modules to perform remediation.
	#>

    # List of required modules
    $requiredModules = @("Az.Resources", "Az.Accounts", "Azure")
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

function Disable-RemoteDesktopAccess
{
    <#
        .SYNOPSIS
        Remediates 'Azure_CloudService_SI_Disable_RemoteDesktop_Access' control.

        .DESCRIPTION
        Remediates 'Azure_CloudService_SI_Disable_RemoteDesktop_Access' control.

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
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 5] Validate and install the modules required to run the script and validating the user"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
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
    
    if(-not($AutoRemediation))
    {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    
    # Safe Check: Checking whether the current account is of type User
    if($context.Account.Type -ne "User")
    {
        Write-Host "This script can only be run by 'User' account type." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return;
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run the script." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    
    Write-Host "To disable RDP access user must have classic role assignment on Subscription: [$($SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)

    #list to store cloud service(s)
    $cloudServices = @()
    $resourceType = "Microsoft.ClassicCompute/domainNames"

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    $controlIds = "Azure_CloudService_SI_Disable_RemoteDesktop_Access"

    Write-Host "[Step 2 of 5] Fetch all Cloud Service(s)"
    Write-Host $([Constants]::SingleDashLine)

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "Error: File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "Fetching all Cloud Service(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Cloud Service(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            try
            {
                $cloudServices += Get-AzResource -ResourceId $_.ResourceId
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
                return
            }
        }
    }
    else
    {
        # If json path not given fetch all cloud service.
        if([string]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all Cloud Service(s) in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            #Get all cloud service(s) in a subscription
            $cloudServices = Get-AzResource -ResourceType $resourceType -ErrorAction Stop

        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                return      
            }

            Write-Host "Fetching all Cloud Service(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Fetching cloud service details for remediation.
            $cloudServicesDetails = Import-Csv -LiteralPath $FilePath
            $validCloudServices = $cloudServicesDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

            $validCloudServices | ForEach-Object { 
                try
                {
                    $cloudServices += Get-AzResource -ResourceId $_.ResourceId
                }
                catch
                {
                    Write-Host "Error while fetching Cloud Service resource: Resource ID: [$($resourceId)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Cloud Service..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
        }
    }

    $totalCloudService = ($cloudServices | Measure-Object).Count
    if($totalCloudService -eq 0)
    {
        Write-Host "No Cloud Service(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning);
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($totalCloudService)] Cloud Service(s)." -ForegroundColor $([Constants]::MessageType.Update)                                                         
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 3 of 5] Fetch all Cloud Service(s) Configuration"
    Write-Host $([Constants]::SingleDashLine)

    $cloudServiceWithEnabledRDPAccess = @()
    $cloudServiceWithDisabledRDPAccess = @()
    $cloudServiceEncounteredError = @()

    # Checking cloud service(s) with enabled RDP acccess
    $cloudServices |  ForEach-Object {
        try {
            $resource = $_
            $rdpEnabledViaExtension = @()
            $rdpEnabledViaConfig = @()
            
            # Fetching cloud service(s) slot i.e. Staging, Production 
            $cloudServiceSlots = Get-AzResource -ResourceGroupName $resource.ResourceGroupName -Name $resource.Name -ResourceType "$resourceType/slots" -ApiVersion "2016-04-01"
            $cloudServiceSlotsName = $cloudServiceSlots.Name | sort -Unique
            
            # Checking RDP extension on each slots
            $cloudServiceSlotsName | ForEach-Object {
                $slot = $_

                # Get Deployment Slot configuration. This will contain Remote Access status for each of the Cloud Service Roles.
                $slotInfo = Get-AzureDeployment -ServiceName $resource.Name -Slot $slot

                if (($null -ne $slotInfo) -and ($null -ne $slotInfo.RolesConfiguration))
                {
                    foreach ($roleConfig in $slotInfo.RolesConfiguration.GetEnumerator())
                    {
                        # Check if Remote Access is enabled for each of the Cloud Service Roles.
                        if ($roleConfig.Value.Settings.Keys.Contains("Microsoft.WindowsAzure.Plugins.RemoteAccess.Enabled"))
                        {
                            if ($roleConfig.Value.Settings["Microsoft.WindowsAzure.Plugins.RemoteAccess.Enabled"] -eq "true")
                            {
                                # Book-keep the Deployment Slot configuration for it to be used to disable Remote Access.
                                $slotConfiguration = [xml]$slotInfo.Configuration
                                $rdpEnabledViaConfig += $roleConfig | select @{N='Slot'; E={$slot}}, @{N='Role'; E={$roleConfig.Key}}, @{N='UserName'; E={$roleConfig.Value.Settings["Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountUsername"]}}, @{N='SlotConfiguration'; E={$slotConfiguration}}
                            }
                        }
                    }
                }

                $cloudServiceExtension = Get-AzureServiceRemoteDesktopExtension -ServiceName $resource.Name -Slot $slot -ErrorAction SilentlyContinue
                $rdpEnabledViaExtension += $cloudServiceExtension | Where-Object { ($null -ne $_) -and ($_.Extension -like "*RDP*") } | select @{N='Slot'; E={$slot}}, @{N='Role'; E={$_.Role}}, @{N='UserName'; E={$_.UserName}}, @{N='Id'; E={$_.Id}}
            }
            
            # Checking if RDP is enabled via extension
            if(($rdpEnabledViaExtension | Measure-Object).Count -gt 0)
            {
                $item = New-Object psobject -Property @{
                    CloudServiceName = $_.Name                
                    ResourceGroupName = $_.ResourceGroupName
                    IsEnabledViaExtension = $true
                    RemoteAccessDetails = $rdpEnabledViaExtension
                    ResourceId = $_.ResourceId
                }

                $cloudServiceWithEnabledRDPAccess += $item
            }
            # Checking if RDP is enabled via configuration
            elseif(($rdpEnabledViaConfig | Measure-Object).Count -gt 0)
            {
                $item = New-Object psobject -Property @{
                    CloudServiceName = $_.Name
                    ResourceGroupName = $_.ResourceGroupName
                    IsEnabledViaExtension = $false
                    RemoteAccessDetails = $rdpEnabledViaConfig
                    ResourceId = $_.ResourceId
                }
                    
                $cloudServiceWithEnabledRDPAccess += $item        
            }
            else {
                $cloudServiceWithDisabledRDPAccess += $_ | Select-Object @{Expression={($resource.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$resource.Name};Label="CloudServiceName"}
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($resource.ResourceGroupName))
                $logResource.Add("ResourceName",($resource.Name))
                $logResource.Add("Reason","Remote Desktop Access is disabled in the Cloud Service.")    
                $logSkippedResources += $logResource
            }
        }
        catch 
        {
            cloudServiceEncounteredError += $_ | Select-Object @{Expression={($resource.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$resource.Name};Label="CloudServiceName"}
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($resource.ResourceGroupName))
            $logResource.Add("ResourceName",($resource.Name))
            $logResource.Add("Reason","Error encountered while processing configuration for the Cloud Service. Error: [$($_)]")    
            $logSkippedResources += $logResource
            return
        }
    }
    
    $totalCloudServiceWithEnableRDPAccess = ($cloudServiceWithEnabledRDPAccess | Measure-Object).Count
    $totalCloudServiceWithDisabledRDPAccess = ($cloudServiceWithDisabledRDPAccess | Measure-Object).Count
    $totalCloudServicesEncounteredError = ($cloudServiceEncounteredError | Measure-Object).Count
    
    if ($totalCloudServiceWithEnableRDPAccess -eq 0)
    {
        Write-Host "No Cloud Service found with Remote Desktop Access enabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation -and $totalCloudService -gt 0) 
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 100  | Out-File $logFile
        }
        return
    }

    Write-Host "Cloud service(s) with enabled RDP access: [$($totalCloudServiceWithEnableRDPAccess)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "Cloud service(s) with disabled RDP access: [$($totalCloudServiceWithDisabledRDPAccess)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "Cloud service(s) which encountered error while processing configuration: [$($totalCloudServicesEncounteredError)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 4 of 5] Back up Cloud Service(s) details"
    Write-Host $([Constants]::SingleDashLine)
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DisableRemoteDesktopAccess"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    $backupFile = "$($backupFolderPath)\CloudServiceWithRDPEnabled.csv"
    $cloudServiceDeatilsWithEnabledRDP = $cloudServiceWithEnabledRDPAccess | Select-Object CloudServiceName, IsEnabledViaExtension, ResourceGroupName, @{Name = 'RemoteAccessDetails'; expression = { $_.RemoteAccessDetails | Select-Object Slot, Role, UserName, Id }}
    $cloudServiceWithEnabledRDPAccess | Export-CSV -Path $backupFile -NoTypeInformation

    Write-Host "Successfully backed up Cloud Services details to [$($backupFolderPath)]." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 5 of 5] Disable Remote Desktop Access for Cloud Services"
    Write-Host $([Constants]::SingleDashLine)

    if(-not $DryRun)
    {
        if(-not $AutoRemediation)
        {
            # Asking user to verify logs and select 'Y' to proceed
            if(-not $Force)
            {
                Write-Host "Rollback command is not available.`nDo you want to disable Remote Desktop(RDP) Access from cloud services listed in above path?" -NoNewline -ForegroundColor $([Constants]::MessageType.Warning)

                $userInput = Read-Host -Prompt "(Y|N)"
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "RDP Access will not be disabled." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host "Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::DoubleDashLine)
                    return;
                }
                Write-Host "User has provided consent to disable RDP Access from the Cloud Services." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                Write-Host "'Force' flag is provided. RDP Access will be disabled from cloud services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        # List for storing remediated Cloud Service(s)
        $cloudServicesRemediated = @()

        # List for storing remediated Cloud Service(s)
        $cloudServicesSkippedRemediation = @()

        $cloudServiceWithEnabledRDPAccess | ForEach-Object {
            $serviceName = $_.CloudServiceName
            $rgName = $_.ResourceGroupName
            $isServiceRemediated = $true
            $isEnabledViaExtension = $_.IsEnabledViaExtension

            try
            {
                Write-Host "Disabling RDP Access on the cloud service: [$($serviceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
                
                :innerLoop foreach($remoteAccessDetail in $_.RemoteAccessDetails){
                    $slotName = $remoteAccessDetail.Slot
                    $roleName = $remoteAccessDetail.Role

                    if($isEnabledViaExtension)
                    {
                        $output = Remove-AzureServiceRemoteDesktopExtension -ServiceName $serviceName -Slot $slotName -Role $roleName -ErrorAction SilentlyContinue
                        if($null -eq $output -and $output.OperationStatus -ine "Succeeded")
                        {
                            $item = New-Object psobject -Property @{
                                CloudServiceName = $serviceName
                                ResourceGroupName = $rgName
                                SlotName = $slotName
                                RoleName = $roleName
                            }

                            $isServiceRemediated = $false
                            $cloudServicesSkippedRemediation += $item
                            break innerLoop 
                        }
                    }
                    else
                    {
                        $index = 0
                        $slotConfiguration=[xml]$_.slotConfiguration
                        $slotConfiguration.ServiceConfiguration.Role | % {
                            if ($($_.name) -eq $roleName)
                            {
                                # The configuration (XML) retrieved from the Get-AzureDeployment command will be used in the call to Set-AzureDeployment, but, with Remote Access set to false.
                                $remoteAccessSetting = $slotConfiguration.ServiceConfiguration.Role[$index].ConfigurationSettings.Setting | Where-Object { $_.name -eq "Microsoft.WindowsAzure.Plugins.RemoteAccess.Enabled" }
                                $remoteAccessSetting.value = "false"

                                $configurationFile = "$($folderpath)\$serviceName_$slotName_$roleName.cfg"

                                # Create a temporary file to store this configuration and upload this file to the Cloud Service instance.
                                $slotConfiguration.Save($configurationFile)

                                $output = Set-AzureDeployment -Config -ServiceName $serviceName -Configuration $configurationFile -Slot $slotName -ErrorAction SilentlyContinue

                                # Remove the temporary file created previously.
                                Remove-Item($configurationFile)

                                if(($null -eq $output) -and ($output.OperationStatus -ine "Succeeded"))
                                {
                                    $item = New-Object psobject -Property @{
                                        CloudServiceName = $serviceName
                                        ResourceGroupName = $rgName
                                        SlotName = $slotName
                                        RoleName = $roleName
                                    }

                                    $isServiceRemediated = $false
                                    $cloudServicesSkippedRemediation += $item
                                    break innerLoop
                                }
                            }

                            $index++
                        }
                    }
                }
                
                if($isServiceRemediated)
                {
                    Write-Host "Remote Desktop Access has been successfully disabled." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    $item = New-Object psobject -Property @{
                        CloudServiceName = $serviceName
                        ResourceGroupName = $rgName
                        SlotName = $slotName
                        RoleName = $roleName
                    }
                    $cloudServicesRemediated += $item
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($rgName))
                    $logResource.Add("ResourceName",($serviceName))
                    $logRemediatedResources += $logResource
                }
                else
                {
                    Write-Host "Remote Desktop Access has not been successfully disabled." -ForegroundColor $([Constants]::MessageType.Error)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($rgName))
                    $logResource.Add("ResourceName",($serviceName))
                    $logResource.Add("Reason","Remote Desktop Access has not been successfully disabled.")    
                    $logSkippedResources += $logResource
                }
            }
            catch
            {
                $item = New-Object psobject -Property @{
                    CloudServiceName = $serviceName
                    ResourceGroupName = $rgName
                    SlotName = $slotName
                    RoleName = $roleName
                }
                $cloudServicesSkippedRemediation += $item
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($rgName))
                $logResource.Add("ResourceName",($serviceName))
                $logResource.Add("Reason","Error encountered while disabling Remote Desktop Access from the cloud service. Error: [$($_)]")    
                $logSkippedResources += $logResource
            }
        }

        if($AutoRemediation)
        {
            if ($($cloudServicesRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $cloudServicesRemediatedFile = "$($backupFolderPath)\RemediatedCloudServices.csv"
                $cloudServicesRemediated | Export-CSV -Path $cloudServicesRemediatedFile -NoTypeInformation
                Write-Host "Remote Desktop Access is disabled on the Cloud Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "`nThis information has been saved to [$($cloudServicesRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($cloudServicesSkippedRemediation | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $cloudServicesSkippedRemediationFile = "$($backupFolderPath)\SkippedRemediationCloudServices.csv"
                $cloudServicesSkippedRemediation | Export-CSV -Path $cloudServicesSkippedRemediationFile -NoTypeInformation
                Write-Host "Error disabling Remote Desktop Access on some Cloud Service(s)." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "`nThis information has been saved to [$($cloudServicesSkippedRemediationFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else 
        { 
            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
            if ($($cloudServicesRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Remote Desktop Access is successfully disabled on the following cloud service(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                $cloudServicesRemediated | Format-Table -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $cloudServicesRemediatedFile = "$($backupFolderPath)\RemediatedCloudServices.csv"
                $cloudServicesRemediated | Export-CSV -Path $cloudServicesRemediatedFile -NoTypeInformation
                Write-Host "`nThis information has been saved to [$($cloudServicesRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($cloudServicesSkippedRemediation | Measure-Object).Count -gt 0)
            {
                Write-Host "`nError disabling Remote Desktop Access on the following cloud service(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                $cloudServicesSkippedRemediation | Format-Table -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $cloudServicesSkippedRemediationFile = "$($backupFolderPath)\SkippedRemediationCloudServices.csv"
                $cloudServicesSkippedRemediation | Export-CSV -Path $cloudServicesSkippedRemediationFile -NoTypeInformation
                Write-Host "`nThis information has been saved to [$($cloudServicesSkippedRemediationFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        if($AutoRemediation){
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 100  | Out-File $logFile
        }

    }
    else
    {
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:`n" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to disable Remote Desktop Access for all Cloud Service resources listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
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

# ***************************************************** #
<#
Run below command to disable remote desktop access from all cloud service(s) of subscription.
Disable-RemoteDesktopAccess -SubscriptionId '<Sub_Id>' `
                            -DryRun

Note: Use -DryRun switch to get details of Cloud service(s) in CSV for pre-check.

Run below command to disable remote desktop access of cloud service(s) for given json file. 
Disable-RemoteDesktopAccess -SubscriptionId '<Sub_Id>' `
                            -Path '<Json file path containing Cloud service details>'`
                            -Force
#>
