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

function Pre_requisites
{
    <#
        .SYNOPSIS
        This command would check pre requisites modules.
        .DESCRIPTION
        This command would check pre requisites modules to perform remediation.
	#>

    # List of required modules
    $requiredModule = @("Az.Resources", "Az.Accounts", "Azure")
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
        Enter subscription id on which remediation need to perform.

        .PARAMETER FilePath
        Json file path which contain failed controls detail to remediate.

        .PARAMETER Force
        To disable RDP access forcefully.

        .PARAMETER DryRun
        Run pre-script before actual remediating Cloud service in the subscription.

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
            Write-Host "[Step 1 of 4] Validate and install the modules required to run the script and validating the user"
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
        Write-Host "[Step 1 of 4] Validate the user" 
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
    if($currentSub.Account.Type -ne "User")
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

    $controlIds = "Azure_CloudService_SI_Disable_RemoteDesktop_Access"
    
    # Array to store resources
    $resources = @()
    $resourceType = "Microsoft.ClassicCompute/domainNames"
    

    Write-Host "[Step 2 of 4] Fetch all Cloud Service(s)"
    Write-Host $([Constants]::SingleDashLine)
    # If json path not given fetch all cloud service.
    if([string]::IsNullOrWhiteSpace($FilePath))
    {
        $resources = Get-AzResource -ResourceType $resourceType
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "Error: Json file containing cloud service(s) detail not found for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            break;        
        }

        # Fetching cloud service details for remediation.
        $controlForRemediation = Get-content -path $FilePath | ConvertFrom-Json
        $controls = $controlForRemediation.FailedControlSet
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId};

        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($resourceDetails.ResourceDetails | Measure-Object).Count -eq 0)
        {
            Write-Host "No cloud service(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
        $resourceDetails.ResourceDetails | ForEach-Object { 
            try
            {
                $resources += Get-AzResource -ResourceId $_.ResourceId
            }
            catch
            {
                Write-Host "Valid resource group(s) or resource name(s) not found in input json file. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                break
            }
        }
    }

    $totalCloudService = ($resources | Measure-Object).Count
    if($totalCloudService -eq 0)
    {
        Write-Host "No cloud service(s) found." -ForegroundColor $([Constants]::MessageType.Error);
        Write-Host $([Constants]::DoubleDashLine)
        break;
    }

    Write-Host "Total cloud service(s): [$($totalCloudService)]"
    $folderPath = [Environment]::GetFolderPath("MyDocuments") 
    if (Test-Path -Path $folderPath)
    {
        $folderPath += "\AzTS\Remediation\Subscriptions\$($subscriptionid.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\DisableRemoteDesktopAccess"
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }

    Write-Host "Checking config of cloud service(s) for remediation: [$(($resources | Measure-Object).Count)]"
    
    try {
        $cloudServiceWithEnabledRDPAccess = @()
        $cloudServiceWithDisabledRDPAccess = @()
        $skippedCloudServiceFromRemediation = @()

        # Checking cloud service(s) with enabled RDP acccess
        $resources |  ForEach-Object {
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
                }
                    
                $cloudServiceWithEnabledRDPAccess += $item        
            }
            else {
                $cloudServiceWithDisabledRDPAccess += $_ | Select-Object @{Expression={($resource.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$resource.Name};Label="CloudServiceName"}
            }
        }   
    }
    catch {
        Write-Host "Error occurred while checking config of cloud service(s). ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        break
    }
    
    $totalCloudServiceWithEnableRDPAccess = ($cloudServiceWithEnabledRDPAccess | Measure-Object).Count
    $totalCloudServiceWithDisabledRDPAccess = ($cloudServiceWithDisabledRDPAccess | Measure-Object).Count
    
    Write-Host "Cloud service(s) with enabled RDP access: [$($totalCloudServiceWithEnableRDPAccess)]"
    Write-Host "Cloud service(s) with disabled RDP access: [$($totalCloudServiceWithDisabledRDPAccess)]"
    Write-Host "`t"

    # Performing remediation on cloud service(s).
    try
    {
        if ($totalCloudServiceWithEnableRDPAccess -gt 0)
        {
            if ($DryRun)
            {
                Write-Host "Exporting configurations of cloud service(s) having Remote Desktop enabled. You may want to use this CSV as a pre-check before actual remediation." -ForegroundColor Cyan
                $cloudServiceDeatilsWithEnabledRDP = $cloudServiceWithEnabledRDPAccess | Select-Object CloudServiceName, IsEnabledViaExtension, ResourceGroupName, @{Name = 'RemoteAccessDetails'; expression = { $_.RemoteAccessDetails | Select-Object Slot, Role, UserName, Id }}
                $cloudServiceDeatilsWithEnabledRDP | Export-CSV -Path "$($folderpath)\CloudServiceWithRDPEnabled.csv" -NoTypeInformation
                Write-Host "Path: $($folderPath)CloudServiceWithRDPEnabled.csv"
                return;
            }
            else
            {
                # Creating the log file
                Write-Host "Backing up config of cloud service(s) detail." -ForegroundColor $([Constants]::MessageType.Info)
                $cloudServiceWithEnabledRDPAccess | ConvertTo-json | out-file "$($folderpath)\CloudServiceWithEnabledRDPAccess.json"  
                Write-Host "Path: $($folderpath)\CloudServiceWithEnabledRDPAccess.json"    
            }

            # Asking user to verify logs and select 'Y' to proceed
            if(-not $Force)
            {
                Write-Host "Rollback script is not available.`nDo you want to disable RDP access from cloud service(s) listed in above path?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                $UserInput = Read-Host -Prompt "(Y|N)"
                if($UserInput -ne "Y")
                {
                    return;
                }
            }
            
            Write-Host "`t"
            Write-Host "Disabling RDP access on [$($totalCloudServiceWithEnableRDPAccess)] cloud service(s)..."
            try
            {
                $cloudServiceWithEnabledRDPAccess | ForEach-Object {
                    $serviceName = $_.CloudServiceName
                    $rgName = $_.ResourceGroupName
                    $isServiceRemediated = $true
                    $isEnabledViaExtension = $_.IsEnabledViaExtension

                    # Disabling RDP access
                    $_.RemoteAccessDetails | ForEach-Object {
                        $slotName = $_.Slot
                        $roleName = $_.Role

                        if ($isEnabledViaExtension)
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
                                $skippedCloudServiceFromRemediation += $item
                                break;
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
                                        $skippedCloudServiceFromRemediation += $item
                                        break
                                    }
                                }

                                $index++
                            }
                        }
                    }

                    if($isServiceRemediated)
                    {
                        $_ | Select-Object @{Expression={($_.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$_.CloudServiceName};Label="CloudServiceName"} | Sort-Object | Format-Table | Out-String
                    }
                }
            }
            catch
            {
                $item = New-Object psobject -Property @{
                    CloudServiceName = $_.CloudServiceName                
                    ResourceGroupName = $_.ResourceGroupName
                }
                $skippedCloudServiceFromRemediation += $item
            }       
        }
        else
        {
            Write-Host "No cloud service(s) found with enabled RDP access." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            break
        }  
    }
    catch {
        Write-Host "Error occurred while performing remediation. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    if(($skippedCloudServiceFromRemediation | Measure-Object).Count -eq 0)
    {
        Write-Host "Successfully disabled RDP access from cloud service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else 
    {
        Write-Host "Remediation was not successful on the following cloud service(s)" -ForegroundColor $([Constants]::MessageType.Warning)
        $skippedCloudServiceFromRemediation | Select-Object @{Expression={($_.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$_.CloudServiceName};Label="CloudServiceName"}
    }
}

class Constants
{
    static [Hashtable] $MessageType = @{
        Error = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info = [System.ConsoleColor]::Cyan
        Update = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [string] $DoubleDashLine    = "================================================================================"
    static [string] $SingleDashLine    = "--------------------------------------------------------------------------------"
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
