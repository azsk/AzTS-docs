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
    Write-Host "Required modules are: $($requiredModule -join ', ')" -ForegroundColor Cyan
    Write-Host "Checking for required modules..."
    $availableModules = $(Get-Module -ListAvailable $requiredModule)

    # Checking if required module is available in user machine
    $requiredModule | ForEach-Object {
        if($availableModules.Name -notcontains $_)
        {
            Write-Host "Installing module $($_)..." -ForegroundColor Yellow
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery'
        }
        else {
            Write-Host "$($_) module is available." -ForegroundColor Green
        }
    }
}

function Disable-RemoteDesktopAccess
{
    <#
        .SYNOPSIS
        This command would help in remediating 'Azure_CloudService_SI_Disable_RemoteDesktop_Access' control.
        .DESCRIPTION
        This command would help in remediating 'Azure_CloudService_SI_Disable_RemoteDesktop_Access' control.
        .PARAMETER SubscriptionId
            Enter subscription id on which remediation need to perform.
        .PARAMETER Path
            Json file path which contain failed controls detail to remediate.
        .Parameter Force
            To disable RDP access forcefully.
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id for remediation")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $false, HelpMessage="Json file path which contain cloud service(s) details to remediate")]
        $Path,

        [switch]
        $Force
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Starting to disable remote desktop access on cloud service(s) from subscription [$($SubscriptionId)]..."
    Write-Host $([Constants]::SingleDashLine)
    
    try 
    {
        Write-Host "Checking for pre-requisites..."
        Pre_requisites
        Write-Host $([Constants]::SingleDashLine)     
    }
    catch 
    {
        Write-Host "Error occured while checking pre-requisites. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)    
        break
    }
    
    # Connect to AzAccount
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet))
    {       
        Write-Host "Connecting to AzAccount..."
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to AzAccount" -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -Force -ErrorAction Stop
    Select-AzureSubscription -SubscriptionId $($SubscriptionId) -ErrorAction Stop
    
    Write-Host "Note: `n Cloud services on which RDP was enabled, during the deployment will not be remediated(These need to be remediated via azure portal)." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host "------------------------------------------------------"
    Write-Host "Metadata Details: `n SubscriptionName: $($currentSub.Subscription.Name) `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)  
    Write-Host "Starting with subscription [$($SubscriptionId)]..."
    Write-Host "`n"
    Write-Host "*** To disable RDP access user must have atleast contributor access on cloud service(s) of Subscription: [$($SubscriptionId)] ***" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host "`n" 
    Write-Host "Validating whether the current user [$($currentSub.Account.Id)] has valid account type [User] to run the script for subscription [$($SubscriptionId)]..."
    
    # Safe Check: Checking whether the current account is of type User
    if($currentSub.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        break;
    }
    
    Write-Host "Successfully validated" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "`t"
    Write-Host "Fetching cloud service(s)..."
    $controlIds = "Azure_CloudService_SI_Disable_RemoteDesktop_Access"
    
    # Array to store resources
    $resources = @()
    $resourceType = "Microsoft.ClassicCompute/domainNames"

    # If json path not given fetch all cloud service.
    if([string]::IsNullOrWhiteSpace($Path))
    {
        $resources = Get-AzResource -ResourceType $resourceType
    }
    else
    {
        if (-not (Test-Path -Path $Path))
        {
            Write-Host "Error: Json file containing cloud service(s) detail not found for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            break;        
        }

        # Fetching cloud service details for remediation.
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
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
    $folderPath = [Environment]::GetFolderPath("LocalApplicationData") 
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
            $rdpExtensions = @()
            
            # Fetching cloud service(s) slot i.e. Staging, Production 
            $cloudServiceSlots = Get-AzResource -ResourceGroupName $resource.ResourceGroupName -Name $resource.Name -ResourceType "$resourceType/slots" -ApiVersion "2016-04-01"
            $cloudServiceSlotsName = $cloudServiceSlots.Name | sort -Unique
            
            # Checking RDP extension on each slots
            $cloudServiceSlotsName | ForEach-Object {
                $slot = $_
                $cloudServiceExtension = Get-AzureServiceRemoteDesktopExtension -ServiceName $resource.Name -Slot $slot -ErrorAction SilentlyContinue
                $rdpExtensions += $cloudServiceExtension | Where-Object { ($null -ne $_) -and ($_.Extension -like "*RDP*") } | select @{N='Slot'; E={$slot}}, @{N='UserName'; E={$_.UserName}}, @{N='Role'; E={$_.Role}}, @{N='Id'; E={$_.Id}}
            }
            
            # Checking RDP extension is present on cloud service(s)
            if(($rdpExtensions | Measure-Object).Count -gt 0)
            {
                $item =  New-Object psobject -Property @{  
                    CloudServiceName = $_.Name                
                    ResourceGroupName = $_.ResourceGroupName
                    RDPExtensionDetails = $rdpExtensions
                }
                    
                $cloudServiceWithEnabledRDPAccess += $item        
            }
            else {
                $cloudServiceWithDisabledRDPAccess += $_ | Select-Object @{Expression={($resource.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$resource.Name};Label="CloudServiceName"}
            }
        }   
    }
    catch {
        Write-Host "Error occured while checking config of cloud service(s). ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
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
            # Creating the log file
            Write-Host "Backing up config of cloud service(s) detail." -ForegroundColor $([Constants]::MessageType.Info)
            $cloudServiceWithEnabledRDPAccess | ConvertTo-json | out-file "$($folderpath)\CloudServiceWithEnabledRDPAccess.json"  
            Write-Host "Path: $($folderpath)\CloudServiceWithEnabledRDPAccess.json"     
            
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
                    
                    # Disabling RDP access
                    $_.RDPExtensionDetails | ForEach-Object {
                        
                        # TODO: Add 'UninstallConfiguration' switch to remove extension configurations associated with the service 
                        $output = Remove-AzureServiceRemoteDesktopExtension -ServiceName $serviceName -Slot $_.Slot -Role $_.Role -ErrorAction SilentlyContinue
                        if($null -eq $output -and $output.OperationStatus -ine "Succeeded")
                        {
                            $item =  New-Object psobject -Property @{  
                                CloudServiceName = $serviceName                
                                ResourceGroupName = $rgName
                            }
    
                            $skippedCloudServiceFromRemediation += $item
                            break;
                        }
                    }

                    if(($skippedCloudServiceFromRemediation | Measure-Object).Count -eq 0)
                    {
                        $_ | Select-Object @{Expression={($_.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$_.CloudServiceName};Label="CloudServiceName"} | Sort-Object | Format-Table | Out-String
                    }
                }
            }
            catch
            {
                $item =  New-Object psobject -Property @{  
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
        Write-Host "Error occured while performing remediation. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
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
