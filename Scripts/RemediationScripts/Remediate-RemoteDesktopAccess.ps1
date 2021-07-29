<##########################################

# Overview:
    This script is used to disable remote Desktop (RDP) access on cloud service(s).

ControlId: 
    Azure_CloudService_SI_Disable_RemoteDesktop_Access

DisplayName:
    Remote Desktop (RDP) access must be disabled on cloud service roles.    

# Pre-requisites:
    You will need co-administrator role on subscription.

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

    Write-Host "Required modules are: Az.Account, Az.Resources, Azure" -ForegroundColor Cyan
    Write-Host "Checking for required modules..."
    $availableModules = $(Get-Module -ListAvailable Az.Resources, Az.Accounts, Azure)
    
    # Checking if 'Az.Accounts' module is available or not.
    if($availableModules.Name -notcontains 'Az.Accounts')
    {
        Write-Host "Installing module Az.Accounts..." -ForegroundColor Yellow
        Install-Module -Name Az.Accounts -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "Az.Accounts module is available." -ForegroundColor Green
    }
    
    # Checking if 'Az.Resources' module is available or not.
    if($availableModules.Name -notcontains 'Az.Resources')
    {
        Write-Host "Installing module Az.Resources..." -ForegroundColor Yellow
        Install-Module -Name Az.Resources -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "Az.Resources module is available." -ForegroundColor Green
    }

    # Checking if 'Azure' module with required version is available or not.
    if($availableModules.Name -notcontains 'Azure')
    {
        Write-Host "Installing module Azure..." -ForegroundColor Yellow
        Install-Module -Name Azure -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "Azure module is available." -ForegroundColor Green
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
    Write-Host "Metadata Details: `n SubscriptionName: $($currentSub.Subscription.Name) `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)  
    Write-Host "Starting with subscription [$($SubscriptionId)]..."
    Write-Host "Validating whether the current user [$($currentSub.Account.Id)] has valid account type [User] to run the script for subscription [$($SubscriptionId)]..."
    
    # Safe Check: Checking whether the current account is of type User
    if($currentSub.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        break;
    }
    
    # Safe Check: Current user need to be co-administrator for the subscription
    $currentLoginRoleAssignments = Get-azroleassignment -Scope "/subscriptions/$($SubscriptionId)" -IncludeClassicAdministrators | Where-Object { $_.SignInName -eq $currentSub.Account.Id }
    $requiredRoleDefinitionName = @("CoAdministrator")
    if(($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -in $requiredRoleDefinitionName} | Measure-Object).Count -le 0 )
    {
        Write-Host "Warning: This script can only be run by an [$($requiredRoleDefinitionName -join ", ")]." -ForegroundColor Yellow
        return;
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
            $rdpExtensions = $()
            $cloudServiceExtension = Get-AzureServiceRemoteDesktopExtension -ServiceName $_.Name -ErrorAction SilentlyContinue
            
            $rdpExtensions += $cloudServiceExtension | Where-Object { ($null -ne $_) -and ($_.Extension -like "*RDP*") }
            
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
                Write-Host "Do you want to disable RDP access on above listed cloud service(s)?" -ForegroundColor Yellow -NoNewline
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
                    # Disabling RDP access at service level
                    $output = $_.RDPExtensionDetails | Remove-AzureServiceRemoteDesktopExtension -ServiceName $_.CloudServiceName -ErrorAction SilentlyContinue
                    
                    if($null -ne $output)
                    {
                        $_ | Select-Object @{Expression={($_.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$_.CloudServiceName};Label="CloudServiceName"} | Sort-Object | Format-Table | Out-String
                    }
                    else
                    {
                        $item =  New-Object psobject -Property @{  
                            CloudServiceName = $_.CloudServiceName                
                            ResourceGroupName = $_.ResourceGroupName
                        }
    
                        $skippedCloudServiceFromRemediation += $item
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
        Write-Host "Successfully disabled RDP access on cloud service(s)." -ForegroundColor $([Constants]::MessageType.Update)
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