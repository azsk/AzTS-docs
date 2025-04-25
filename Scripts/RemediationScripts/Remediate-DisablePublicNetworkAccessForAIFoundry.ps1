<##########################################

# Overview:
    This script is used to set required public network access for Azure AI Foundry services in a Subscription.

# Control ID:
    Azure_AIFoundry_NetSec_Disable_Public_Network_Access

# Display Name:
    Public network access on Azure AI Foundry services should be disabled.

# Prerequisites:
    1. Contributor or higher privileges on the Azure AI Foundry services in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of Azure AI Foundry services in a Subscription that have public network access enabled.
        3. Back up details of Azure AI Foundry services that are to be remediated.
        4. Set public network access as 'Disabled' on all Azure AI Foundry services in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Azure AI Foundry services in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set public network access as 'Enabled' on all Azure AI Foundry services in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable public network access in all Azure AI Foundry services in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable public network access in all Azure AI Foundry services in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Azure AI Foundry services in a Subscription that will be remediated:
           Disable-AIFoundryPublicNetworkAccess -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To disable public network access on all Azure AI Foundry services in a Subscription:
           Disable-AIFoundryPublicNetworkAccess -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To disable public network access on all Azure AI Foundry services in a Subscription, from a previously taken snapshot:
           Disable-AIFoundryPublicNetworkAccess -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\disablePublicNetworkAccessForAIFoundry\AIFoundryWithPublicAccessEnabled.csv

        4. To disable public network access on all Azure AI Foundry services in a Subscription without taking back up before actual remediation:
           Disable-AIFoundryPublicNetworkAccess -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Disable-AIFoundryPublicNetworkAccess -Detailed

    To roll back:
        1. To reset public network access of all Azure AI Foundry services in a Subscription, from a previously taken snapshot:
           Enable-AIFoundryPublicNetworkAccess -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\disablePublicNetworkAccessForAIFoundry\RemediatedAIFoundry.csv

        To know more about the options supported by the roll back command, execute:
        Get-Help Enable-AIFoundryPublicNetworkAccess -Detailed

########################################
#>
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
    $requiredModules = @("Az.Accounts")

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
function Disable-AIFoundryPublicNetworkAccess {

    <#
        .SYNOPSIS
        Remediates 'Azure_AIFoundry_NetSec_Disable_Public_Network_Access' Control.

        .DESCRIPTION
        Remediates 'Azure_AIFoundry_NetSec_Disable_Public_Network_Access' Control.
        Public network access on Azure AI Foundry services should be disabled. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .PARAMETER PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER SkipBackup
        Specifies that no backup will be taken by the script before remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies the script is run as a subroutine of the AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of the file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Disable-AIFoundryPublicNetworkAccess.

        .OUTPUTS
        None. Disable-AIFoundryPublicNetworkAccess does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-AIFoundryPublicNetworkAccess -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Disable-AIFoundryPublicNetworkAccess -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Disable-AIFoundryPublicNetworkAccess -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\disablePublicNetworkAccessForAIFoundry\AIFoundryWithPublicAccessEnabled.csv

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

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies no back up will be taken by the script before remediation")]
        $SkipBackup,

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
    

    if(-not($AutoRemediation))	
    {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "To disable public network access on Azure AI Foundry services in a Subscription, Contributor or higher privileges on the Azure AI Foundry servicesAzure AI Foundry services are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 5] Fetch all Azure AI Foundry services"
    Write-Host $([Constants]::SingleDashLine)
    $aiFoundryResources = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()
    $aiFoundryAPI = "https://management.azure.com/subscriptions/abb5301a-22a4-41f9-9e5f-99badff261f8/providers/Microsoft.MachineLearningServices/workspaces?api-version=2024-10-01"
    # Control Id
    $controlIds = "Azure_AIFoundry_NetSec_Disable_Public_Network_Access"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "Fetching all Azure AI Foundry services failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceName)}

        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Azure AI Foundry service(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        } 

        $validResources | ForEach-Object { 
            try
            {
                $name = $_.ResourceName
                $resourceGroupName = $_.ResourceGroupName
                $resAIFoundry = Get-AzMLWorkspace  -Name $name -ResourceGroupName $resourceGroupName  -ErrorAction SilentlyContinue
                $aiFoundryResources = $aiFoundryResources + $resAIFoundry
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
            }
        }
    }
    else
    {
        # No file path provided as input to the script. Fetch all Azure AI Foundry service(s) in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all Azure AI Foundry service(s) in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all Azure AI Foundry service(s) in the Subscription
            #$aiFoundryResources = Get-AzMLWorkspace  -ErrorAction SilentlyContinue
            $aiFoundryResources = Fetch-API -Method Get -Uri $aiFoundryAPI -ErrorAction Stop

            $aiFoundryResources = $aiFoundryResources.value | Select-Object @{N='ResourceId';E={$_.Id}},    
                                                                @{N='ResourceGroupName';E={($_.Id -split '/')[4]}},
                                                                @{N='Name';E={$_.Name}},
                                                                @{N='PublicNetworkAccess';E={$_.Properties.publicNetworkAccess}},
                                                                @{N='Location';E={$_.Location}},
                                                                @{N='Kind';E={$_.Kind}},
                                                                @{N='ipAllowlist';E={$_.properties.ipAllowlist}}




            $totalAIFoundryResources = ($aiFoundryResources | Measure-Object).Count
        
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }

            Write-Host "Fetching all Azure AI Foundry service(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $aiFoundryResourcesFromFile = Import-Csv -LiteralPath $FilePath
            $aiFoundryResources = $saiFoundryResourcesFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceName)-and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName)}
                
        }
    }

    $totalAIFoundryResources = ($aiFoundryResources | Measure-Object).Count

    if ($totalAIFoundryResources -eq 0)
    {
        Write-Host "No Azure AI Foundry service(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($totalAIFoundryResources)] Azure AI Foundry service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
 
    # Includes Azure AI Foundry service(s) where public network access is Disabled  
    $aiFoundryWithPublicAccessDisabled= @()

    # Includes Azure AI Foundry service(s) where public network access is Enabled  
    $aiFoundryWithPublicAccessEnabled= @()

    # Includes Azure AI Foundry service(s) that were skipped during remediation. There were errors remediating them.
    $aiFoundrySkipped = @()

    Write-Host "[Step 3 of 5] Fetching Azure AI Foundry service(s)"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Azure AI Foundry service(s) for which public network access is not 'Disabled' ..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $excludekinds = @("Default", "FeatureStore", "Project")

    $aiFoundryResources | ForEach-Object {  
        $aiFoundryResource = $_  

        if($excludekinds -notcontains $_.Kind -and $_.ipAllowlist -eq $null)
        {
            if($_.PublicNetworkAccess -ne "Disabled")
            {
                
                $aiFoundryWithPublicAccessEnabled += $aiFoundryResource | Select-Object @{N='Name';E={$_.Name}},
                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                        @{N='Location';E={$_.Location}},
                                                        @{N='Kind';E={$_.Kind}},
                                                        @{N='PublicNetworkAccess';E={$_.PublicNetworkAccess}}
                  
            }
            else
            {
                $aiFoundryWithPublicAccessDisabled += $aiFoundryResource | Select-Object @{N='Name';E={$_.Name}},
                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                        @{N='Location';E={$_.Location}},
                                                        @{N='Kind';E={$_.Kind}},
                                                        @{N='PublicNetworkAccess';E={$_.PublicNetworkAccess}}

                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("Name",($_.Name))
                $logResource.Add("Reason","Public Network Access is already disabled in Azure AI Foundry service.")    
                $logSkippedResources += $logResource
                
            }
          }
    }
    $totalAIFoundryWithPublicAccessEnabled = ($aiFoundryWithPublicAccessEnabled | Measure-Object).Count
    
    if ($totalAIFoundryWithPublicAccessEnabled  -eq 0)
    {
        Write-Host "No Azure AI Foundry service(s) found where public network access is enabled.. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        
        if($AutoRemediation -and ($aiFoundryResources |Measure-Object).Count -gt 0) 
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }	

        return
    } 

    Write-Host "Found [$($totalAIFoundryWithPublicAccessEnabled)] Azure AI Foundry service(s) where public network access is not 'Disabled'." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
     
    if(-not($AutoRemediation))
    {
        Write-Host "Following Azure AI Foundry service(s) are :" -ForegroundColor $([Constants]::MessageType.Info)
        $colsProperty =     @{Expression={$_.Name};Label="Name";Width=30;Alignment="left"},
                            @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"},
                            @{Expression={$_.Location};Label="Location";Width=12;Alignment="left"},
                            @{Expression={$_.Kind};Label="Kind";Width=7;Alignment="left"},
                            @{Expression={$_.PublicNetworkAccess};Label="Public Network Access";Width=20;Alignment="left"}

        $aiFoundryWithPublicAccessEnabled | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\AIFoundryPublicNetworkAccess"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 4 of 5] Backing up Azure AI Foundry service(s) details"
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
        if(-not $SkipBackup)
        {
            # Backing up Azure AI Foundry service details.
            $backupFile = "$($backupFolderPath)\AIFoundryWithPublicAccessEnabled.csv"
            $aiFoundryWithPublicAccessEnabled | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "Azure AI Foundry service(s) details have been successful backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun)
    {  
         # Here AutoRemediation switch is used as there is no need to take user input at BRS level if user has given consent to proceed with the remediation in AutoRemediation Script.
        if(-not $AutoRemediation)
        {

            Write-Host "Public network accesss will be set as 'Disabled' on all Azure AI Foundry service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            if (-not $Force)
            {
                Write-Host "Do you want to disable public network access for all Azure AI Foundry service(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                
                $userInput = Read-Host -Prompt "(Y|N)" 
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "Public network access will not be changed for any Azure AI Foundry service(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    return
                }
                else
                {
                    Write-Host "Public network access will be set as 'Disabled' for all Azure AI Foundry service(s)" -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. Public network access will be set as 'Disabled' for all Azure AI Foundry service(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host "[Step 5 of 5] Configuring public network access for Azure AI Foundry service(s)"
        Write-Host $([Constants]::SingleDashLine)
        # To hold results from the remediation.
        $aiFoundryRemediated = @()
    
        # Remediate Controls by disabling public network access
        $aiFoundryWithPublicAccessEnabled | ForEach-Object {
            $aiFoundry = $_
            $Name = $_.Name;
            $resourceGroupName = $_.ResourceGroupName; 
            $publicNetworkAccess = $_.PublicNetworkAccess;

            # Holds the list of Azure AI Foundry service(s) where public network access change is skipped
            $aiFoundrySkipped = @()
            try
            {   
                Write-Host "Disabling public network access for Azure AI Foundry service : [$Name]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                $aiFoundryResponse = Update-AzMLWorkspace -ResourceGroupName $resourceGroupName -Name $Name -PublicNetworkAccess Disabled

                if ($aiFoundryResponse.PublicNetworkAccess -ne "Disabled")
                {
                    $aiFoundrySkipped += $aiFoundry
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("Name",($_.Name))
                    $logResource.Add("Reason", "Error while setting public network access for Azure AI Foundry service")
                    $logSkippedResources += $logResource    
                }
                else
                {
                    $aiFoundryRemediated += $aiFoundry | Select-Object @{N='Name';E={$Name}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='Location';E={$_.Location}},
                                                                        @{N='Kind';E={$_.Kind}}, 
                                                                        @{N='PublicNetworkAccessBeforeRemediation';E={$publicNetworkAccess}},
                                                                        @{N='PublicNetworkAccessAfterRemediation';E={$aiFoundryResponse.PublicNetworkAccess}}

                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("Name",($_.Name))
                    $logRemediatedResources += $logResource
 
                }
            }
            catch
            {
                $aiFoundrySkipped += $aiFoundry
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("Name",($_.Name))
                $logResource.Add("Reason", "Error while setting public network access for Azure AI Foundry service")
                $logSkippedResources += $logResource 
            }
        }

        $totalRemediatedAIFoundry = ($aiFoundryRemediated | Measure-Object).Count

        if ($totalRemediatedAIFoundry -eq ($aiFoundryWithPublicAccessEnabled | Measure-Object).Count)
        {
            Write-Host "Public network access changed to 'Disabled' for all [$($totalAIFoundryWithPublicAccessEnabled)] Azure AI Foundry service(s) ." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "Public network access changed to 'Disabled' for [$($totalRemediatedAIFoundry)] out of [$($totalAIFoundryWithPublicAccessEnabled)] Azure AI Foundry service(s)" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        $colsProperty = @{Expression={$_.Name};Label="Name";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"},
                        @{Expression={$_.Kind};Label="Kind";Width=7;Alignment="left"},
                        @{Expression={$_.PublicNetworkAccessBeforeRemediation};Label="Public Network Access(Before Remediation)";Width=15;Alignment="left"},
                        @{Expression={$_.PublicNetworkAccessAfterRemediation};Label="Public Network Access(After Remediation)";Width=15;Alignment="left"}
  
        if($AutoRemediation)
        {
            if ($($aiFoundryRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $aiFoundryRemediatedFile = "$($backupFolderPath)\RemediatedAIFoundryPublicNetworkAccess.csv"
                $aiFoundryRemediated| Export-CSV -Path $aiFoundryRemediatedFile -NoTypeInformation
                Write-Host "The information related to Azure AI Foundry service(s) where public network access is successfully disabled has been saved to [$($aiFoundryRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($aiFoundrySkipped | Measure-Object).Count -gt 0)
            {   
                # Write this to a file.
                $aiFoundrySkippedFile = "$($backupFolderPath)\SkippedaiFoundryPublicNetworkAccess.csv"
                $aiFoundrySkipped | Export-CSV -Path $aiFoundrySkippedFile -NoTypeInformation
                Write-Host "The information related to Azure AI Foundry service(s) where public network access is enabled has been saved to [$($aiFoundrySkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($aiFoundryRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Successfully set the public network access to 'Disabled' on the following Azure AI Foundry service(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $aiFoundryRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $aiFoundryRemediatedFile = "$($backupFolderPath)\RemediatedAIFoundryPublicNetworkAccess.csv"
                $aiFoundryRemediated| Export-CSV -Path $aiFoundryRemediatedFile -NoTypeInformation
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "This information has been saved to [$($aiFoundryRemediatedFile)]"
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }

             if ($($aiFoundrySkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error changing public network access for following Azure AI Foundry service(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $aiFoundrySkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $aiFoundrySkippedFile = "$($backupFolderPath)\SkippedAIFoundryPublicNetworkAccess.csv"
                $aiFoundrySkipped | Export-CSV -Path $aiFoundrySkippedFile -NoTypeInformation
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "This information has been saved to [$($aiFoundryResourcesSkippedFile)]"
                Write-Host $([Constants]::SingleDashLine)
            }
    }

    if($AutoRemediation)
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources 
                    $logControl.RollbackFile = $aiFoundryRemediatedFile
                }
            }
            
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }

    }
    else
    {
        Write-Host "[Step 5 of 5] Disabling public network access for Azure AI Foundry service(s)"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps: " -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to disable public network access for all Azure AI Foundry service(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
    }  

}
function Enable-AIFoundryPublicNetworkAccess {

<#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_AIFoundry_NetSec_Disable_Public_Network_Access' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_AIFoundry_NetSec_Disable_Public_Network_Access' Control.
        Resets public network access to 'Enabled' for all Azure AI Foundry services in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Enable-AIFoundryPublicNetworkAccess.

        .OUTPUTS
        None. Enable-AIFoundryPublicNetworkAccess does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-AIFoundryPublicNetworkAccess -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\disablePublicNetworkAccessForAIFoundry\RemediatedAIFoundry.csv

        .EXAMPLE
        PS> Enable-AIFoundryPublicNetworkAccess -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -ExcludeNonProductionSlots -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\disablePublicNetworkAccessForAIFoundry\RemediatedAIFoundry.csv

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

    Write-Host "To reset public network access for Azure AI Foundry service(s) in a Subscription, Contributor or higher privileges on the Azure AI Foundry service(s) are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Azure AI Foundry service(s)"
    Write-Host $([Constants]::SingleDashLine)
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Fetching all Azure AI Foundry service(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
       
    $aiFoundryFromFile = Import-Csv -LiteralPath $FilePath
    $validAIFoundry = $aiFoundryFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.Name) }
    
    $aiFoundryResources = @()
    $aiFoundryList = @()

    $validAIFoundry | ForEach-Object {
        $aiFoundry = $_
        $Name = $_.Name
        $resourceGroupName = $_.ResourceGroupName
        $publicNetworkAccessBeforeRemediation = $_.PublicNetworkAccessBeforeRemediation
        $publicNetworkAccessAfterRemediation = $_.PublicNetworkAccessAfterRemediation

        try
        {
            $aiFoundryList = ( Get-AzMLWorkspace -Name $Name  -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue) 
            $aiFoundryResources += $aiFoundryList | Select-Object @{N='Name';E={$Name}},
                                                            @{N='ResourceGroupName';E={$resourceGroupName}},
                                                            @{N='Location';E={$_.Location}},
                                                            @{N='Kind';E={$_.Kind}},
                                                            @{N='CurrentPublicNetworkAccess';E={$_.PublicNetworkAccess}},
                                                            @{N='PreviousPublicNetworkAccess';E={$publicNetworkAccessBeforeRemediation}}
                                                                
        }
        catch
        {
            Write-Host "Error fetching Azure AI Foundry service : [$($Name)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this Azure AI Foundry service..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
    }

    # Includes Azure AI Foundry service(s)
    $aiFoundryWithPublicAccessEnabled = @()
 
    Write-Host "[Step 3 of 4] Fetching SAzure AI Foundry service(s)"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Azure AI Foundry service(s) where public network access is Enabled..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $aiFoundryResources | ForEach-Object {
        $aiFoundry = $_        
            if($aiFoundry.CurrentPublicNetworkAccess -ne 'Enabled')
            {
                $aiFoundryWithPublicAccessEnabled += $aiFoundry
            }
    }

    $totalAIFoundryWithPublicAccessEnabled = ($aiFoundryWithPublicAccessEnabled | Measure-Object).Count

    if ($totalAIFoundryWithPublicAccessEnabled  -eq 0)
    {
        Write-Host "No Azure AI Foundry service(s) found where public network access need to be changed.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }
    
    Write-Host "Found [$($totalAIFoundryWithPublicAccessEnabled)] Azure AI Foundry service(s) " -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
    
     # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableAIFoundryPublicNetworkAccess"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    } 
    
    if (-not $Force)
    {
        Write-Host "Do you want to enable public network access for all Azure AI Foundry service(s)?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "Public network access will not be enabled for any of the Azure AI Foundry service(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Public network access will be enabled for all of the Azure AI Foundry service(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 4 of 4] Enabling public network access for Azure AI Foundry service(s)"
    Write-Host $([Constants]::SingleDashLine)
    # Includes Azure AI Foundry service(s), to which, previously made changes were successfully rolled back.
    $aiFoundryRolledBack = @()

    # Includes Azure AI Foundry service(s) that were skipped during roll back. There were errors rolling back the changes made previously.
    $aiFoundrySkipped = @()
   
     # Roll back by enabling public network access 
        $aiFoundryWithPublicAccessEnabled | ForEach-Object {
            $aiFoundry = $_
            $Name = $_.Name
            $resourceGroupName = $_.ResourceGroupName
            $currentPublicNetworkAccess = $_.CurrentPublicNetworkAccess
            $previousPublicNetworkAccess = $_.PreviousPublicNetworkAccess
           
            try
            {  
                
                Write-Host "Enabling public network access for Azure AI Foundry service : [$Name]" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                $aiFoundryResource =  Update-AzMLWorkspace -Name $Name  -ResourceGroupName $resourceGroupName -PublicNetworkAccess $previousPublicNetworkAccess

                if ($aiFoundryResource.PublicNetworkAccess -ne $publicNetworkAccessBeforeRemediation)
                {
                    $aiFoundrySkipped += $aiFoundry
                       
                }
                else
                {
                    $aiFoundryRolledBack += $aiFoundry | Select-Object @{N='Name';E={$Name}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='Location';E={$_.Location}},
                                                                        @{N='Kind';E={$_.Kind}}, 
                                                                        @{N='PublicNetworkAccessBeforeRollback';E={$currentPublicNetworkAccess}},
                                                                        @{N='PublicNetworkAccessAfterRollback';E={$aiFoundryResource.PublicNetworkAccess}}
                }
            }
            catch
            {
                $aiFoundrySkipped += $aiFoundry
            }
       }
    
    $totalAIFoundryRolledBack = ($aiFoundryRolledBack | Measure-Object).Count

    if ($totalAIFoundryRolledBack -eq $totalAIFoundryWithPublicAccessEnabled)
    {
        Write-Host "Public network access enabled for all [$($totalAIFoundryWithPublicAccessEnabled)] Azure AI Foundry service(s) ." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "Public network access enabled for [$($totalAIFoundryRolledBack)] out of [$($totalAIFoundryWithPublicAccessEnabled)] Azure AI Foundry service(s)" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
    
    Write-Host "Rollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
    
    $colsProperty = @{Expression={$_.Name};Label="Name";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resrouce Group";Width=20;Alignment="left"},
                    @{Expression={$_.Location};Label="Location";Width=10;Alignment="left"},
                    @{Expression={$_.Kind};Label="Kind";Width=7;Alignment="left"},
                    @{Expression={$_.PublicNetworkAccessAfterRollback};Label="Public Network Access After Rollback";Width=15;Alignment="left"},
                    @{Expression={$_.PublicNetworkAccessBeforeRollback};Label="Public Network Access Before Rollback";Width=15;Alignment="left"}

    if ($($aiFoundryRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "Enabling public network access for below Azure AI Foundry service(s):" -ForegroundColor $([Constants]::MessageType.Update)
        $aiFoundryRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $aiFoundryRolledBackFile = "$($backupFolderPath)\RolledBackAIFoundry.csv"
        $aiFoundryRolledBack| Export-CSV -Path $aiFoundryRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to [$($aiFoundryRolledBackFile)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($($aiFoundrySkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error enabling public network access for following Azure AI Foundry service(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $aiFoundrySkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
        
        # Write this to a file.
        $aiFoundrySkippedFile = "$($backupFolderPath)\RollbackSkippedAIFoundry.csv"
        $aiFoundrySkipped | Export-CSV -Path $aiFoundrySkippedFile -NoTypeInformation
        Write-Host "This information has been saved to [$($aiFoundrySkippedFile)]"
        Write-Host $([Constants]::SingleDashLine)
    }
}
function Fetch-API {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Method,
        
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Body = @{},
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Headers = @{}
    )

    $cloudEnvironmentResourceManagerUrl = (Get-AzContext).Environment.ResourceManagerUrl
    $accessTokenSecure = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl -AsSecureString -WarningAction SilentlyContinue
    $accessToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($accessTokenSecure.Token)
    )
    $authHeader = "Bearer " + $accessToken
    $Headers["Authorization"] = $authHeader
    $Headers["Content-Type"] = "application/json"

    try {
        switch ($Method.ToUpper()) {
            "GET" {
                $response = Invoke-WebRequest -Uri $Uri -Method Get -Headers $Headers -UseBasicParsing -ErrorAction Stop
            }
            "POST" {
                $jsonBody = $Body | ConvertTo-Json
                $response = Invoke-WebRequest -Uri $Uri -Method Post -Headers $Headers -Body $jsonBody -UseBasicParsing -ErrorAction Stop
            }
            "PUT" {
                $jsonBody = $Body | ConvertTo-Json
                $response = Invoke-WebRequest -Uri $Uri -Method Put -Headers $Headers -Body $jsonBody -UseBasicParsing -ErrorAction Stop
            }
            "DELETE" {
                $response = Invoke-WebRequest -Uri $Uri -Method Delete -Headers $Headers -UseBasicParsing -ErrorAction Stop
            }
            default {
                throw "Unsupported HTTP method: $Method"
            }
        }

        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
            return $response.Content | ConvertFrom-Json
        }
        else {
            throw "API call failed with status code $($response.StatusCode)"
        }
    }
    catch {
        Write-Error "Error occurred: $_"
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