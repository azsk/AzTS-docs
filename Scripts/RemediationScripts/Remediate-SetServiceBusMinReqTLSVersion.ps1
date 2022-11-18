<###
# Overview:
    This script is used to set minimium required TLS version for Azure Service Bus Namespace(s) in a Subscription.
# Control ID:
    Azure_ServiceBus_DP_Use_Secure_TLS_Version
# Display Name:
    Azure Service Bus Namespaces Announcing SSL enforcement and minimum TLS version choice.
# Prerequisites:    
    Contributor on Subscription/RG or Azure Data Owner role on the Service Bus Namespace(s) is required.
# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Azure Service Bus Namespace(s) in a Subscription that have server parameter MinimumTLSVersion set as versions less than minimum required TLS version.
        3. Back up details of Azure Service Bus Namespace(s) that are to be remediated.
        4. Set supported minimum required TLS version by updating server parameter MinimumTLSVersion to the secure version for Azure Service Bus Namespace(s).
    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Azure Service Bus Namespace(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the server parameter MinimumTLSVersion to original value as per input file.
# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set supported TLS version for Azure Service Bus Namespace(s) in the Subscription. Refer `Examples`, below.
    
    After script execution: 
        As MinimumTLSVersion is Static parameter that needs server restart for updated value to take effect, server restart is recommended to be done seperately after script execution.
        This script does not restart server to avoid any disruptions to the operations.
    
    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set supported TLS version for Azure Service Bus Namespace(s) in the Subscription. Refer `Examples`, below.
# Examples:
    To remediate:
        1. To review the Azure Service Bus Namespace(s) in a Subscription that will be remediated:
    
           Set-SecureTLSVersionForServiceBusNamespaces -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Set TLS version for Azure Service Bus Namespace(s) in the Subscription:
       
           Set-SecureTLSVersionForServiceBusNamespaces -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Set TLS version for Azure Service Bus Namespace(s) in the Subscription, from a previously taken snapshot:
       
           Set-SecureTLSVersionForServiceBusNamespaces -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -InputFilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202209131040\SetSecureTLSVersionForServiceBusNamespaces\ServiceBusNamespacesBackUp.csv
        
        To know more about the options supported by the remediation command, execute:
        
        Get-Help Set-SecureTLSVersionForServiceBusNamespaces -Detailed

    To roll back:

        1. Set TLS version for Azure Service Bus Namespace(s) in the Subscription, from a previously taken snapshot:
        
            Reset-SecureTLSVersionForServiceBusNamespaces -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -RollbackFilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForServiceBusNamespaces\ServiceBusNamespacesBackUp.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Reset-SecureTLSVersionForServiceBusNamespaces -Detailed        
###>


function Setup-Prerequisites {
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
    $requiredModules = @("Az.Accounts", "Az.ServiceBus")

    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)    
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_) {
            Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host $([Constants]::SingleDashLine)
}

function Set-SecureTLSVersionForServiceBusNamespaces {
    <#
        .SYNOPSIS
        Remediates 'Azure_ServiceBus_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Remediates 'Azure_ServiceBus_DP_Use_Secure_TLS_Version' Control.
        Set secure TLS version as minimum required TLS version for Azure Service Bus Namespace(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.
        
        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation.

        .INPUTS
        None. You cannot pipe objects to Set-SecureTLSVersionForServiceBusNamespaces.

        .OUTPUTS
        None. Set-SecureTLSVersionForServiceBusNamespaces does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-SecureTLSVersionForServiceBusNamespaces -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-SecureTLSVersionForServiceBusNamespaces -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-SecureTLSVersionForServiceBusNamespaces -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -InputFilePath 

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies a forceful remediation without any prompts")]
        $Force,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", HelpMessage = "Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage = "Specifies a dry run of the actual remediation")]
        $DryRun,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the path to the file to be used as input for the remediation")]
        $InputFilePath,

        [Switch]        
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies script is run as a subroutine of AutoRemediation Script")]
        $AutoRemediation,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used")]
        $Path,

        [String]        
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used")]
        $TimeStamp
    )

    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script and validating the user..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)            
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else {
        Write-Host "[Step 1 of 4] Validate the user... "
        Write-Host $([Constants]::SingleDashLine)
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context)) {
        Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)        
        Write-Host $([Constants]::SingleDashLine)
    }
    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop   

    if (-not($AutoRemediation)) {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }
    Write-Host "To set secure TLS version for Azure Service Bus(s) in the Subscription, Contributor on Subscription/RG or Azure Data Owner role on Service Bus Namespace(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)  

    # list to store Service Bus Namespace details.
    $serviceBusNamespacesDetails = @()

    # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources = @()	

    $controlId = "Azure_ServiceBus_DP_Use_Secure_TLS_Version"

    if ($AutoRemediation) {
        if (-not (Test-Path -Path $Path)) {	
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	
        }

        Write-Host "Fetching all Azure Service Bus Namespace(s) details failing for the [$($controlId)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # list to store Service Bus Namespace details.
        $serviceBusNamespacesDetails = @()
        
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlId -eq $_.ControlId };

        $validServiceBusNampespaces = $resourceDetails.FailedResourceList | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }	
        if (($resourceDetails | Measure-Object).Count -eq 0 -or ($validServiceBusNampespaces | Measure-Object).Count -eq 0) {

            Write-Host "No Azure Service Bus Namespace(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	
        }
        $validServiceBusNampespaces | ForEach-Object { 	
            try {
                $currentServiceBusNamespaceDetails = Get-AzServiceBusNamespace -ResourceGroupName $_.ResourceGroupName -NamespaceName $_.ResourceName -ErrorAction SilentlyContinue
                $currentTLSVersion = ($currentServiceBusNamespaceDetails).MinimumTlsVersion
                $serviceBusNamespacesDetails += $currentServiceBusNamespaceDetails  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                @{N = 'ResourceName'; E = { $_.Name } }, 
                @{N = 'MinimumTLSVersion'; E = { $currentTLSVersion } }
            }
            catch {
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host "Skipping the Resource:  [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)	
                $logResource = @{}
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                $logResource.Add("ResourceName", ($_.ResourceName))	
                $logResource.Add("Reason", "Valid resource id(s) not found in input json file.")    	
                $logSkippedResources += $logResource	
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Error fetching Azure Service Bus Namespace for resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }	
        }	
    }
    else {	
        if ([String]::IsNullOrWhiteSpace($InputFilePath)) {
            Write-Host "Fetching all Azure Service Bus Namespace(s) in Subscription: [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all Azure Serivce Bus Namespace(s) in a Subscription
            $serviceBusNamespaces = @();
            $serviceBusNamespaces = Get-AzServiceBusNamespace -ErrorAction Stop
            $serviceBusNamespaces | ForEach-Object { 	
                $currentTLSVersion = $_.MinimumTlsVersion 
                $serviceBusNamespacesDetails += $_  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                @{N = 'ResourceName'; E = { $_.Name } }, 
                @{N = 'MinimumTLSVersion'; E = { $currentTLSVersion } }
            }        
        }
        else {
            if (-not (Test-Path -Path $InputFilePath)) {
                Write-Host "ERROR: Input file: [$($InputFilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }

            Write-Host "Fetching all Azure Service Bus Namespace(s) from [$($InputFilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $inputServiceBusNampespaces = Import-Csv -LiteralPath $InputFilePath

            $validServiceBusNampespaces = $inputServiceBusNampespaces | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

            $validServiceBusNampespaces | ForEach-Object {
                $resourceId = $_.ResourceId

                try {                
                    $currentServiceBusNamespaceDetails = Get-AzServiceBusNamespace -ResourceGroupName $_.ResourceGroupName -NamespaceName $_.ResourceName -ErrorAction SilentlyContinue
                    $currentTLSVersion = ($currentServiceBusNamespaceDetails).MinimumTlsVersion
                    $serviceBusNamespacesDetails += $_  | Select-Object @{N = 'ResourceId'; E = { $currentServiceBusNamespaceDetails.Id } },
                    @{N = 'ResourceGroupName'; E = { $currentServiceBusNamespaceDetails.Id.Split("/")[4] } },
                    @{N = 'ResourceName'; E = { $currentServiceBusNamespaceDetails.Name } }, 
                    @{N = 'MinimumTLSVersion'; E = { $currentTLSVersion } }

                }
                catch {
                    Write-Host "Error fetching Azure Service Bus Namespace details for resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
        }
    }

    $serviceBusNamespacesCount = ($serviceBusNamespacesDetails | Measure-Object).Count

    if ($serviceBusNamespacesCount -eq 0) {
        Write-Host "No Azure Service Bus Namespace(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($serviceBusNamespacesCount)] Azure Service Bus Namespace(s)." -ForegroundColor $([Constants]::MessageType.Update)

    Write-Host $([Constants]::SingleDashLine)

    # List for actionable service bus namespace(s)
    $actionableServiceBusNamespacesDetails = @()

    Write-Host "Filtering Azure Service Bus Namespace(s) for which secure TLS version is not secure..." -ForegroundColor $([Constants]::MessageType.Info)

    $serviceBusNamespacesDetails | ForEach-Object {
        if (-not (CheckIfCurrentTLSVersionIsSecure($_.MinimumTLSVersion))) {
            $actionableServiceBusNamespacesDetails += $_
        }
    }

    $actionableServiceBusNamespacesDetailsCount = ($actionableServiceBusNamespacesDetails | Measure-Object).Count

    if ($actionableServiceBusNamespacesDetailsCount -eq 0) {
        Write-Host "No Azure Service Bus Namespaces(s) found with non-secure TLS version enabled.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($actionableServiceBusNamespacesDetailsCount )] Azure Service Bus Namespace(s) for which non secure TLS version is enabled ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 100; Alignment = "left" },
    @{Expression = { $_.MinimumTLSVersion }; Label = "MinimumTLSVersion"; Width = 100; Alignment = "left" }

    if (-not $AutoRemediation) {
        Write-Host "Azure Service Bus Namespace(s) with non-secure TLS version enabled are:"
        $actionableServiceBusNamespacesDetails  | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\Set-SecureTLSVersionForServiceBusNamespaces"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "[Step 3 of 4] Back up Azure Service Bus Namespace(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($InputFilePath)) {
        # Backing up actionable Azure Service Bus Namespace(s) details.
        $backupFile = "$($backupFolderPath)\ServiceBusNamespacesDetailsBackUp.csv"
        $actionableServiceBusNamespacesDetails | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Azure Service Bus Namespace(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "Skipped as -InputFilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enable secure TLS version on Azure Service Bus Namespace(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)


        if (-not $Force) {
            Write-Host "Do you want to enable secure TLS version on Azure Service Bus Namespace(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)

            $userInput = Read-Host -Prompt "(Y|N)"

            if ($userInput -ne "Y") {
                Write-Host "TLS version will not be changed for Azure Service Bus Namespace(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
        }
        else {
            Write-Host "'Force' flag is provided. Secure TLS version will be enabled on Azure Service Bus Namespace(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        # List for storing remediated Azure Service Bus Namespace(s)
        $serviceBusNamespacesRemediated = @()

        # List for storing skipped Azure Service Bus Namespace(s)
        $serviceBusNamespacesSkipped = @()

        Write-Host "Setting secure TLS version on Azure Service Bus Namespace(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of Azure Service Bus Namespace(s) which needs to be remediated.
        $actionableServiceBusNamespacesDetails  | ForEach-Object {
            try {
                $updatedTLSVersion = (Set-AzServiceBusNamespace -ResourceGroupName $_.ResourceGroupName -NamespaceName $_.ResourceName -MinimumTlsVersion $([Constants]::MinRequiredTLSVersionValue)).MinimumTlsVersion 

                if (CheckIfCurrentTLSVersionIsSecure($updatedTLSVersion)) {
                    $_.MinimumTLSVersion = $updatedTLSVersion
                    $serviceBusNamespacesRemediated += $_
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))	
                    $logRemediatedResources += $logResource	
                }
                else {
                    $serviceBusNamespacesSkipped += $_
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))
                    $logResource.Add("Reason", "Error setting server parameter MinimumTLSVersion: [$($_)]")            
                    $logSkippedResources += $logResource	

                }                
            }
            catch {
                $serviceBusNamespacesSkipped += $_
                $logResource = @{}	
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                $logResource.Add("ResourceName", ($_.ResourceName))	
                $logResource.Add("Reason", "Encountered error while setting server parameter MinimumTLSVersion")    	
                $logSkippedResources += $logResource	
                Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host $([Constants]::DoubleDashLine)


        if ($AutoRemediation) {
            if ($($serviceBusNamespacesRemediated | Measure-Object).Count -gt 0) {

                # Write this to a file.
                $serviceBusNamespacesRemediatedFile = "$($backupFolderPath)\RemediatedServiceBusNamespaces.csv"
                $serviceBusNamespacesRemediated | Export-CSV -Path $serviceBusNamespacesRemediatedFile -NoTypeInformation

                Write-Host "The information related to Azure Service Bus Namespace(s) where server parameter MinimumTLSVersion changed has been saved to [$($serviceBusNamespacesRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($serviceBusNamespacesSkipped | Measure-Object).Count -gt 0) {
                $serviceBusNamespacesSkipped | Format-Table -Property $colsProperty -Wrap            
                # Write this to a file.
                $serviceBusNamespacesSkippedFile = "$($backupFolderPath)\SkippedServiceBusNamespaces.csv"
                $serviceBusNamespacesSkipped | Export-CSV -Path $serviceBusNamespacesSkippedFile -NoTypeInformation
                Write-Host "The information related to Azure Service Bus Namespace(s) where server parameter MinimumTLSVersion not changed has been saved to [$($serviceBusNamespacesSkippedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

        }
        else {

            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            if ($($serviceBusNamespacesRemediated | Measure-Object).Count -gt 0) {
                Write-Host "Successfully set secure TLS version for the following Service Bus Namespaces(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $serviceBusNamespacesRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $serviceBusNamespacesRemediatedFile = "$($backupFolderPath)\RemediatedServiceBusNamespaces.csv"
                $serviceBusNamespacesRemediated | Export-CSV -Path $serviceBusNamespacesRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($serviceBusNamespacesRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            }

            if ($($serviceBusNamespacesSkipped | Measure-Object).Count -gt 0) {

                Write-Host "Error while setting up the server parameter MinimumTLSVersion for the following Azure Service Bus Namespaces(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $serviceBusNamespacesSkipped | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $serviceBusNamespacesSkippedFile = "$($backupFolderPath)\SkippedServiceBusNamespaces.csv"
                $serviceBusNamespacesSkipped | Export-CSV -Path $serviceBusNamespacesSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($serviceBusNamespacesSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            }
        }
        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlId) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $serviceBusNamespacesRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else {
        Write-Host "[Step 4 of 4] Enable secure TLS version on Azure Service Bus Namespaces(s) in the Subscription." 
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -InputFilePath $($backupFile) and without -DryRun, to set secure TLS version for Azure Service Bus Namespaces(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Reset-SecureTLSVersionForServiceBusNamespaces {
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_ServiceBus_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_ServiceBus_DP_Use_Secure_TLS_Version' Control.
        Change TLS version to Previous Value on Azure Service Bus Namespace(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER RollbackFilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to function Reset-SecureTLSVersionForServiceBusNamespacesNamespaces.

        .OUTPUTS
        None. function Reset-SecureTLSVersionForServiceBusNamespacesNamespaces does not return anything that can be piped and used as an input to another command.
        
        .EXAMPLE
        PS> Reset-SecureTLSVersionForServiceBusNamespacesNamespaces -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -RollbackFilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForServiceBusNamespaces\RemediatedServiceBusNamespaces.csv
        
        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

        [Switch]
        [Parameter(HelpMessage = "Specifies a forceful roll back without any prompts")]
        $Force,

        [Switch]
        [Parameter(HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the path to the file to be used as input for the roll back")]
        $RollbackFilePath
    )

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 3] Validate and install the modules required to run the script and validate the user..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites"	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)	
            return
        }
    }
    else {
        Write-Host "[Step 1 of 3] Validate the user..." 
        Write-Host $([Constants]::SingleDashLine)
    } 

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context)) {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else {
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

    Write-Host "To set secure TLS version for Azure Service Bus Namespace(s) in the Subscription, Contributor on Subscription/RG or Azure Data Owner role on Service Bus Namespace(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Azure Service Bus Namespace(s)"
    Write-Host $([Constants]::SingleDashLine)

    if (-not (Test-Path -Path $RollbackFilePath)) {
        Write-Host "Input file:  [$($RollbackFilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Fetching all Azure Service Bus Namespace(s) from" -NoNewline
    Write-Host " [$($RollbackFilePath)\...]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $serviceBusNamespacesDetails = Import-Csv -LiteralPath $RollbackFilePath

    $validServiceBusNamespacesDetails = $serviceBusNamespacesDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $validServiceBusNamespacesDetailsCount = $(($validServiceBusNamespacesDetails | Measure-Object).Count)

    if ($validServiceBusNamespacesDetailsCount -eq 0) {
        Write-Host "No Azure Service Bus Namespace(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($validServiceBusNamespacesDetailsCount)] Azure Service Bus Namespace(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 100; Alignment = "left" },
    @{Expression = { $_.MinimumTLSVersion }; Label = "MinimumTLSVersion"; Width = 100; Alignment = "left" }

    $validServiceBusNamespacesDetails | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\Reset-SecureTLSVersionForServiceBusNamespacesNamespaces"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Set TLS version to previous value on all Azure Service Bus Namespace(s) in the Subscription"
    Write-Host $([Constants]::SingleDashLine)

    if (-not $Force) {

        Write-Host "Do you want to change TLS version for all Azure Service Bus Namespace(s) mentioned in the file?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y") {
            Write-Host "TLS version will not be rolled back on Azure Service Bus Namespace(s) mentioned in the file. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "TLS version will be rolled back on Azure Service Bus Namespace(s) mentioned in the file." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "'Force' flag is provided. TLS version will be rolled back on Azure Service Bus Namespace(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Service Bus Namespace(s).
    $serviceBusNamespacesRolledBack = @()

    # List for storing skipped rolled back Service Bus Namespace(s).
    $serviceBusNamespacesSkipped = @()

    $validServiceBusNamespacesDetails | ForEach-Object {
        try {   
            Set-AzServiceBusNamespace -ResourceGroupName $_.ResourceGroupName -NamespaceName $_.ResourceName -MinimumTlsVersion $_.MinimumTlsVersion
            $serviceBusNamespacesRolledBack += $_
        }
        catch {
            $serviceBusNamespacesSkipped += $_
        }
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

    if ($($serviceBusNamespacesRolledBack | Measure-Object).Count -gt 0) {
        Write-Host "TLS version has been rolled back on the following Azure Service Bus Namespace(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
        $serviceBusNamespacesRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $serviceBusNamespacesRolledBackFile = "$($backupFolderPath)\RolledBackServiceBusNamespaces.csv"
        $serviceBusNamespacesRolledBack | Export-CSV -Path $serviceBusNamespacesRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($serviceBusNamespacesRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }

    if ($($serviceBusNamespacesSkipped | Measure-Object).Count -gt 0) {
        Write-Host "Error while rolling back TLS version on Azure Service Bus Namespace(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
        $serviceBusNamespacesSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)


        # Write this to a file.
        $serviceBusNamespacesSkippedFile = "$($backupFolderPath)\RolledBackServiceBusNamespaces.csv"
        $serviceBusNamespacesSkipped | Export-CSV -Path $serviceBusNamespacesSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($serviceBusNamespacesSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }
}

function  CheckIfCurrentTLSVersionIsSecure {
    param ([String] $TLSVersion)
    if ($TLSVersion -lt [Constants]::MinRequiredTLSVersionValue) {
        return $false
    }
    else {
        Return $true
    }
}

# Defines commonly used constants.
class Constants {
    # Defines commonly used colour codes, corresponding to the severity of the log...
    static [Hashtable] $MessageType = @{
        Error   = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info    = [System.ConsoleColor]::Cyan
        Update  = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }
    static [double] $MinRequiredTLSVersionValue = 1.2
    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}