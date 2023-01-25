<###
# Overview:
    This script is used to set Tls version for Event Hub namespaces in a Subscription.

# Control ID:
    Azure_EventHub_DP_Use_Secure_TLS_Version_Trial

# Display Name:
    [Trial] Use approved version of TLS for Event Hub Namespace.

# Prerequisites:    
    Owner or higher priviliged role on the Event Hub Namespace(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Event Hub Namespace(s) in a Subscription that does not have min TLS version configured.
        3. Back up details of Event Hub Namespace(s) that are to be remediated.
        4. Set the min TLS version on Event Hub Namespace(s) in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Event Hub Namespace(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the TLS version to previous value on Event Hub Namespace(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the min TLS version on Event Hub Namespace(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the min TLS version on Event Hub Namespace(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Event Hub Namespace(s) in a Subscription that will be remediated:
    
           Set-MinTLSVersionForEventHubNamespace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Set the min TLS version on Event Hub Namespace(s) in the Subscription:
       
           Set-MinTLSVersionForEventHubNamespace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Set the min TLS version on Event Hub Namespace(s) in the Subscription, from a previously taken snapshot:
       
           Set-MinTLSVersionForEventHubNamespace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetEventHubNamespaceMinTLSVersion\EventHubNamespaceDetailsBackUp.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Set-MinTLSVersionForEventHubNamespace -Detailed

    To roll back:
        1. Set the TLS version to Previous Value on Event Hub Namespace(s) in the Subscription, from a previously taken snapshot:
           Set-PreviousTLSVersionForEventHubNamespace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetEventHubNamespaceMinTLSVersion\EventHubNamespaceDetailsBackUp.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Set-PreviousTLSVersionForEventHubNamespace -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.EventHub")

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
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
}


function Set-MinTLSVersionForEventHubNamespace
{
    <#
        .SYNOPSIS
        Remediates 'Azure_EventHub_DP_Use_Secure_TLS_Version_Trial' Control.

        .DESCRIPTION
        Remediates 'Azure_EventHub_DP_Use_Secure_TLS_Version_Trial' Control.
        Set the min TLS version on Event Hub Namespace(s) in the Subscription. 
        
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
        None. You cannot pipe objects to Set-MinTLSVersionForEventHubNamespace.

        .OUTPUTS
        None. Set-MinTLSVersionForEventHubNamespace does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-MinTLSVersionForEventHubNamespace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-MinTLSVersionForEventHubNamespace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-MinTLSVersionForEventHubNamespace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetEventHubNamespaceMinTLSVersion\EventHubNamespaceDetailsBackUp.csv

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
            Write-Host "[Step 1 of 4] Validate and install the modules required to run the script and validate the user..."
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
        Write-Host "[Step 1 of 4] Validate the user... "
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
    Write-Host " To change TLS version for Event Hub Namespace in a Subscription, Contributor or higher privileged role assignment on the Event Hub Namespace(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)  

    Write-Host "[Step 2 of 4] Fetch all Event Hub Namespace(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Container details.
    $EventHubNamespaceDetails = @()

     # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources=@()	

    # Control Id	
    $controlIds = "Azure_EventHub_DP_Use_Secure_TLS_Version_Trial"


    # No file path provided as input to the script. Fetch all Event Hub Namespace(s) in the Subscription.

    if($AutoRemediation)	
    {
         if(-not (Test-Path -Path $Path))	
        {	
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	
        }

         Write-Host "Fetching all Event Hub Namespace(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
         Write-Host $([Constants]::SingleDashLine)
         $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
         $controls = $controlForRemediation.ControlRemediationList
         $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };

         $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}	
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            	
            Write-Host "No Event Hub Namespace(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	
        
        }
         $validResources | ForEach-Object { 	
            try	
            {
            $EventHubNamespaceResource =  Get-AzEventHubNamespace -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
            $EventHubNamespaceDetails += $EventHubNamespaceResource  | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                          @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                          @{N='ResourceName';E={$_.Name}}, 
                                                                          @{N='CurrentTlsVersion';E={$_.MinimumTlsVersion}}
             }
            catch
            {
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host "Skipping the Resource:  [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)	
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                $logResource.Add("ResourceName",($_.ResourceName))	
                $logResource.Add("Reason","Valid resource id(s) not found in input json file.")    	
                $logSkippedResources += $logResource	
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Error fetching Event Hub Namespace(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
             }	
        }	
    }
    else
    {	
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
        Write-Host "Fetching all Event Hub Namespace(s) in Subscription: [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Get all Event Hub Namespace(s) in a Subscription
        $EventHubNamespaceDetails =  Get-AzEventHubNamespace -ErrorAction Stop

        # Seperating required properties
        $EventHubNamespaceDetails = $EventHubNamespaceDetails | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                          @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                          @{N='ResourceName';E={$_.Name}}, 
                                                                          @{N='CurrentTlsVersion';E={$_.MinimumTlsVersion}}

        }
        else
        {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)	
            return
        }

        Write-Host "Fetching all Event Hub Namespace(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $EventHubNamespaceResources = Import-Csv -LiteralPath $FilePath

        $validEventHubNamespaceResources = $EventHubNamespaceResources| Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

        $validEventHubNamespaceResources| ForEach-Object {
            $resourceId = $_.ResourceId

            try
            {                
                $EventHubNamespaceResource =  Get-AzEventHubNamespace -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
            
                $EventHubNamespaceDetails += $EventHubNamespaceResource  | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                          @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                          @{N='ResourceName';E={$_.Name}}, 
                                                                          @{N='CurrentTlsVersion';E={$_.MinimumTlsVersion}}
            }
            catch
            {
                Write-Host "Error fetching Event Hub Namespace(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }
            }
        }
                                                                
    }
    
    $totalEventHubNamespace = ($EventHubNamespaceDetails| Measure-Object).Count
    $requiredMinTLSVersion = 1.2

    if ($totalEventHubNamespace -eq 0)
    {
        Write-Host "No Event Hub Namespace(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }
  
    Write-Host "Found [$($totalEventHubNamespace)] Event Hub Namespace(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Event Hub Namespace(s) for which TLS version is not configured.
    $EventHubNamespaceWithoutMinTLSVersionRequired = @()

    Write-Host "Separating Event Hub Namespace(s) for which min TLS version is not configured..." -ForegroundColor $([Constants]::MessageType.Info)

    $EventHubNamespaceDetails | ForEach-Object {
        $EventHubNamespace = $_        
            if($_.CurrentTlsVersion -ne $requiredMinTLSVersion)
            {
                $EventHubNamespaceWithoutMinTLSVersionRequired += $EventHubNamespace
            }
    }
   
    $totalEventHubNamespaceWithoutMinTLSVersionRequired  = ($EventHubNamespaceWithoutMinTLSVersionRequired | Measure-Object).Count

    if ($totalEventHubNamespaceWithoutMinTLSVersionRequired  -eq 0)
    {
        Write-Host "No Event Hub Namespace(s) found where TLS version is not as expected min TLS version.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalEventHubNamespaceWithoutMinTLSVersionRequired)] Event Hub Namespace(s) for which TLS version is not as expected min TLS version ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression={$_.ResourceId};Label="ResourceId";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceName};Label="ResourceName";Width=100;Alignment="left"},
                    @{Expression={$_.CurrentTlsVersion};Label="CurrentTlsVersion";Width=100;Alignment="left"}

      if(-not $AutoRemediation)
      {
        Write-Host "Event Hub Namespace(s) without TLS version as min TLS version:"
        $EventHubNamespaceWithoutMinTLSVersionRequired | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
      }    
    

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetEventHubNamespaceMinTLSVersion"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 3 of 4] Back up Event Hub Namespace(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        # Backing up Event Hub Namespace(s) details.
        $backupFile = "$($backupFolderPath)\EventHubNamespaceDetailsBackUp.csv"
        $EventHubNamespaceWithoutMinTLSVersionRequired | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Event Hub Namespace(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
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
        Write-Host "[Step 4 of 4] Configure the min TLS Version on Event Hub Namespace(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)
        

        if (-not $Force)
        {
            Write-Host "Do you want to configure the TLS version as minimum expected version on Event Hub Namespace(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "TLS version will not be configured as minimum expected version on Event Hub Namespace(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. TLS version will be configured as minimum expected version on Event Hub Namespace(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        # List for storing remediated Event Hub Namespace(s)
        $EventHubNamespaceRemediated = @()

        # List for storing skipped Event Hub Namespace(s)
        $EventHubNamespaceSkipped = @()

        Write-Host "Setting TLS version as Min expected Version on Event Hub Namespace(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of Event Hub Namespace(s) which needs to be remediated.
        $EventHubNamespaceWithoutMinTLSVersionRequired | ForEach-Object {
            $EventHubNamespace = $_
            try
            {
                $EventHubNamespaceResource = Set-AzEventHubNamespace -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -MinimumTlsVersion $requiredMinTLSVersion              
                
                if($EventHubNamespaceResource.MinimumTlsVersion -eq $requiredMinTLSVersion)
                {
                    $EventHubNamespaceRemediated += $EventHubNamespace
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                    $logResource.Add("ResourceName",($_.ResourceName))	
                    $logRemediatedResources += $logResource	
                }
                else
                {
                    $EventHubNamespaceSkipped += $EventHubNamespace
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Error configuring TLS version for Event Hub Namespace: [$($EventHubNamespace)]")            
                    $logSkippedResources += $logResource	

                }
                
            }
            catch
            {
                $EventHubNamespaceSkipped += $EventHubNamespace
                $logResource = @{}	
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                $logResource.Add("ResourceName",($_.ResourceName))	
                $logResource.Add("Reason","Error configuring TLS version for Event Hub Namespace")    	
                $logSkippedResources += $logResource	
                Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host $([Constants]::SingleDashLine)
                }
             }

        Write-Host $([Constants]::DoubleDashLine)
        
        
        if($AutoRemediation)
        {
            if ($($EventHubNamespaceRemediated | Measure-Object).Count -gt 0)
            {
                
                # Write this to a file.
                $EventHubNamespaceRemediatedFile = "$($backupFolderPath)\RemediatedEventHubNamespace.csv"
                $EventHubNamespaceRemediated | Export-CSV -Path $EventHubNamespaceRemediatedFile -NoTypeInformation

                Write-Host "The information related to EventHubNamespace(s) where TLS version changed has been saved to [$($EventHubNamespaceRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        
            if ($($EventHubNamespaceSkipped | Measure-Object).Count -gt 0)
            {
                $EventHubNamespaceSkipped | Format-Table -Property $colsProperty -Wrap            
                # Write this to a file.
                $EventHubNamespaceSkippedFile = "$($backupFolderPath)\SkippedEventHubNamespace.csv"
                $EventHubNamespaceSkipped | Export-CSV -Path $EventHubNamespaceSkippedFile -NoTypeInformation
                Write-Host "The information related to Event Hub Namespace(s) where TLS Version not changed has been saved to [$($EventHubNamespaceSkippedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

        }
        else
            {

            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            if ($($EventHubNamespaceRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Successfully set the TLS version to min required version on the following Event Hub Namespace(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $EventHubNamespaceRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $EventHubNamespaceRemediatedFile = "$($backupFolderPath)\RemediatedEventHubNamespace.csv"
                $EventHubNamespaceRemediated | Export-CSV -Path $EventHubNamespaceRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($EventHubNamespaceRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            }
        
            if ($($EventHubNamespaceSkipped | Measure-Object).Count -gt 0)
            {

                Write-Host "Error while setting up the min TLS version in Event Hub Namespace(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $EventHubNamespaceSkipped | Format-Table -Property $colsProperty -Wrap
            
                # Write this to a file.
                $EventHubNamespaceSkippedFile = "$($backupFolderPath)\SkippedEventHubNamespace.csv"
                $EventHubNamespaceSkipped | Export-CSV -Path $EventHubNamespaceSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($EventHubNamespaceSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            }
        }
        if($AutoRemediation){
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                    $logControl.RollbackFile = $EventHubNamespaceRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
        ''
    }
    else
    {
        Write-Host "[Step 4 of 4] Set the min required TLS version on Event Hub Namespace(s) in the Subscription." 
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath [$($backupFile)] and without -DryRun, to Change TLS version to min required version on Event Hub Namespace(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Set-PreviousTLSVersionForEventHubNamespace
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_EventHub_DP_Use_Secure_TLS_Version_Trial' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_EventHub_DP_Use_Secure_TLS_Version_Trial' Control.
        Change TLS version to Previous Value on Event Hub Namespace(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Set-PreviousTLSVersionForEventHubNamespace.

        .OUTPUTS
        None. Set-PreviousTLSVersionForEventHubNamespace does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-PreviousTLSVersionForEventHubNamespace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetTLSVersionforEventHubNamespace\RemediatedEventHubNamespace.csv

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

    Write-Host "To change TLS version on Event Hub Namespace(s) in a Subscription, Contributor or higher privileged role assignment on the Event Hub Namespace(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Event Hub Namespace(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file:  [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Fetching all Event Hub Namespace(s) from" -NoNewline
    Write-Host " [$($FilePath)\...]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $EventHubNamespaceDetails = Import-Csv -LiteralPath $FilePath

    $validEventHubNamespaceDetails = $EventHubNamespaceDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalEventHubNamespace = $(($validEventHubNamespaceDetails|Measure-Object).Count)

    if ($totalEventHubNamespace -eq 0)
    {
        Write-Host "No Event Hub Namespace(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$(($validEventHubNamespaceDetails|Measure-Object).Count)] Event Hub Namespace(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"},
                    @{Expression={$_.CurrentTlsVersion};Label="CurrentTlsVersion";Width=100;Alignment="left"}
        
    $validEventHubNamespaceDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetTLSVersionforEventHubNamespace"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Set TLS version to previous value on all Event Hub Namespace(s) in the Subscription"
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        
        Write-Host "Do you want to change TLS Version on all Event Hub Namespace(s) mentioned in the file?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "TLS Version will not be rolled back on Event Hub Namespace(s) mentioned in the file. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }
            Write-Host "TLS Version will be rolled back on Event Hub Namespace(s) mentioned in the file." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. TLS Version will be rolled back on Event Hub Namespace(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Event Hub Namespace resource.
    $EventHubNamespaceRolledBack = @()

    # List for storing skipped rolled back Event Hub Namespace resource.
    $EventHubNamespaceSkipped = @()


    $validEventHubNamespaceDetails | ForEach-Object {
        $EventHubNamespace = $_
        try
        {   
            
            $EventHubNamespaceResource = Set-AzEventHubNamespace -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -MinimumTlsVersion $_.CurrentTlsVersion
            if($EventHubNamespaceResource.MinimumTlsVersion -eq $_.CurrentTlsVersion)
            {
                $EventHubNamespaceRolledBack += $EventHubNamespace
            }
            else
            {
                $EventHubNamespaceSkipped += $EventHubNamespace
            }
        }
        catch
        {
            $EventHubNamespaceSkipped += $EventHubNamespace
        }
    }


    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
    if ($($EventHubNamespaceRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "TLS Version has been rolled back on the following Event Hub Namespace(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
        $EventHubNamespaceRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $EventHubNamespaceRolledBackFile = "$($backupFolderPath)\RolledBackEventHubNamespace.csv"
        $EventHubNamespaceRolledBack | Export-CSV -Path $EventHubNamespaceRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($EventHubNamespaceRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }

    if ($($EventHubNamespaceSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error while rolling back TLS Version on Event Hub Namespace(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
        $EventHubNamespaceSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

            
        # Write this to a file.
        $EventHubNamespaceSkippedFile = "$($backupFolderPath)\RollbackSkippedEventHubNamespace.csv"
        $EventHubNamespaceSkipped | Export-CSV -Path $EventHubNamespaceSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($EventHubNamespaceSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
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
