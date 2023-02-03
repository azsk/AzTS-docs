<###
# Overview:
    This script is used to enable SSL for Azure Database for MySQL flexible server in a Subscription.

# Control ID:
    Azure_DBForMySQLFlexibleServer_DP_Enable_SSL

# Display Name:
    SSL must be enabled for Azure database for MySQL flexible server

# Prerequisites:    
    Contributor or higher priviliged role on the Azure Database for MySQL flexible server(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of Azure Database for MySQL flexible server(s) in a Subscription that have server parameter require_secure_transport not set as ON.
        3. Back up details of Azure Database for MySQL flexible server(s) that are to be remediated.
        4. Enable SSL by updating server parameter require_secure_transport as ON for Azure Database for MySQL flexible server(s).

    To roll back:
        1. Validate and install the modules required to run the script.
        2.  Get the list of Azure Database for MySQL flexible server(s) in a Subscription, to which changes were made previously and are to be rolled back, from the backed-up data.
        3. Set the server parameter require_secure_transport to original value as per input file.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable SSL for Azure Database for MySQL flexible server(s) in the Subscription. Refer `Examples`, below.
    
    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable SSL for Azure Database for MySQL flexible server(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Azure Database for MySQL flexible server(s) in a Subscription that will be remediated:
    
           Enable-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Enable SSL for Azure Database for MySQL flexible server(s) in the Subscription:
       
           Enable-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Enable SSL for Azure Database for MySQL flexible server(s) in the Subscription, from a previously taken snapshot:
       
           Enable-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSSLForDBForMySQLFlexibleServer\DBForMySQLFlexibleServerWithSSLDisabled.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-SSLForDBForMySQLFlexibleServer -Detailed

    To roll back:
        1. Enable SSL for Azure Database for MySQL flexible server(s) in the Subscription, from a previously taken snapshot:
           Disable-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSSLForDBForMySQLFlexibleServer/DBForMySQLFlexibleServerWithSSLDisabled.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Enable-SSLForDBForMySQLFlexibleServer -Detailed        
###>


function Setup-Prerequisites {
    <#
        .SYNOPSIS
        Checks if the prerequisites are met, else, set them up.

        .DESCRIPTION
        Checks if the prerequisites are met, else, set them up.
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
    $requiredModules = @("Az.Accounts", "Az.MySql")

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


function Enable-SSLForDBForMySQLFlexibleServer {
    <#
        .SYNOPSIS
        Remediates 'Azure_DBForMySQLFlexibleServer_DP_Enable_SSL' Control.

        .DESCRIPTION
        Remediates 'Azure_DBForMySQLFlexibleServer_DP_Enable_SSL' Control.
        Enable SSL as ON for Azure Database for MySQL flexible server(s) in the Subscription. 
        
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

        .INPUTS
        None. You cannot pipe objects to Enable-SSLForDBForMySQLFlexibleServer.

        .OUTPUTS
        None. Enable-SSLForDBForMySQLFlexibleServer does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSSLForDBForMySQLFlexibleServer\DBForMySQLFlexibleServerWithSSLDisabled.csv

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
        $FilePath,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used")]
        $Path,

        [Switch]        
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies script is run as a subroutine of AutoRemediation Script")]
        $AutoRemediation,

        [String]        
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used")]
        $TimeStamp
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Validate and install the modules required to run the script."
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck) {
        try {
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
        Write-Host "Skipped as -PerformPreReqCheck switch is not provided." -ForegroundColor $([Constants]::MessageType.Warning)
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
    Write-Host "To enable SSL for Azure Database for MySQL flexible server(s) in the Subscription, Contributor or higher privileged role assignment on the Azure Database for MySQL flexible server(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)  

    Write-Host "[Step 2 of 4] Prepare to fetch all Azure Database for MySQL flexible server(s)."
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Container details.
    $DBForMySQLFlexibleServerDetails = @()

    # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources = @()	

    $controlIds = "Azure_DBForMySQLFlexibleServer_DP_Enable_SSL"

    if ($AutoRemediation) {
        if (-not (Test-Path -Path $Path)) {	
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	
        }

        Write-Host "Fetching all Azure Database for MySQL flexible server(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };

        $validResources = $resourceDetails.FailedResourceList | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }	
        if (($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0) {
            	
            Write-Host "No Azure Database for MySQL flexible server(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)	
            Write-Host $([Constants]::DoubleDashLine)	
            return	
        }
        $validResources | ForEach-Object { 
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName
            try 
            {
                $DBForMySQLFSResource = Get-AzMySqlFlexibleServer -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction Continue
                if($DBForMySQLFSResource -ne $null)
                {
                    $parameterValue = (Get-AzMySqlFlexibleServerConfiguration -Name $([Constants]::ParameterName) -ResourceGroupName $_.ResourceGroupName -ServerName $_.ResourceName ).Value
                    $DBForMySQLFlexibleServerDetails += $DBForMySQLFSResource  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                    @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName } },
                    @{N = 'ResourceName'; E = { $_.Name } }, 
                    @{N = 'SSLStatus'; E = { $parameterValue } }
                }
            }
            catch {
                Write-Host "Valid resource id not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)	
                Write-Host "Skipping the Resource: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)	
                $logResource = @{}
                $logResource.Add("ResourceGroupName", ($resourceGroupName))	
                $logResource.Add("ResourceName", ($resourceName))	
                $logResource.Add("Reason", "Valid resource id(s) not found in input json file.")    	
                $logSkippedResources += $logResource	
                Write-Host $([Constants]::SingleDashLine)
            }	
        }	
    }
    else {	
    # No file path provided as input to the script. Fetch all Azure Database for MySQL flexible server(s) in the Subscription
        if ([String]::IsNullOrWhiteSpace($FilePath)) {
            Write-Host "Fetching all Azure Database for MySQL flexible server(s) in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all Azure Database for MySQL flexible server(s) in a Subscription
            $servers = @();
            $servers = Get-AzMySqlFlexibleServer -ErrorAction Stop
            $servers | ForEach-Object { 	
                $parameterValue = (Get-AzMySqlFlexibleServerConfiguration -Name $([Constants]::ParameterName)  -ResourceGroupName $_.Id.Split("/")[4] -ServerName $_.Name ).Value 
                $DBForMySQLFlexibleServerDetails += $_  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                @{N = 'ResourceName'; E = { $_.Name } }, 
                @{N = 'SSLStatus'; E = { $parameterValue } }
            }        
        }
        else {
            if (-not (Test-Path -Path $FilePath)) {
                Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }

            Write-Host "Fetching all Azure Database for MySQL flexible server(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $DBForMySQLFSResources = Import-Csv -LiteralPath $FilePath

            $validDBForMySQLFSResources = $DBForMySQLFSResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

            $validDBForMySQLFSResources | ForEach-Object {
                $resourceId = $_.ResourceId

                try {                
                    $DBForMySQLFSResource = Get-AzMySqlFlexibleServer -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction Continue
                    if($DBForMySQLFSResource -ne $null)
                    {
                        $parameterValue = (Get-AzMySqlFlexibleServerConfiguration -Name $([Constants]::ParameterName) -ResourceGroupName $_.ResourceGroupName -ServerName $_.ResourceName ).Value
                        $DBForMySQLFlexibleServerDetails += $_  | Select-Object @{N = 'ResourceId'; E = { $_.ResourceId } },
                        @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName }},
                        @{N = 'ResourceName'; E = { $_.ResourceName } }, 
                        @{N = 'SSLStatus'; E = { $parameterValue } }
                    }
                }
                catch {
                    Write-Host "Error fetching Azure Database for MySQL flexible server(s) resource: Resource ID: [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
        }                                                           
    }
    
    $totalDBForMySQLFS = ($DBForMySQLFlexibleServerDetails | Measure-Object).Count

    if ($totalDBForMySQLFS -eq 0) {
        Write-Host "No Azure Database for MySQL flexible server(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }
  
    Write-Host "Found [$($totalDBForMySQLFS)] Azure Database for MySQL flexible server(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Azure Database for MySQL flexible server(s) for which server parameter require_secure_transport in not ON
     $DBForMySQLFSWithSSLNotEnabled = @()

    Write-Host "Separating Azure Database for MySQL flexible server(s) for which SSL is disabled..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $DBForMySQLFlexibleServerDetails | ForEach-Object {
        if (-not (CheckIfSSLConfigured($_.SSLStatus))) {
             $DBForMySQLFSWithSSLNotEnabled += $_
        }
        else {
            $logResource = @{}	
            $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
            $logResource.Add("ResourceName", ($_.ResourceName))
            $logResource.Add("Reason", "Encountered error while fetching server parameter require_secure_transport")            
            $logSkippedResources += $logResource	
        }   
    }
   
     $totalDBForMySQLFSWithSSLNotEnabled = ( $DBForMySQLFSWithSSLNotEnabled  | Measure-Object).Count

    if ( $totalDBForMySQLFSWithSSLNotEnabled -eq 0) {
        Write-Host "No Azure Database for MySQL flexible server(s) found with SSL disabled.Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlId) {
                    $logControl.SkippedResources = $logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$( $totalDBForMySQLFSWithSSLNotEnabled )] Azure Database for MySQL flexible server(s) for which SSL is disabled." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.SSLStatus }; Label = "'SSL Status'"; Width = 30; Alignment = "Center" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 100; Alignment = "left" }

    $colsProperty1 = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 100; Alignment = "left" }

    if (-not $AutoRemediation) {
        Write-Host "Azure Database for MySQL flexible server(s) with SSL disabled are:"
         $DBForMySQLFSWithSSLNotEnabled  | Format-Table -Property $colsProperty1 -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }    
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSSLForDBForMySQLFlexibleServer"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 3 of 4] Back up Azure Database for MySQL flexible server(s) details."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Azure Database for MySQL flexible server(s) details.
        $backupFile = "$($backupFolderPath)\DBForMySQLFlexibleServerWithSSLDisabled.csv"
         $DBForMySQLFSWithSSLNotEnabled  | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Azure Database for MySQL flexible server(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else {
        Write-Host "Skipped as -FilePath is provided." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 4 of 4] Enable SSL for Azure Database for MySQL flexible server(s) in the Subscription."
    Write-Host $([Constants]::SingleDashLine)

    if (-not $DryRun) {
        
        if (-not $AutoRemediation) {
            if (-not $Force) {
                Write-Host "Do you want to enable SSL for Azure Database for MySQL flexible server(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
                
                $userInput = Read-Host -Prompt "(Y|N)"

                if ($userInput -ne "Y") {
                    Write-Host "SSL will not be enabled for Azure Database for MySQL flexible server(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::DoubleDashLine)	
                    return
                }
                else {
                    Write-Host "Enabling server parameter 'require_secure_transport' to enforce SSL for Azure Database for MySQL flexible server(s) in the Subscription..." -ForegroundColor $([Constants]::MessageType.Update)
                }
            }
            else {
                Write-Host "'Force' flag is provided. Enabling server parameter 'require_secure_transport' to enforce SSL for Azure Database for MySQL flexible server(s) in the Subscription without any further prompts..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
        # List for storing remediated Azure Database for MySQL flexible server(s)
        $DBForMySQLFSRemediated = @()

        # List for storing skipped Azure Database for MySQL flexible server(s)
        $DBForMySQLFSSkipped = @()

        # Loop through the list of Azure Database for MySQL flexible server(s) which needs to be remediated.
        $DBForMySQLFSWithSSLNotEnabled  | ForEach-Object {
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName
            $DBForMySQLFS = $_
            try {
                $paramValue = (Update-AzMySqlFlexibleServerConfiguration -Name $([Constants]::ParameterName)  -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -Value $([Constants]::EnableSSLParameterValue)).Value 
                
                if (CheckIfSSLConfigured($paramValue)) {
                    $DBForMySQLFSRemediated += $_ | Select-Object @{N = 'ResourceId'; E = { $_.ResourceId } },
                    @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName }},
                    @{N = 'ResourceName'; E = { $_.ResourceName } }, 
                    @{N = 'SSLStatus'; E = { $paramValue } }
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))	
                    $logRemediatedResources += $logResource	
                }
                else {
                    $DBForMySQLFSSkipped += $_
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))
                    $logResource.Add("Reason", "Encountered error while setting server parameter require_secure_transport")            
                    $logSkippedResources += $logResource	
                }                
            }
            catch {
                $DBForMySQLFSSkipped += $_
                $logResource = @{}	
                $logResource.Add("ResourceGroupName", ($resourceGroupName))	
                $logResource.Add("ResourceName", ($resourceName))	
                $logResource.Add("Reason", "Encountered error while setting server parameter require_secure_transport")    	
                $logSkippedResources += $logResource
            }
        }
        
        Write-Host $([Constants]::DoubleDashLine) 

        if ($AutoRemediation) {
            if ($($DBForMySQLFSRemediated | Measure-Object).Count -gt 0) {        
                # Write this to a file.
                $DBForMySQLFSRemediatedFile = "$($backupFolderPath)\RemediatedDBForMySQLFS.csv"
                $DBForMySQLFSRemediated | Export-CSV -Path $DBForMySQLFSRemediatedFile -NoTypeInformation

                Write-Host "The information related to Azure Database for MySQL flexible server(s) which are remediated has been saved to [$($DBForMySQLFSRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }        
            if ($($DBForMySQLFSSkipped | Measure-Object).Count -gt 0) {
                $DBForMySQLFSSkipped | Format-Table -Property $colsProperty -Wrap            
                # Write this to a file.
                $DBForMySQLFSSkippedFile = "$($backupFolderPath)\SkippedDBForMySQLFS.csv"
                $DBForMySQLFSSkipped | Export-CSV -Path $DBForMySQLFSSkippedFile -NoTypeInformation
                Write-Host "The information related to Azure Database for MySQL flexible server(s) which are not remediated has been saved to [$($DBForMySQLFSSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else {
            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            if ($($DBForMySQLFSRemediated | Measure-Object).Count -gt 0) {
                Write-Host "Successfully enabled SSL for the following Azure Database for MySQL flexible server(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                $DBForMySQLFSRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $DBForMySQLFSRemediatedFile = "$($backupFolderPath)\RemediatedDBForMySQLFS.csv"
                $DBForMySQLFSRemediated | Export-CSV -Path $DBForMySQLFSRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($DBForMySQLFSRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }
        
            if ($($DBForMySQLFSSkipped | Measure-Object).Count -gt 0) {

                Write-Host "Error occured while enabling SSL for following Azure Database for MySQL flexible server(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                $DBForMySQLFSSkipped | Format-Table -Property $colsProperty -Wrap
               
                # Write this to a file.
                $DBForMySQLFSSkippedFile = "$($backupFolderPath)\SkippedDBForMySQLFS.csv"
                $DBForMySQLFSSkipped | Export-CSV -Path $DBForMySQLFSSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($DBForMySQLFSSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::DoubleDashLine)
            }
        }
        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $DBForMySQLFSRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else { 
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath [$($backupFile)] and without -DryRun, to Enable SSL for Azure Database for MySQL flexible server(s) listed in the file."
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Disable-SSLForDBForMySQLFlexibleServer {
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_DBForMySQLFlexibleServer_DP_Enable_SSL' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_DBForMySQLFlexibleServer_DP_Enable_SSL' Control.
        Change SSL to Previous Value on Azure Database for MySQL flexible server(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-SSLForDBForMySQLFlexibleServer.

        .OUTPUTS
        None. Disable-SSLForDBForMySQLFlexibleServer does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSSLForDBForMySQLFlexibleServer\RemediatedDBForMySQLFS.csv

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
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 3] Validate and install the modules required to run the script."
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck) {
        try {
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
        Write-Host "Skipped as -PerformPreReqCheck switch is not provided." -ForegroundColor $([Constants]::MessageType.Warning)
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
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    # Note about the required access required for remediation

    Write-Host "To disable SSL for Azure Database for MySQL flexible server(s) in the Subscription, Contributor or higher privileged role assignment on the Azure Database for MySQL flexible server(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Fetch all Azure Database for MySQL flexible server(s)."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Fetching all Azure Database for MySQL flexible server(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $DBForMySQLFlexibleServerDetails = Import-Csv -LiteralPath $FilePath

    $validDBForMySQLFSDetails = $DBForMySQLFlexibleServerDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalDBForMySQLFS = $(($validDBForMySQLFSDetails | Measure-Object).Count)

    if ($totalDBForMySQLFS -eq 0) {
        Write-Host "No Azure Database for MySQL flexible server(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$(($validDBForMySQLFSDetails|Measure-Object).Count)] Azure Database for MySQL flexible server(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.SSLStatus }; Label = "'SSL Status'"; Width = 30; Alignment = "center" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 100; Alignment = "left" }

    $colsProperty1 = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 100; Alignment = "left" }
        
    $validDBForMySQLFSDetails | Format-Table -Property $colsProperty1 -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSSLForDBForMySQLFlexibleServer"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }  
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 3 of 3] Disable SSL on all Azure Database for MySQL flexible server(s) in the Subscription."
    Write-Host $([Constants]::SingleDashLine)

    if ( -not $Force) {        
        Write-Host "Do you want to disable SSL for all Azure Database for MySQL flexible server(s)?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y") {
            Write-Host "SSL server parameter 'require_secure_transport' will not be rolled back on Azure Database for MySQL flexible server(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "Rolling back SSL server parameter 'require_secure_transport' on Azure Database for MySQL flexible server(s)..." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else {
        Write-Host "'Force' flag is provided. Rolling back SSL server parameter 'require_secure_transport' on Azure Database for MySQL flexible server(s) in the Subscription without any further prompts..." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    # List for storing rolled back Service Fabric resource.
    $DBForMySQLFSRolledBack = @()

    # List for storing skipped rolled back DBForMySQLFS resource.
    $DBForMySQLFSSkipped = @()

    $validDBForMySQLFSDetails | ForEach-Object {
        $DBForMySQLFS = $_
        try {   
            $RequireSecureTransportRolledBack = Update-AzMySqlFlexibleServerConfiguration -Name $([Constants]::ParameterName)  -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -Value $([Constants]::DisableSSLParameterValue)
            if($RequireSecureTransportRolledBack.Value -eq $([Constants]::DisableSSLParameterValue))
            {
                $DBForMySQLFSRolledBack += $DBForMySQLFS  | Select-Object @{N = 'ResourceId'; E = { $_.ResourceId } },
                @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName }},
                @{N = 'ResourceName'; E = { $_.ResourceName } }, 
                @{N = 'SSLStatus'; E = { $([Constants]::DisableSSLParameterValue) } }
            }
            else 
            {
                $DBForMySQLFSSkipped += $DBForMySQLFS
            }
        }
        catch 
        {
            $DBForMySQLFSSkipped += $DBForMySQLFS
        }
    }
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Rollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    if ($($DBForMySQLFSRolledBack | Measure-Object).Count -gt 0) {
        Write-Host "Successfully rolled back SSL on the following Azure Database for MySQL flexible server(s) in the Subscription:" -ForegroundColor $([Constants]::MessageType.Update)
        $DBForMySQLFSRolledBack | Format-Table -Property $colsProperty -Wrap

        # Write this to a file.
        $DBForMySQLFSRolledBackFile = "$($backupFolderPath)\RolledBackDBForMySQLFS.csv"
        $DBForMySQLFSRolledBack | Export-CSV -Path $DBForMySQLFSRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($DBForMySQLFSRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($($DBForMySQLFSSkipped | Measure-Object).Count -gt 0) {
        Write-Host "Error occured while rolling back SSL on the following Azure Database for MySQL flexible server(s) in the Subscription:" -ForegroundColor $([Constants]::MessageType.Error)
        $DBForMySQLFSSkipped | Format-Table -Property $colsProperty -Wrap
        # Write this to a file.
        $DBForMySQLFSSkippedFile = "$($backupFolderPath)\RollbackSkippedDBForMySQLFS.csv"
        $DBForMySQLFSSkipped | Export-CSV -Path $DBForMySQLFSSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($DBForMySQLFSSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
        Write-Host $([Constants]::SingleDashLine)
    }
}
function  CheckIfSSLConfigured {
    param (
        [String] $RequireSecureTransport 
    )
    #Check if server parameter 'require_Secure_transport' is set as ON    
    if ($RequireSecureTransport -eq $([Constants]::EnableSSLParameterValue)) {
        return $true
    }
    else {
        Return $false
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
    static [String] $ParameterName = "require_secure_transport"
    static [String] $EnableSSLParameterValue = "ON"
    static [String] $DisableSSLParameterValue = "OFF"
    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}