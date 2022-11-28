<###
# Overview:
    This script is used to set SSL for Azure Database for MySQL flexible server in a Subscription.

# Control ID:
    Azure_DBForMySQLFlexibleServer_DP_Enable_SSL_Trial

# Display Name:
    Azure Database for MySQL - Flexible Servers Announcing SSL enforcement

# Prerequisites:    
    Contributor or higher priviliged role on the Azure Database for MySQL flexible server(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Azure Database for MySQL flexible server(s) in a Subscription that have server parameter require_secure_transport not set as ON.
        3. Back up details of Azure Database for MySQL flexible server(s) that are to be remediated.
        4. Set SSL by updating server parameter require_secure_transport as ON for Azure Database for MySQL flexible server(s).

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Azure Database for MySQL flexible server(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the server parameter require_secure_transport to original value as per input file.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set SSL for Azure Database for MySQL flexible server(s) in the Subscription. Refer `Examples`, below.
    
    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set SSL for Azure Database for MySQL flexible server(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Azure Database for MySQL flexible server(s) in a Subscription that will be remediated:
    
           Set-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Set SSL for Azure Database for MySQL flexible server(s) in the Subscription:
       
           Set-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Set SSL for Azure Database for MySQL flexible server(s) in the Subscription, from a previously taken snapshot:
       
           Set-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSSLForDBForMySQLFlexibleServer\DBForMySQLFlexibleServerDetailsBackUp.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Set-SSLForDBForMySQLFlexibleServer -Detailed

    To roll back:
        1. Set SSL for Azure Database for MySQL flexible server(s) in the Subscription, from a previously taken snapshot:
           Set-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSSLForDBForMySQLFlexibleServer/DBForMySQLFlexibleServerDetailsBackUp.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Set-SSLForDBForMySQLFlexibleServer -Detailed        
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


function Set-SSLForDBForMySQLFlexibleServer {
    <#
        .SYNOPSIS
        Remediates 'Azure_DBForMySQLFlexibleServer_DP_Enable_SSL_Trial' Control.

        .DESCRIPTION
        Remediates 'Azure_DBForMySQLFlexibleServer_DP_Enable_SSL_Trial' Control.
        Set SSL as ON for Azure Database for MySQL flexible server(s) in the Subscription. 
        
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
        None. You cannot pipe objects to Set-SSLForDBForMySQLFlexibleServer.

        .OUTPUTS
        None. Set-SSLForDBForMySQLFlexibleServer does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-SSLForDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSSLForDBForMySQLFlexibleServer\DBForMySQLFlexibleServerDetailsBackUp.csv

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

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script and validating the user"
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
        Write-Host "[Step 1 of 4] Validate the user"
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
    Write-Host "To set SSL for Azure Database for MySQL flexible server(s) in the Subscription, Contributor or higher privileged role assignment on the Azure Database for MySQL flexible server(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)  

    Write-Host "[Step 2 of 4] Fetch all Azure Database for MySQL flexible server(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Container details.
    $DBForMySQLFlexibleServerDetails = @()

    # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources = @()	

    $controlIds = "Azure_DBForMySQLFlexibleServer_DP_Enable_SSL_Trial"

    # No file path provided as input to the script. Fetch all Azure Database for MySQL flexible server(s) in the Subscription.

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
            try {
                $DBForMySQLFSResource = Get-AzMySqlFlexibleServer -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                $parameterValue = (Get-AzMySqlFlexibleServerConfiguration -Name $([Constants]::ParameterName)  -ResourceGroupName $_.ResourceGroupName -ServerName $_.ResourceName -SubscriptionId $SubscriptionId).Value
                $DBForMySQLFlexibleServerDetails += $DBForMySQLFSResource  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                @{N = 'ResourceName'; E = { $_.Name } }, 
                @{N = 'RequireSecureTransport'; E = { $parameterValue } }
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
                Write-Host "Error fetching Azure Database for MySQL flexible server(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }	
        }	
    }
    else {	
        if ([String]::IsNullOrWhiteSpace($FilePath)) {
            Write-Host "Fetching all Azure Database for MySQL flexible server(s) in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all Azure Database for MySQL flexible server(s) in a Subscription
            $servers = @();
            $servers = Get-AzMySqlFlexibleServer -ErrorAction Stop
            $servers | ForEach-Object { 	
                #$DBForMySQLFSResource =  Get-AzMySqlFlexibleServer -Name $_.Name -ResourceGroupName $_.Id.Split("/")[4]  -ErrorAction SilentlyContinue 
                $parameterValue = (Get-AzMySqlFlexibleServerConfiguration -Name $([Constants]::ParameterName)  -ResourceGroupName $_.Id.Split("/")[4] -ServerName $_.Name -SubscriptionId $SubscriptionId).Value 
                $DBForMySQLFlexibleServerDetails += $_  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                @{N = 'ResourceName'; E = { $_.Name } }, 
                @{N = 'RequireSecureTransport'; E = { $parameterValue } }
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
                    $DBForMySQLFSResource = Get-AzMySqlFlexibleServer -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
            
                    $parameterValue = (Get-AzMySqlFlexibleServerConfiguration -Name $[Constants]::ParameterName -ResourceGroupName $_.ResourceGroupName -ServerName $_.ResourceName -SubscriptionId $SubscriptionId).Value
                    $DBForMySQLFlexibleServerDetails += $_  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                    @{N = 'ResourceGroupName'; E = { $_.Id.Split("/")[4] } },
                    @{N = 'ResourceName'; E = { $_.Name } }, 
                    @{N = 'RequireSecureTransport'; E = { $parameterValue } }
            
                }
                catch {
                    Write-Host "Error fetching Azure Database for MySQL flexible server(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
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

    Write-Host "Separating Azure Database for MySQL flexible server(s) for which SSL is not enabled..." -ForegroundColor $([Constants]::MessageType.Info)

    $DBForMySQLFlexibleServerDetails | ForEach-Object {
        if (-not (CheckIfSSLConfigured($_.RequireSecureTransport))) {
             $DBForMySQLFSWithSSLNotEnabled += $_
        }
    }
   
     $totalDBForMySQLFSWithSSLNotEnabled = ( $DBForMySQLFSWithSSLNotEnabled  | Measure-Object).Count

    if ( $totalDBForMySQLFSWithSSLNotEnabled -eq 0) {
        Write-Host "No Azure Database for MySQL flexible server(s) found with SSL disabled.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$( $totalDBForMySQLFSWithSSLNotEnabled )] Azure Database for MySQL flexible server(s) for which SSL is not enabled." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 100; Alignment = "left" },
    @{Expression = { $_.RequireSecureTransport }; Label = "RequireSecureTransport"; Width = 100; Alignment = "left" }

    if (-not $AutoRemediation) {
        Write-Host "Azure Database for MySQL flexible server(s) with SSL disabled are:"
         $DBForMySQLFSWithSSLNotEnabled  | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }    
    

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSSLForDBForMySQLFlexibleServer"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 3 of 4] Back up Azure Database for MySQL flexible server(s) details"
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Azure Database for MySQL flexible server(s) details.
        $backupFile = "$($backupFolderPath)\DBForMySQLFlexibleServerDetailsBackUp.csv"
         $DBForMySQLFSWithSSLNotEnabled  | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Azure Database for MySQL flexible server(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "Skipped as -FilePath is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun) {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "[Step 4 of 4] Enable SSL for Azure Database for MySQL flexible server(s) in the Subscription" 
        Write-Host $([Constants]::SingleDashLine)
        

        if (-not $Force) {
            Write-Host "Do you want to enable SSL for Azure Database for MySQL flexible server(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if ($userInput -ne "Y") {
                Write-Host "SSL will not be changed for Azure Database for MySQL flexible server(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
        }
        else {
            Write-Host "'Force' flag is provided. SSL will be enabled on Azure Database for MySQL flexible server(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        # List for storing remediated Azure Database for MySQL flexible server(s)
        $DBForMySQLFSRemediated = @()

        # List for storing skipped Azure Database for MySQL flexible server(s)
        $DBForMySQLFSSkipped = @()

        Write-Host "Enabling SSL for Azure Database for MySQL flexible server(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of Azure Database for MySQL flexible server(s) which needs to be remediated.
         $DBForMySQLFSWithSSLNotEnabled  | ForEach-Object {
            $DBForMySQLFS = $_
            try {
                $paramValue = (Update-AzMySqlFlexibleServerConfiguration -Name $([Constants]::ParameterName)  -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -Value $([Constants]::EnableSSLParameterValue)).Value 
                
                if (CheckIfSSLConfigured($paramValue)) {
                    $DBForMySQLFSRemediated += $_
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
                    $logResource.Add("Reason", "Encountered error while setting server parameter require_secure_transport: [$($DBForMySQLFS)]")            
                    $logSkippedResources += $logResource	

                }                
            }
            catch {
                $DBForMySQLFSSkipped += $_
                $logResource = @{}	
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                $logResource.Add("ResourceName", ($_.ResourceName))	
                $logResource.Add("Reason", "Encountered error while setting server parameter require_secure_transport")    	
                $logSkippedResources += $logResource	
                Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host $([Constants]::DoubleDashLine)
        
        
        if ($AutoRemediation) {
            if ($($DBForMySQLFSRemediated | Measure-Object).Count -gt 0) {
                
                # Write this to a file.
                $DBForMySQLFSRemediatedFile = "$($backupFolderPath)\RemediatedDBForMySQLFS.csv"
                $DBForMySQLFSRemediated | Export-CSV -Path $DBForMySQLFSRemediatedFile -NoTypeInformation

                Write-Host "The information related to Azure Database for MySQL flexible server(s) where server parameter require_secure_transport changed has been saved to [$($DBForMySQLFSRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        
            if ($($DBForMySQLFSSkipped | Measure-Object).Count -gt 0) {
                $DBForMySQLFSSkipped | Format-Table -Property $colsProperty -Wrap            
                # Write this to a file.
                $DBForMySQLFSSkippedFile = "$($backupFolderPath)\SkippedDBForMySQLFS.csv"
                $DBForMySQLFSSkipped | Export-CSV -Path $DBForMySQLFSSkippedFile -NoTypeInformation
                Write-Host "The information related to Azure Database for MySQL flexible server(s) where server parameter require_secure_transport not changed has been saved to [$($DBForMySQLFSSkippedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

        }
        else {

            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            if ($($DBForMySQLFSRemediated | Measure-Object).Count -gt 0) {
                Write-Host "Successfully set SSL for the following DBForMySQLFS(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $DBForMySQLFSRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $DBForMySQLFSRemediatedFile = "$($backupFolderPath)\RemediatedDBForMySQLFS.csv"
                $DBForMySQLFSRemediated | Export-CSV -Path $DBForMySQLFSRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($DBForMySQLFSRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            }
        
            if ($($DBForMySQLFSSkipped | Measure-Object).Count -gt 0) {

                Write-Host "Error while setting up the server parameter require_secure_transport for Azure Database for MySQL flexible server(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $DBForMySQLFSSkipped | Format-Table -Property $colsProperty -Wrap
            
                # Write this to a file.
                $DBForMySQLFSSkippedFile = "$($backupFolderPath)\SkippedDBForMySQLFS.csv"
                $DBForMySQLFSSkipped | Export-CSV -Path $DBForMySQLFSSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($DBForMySQLFSSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
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
        Write-Host "[Step 4 of 4] Enable SSL on Azure Database for MySQL flexible server(s) in the Subscription." 
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath [$($backupFile)] and without -DryRun, to set SSL for Azure Database for MySQL flexible server(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Set-RequireSecureTransporttoPreviousValueforDBForMySQLFlexibleServer {
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_DBForMySQLFlexibleServer_DP_Enable_SSL_Trial' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_DBForMySQLFlexibleServer_DP_Enable_SSL_Trial' Control.
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
        None. You cannot pipe objects to Set-RequireSecureTransporttoPreviousValueforDBForMySQLFlexibleServer.

        .OUTPUTS
        None. Set-RequireSecureTransporttoPreviousValueforDBForMySQLFlexibleServer does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-RequireSecureTransporttoPreviousValueforDBForMySQLFlexibleServer -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSSLForDBForMySQLFlexibleServer\RemediatedDBForMySQLFS.csv

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

    Write-Host "To set SSL for Azure Database for MySQL flexible server(s) in the Subscription, Contributor or higher privileged role assignment on the Azure Database for MySQL flexible server(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Azure Database for MySQL flexible server(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "Input file:  [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Fetching all Azure Database for MySQL flexible server(s) from" -NoNewline
    Write-Host " [$($FilePath)\...]..." -ForegroundColor $([Constants]::MessageType.Info)
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
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 100; Alignment = "left" },
    @{Expression = { $_.RequireSecureTransport }; Label = "RequireSecureTransport"; Width = 100; Alignment = "left" }
        
    $validDBForMySQLFSDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSSLForDBForMySQLFlexibleServer"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 3 of 3] Set SSL to previous value on all Azure Database for MySQL flexible server(s) in the Subscription"
    Write-Host $([Constants]::SingleDashLine)

    if ( -not $Force) {
        
        Write-Host "Do you want to enable SSL for all Azure Database for MySQL flexible server(s) mentioned in the file?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y") {
            Write-Host "SSL server parameter (require_secure_transport) will not be rolled back on Azure Database for MySQL flexible server(s) mentioned in the file. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "SSL server parameter (require_secure_transport) will be rolled back on Azure Database for MySQL flexible server(s) mentioned in the file." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "'Force' flag is provided. SSL will be rolled back on Azure Database for MySQL flexible server(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Service Fabric resource.
    $DBForMySQLFSRolledBack = @()

    # List for storing skipped rolled back DBForMySQLFS resource.
    $DBForMySQLFSSkipped = @()

    $validDBForMySQLFSDetails | ForEach-Object {
        $DBForMySQLFS = $_
        try {   
            $RequireSecureTransportRolledBack = Update-AzMySqlFlexibleServerConfiguration -Name $([Constants]::ParameterName)  -ResourceGroupName $_.ResourceGroupName  -ServerName $_.ResourceName -Value $_.RequireSecureTransport
            $DBForMySQLFSRolledBack += $DBForMySQLFS
        }
        catch {
                $DBForMySQLFSSkipped += $DBForMySQLFS
        }
    }


        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($DBForMySQLFSRolledBack | Measure-Object).Count -gt 0) {
            Write-Host "SSL server parameter (require_secure_transport) has been rolled back on the following Azure Database for MySQL flexible server(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
            $DBForMySQLFSRolledBack | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)

            # Write this to a file.
            $DBForMySQLFSRolledBackFile = "$($backupFolderPath)\RolledBackDBForMySQLFS.csv"
            $DBForMySQLFSRolledBack | Export-CSV -Path $DBForMySQLFSRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($DBForMySQLFSRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
        }

        if ($($DBForMySQLFSSkipped | Measure-Object).Count -gt 0) {
            Write-Host "Error while rolling back SSL server parameter (require_secure_transport) on Azure Database for MySQL flexible server(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
            $DBForMySQLFSSkipped | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)

            
            # Write this to a file.
            $DBForMySQLFSSkippedFile = "$($backupFolderPath)\RollbackSkippedDBForMySQLFS.csv"
            $DBForMySQLFSSkipped | Export-CSV -Path $DBForMySQLFSSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($DBForMySQLFSSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
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
        # Control Id	
        static [String] $ParameterName = "require_secure_transport"
        static [String] $EnableSSLParameterValue = "ON"
        static [String] $DoubleDashLine = "========================================================================================================================"
        static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
    }