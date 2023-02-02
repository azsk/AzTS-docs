<###
# Overview:
    This script is used to set required TLS version for SQL Managed Instance in a Subscription.

# Control ID:
    Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version

# Display Name:
    Use approved version of TLS for Azure SQL Managed Instance.

# Prerequisites:
    1. Contributor or higher privileges on the SQL Managed Instance in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Managed Instances in a Subscription that do not use the required TLS version
        3. Back up details of SQL Managed Instances that are to be remediated.
        4. Set the required TLS version on the all SQL Managed Instances in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of SQL Managed Instances in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the previous TLS versions on all SQL Managed Instances in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the required TLS version in all SQL Managed Instances in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the previous TLS versions in all SQL Managed Instances in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the SQL Managed Instances in a Subscription that will be remediated:
           Set-SQLManagedInstanceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To set minimal required TLS version  of all SQL Managed Instances in a Subscription:
           Set-SQLManagedInstanceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To set minimal required TLS version on the of all SQL Managed Instances in a Subscription, from a previously taken snapshot:
           Set-SQLManagedInstanceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForSQLManagedInstances\SQLManagedInstancesWithoutMinReqTLSVersion.csv

        4. To set minimal required TLS version of all SQL Managed Instances in a Subscription without taking back up before actual remediation:
           Set-SQLManagedInstanceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Set-SQLManagedInstanceRequiredTLSVersion -Detailed

    To roll back:
        1. To reset minimal required TLS version of all SQL Managed Instances in a Subscription, from a previously taken snapshot:
           Reset-SQLManagedInstanceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForSQLManagedInstances\RemediatedSQLManagedInstances.csv
        
        2. To reset minimal required TLS version of all SQL Managed Instances in a Subscription, from a previously taken snapshot:
           Reset-SQLManagedInstanceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForSQLManagedInstances\RemediatedSQLManagedInstances.csv

        To know more about the options supported by the roll back command, execute:
        Get-Help Reset-SQLManagedInstanceRequiredTLSVersion -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Sql")

    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)    
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    $AzSqlModule = $availableModules | Where-Object{$_.Name -eq "Az.Sql"} | Sort-Object -Property Version -Descending | Select-Object -First 1
    $AzSqlVersion = $AzSqlModule.Version
    
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
            if($_ -eq "Az.Sql" -and $AzSqlVersion -lt "4.2.0")
            {
                Write-Host "[$($_)] module is present but the version is older." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Installing required version of [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
                Install-Module -Name $_ -AllowClobber -Force -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
                Write-Host "Required version of [$($_)] module is installed." -ForegroundColor $([Constants]::MessageType.Update)
            }
            else
            {
                Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
            }
        }
    }
}

function Set-SQLManagedInstanceRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Remediates 'Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Remediates 'Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version' Control.
        Sets the required minimal TLS version on the all SQL ManagedInstances in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER SkipBackup
        Specifies that no back up will be taken by the script before remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Set-SQLManagedInstanceRequiredTLSVersion.

        .OUTPUTS
        None. Set-SQLManagedInstanceRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-SQLManagedInstanceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-SQLManagedInstanceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-SQLManagedInstanceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForSQLManagedInstances\SQLManagedInstancesWithoutMinReqTLSVersion.csv

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

    Write-Host "To set minimal TLS version for SQL Managed Instances in a Subscription, Contributor or higher privileges on the SQL Managed Instances are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 5] Fetch all SQL Managed Instances"
    Write-Host $([Constants]::SingleDashLine)
    $sqlManagedInstanceResources = @()
    $requiredMinTLSVersion = 1.2

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()
    
    # Control Id
    $controlIds = "Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "Fetching all SQL Managed Instances failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}

        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No SQL Managed Instances found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        } 

        $validResources | ForEach-Object { 
            try
            {
                $name = $_.ResourceName
                $resourceGroupName = $_.ResourceGroupName
                $sqlManagedInstance = Get-AzSqlInstance -Name $name -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue
                $sqlManagedInstanceResources += $sqlManagedInstance
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
        # No file path provided as input to the script. Fetch all SQL Managed Instances in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all SQL Managed Instances in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all SQL Managed Instances in the Subscription
            $sqlManagedInstanceResources = Get-AzSqlInstance -ErrorAction SilentlyContinue
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }

            Write-Host "Fetching all SQL Managed Instances from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $sqlManagedInstanceResourcesFromFile = Import-Csv -LiteralPath $FilePath
            $validSqlManagedInstanceResources = $sqlManagedInstanceResourcesFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.SQLManagedInstanceName) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) }
    
            $validSqlManagedInstanceResources | ForEach-Object {
                $resourceGroupName = $_.ResourceGroupName        
                $name = $_.SQLManagedInstanceName               

                try
                {
                    $sqlManagedInstanceResources += (Get-AzSqlInstance -ResourceGroupName $resourceGroupName -Name $name -ErrorAction SilentlyContinue) 

                }
                catch
                {
                    Write-Host "Error fetching SQL Managed Instance: [$($name)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this SQL Managed Instance..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
        }
    }

    $totalSqlManagedInstanceResources = ($sqlManagedInstanceResources | Measure-Object).Count

    if ($totalSqlManagedInstanceResources -eq 0)
    {
        Write-Host "No SQL Managed Instances found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($totalSqlManagedInstanceResources)] SQL Managed Instance(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
 
     
    # Includes SQL Managed Instances where minimal required TLS version is set  
    $sqlManagedInstancesWithReqMinTLSVersion = @()

    # Includes SQL Managed Instances where minimal required TLS version is not set   
    $sqlManagedInstancesWithoutReqMinTLSVersion = @()

    # Includes SQL Managed Instances that were skipped during remediation. There were errors remediating them.
    $sqlManagedInstancesSkipped = @()

     
    Write-Host "[Step 3 of 5] Fetching SQL Managed Instances with minimal TLS version less than minimal required TLS version"
    Write-Host $([Constants]::SingleDashLine)
    $sqlManagedInstanceResources | ForEach-Object {
        $sqlManagedInstance = $_        
        if($_.MinimalTlsVersion -lt $requiredMinTLSVersion) 
        {
            $sqlManagedInstancesWithoutReqMinTLSVersion +=  $sqlManagedInstance | Select-Object @{N='SQLManagedInstanceName';E={$_.ManagedInstanceName}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='MinimalTlsVersion';E={$_.MinimalTlsVersion}}
        }
        else{
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ManagedInstanceName))
                $logResource.Add("Reason","Minimal TLS Version already set to required Minimal TLS Version")    
                $logSkippedResources += $logResource
        }
    }

    $totalSqlManagedInstancesWithoutReqMinTLSVersion = ($sqlManagedInstancesWithoutReqMinTLSVersion | Measure-Object).Count
     
    if ($totalSqlManagedInstancesWithoutReqMinTLSVersion  -eq 0)
    {
        Write-Host "No SQL Managed Instances found where minimal TLS version is less than required minimal TLS version. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        if($AutoRemediation) 
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

    Write-Host "Found [$($totalSqlManagedInstancesWithoutReqMinTLSVersion)] SQL Managed Instances where minimal TLS version is either not set or less than required minimal TLS version." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
     
    $colsProperty = @{Expression={$_.SQLManagedInstanceName};Label="SQL Managed Instance Name";Width=35;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"},
                    @{Expression={$_.MinimalTlsVersion};Label="Minimal TLS Version";Width=10;Alignment="left"}

    if(-not($AutoRemediation))
    {
        $sqlManagedInstancesWithoutReqMinTLSVersion | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetSQLManagedInstanceMinReqTLSVersion"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 4 of 5] Backing up SQL Managed Instance details"
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
        if(-not $SkipBackup)
        {
            # Backing up SQL Managed Instance details.
            $backupFile = "$($backupFolderPath)\SQLManagedInstancesWithoutReqMinTLSVersion.csv"
            $sqlManagedInstancesWithoutReqMinTLSVersion | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "SQL Managed Instances details have been successful backed up to [$($backupFolderPath)]" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
  

    Write-Host "[Step 5 of 5] Set Minimal TLS version for SQL Managed Instance"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not $DryRun)
    {  
        # Here AutoRemediation switch is used as there is no need to take user input at BRS level if user has given consent to proceed with the remediation in AutoRemediation Script.
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "Do you want to set minimal TLS version to minimal required TLS version on all SQL Managed Instances? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                $userInput = Read-Host -Prompt "(Y|N)"

                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "Minimal TLS version will not be set to minimal required TLS version on any SQL Managed Instances. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    return
                }
                else
                {
                    Write-Host "User has provided consent to set minimal TLS version to minimal required TLS version on all SQL Managed Instances." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. Minimal TLS version will be set to required minimal TLS version on all SQL Managed Instances without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        # To hold results from the remediation.
        $sqlManagedInstancesRemediated = @()
    
        Write-Host "Setting minimal TLS version to the required minimal TLS version on all the SQL Managed Instances..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Remediate Controls by setting minimum TLS version to required TLS version
        $sqlManagedInstancesWithoutReqMinTLSVersion | ForEach-Object {
            $sqlManagedInstance = $_
            $name = $_.SQLManagedInstanceName;
            $resourceGroupName = $_.ResourceGroupName; 
            $tls = $_.MinimalTlsVersion;

            # Holds the list of SQL Managed Instances where TLS version change is skipped
            $sqlManagedInstancesSkipped = @()
             
            try
            {   
                $sqlManagedInstanceTLS = Set-AzSqlInstance -Name $name -ResourceGroupName $resourceGroupName -MinimalTlsVersion $requiredMinTLSVersion -Force

                if ($sqlManagedInstanceTLS.MinimalTlsVersion -ne $requiredMinTLSVersion)
                {
                    $sqlManagedInstancesSkipped += $sqlManagedInstance
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($resourceGroupName))
                    $logResource.Add("ResourceName",($name))
                    $logResource.Add("Reason", "Error while setting the minimal required TLS version for SQL Managed Instance")
                    $logSkippedResources += $logResource    
                }
                else
                {
                    $sqlManagedInstancesRemediated += $sqlManagedInstance | Select-Object @{N='SQLManagedInstanceName';E={$name}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='MinimalTlsVersionBefore';E={$tls}},
                                                                        @{N='MinimalTlsVersionAfter';E={$sqlManagedInstanceTLS.MinimalTlsVersion}}

                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($resourceGroupName))
                    $logResource.Add("ResourceName",($name))
                    $logRemediatedResources += $logResource
 
                }
            }
            catch
            {
                $sqlManagedInstancesSkipped += $sqlManagedInstance
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($resourceGroupName))
                $logResource.Add("ResourceName",($name))
                $logResource.Add("Reason", "Error while setting the minimal required TLS version for SQL Managed Instance")
                $logSkippedResources += $logResource 
            }
        }

        $totalRemediatedSQLManagedInstances = ($sqlManagedInstancesRemediated | Measure-Object).Count
         

        if ($totalRemediatedSQLManagedInstances -eq $totalSqlManagedInstancesWithoutReqMinTLSVersion)
        {
            Write-Host "Minimal TLS Version is set to minimal required TLS version for all [$($totalSqlManagedInstancesWithoutReqMinTLSVersion)] SQL Managed Instances." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "Minimal TLS Version set to minimal required TLS version for [$($totalRemediatedSQLManagedInstances)] out of [$($totalSqlManagedInstancesWithoutReqMinTLSVersion)] SQL Managed Instances." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        $colsProperty1 = @{Expression={$_.SQLManagedInstanceName};Label="SQL Managed Instance Name";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersionBefore};Label="Minimal TLS Version before Remediation";Width=10;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersionAfter};Label="Minimal TLS Version after Remediation";Width=10;Alignment="left"}

        $colsProperty2 = @{Expression={$_.SQLManagedInstanceName};Label="SQL Managed Instance Name";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)

        if($AutoRemediation)
        {
            if ($($sqlManagedInstancesRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $sqlManagedInstancesRemediatedFile = "$($backupFolderPath)\RemediatedSQLManagedInstancesFileforMinTLS.csv"
                $sqlManagedInstancesRemediated| Export-CSV -Path $sqlManagedInstancesRemediatedFile -NoTypeInformation
                Write-Host "The information related to SQL Managed Instances where minimal TLS version is successfully set to minimal required TLS version has been saved to [$($sqlManagedInstancesRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($sqlManagedInstancesSkipped | Measure-Object).Count -gt 0)
            {   
                # Write this to a file.
                $sqlManagedInstancesSkippedFile = "$($backupFolderPath)\SkippedSQLManagedInstancesFileforMinTLS.csv"
                $sqlManagedInstancesSkipped | Export-CSV -Path $sqlManagedInstancesSkippedFile -NoTypeInformation
                Write-Host "The information related to SQL Managed Instances where minimal TLS version is not set to minimal required TLS version has been saved to [$($sqlManagedInstancesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($sqlManagedInstancesRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Successfully set the minimal TLS version to minimal required TLS version on the following SQL Managed Instances in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $sqlManagedInstancesRemediated | Format-Table -Property $colsProperty1 -Wrap

                # Write this to a file.
                $sqlManagedInstancesRemediatedFile = "$($backupFolderPath)\RemediatedSQLManagedInstancesFileforMinTLS.csv"
                $sqlManagedInstancesRemediated| Export-CSV -Path $sqlManagedInstancesRemediatedFile -NoTypeInformation
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "This information has been saved to [$($sqlManagedInstancesRemediatedFile)]"
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($sqlManagedInstancesSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error while setting minimal TLS version for following SQL Managed Instances:" -ForegroundColor $([Constants]::MessageType.Error)
                $sqlManagedInstancesSkipped | Format-Table -Property $colsProperty2 -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $sqlManagedInstanceskippedFile = "$($backupFolderPath)\SkippedSQLManagedInstancesFileforMinTLS.csv"
                $sqlManagedInstancesSkipped | Export-CSV -Path $sqlManagedInstanceskippedFile -NoTypeInformation
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "This information has been saved to [$($sqlManagedInstanceskippedFile)]"
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
                    $logControl.RollbackFile = $sqlManagedInstancesRemediatedFile
                }
            }
            
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps: " -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to set the minimal TLS version to minimal required TLS version for all SQL Managed Instances listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Reset-SQLManagedInstanceRequiredTLSVersion
{
     <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version' Control.
        Resets minimal TLS Version in all SQL Managed Instances in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .Parameter ExcludeNonProductionSlots
        Specifies exclusion of non-production slots from roll back.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-SQLManagedInstanceRequiredTLSVersion.

        .OUTPUTS
        None. Reset-SQLManagedInstanceRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-SQLManagedInstanceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForSQLManagedInstances\RemediatedSQLManagedInstances.csv

        .EXAMPLE
        PS> Reset-SQLManagedInstanceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForSQLManagedInstances\RemediatedSQLManagedInstances.csv

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
            Write-Host "[Step 1 of 3] Validate and install the modules required to run the script and validate the user"
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
        Write-Host "[Step 1 of 3] Validate the user" 
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

    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    # Note about the required access required for remediation

    Write-Host "To reset TLS version for SQL Managed Instances in a Subscription, Contributor or higher privileges on the SQL Managed Instances are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 2 of 3] Fetching all SQL Managed Instances"
    Write-Host $([Constants]::SingleDashLine)

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Fetching all SQL Managed Instances from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
       
    $sqlManagedInstancesFromFile = Import-Csv -LiteralPath $FilePath
    $validSqlManagedInstances = $sqlManagedInstancesFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.SQLManagedInstanceName -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName)) }
    
    $sqlManagedInstances = @()

    $validSqlManagedInstances | ForEach-Object {
        $name = $_.SQLManagedInstanceName
        $resourceGroupName = $_.ResourceGroupName
        $minimalTlsVersionBefore = $_.MinimalTlsVersionBefore
        $minimalTlsVersionAfter = $_.MinimalTlsVersionAfter

        try
        {
            $sqlManagedInstance = Get-AzSqlInstance -Name $name -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue
            $sqlManagedInstances += $sqlManagedInstance | Select-Object @{N='SQLManagedInstanceName';E={$name}},
                                                                    @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                    @{N='MinimalTlsVersionAfter';E={$minimalTlsVersionAfter}},
                                                                    @{N='MinimalTlsVersionBefore';E={$minimalTlsVersionBefore}},
                                                                    @{N='MinimalTlsVersionCurrent';E={$sqlManagedInstance.MinimalTlsVersion}}
        }
        catch
        {
            Write-Host "Error while fetching SQL Managed Instance: [$($name)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this SQL Managed Instance..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
    }

    $totalSqlManagedInstances = ($sqlManagedInstances | Measure-Object).Count

    Write-Host "Found [$($totalSqlManagedInstances)] SQL Managed Instances." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
    
     # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ResetSQLManagedInstanceMinReqTLSVersion"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    } 

    Write-Host "[Step 3 of 3] Reset the minimal TLS Version on the SQL Managed Instances"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not $Force)
    {
        Write-Host "Do you want to reset minimal TLS Version on all SQL Managed Instances? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)

        if($userInput -ne "Y")
        {
            Write-Host "Minimal TLS version will not be reset on any of the SQL Managed Instance. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "User has provided consent to reset minimal required TLS version on all of the SQL Managed Instances." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. Minimal TLS version will be reset on all of the SQL Managed Instances without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

    # Includes SQL Managed Instance(s), to which, previously made changes were successfully rolled back.
    $sqlManagedInstancesRolledBack = @()

    # Includes SQL Managed Instance(s) that were skipped during roll back. There were errors rolling back the changes made previously.
    $sqlManagedInstancesSkipped = @()

    Write-Host "Rolling back the minimal TLS version on all the SQL Managed Instances..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    # Roll back by resetting TLS Version
    $sqlManagedInstances | ForEach-Object {
        $name = $_.SQLManagedInstanceName
        $resourceGroupName = $_.ResourceGroupName
        $minimalTlsVersionBefore = $_.MinimalTlsVersionBefore
        $minimalTlsVersionAfter = $_.MinimalTlsVersionAfter
        $minimalTlsVersionCurrent = $_.MinimalTlsVersionCurrent
        
        try
        {  
            if([String]::IsNullOrWhiteSpace($minimalTlsVersionBefore))
            {
                $sqlManagedInstancesSkipped += $_
                Write-Host "The minimal TLS version for the SQL Managed Instance: [$($name)] can't be rolled back as it was set to null before remediation and minimum TLS version can't be set to null." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                return;
            }

            if($minimalTlsVersionAfter -ne $minimalTlsVersionCurrent)
            {
                $sqlManagedInstancesSkipped += $_
                Write-Host "The minimal TLS version for the SQL Managed Instance: [$($name)] can't be rolled back as the minimal TLS version is changed after performing remediation via script." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                return;
            }

            $sqlManagedInstance = Set-AzSqlInstance -Name $name -ResourceGroupName $resourceGroupName -MinimalTlsVersion $minimalTlsVersionBefore -Force

            if ($sqlManagedInstance.MinimalTlsVersion -ne $minimalTlsVersionBefore)
            {
                $sqlManagedInstancesSkipped += $sqlManagedInstance      
            }
            else
            {
                $sqlManagedInstancesRolledBack += $sqlManagedInstance | Select-Object @{N='SQLManagedInstanceName';E={$name}},
                                                                    @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                    @{N='MinimalTlsVersionBefore';E={$MinimalTlsVersionAfter}},
                                                                    @{N='MinimalTlsVersionAfter';E={$sqlManagedInstance.MinimalTlsVersion}}
            }
        }
        catch
        {
            $sqlManagedInstancesSkipped += $sqlManagedInstance
        }
    }
    

    $totalSqlManagedInstancesRolledBack = ($sqlManagedInstancesRolledBack | Measure-Object).Count

    Write-Host "Minimum TLS version is rolled back for [$($totalSqlManagedInstancesRolledBack)] out of [$($totalSqlManagedInstances)] SQL Managed Instances." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::DoubleDashLine)
    

    Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
    
    $colsProperty1 = @{Expression={$_.SQLManagedInstanceName};Label="SQL Managed Instance Name";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersionBefore};Label="Minimal TLS Version before Rollback";Width=10;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersionAfter};Label="Minimal TLS Version after Rollback";Width=10;Alignment="left"}   
    
    $colsProperty2 = @{Expression={$_.SQLManagedInstanceName};Label="SQL Managed Instance Name";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersionCurrent};Label="Minimal TLS Version";Width=10;Alignment="left"}   


    if ($($sqlManagedInstancesRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "Successfully rolled back minimal TLS version for following SQL Managed Instance:" -ForegroundColor $([Constants]::MessageType.Update)
        $sqlManagedInstancesRolledBack | Format-Table -Property $colsProperty1 -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $sqlManagedInstancesRolledBackFile = "$($backupFolderPath)\RolledBackSQLManagedInstanceForMinimalTls.csv"
        $sqlManagedInstancesRolledBack| Export-CSV -Path $sqlManagedInstancesRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to [$($sqlManagedInstancesRolledBackFile)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($($sqlManagedInstancesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error while rolling back minimal TLS version for following SQL Managed Instances:" -ForegroundColor $([Constants]::MessageType.Error)
        $sqlManagedInstancesSkipped | Format-Table -Property $colsProperty2 -Wrap
        Write-Host $([Constants]::SingleDashLine)
        
        # Write this to a file.
        $sqlManagedInstancesSkippedFile = "$($backupFolderPath)\RollbackSkippedSQLManagedInstanceForMinimalTls.csv"
        $sqlManagedInstancesSkipped | Export-CSV -Path $sqlManagedInstancesSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to [$($sqlManagedInstancesSkippedFile)]"
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