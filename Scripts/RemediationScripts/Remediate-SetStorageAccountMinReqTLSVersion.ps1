<###
# Overview:
    This script is used to set required TLS version for Storage Account in a Subscription.

# Control ID:
    Azure_Storage_DP_Use_Secure_TLS_Version_Trial

# Display Name:
    Use Approved TLS Version in Storage Account.

# Prerequisites:
    1. Contributor or higher privileges on the Storage Accounts in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of Storage Accounts in a Subscription that do not use the required TLS version
        3. Back up details of Storage Accounts that are to be remediated.
        4. Set the required TLS version on the all Storage Accounts in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Storage Accounts in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the previous TLS versions on all Storage Accounts in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the required TLS version in all Storage Accounts in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the previous TLS versions in all Storage Accounts in the Subscription. Refer `Examples`, below.
        
# Examples:
    To remediate:
        1. To review the Storage Accounts in a Subscription that will be remediated:
           Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To set minimal required TLS version  of all Storage Accounts in a Subscription:
           Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To set minimal required TLS version on the of all Storage Accounts in a Subscription, from a previously taken snapshot:
           Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForStorageAccounts\StorageAccountsWithoutMinReqTLSVersion.csv

        4. To set minimal required TLS version of all Storage Accounts in a Subscription without taking back up before actual remediation:
           Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Set-StorageAccountRequiredTLSVersion -Detailed

    To roll back:
        1. To reset minimal required TLS version of all Storage Accounts in a Subscription, from a previously taken snapshot:
           Reset-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForStorageAccounts\RemediatedStorageAccounts.csv
        
        2. To reset minimal required TLS version of all Storage Accounts in a Subscription, from a previously taken snapshot:
           Reset-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForStorageAccounts\RemediatedStorageAccounts.csv

        To know more about the options supported by the roll back command, execute:
        Get-Help Reset-StorageAccountRequiredTLSVersion -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.Storage")

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
        }
        else
        {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
}

function Set-StorageAccountRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Remediates 'Azure_StorageAccount_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Remediates 'Azure_StorageAccount_DP_Use_Secure_TLS_Version' Control.
        Sets the required minimal TLS version on the all Storage Accounts in the Subscription. 
        
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
        None. You cannot pipe objects to Set-StorageAccountRequiredTLSVersion.

        .OUTPUTS
        None. Set-StorageAccountRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForStorageAccounts\StorageAccountsWithoutMinReqTLSVersion.csv

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
    Write-Host "[Step 1 of 4] Prepare to set required TLS version for Storage Accounts in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..."
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        break
    }

   
    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    if(-not($AutoRemediation))
    {
        Write-Host "Subscription Name: $($context.Subscription.Name)"
        Write-Host "Subscription ID: $($context.Subscription.SubscriptionId)"
        Write-Host "Account Name: $($context.Account.Id)"
        Write-Host "Account Type: $($context.Account.Type)"
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "To Set minimal TLS version for Storage Accounts in a Subscription, Contributor or higher privileges on the Storage Accounts are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Fetch all Storage Accounts"
    Write-Host $([Constants]::SingleDashLine)
    
    $storageAccountResources = @()
    $requiredMinTLSVersion = "TLS1_2"


    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources = @()

    # Control Id
    $controlIds = "Azure_Storage_DP_Use_Secure_TLS_Version_Trial"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
        Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
        }
        Write-Host "Fetching all Storage Accounts failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}

        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Storage Account(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }  
        $validResources | ForEach-Object { 
            try
            {
                $name = $_.ResourceName
                $resourceGroupName = $_.ResourceGroupName
            
                $resStorageAccount = Get-AzStorageAccount  -Name $name  -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue
                $storageAccountResources = $resStorageAccount | Select-Object @{N='StorageAccountName';E={$_.StorageAccountName}},
                                                                            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                            @{N='PrimaryLocation';E={$_.PrimaryLocation}},
                                                                            @{Name ='MinimalTlsVersion';Expression={ (Get-AzStorageAccount -Name $_.StorageAccountName -ResourceGroupName $_.ResourceGroupName).MinimumTlsVersion }}
       
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
        # No file path provided as input to the script. Fetch all Storage Accounts in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "`nFetching all Storage Accounts in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            # Get all Storage Accounts in the Subscription
            $storageAccounts = Get-AzStorageAccount  -ErrorAction Stop
            $storageAccountResources = $storageAccounts | Select-Object @{N='StorageAccountName';E={$_.StorageAccountName}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='PrimaryLocation';E={$_.PrimaryLocation}},
                                                                        @{Name ='MinimalTlsVersion';Expression={ (Get-AzStorageAccount -Name $_.StorageAccountName -ResourceGroupName $_.ResourceGroupName).MinimumTlsVersion }}
       
            $totalstorageAccountResources = ($storageAccountResources | Measure-Object).Count
        
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                break
            }

            Write-Host "Fetching all Storage Accounts(s) from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $storageAccountResourcesFromFile = Import-Csv -LiteralPath $FilePath
            $validstorageAccountResources = $storageAccountResourcesFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.StorageAccountName) }

            $validstorageAccountResources | ForEach-Object {
                $resourceGroupName = $_.ResourceGroupName        
                $storageAccountName = $_.StorageAccountName               
                try
                {
                    $storageAccount = Get-AzStorageAccount  -ResourceGroupName $resourceGroupName -Name $storageAccountName -ErrorAction SilentlyContinue
                    $storageAccountResources += $storageAccount | Select-Object @{N='StorageAccountName';E={$_.StorageAccountName}},
                                                                @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                @{N='PrimaryLocation';E={$_.PrimaryLocation}},
                                                                @{Name ='MinimalTlsVersion';Expression={ (Get-AzStorageAccount -Name $_.StorageAccountName -ResourceGroupName $_.ResourceGroupName).MinimumTlsVersion }}

                }
                catch
                {
                    Write-Host "Error fetching Storage Account:   - $($StorageAccountName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Storage Account..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
        }
    }
    
    $totalstorageAccountResources = ($storageAccountResources | Measure-Object).Count

    if ($totalstorageAccountResources -eq 0)
    {
        Write-Host "No Storage Accounts found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        break
    }

    Write-Host "Found $($totalstorageAccountResources) Storage Account(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
 
     
    # Includes Storage Accounts where minimal required TLS version is set  
    $StorageAccountsWithReqMinTLSVersion = @()

    # Includes Storage Accounts where minimal required TLS version is not set   
    $StorageAccountsWithoutReqMinTLSVersion = @()

    # Includes Storage Accounts that were skipped during remediation. There were errors remediating them.
    $StorageAccountsSkipped = @()

     
    
    Write-Host "`n[Step 3 of 5] Fetching Storage Accounts with (s)..."
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Storage Account(s) for which TLS is less than required TLS version ..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $storageAccountResources | ForEach-Object {
        $storageAccount = $_        
        if($_.MinimalTlsVersion -ne $requiredMinTLSVersion) 
        {
            $StorageAccountsWithoutReqMinTLSVersion +=  $storageAccount 
        }
    }

    $totalStorageAccountsWithoutReqMinTLSVersion = ($StorageAccountsWithoutReqMinTLSVersion | Measure-Object).Count
     
    if ($totalStorageAccountsWithoutReqMinTLSVersion  -eq 0)
    {
        Write-Host "No Storage Account(s) found where TLS is less than required TLS version.. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        
        if($AutoRemediation -and ($storageAccountResources |Measure-Object).Count -gt 0) 
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

    Write-Host "Found [$($totalStorageAccountsWithoutReqMinTLSVersion)] Storage Accounts where TLS version is either not set or less than required minimal TLS version." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
     
    if(-not($AutoRemediation))
    {
        Write-Host "`nFollowing Storage Accounts are having TLS version either not set or less than required minimal TLS version less than required TLS Version:" -ForegroundColor $([Constants]::MessageType.Info)
       $colsProperty =  @{Expression={$_.StorageAccountName};Label="Storage Account Name";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.PrimaryLocation};Label="Primary Location";Width=7;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersion};Label="Minimal TLS Version";Width=7;Alignment="left"}

        $StorageAccountsWithoutReqMinTLSVersion | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetStorageAccountMinReqTLSVersion"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    
    Write-Host "`n[Step 4 of 5] Backing up Storage Account(s) details..."
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
        if(-not $SkipBackup)
        {
            # Backing up Storage Account details.
            $backupFile = "$($backupFolderPath)\StorageAccountsWithoutReqMinTLSVersion.csv"
            $StorageAccountsWithoutReqMinTLSVersion | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "Storage Account(s) details have been successful backed up to $($backupFolderPath)" -ForegroundColor $([Constants]::MessageType.Update)
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

            Write-Host "TLS Version will be set to required TLS version for all Storage Accounts(s)." -ForegroundColor $([Constants]::MessageType.Warning)

            if (-not $Force)
            {
                Write-Host "Do you want to set TLS version to required TLS version for all Storage Account(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        

                $userInput = Read-Host -Prompt "(Y|N)" #TODO: 
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "TLS version will not be changed for any Storage Account(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    break
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. TLS version will be changed to required TLS version for all Storage Account(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

       
        Write-Host "`n[Step 5 of 5] Configuring TLS version for Storage Account(s)..."
        Write-Host $([Constants]::SingleDashLine)
        # To hold results from the remediation.
        $StorageAccountsRemediated = @()
    
        # Remidiate Controls by setting TLS version to required TLS version
        $StorageAccountsWithoutReqMinTLSVersion | ForEach-Object {
            $StorageAccount = $_
            $storageAccountName = $_.StorageAccountName;
            $resourceGroupName = $_.ResourceGroupName; 
            $tls = $_.MinimalTlsVersion;

            # Holds the list of Storage Accounts where TLS version change is skipped
            $StorageAccountsSkipped = @()
             
            try
            {   
                $storageAccounts = Set-AzStorageAccount -Name $storageAccountName  -ResourceGroupName $resourceGroupName -MinimumTlsVersion $requiredMinTLSVersion
                $StorageAccountTls = (Get-AzStorageAccount -Name $storageAccountName -ResourceGroupName $resourceGroupName).MinimumTlsVersion
                if ($StorageAccountTls -ne $requiredMinTLSVersion)
                {
                    $StorageAccountsSkipped += $StorageAccount
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.StorageAccountName))
                    $logResource.Add("Reason", "Error while setting the minimum required TLS version for Storage Account")
                    $logSkippedResources += $logResource   
                }
                else
                {
                    $StorageAccountsRemediated += $StorageAccount | Select-Object @{N='StorageAccountName';E={$StorageAccountName}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='PrimaryLocation';E={$_.PrimaryLocation}},
                                                                        @{N='MinimalTlsVersionBefore';E={$tls}},
                                                                        @{N='MinimalTlsVersionAfter';E={$StorageAccountTls}}

                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.StorageAccountName))
                    $logRemediatedResources += $logResource
 
                }
            }
            catch
            {
                $StorageAccountsSkipped += $StorageAccount
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.StorageAccountName))
                $logResource.Add("Reason", "Error while setting the minimum required TLS version for Storage Account")
                $logSkippedResources += $logResource  
            }
        }

        $totalRemediatedStorageAccounts = ($StorageAccountsRemediated | Measure-Object).Count

        Write-Host $([Constants]::SingleDashLine)

        if ($totalRemediatedStorageAccounts -eq $StorageAccountsWithoutReqMinTLSVersion)
        {
            Write-Host "TLS Version changed to required TLS version for all $($totalStorageAccountsWithoutReqMinTLSVersion) Storage Account(s) ." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)       
        }
        else
        {
            Write-Host "TLS Version changed to required TLS version for $totalRemediatedStorageAccounts out of $($totalStorageAccountsWithoutReqMinTLSVersion) Storage Account(s)" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        $colsProperty = @{Expression={$_.StorageAccountName};Label="Storage Account Name";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=10;Alignment="left"},
                        @{Expression={$_.PrimaryLocation};Label="Primary Location";Width=7;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersionBefore};Label="Minimal TLS Ver. Before";Width=7;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersionAfter};Label="Minimal TLS Ver. After";Width=7;Alignment="left"}
 
                       
                      
       
        if($AutoRemediation)
        {
            if ($($StorageAccountsRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $StorageAccountsRemediatedFile = "$($backupFolderPath)\RemediatedStorageAccountsFileforMinTLS.csv"
                $StorageAccountsRemediated| Export-CSV -Path $StorageAccountsRemediatedFile -NoTypeInformation
                Write-Host "The information related to Storage Account(s) where minimum required TLS version is successfully set has been saved to [$($StorageAccountsRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($StorageAccountsSkipped | Measure-Object).Count -gt 0)
            {   
                # Write this to a file.
                $StorageAccountSkippedFile = "$($backupFolderPath)\SkippedStorageAccountsFileforMinTLS.csv"
                $StorageAccountsSkipped | Export-CSV -Path $StorageAccountSkippedFile -NoTypeInformation
                Write-Host "The information related to Storage Account(s) where minimum required TLS version is not set has been saved to [$($StorageAccountsSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "`nRemediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($StorageAccountsRemediated | Measure-Object).Count -gt 0)
            {
                $StorageAccountsRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $StorageAccountsRemediatedFile = "$($backupFolderPath)\RemediatedStorageAccountsFileforMinTLS.csv"
                $StorageAccountsRemediated| Export-CSV -Path $StorageAccountsRemediatedFile -NoTypeInformation
                Write-Host "This information has been saved to $($StorageAccountsRemediatedFile)"
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($StorageAccountsSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "`nError changing minimal TLS version for following Storage Account(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $StorageAccountsSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
            
                # Write this to a file.
                $StorageAccountSkippedFile = "$($backupFolderPath)\SkippedStorageAccountsFileforMinTLS.csv"
                $StorageAccountsSkipped | Export-CSV -Path $StorageAccountSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to $($storageAccountResourcesSkippedFile)"
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
                    $logControl.RollbackFile = $StorageAccountsRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
       
        Write-Host "`n[Step 5 of 5] Changing minimal TLS version for Storage Accounts(s)..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "`n**Next steps:**" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to change the minimal TLS version to required TLS version for all Storage Account(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Reset-StorageAccountRequiredTLSVersion
{
     <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_StorageAccount_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_StorageAccount_DP_Use_Secure_TLS_Version' Control.
        Resets minimal TLS Version on the production slot and all non-production slots in all Storage Accounts in the Subscription. 
        
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
        None. You cannot pipe objects to Reset-StorageAccountRequiredTLSVersion.
        
        .OUTPUTS
        None. Reset-StorageAccountRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForStorageAccounts\RemediatedStorageAccounts.csv

        .EXAMPLE
        PS> Reset-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -ExcludeNonProductionSlots -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\setMinTLSVersionForStorageAccounts\RemediatedStorageAccounts.csv

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
    Write-Host "`n[Step 1 of 4] Preparing to reset Storage Account TLS Version in Subscription: $($SubscriptionId)"
    Write-Host $([Constants]::SingleDashLine)
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        break
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: $($context.Subscription.Name)"
    Write-Host "Subscription ID: $($context.Subscription.SubscriptionId)"
    Write-Host "Account Name: $($context.Account.Id)"
    Write-Host "Account Type: $($context.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "*** To reset TLS Versions for Storage Account(s) in a Subscription, Contributor or higher privileges on the Storage Account(s) are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "`n[Step 2 of 4] Preparing to fetch all Storage Account(s)..."
    Write-Host $([Constants]::SingleDashLine)
    if(-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        break
    }

    Write-Host "Fetching all Storage Account(s) from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
       
    $storageAccountsFromFile = Import-Csv -LiteralPath $FilePath
    $validStorageAccounts = $storageAccountsFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.StorageAccountName) }
        
    $StorageAccounts = @()
    $StorageAccountList = @()

    $validStorageAccounts | ForEach-Object {
        $storageAccount = $_
        $storageAccountName = $_.StorageAccountName
        $resourceGroupName = $_.ResourceGroupName
        $minimalTlsVersionBefore = $_.MinimalTlsVersionBefore
        $minimalTlsVersionAfter = $_.MinimalTlsVersionAfter

        try
        {
            $StorageAccount = ( Get-AzStorageAccount -StorageAccountName $storageAccountName  -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue) 
            $StorageAccountTls = (Get-AzStorageAccount -Name $storageAccountName -ResourceGroupName $resourceGroupName).MinimumTlsVersion
            $StorageAccounts += $StorageAccount | Select-Object @{N='StorageAccountName';E={$StorageAccountName}},
                                                                    @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                    @{N='PrimaryLocation';E={$_.PrimaryLocation}},
                                                                    @{N='MinimalTlsVersionAfter';E={$StorageAccountTls}},
                                                                    @{N='MinimalTlsVersionBefore';E={$minimalTlsVersionBefore}}
                                                                  


        }
        catch
        {
            Write-Host "Error fetching Storage Account :  $($storageAccountName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this Storage Account..." -ForegroundColor $([Constants]::MessageType.Warning)
        }
    }


        
    # Includes Storage Accounts
    $StorageAccountsWithChangedTLS = @()

    
   
    Write-Host "`n[Step 3 of 4] Fetching Storage Account(s)..."
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Storage Accounts..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $StorageAccounts | ForEach-Object {
        $StorageAccount = $_        
            if($_.MinimalTlsVersionAfter -ne $_.MinimalTlsVersionBefore)
            {
                $StorageAccountsWithChangedTLS += $StorageAccount
            }
    }

    $totalStorageAccountsWithChangedTLS = ($StorageAccountsWithChangedTLS | Measure-Object).Count
     
    if ($totalStorageAccountsWithChangedTLS  -eq 0)
    {
        Write-Host "No Storage Accounts found where minimal TLS version need to be changed.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return
    } 

    
    Write-Host "Found [$($totalStorageAccountsWithChangedTLS)] Storage Accounts " -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
    
     # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\resetStorageAccountMinReqTLSVersion"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    } 
    
    if (-not $Force)
    {
        Write-Host "Do you want to reset minimal TLS Version for all Storage Account(s)?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "minimal TLS Version will not be reseted for any of the Storage Account(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. TLS Version will  be reseted for all of the Storage Account(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    Write-Host "`n[Step 3 of 4] Resetting the minimal TLS Version for Storage Account(s) ..."
    Write-Host $([Constants]::SingleDashLine)
    # Includes Storage Account(s), to which, previously made changes were successfully rolled back.
    $StorageAccountsRolledBack = @()

    # Includes Storage Account(s) that were skipped during roll back. There were errors rolling back the changes made previously.
    $StorageAccountsSkipped = @()

     # Roll back by resetting TLS Version
        $StorageAccountsWithChangedTLS | ForEach-Object {
            $StorageAccount = $_
            $StorageAccountName = $_.StorageAccountName
            $resourceGroupName = $_.ResourceGroupName
            $minimalTlsVersionBefore = $_.MinimalTlsVersionBefore
            $minimalTlsVersionAfter = $_.MinimalTlsVersionAfter

            try
            {  
                $StorageAccountResource =  Set-AzStorageAccount -StorageAccountName $StorageAccountName  -ResourceGroupName $resourceGroupName -MinimumTlsVersion $minimalTlsVersionBefore
                $StorageAccountTls = (Get-AzStorageAccount -Name $storageAccountName -ResourceGroupName $resourceGroupName).MinimumTlsVersion
                if ($StorageAccountTls -ne $minimalTlsVersionBefore)
                {
                    $StorageAccountsSkipped += $StorageAccount   
                }
                else
                {
                   
                    $StorageAccountsRolledBack += $StorageAccount | Select-Object @{N='StorageAccountName';E={$StorageAccountName}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='PrimaryLocation';E={$_.PrimaryLocation}},
                                                                        @{N='MinimalTlsVersionBefore';E={$MinimalTlsVersionAfter}},
                                                                        @{N='MinimalTlsVersionAfter';E={$StorageAccountTls}}
                }
            }
            catch
            {
                $StorageAccountsSkipped += $StorageAccount
            }
       }
    

        $totalStorageAccountsRolledBack = ($StorageAccountsRolledBack | Measure-Object).Count
 
        if ($totalStorageAccountsRolledBack -eq $totalStorageAccountsWithChangedTLS)
        {
            Write-Host "TLS Version resetted for all $($totalStorageAccountsWithChangedTLS) Storage Account(s) ." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "TLS Version resetted  for  $totalStorageAccountsRolledBack out of $($totalStorageAccountsWithChangedTLS) Storage Accounts(s)" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
         
        Write-Host "`nRollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        
        $colsProperty = @{Expression={$_.StorageAccountName};Label="Storage Account Name";Width=10;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resrouce Group";Width=10;Alignment="left"},
                        @{Expression={$_.PrimaryLocation};Label="Primary Location";Width=10;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersionAfter};Label="Minimal Tls Version After";Width=7;Alignment="left"},
                        @{Expression={$_.MinimalTlsVersionBefore};Label="Minimal Tls Version Before";Width=7;Alignment="left"}
            
        if ($($StorageAccountsRolledBack | Measure-Object).Count -gt 0)
        {
            $StorageAccountsRolledBack | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $StorageAccountsRolledBackFile = "$($backupFolderPath)\RolledBackStorageAccountForMinimalTls.csv"
            $StorageAccountsRolledBack| Export-CSV -Path $StorageAccountsRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to $($StorageAccountsRolledBackFile)"
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($StorageAccountsSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError resetting TLS for following Storage Account(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $StorageAccountsSkipped | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            
            # Write this to a file.
            $StorageAccountsSkippedFile = "$($backupFolderPath)\RollbackSkippedStorageAccountForMinimalTls.csv"
            $StorageAccountsSkipped | Export-CSV -Path $StorageAccountsSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to $($StorageAccountsSkippedFile)"
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