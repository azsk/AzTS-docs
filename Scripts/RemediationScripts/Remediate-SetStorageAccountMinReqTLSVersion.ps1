﻿<###
# Overview:
    This script is used to set required minimum TLS version for Storage Accounts in a Subscription.

# Control ID:
    Azure_Storage_DP_Use_Secure_TLS_Version

# Display Name:
    Use approved version of TLS for Azure Storage.

# Prerequisites:
    1. Contributor or higher privileges on the Storage Accounts in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script and validate the user.
        2. Get the list of Storage Accounts in a Subscription that do not use the required minimum TLS version.
        3. Back up details of Storage Accounts that are to be remediated.
        4. Set the required minimum TLS version on the all Storage Accounts in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script and validate the user.
        2. Get the list of Storage Accounts in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the previous minimum TLS versions on all Storage Accounts in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the required minimum TLS version in all Storage Accounts in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the previous minimum TLS versions in all Storage Accounts in the Subscription. Refer `Examples`, below.
        
# Examples:
    To remediate:
        1. To review the Storage Accounts in a Subscription that will be remediated:
           Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To set Minimum required TLS version  of all Storage Accounts in a Subscription:
           Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To set Minimum required TLS version on the of all Storage Accounts in a Subscription, from a previously taken snapshot:
           Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForStorageAccounts\StorageAccountsWithoutMinReqTLSVersion.csv

        4. To set Minimum required TLS version of all Storage Accounts in a Subscription without taking back up before actual remediation:
           Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Set-StorageAccountRequiredTLSVersion -Detailed

    To roll back:
        1. To rollback Minimum required TLS version of all Storage Accounts in a Subscription, from a previously taken snapshot:
           Reset-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForStorageAccounts\RemediatedStorageAccounts.csv
        
        2. To rollback Minimum required TLS version of all Storage Accounts in a Subscription, from a previously taken snapshot:
           Reset-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForStorageAccounts\RemediatedStorageAccounts.csv

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
    $requiredModules = @("Az.Accounts", "Az.Storage")

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
 
function Set-StorageAccountRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Remediates 'Azure_Storage_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Remediates 'Azure_Storage_DP_Use_Secure_TLS_Version' Control.
        Sets the required Minimum TLS version on the all Storage Accounts in the Subscription. 
        
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
        PS> Set-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForStorageAccounts\StorageAccountsWithoutMinReqTLSVersion.csv

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
        Write-Host "[Step 1 of 4] Validate the user..."
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

    Write-Host "To Set Minimum TLS version for Storage Accounts in a Subscription, Contributor or higher privileges on the Storage Accounts are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 2 of 4] Fetch Storage Accounts with Minimum TLS version less than required minimum TLS version..."
    Write-Host $([Constants]::SingleDashLine)
    
    $storageAccountResources = @()
    $requiredMinTLSVersion = "TLS1_2"


    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    # Control Id
    $controlIds = "Azure_Storage_DP_Use_Secure_TLS_Version"

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
                $storageAccountResources += $resStorageAccount | Select-Object @{N='StorageAccountName';E={$_.StorageAccountName}},
                                                                            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                            @{N='Kind';E={$_.Kind}},
                                                                            @{N ='MinimumTlsVersion';Expression={$_.MinimumTlsVersion}}
       
                                                                            
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
            
            Write-Host "Fetching all Storage Accounts in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all Storage Accounts in the Subscription
            $storageAccounts = Get-AzStorageAccount  -ErrorAction SilentlyContinue
            $storageAccountResources = $storageAccounts | Select-Object @{N='StorageAccountName';E={$_.StorageAccountName}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='Kind';E={$_.Kind}},
                                                                        @{N='MinimumTlsVersion';E={$_.MinimumTlsVersion}}
           
            $totalstorageAccountResources = ($storageAccountResources | Measure-Object).Count
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }

            Write-Host "Fetching all Storage Accounts(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
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
                                                                @{N='Kind';E={$_.Kind}}, 
                                                                @{N='MinimumTlsVersion';E={$_.MinimumTlsVersion}}
                }
                catch
                {
                    Write-Host "Error fetching Storage Account : [$($StorageAccountName)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Storage Account..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
        }
    }
    
    $totalstorageAccountResources = ($storageAccountResources | Measure-Object).Count

    if ($totalstorageAccountResources -eq 0)
    {
        Write-Host "No Storage Accounts found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($totalstorageAccountResources)] Storage Account(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
 
     
    # Includes Storage Accounts where Minimum required TLS version is not set   
    $StorageAccountsWithoutReqMinTLSVersion = @()

    # Includes Storage Accounts that were skipped during remediation. There were errors remediating them.
    $StorageAccountsSkipped = @()

    Write-Host "Separating Storage Account(s) for which minimum TLS is less than required minimum TLS version ..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $storageAccountResources | ForEach-Object {
        $storageAccount = $_        
        if($_.MinimumTlsVersion -ne $requiredMinTLSVersion) 
        {
            $StorageAccountsWithoutReqMinTLSVersion +=  $storageAccount 
        }
        else
        {
                if($AutoRemediation){
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason","Storage Account Minimum TLS version is already set to required Minimum TLS version.")    
                    $logSkippedResources += $logResource
                }
        }
    }

    $totalStorageAccountsWithoutReqMinTLSVersion = ($StorageAccountsWithoutReqMinTLSVersion | Measure-Object).Count
     
    if ($totalStorageAccountsWithoutReqMinTLSVersion  -eq 0)
    {
        Write-Host "No Storage Account(s) found where minimum TLS version is less than required minimum TLS version.. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
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

    Write-Host "Found [$($totalStorageAccountsWithoutReqMinTLSVersion)] Storage Accounts where minimum TLS version is either not set or less than required Minimum TLS version." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
     
    if(-not($AutoRemediation))
    {
        Write-Host "Following Storage Accounts are having minimum TLS version either not set or less than required Minimum TLS version:" -ForegroundColor $([Constants]::MessageType.Info)
       $colsProperty =  @{Expression={$_.StorageAccountName};Label="Storage Account Name";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=30;Alignment="left"},
                        @{Expression={$_.Kind};Label="Kind";Width=30;Alignment="left"},
                        @{Expression={$_.MinimumTlsVersion};Label="Minimum TLS version";Width=30;Alignment="left"}

        $StorageAccountsWithoutReqMinTLSVersion | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetStorageAccountMinReqTLSVersion"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    
    Write-Host "[Step 3 of 4] Back up Storage Account(s) details..."
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
        if(-not $SkipBackup)
        {
            # Backing up Storage Account details.
            $backupFile = "$($backupFolderPath)\StorageAccountsWithoutReqMinTLSVersion.csv"
            $StorageAccountsWithoutReqMinTLSVersion | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "Storage Account(s) details have been successful backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
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

            Write-Host "[Step 4 of 4] Configure required minimum TLS version on the Storage Accounts in the Subscription..."
            Write-Host $([Constants]::SingleDashLine)

            if (-not $Force)
            {
                Write-Host "Do you want to set minimum TLS version to required minimum TLS version for all Storage Account(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        

                $userInput = Read-Host -Prompt "(Y|N)" #TODO: 
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "Minimum TLS version will not be changed for any Storage Account(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    return
                }
                else
                {
                    Write-Host "Configuring required minimum TLS version for all Storage Account(s)..." -ForegroundColor $([Constants]::MessageType.Update)
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. Setting required minimum TLS version for all Storage Account(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }

        # To hold results from the remediation.
        $StorageAccountsRemediated = @()
    
        # Remidiate Controls by setting minimum TLS version to required minimum TLS version
        $StorageAccountsWithoutReqMinTLSVersion | ForEach-Object {
            $StorageAccount = $_
            $storageAccountName = $_.StorageAccountName;
            $resourceGroupName = $_.ResourceGroupName; 
            $TLS = $_.MinimumTlsVersion;

            # Holds the list of Storage Accounts where minimum TLS version change is skipped
            $StorageAccountsSkipped = @()
             
            try
            {   
                $storageAccount = Set-AzStorageAccount -Name $storageAccountName  -ResourceGroupName $resourceGroupName -MinimumTlsVersion $requiredMinTLSVersion
                if ($storageAccount.MinimumTlsVersion -ne $requiredMinTLSVersion)
                {
                    $StorageAccountsSkipped += $StorageAccount
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.StorageAccountName))
                    $logResource.Add("Reason", "Error while setting the minimum required TLS version for Storage Account")
                       
                }
                else
                {
                    $StorageAccountsRemediated += $StorageAccount | Select-Object @{N='StorageAccountName';E={$StorageAccountName}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='Kind';E={$_.Kind}},
                                                                        @{N='MinimumTlsVersionBefore';E={$TLS}},
                                                                        @{N='MinimumTlsVersionAfter';E={$($storageAccount.MinimumTlsVersion)}}

                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($resourceGroupName))
                    $logResource.Add("ResourceName",($storageAccountName))
                    $logRemediatedResources += $logResource
 
                }
            }
            catch
            {
                $StorageAccountsSkipped += $StorageAccount
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($resourceGroupName))
                $logResource.Add("ResourceName",($storageAccountName))
                $logResource.Add("Reason", "Error while setting the minimum required TLS version for Storage Account")
            }
        }

        $colsProperty1 = @{Expression={$_.StorageAccountName};Label="Storage Account Name";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=30;Alignment="left"},
                        @{Expression={$_.Kind};Label="Kind";Width=30;Alignment="left"},
                        @{Expression={$_.MinimumTlsVersionAfter};Label="Minimum TLS version";Width=30;Alignment="left"}
 
                       
                      
       
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
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
        
            if ($($StorageAccountsRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Successfully set the Minimum TLS version to required Minimum TLS version on the following Storage Account(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                $StorageAccountsRemediated | Format-Table -Property $colsProperty1 -Wrap

                # Write this to a file.
                $StorageAccountsRemediatedFile = "$($backupFolderPath)\RemediatedStorageAccountsFileforMinTLS.csv"
                $StorageAccountsRemediated| Export-CSV -Path $StorageAccountsRemediatedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($StorageAccountsRemediatedFile)]"
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($StorageAccountsSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error changing Minimum TLS version for following Storage Account(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $StorageAccountsSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
            
                # Write this to a file.
                $StorageAccountSkippedFile = "$($backupFolderPath)\SkippedStorageAccountsFileforMinTLS.csv"
                $StorageAccountsSkipped | Export-CSV -Path $StorageAccountSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($storageAccountResourcesSkippedFile)]"
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
       
        Write-Host "[Step 4 of 4] Configure required minimum TLS version on the Storage Accounts in the Subscription..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps: " -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to change the Minimum TLS version to required minimum TLS version for all Storage Account(s) listed in the file."
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Reset-StorageAccountRequiredTLSVersion
{
     <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_Storage_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_Storage_DP_Use_Secure_TLS_Version' Control.
        Resets Minimum TLS version on all Storage Accounts in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-StorageAccountRequiredTLSVersion.
        
        .OUTPUTS
        None. Reset-StorageAccountRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForStorageAccounts\RemediatedStorageAccounts.csv

        .EXAMPLE
        PS> Reset-StorageAccountRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForStorageAccounts\RemediatedStorageAccounts.csv

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
            Write-Host "[Step 1 of 3] Validate and install the modules required to run the script and validate the user..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites"	
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

    Write-Host "To rollback minimum TLS versions for Storage Account(s) in a Subscription, Contributor or higher privileges on the Storage Account(s) are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Storage Account(s)..."
    Write-Host $([Constants]::SingleDashLine)
    if(-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Fetching all Storage Account(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
       
    $storageAccountsFromFile = Import-Csv -LiteralPath $FilePath
    $validStorageAccounts = $storageAccountsFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.StorageAccountName) }
   
    $totalStorageAccountsWithChangedTLS = ($validStorageAccounts | Measure-Object).Count
     
    if ($totalStorageAccountsWithChangedTLS  -eq 0)
    {
        Write-Host "No Storage Accounts found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return
    } 

    Write-Host "Found [$($totalStorageAccountsWithChangedTLS)] Storage Account(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    $colsProperty = @{Expression={$_.StorageAccountName};Label="Storage Account Name";Width=30;Alignment="left"},
    @{Expression={$_.ResourceGroupName};Label="Resrouce Group";Width=30;Alignment="left"},
    @{Expression={$_.Kind};Label="Kind";Width=30;Alignment="left"},
    @{Expression={$_.MinimumTlsVersionAfter};Label="Minimum TLS version";Width=30;Alignment="left"}
                
    $validStorageAccounts | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\resetStorageAccountMinReqTLSVersion"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    } 
    
    Write-Host "[Step 3 of 3] Rollback the minimum TLS version for Storage Account(s)..."
    Write-Host $([Constants]::SingleDashLine)

    if (-not $Force)
    {
        Write-Host "Do you want to rollback minimum TLS version for all Storage Account(s)?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Minimum TLS version will not be rolledback for any of the Storage Account(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "Rolling back the minimum TLS version for Storage Account(s)..." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "'Force' flag is provided. Rolling back minimum TLS version for all of the Storage Account(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    # Includes Storage Account(s), to which, previously made changes were successfully rolled back.
    $StorageAccountsRolledBack = @()

    # Includes Storage Account(s) that were skipped during roll back. There were errors rolling back the changes made previously.
    $StorageAccountsSkipped = @()

     # Roll back by resetting minimum TLS version
        $validStorageAccounts | ForEach-Object {
            $StorageAccount = $_
            $StorageAccountName = $_.StorageAccountName
            $resourceGroupName = $_.ResourceGroupName
            $MinimumTlsVersionBefore = $_.MinimumTlsVersionBefore
            $MinimumTlsVersionAfter = $_.MinimumTlsVersionAfter

            try
            {  
                $StorageAccountResource =  Set-AzStorageAccount -StorageAccountName $StorageAccountName  -ResourceGroupName $resourceGroupName -MinimumTlsVersion $MinimumTlsVersionBefore
                if ($StorageAccountResource.MinimumTlsVersion -ne $MinimumTlsVersionBefore)
                {
                    $StorageAccountsSkipped += $StorageAccount | Select-Object  @{N='StorageAccountName';E={$StorageAccountName}},
                                                                                @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                @{N='Kind';E={$_.Kind}},
                                                                                @{N='MinimumTlsVersion';E={$MinimumTlsVersionAfter}}   
                }
                else
                {
                   
                    $StorageAccountsRolledBack += $StorageAccount | Select-Object   @{N='StorageAccountName';E={$StorageAccountName}},
                                                                                    @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                    @{N='Kind';E={$_.Kind}},
                                                                                    @{N='MinimumTlsVersion';E={$StorageAccountResource.MinimumTlsVersion}}
                }
            }
            catch
            {
                $StorageAccountsSkipped +=$StorageAccount | Select-Object   @{N='StorageAccountName';E={$StorageAccountName}},
                                                                            @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                            @{N='Kind';E={$_.Kind}},
                                                                            @{N='MinimumTlsVersion';E={$MinimumTlsVersionAfter}} 
            }
       }
         
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Rollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        
        $colsProperty = @{Expression={$_.StorageAccountName};Label="Storage Account Name";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resrouce Group";Width=30;Alignment="left"},
                        @{Expression={$_.Kind};Label="Kind";Width=30;Alignment="left"},
                        @{Expression={$_.MinimumTlsVersion};Label="Minimum TLS version";Width=30;Alignment="left"}
                        
        if ($($StorageAccountsRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Successfully rolled back minimum TLS version for following Storage Account(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $StorageAccountsRolledBack | Format-Table -Property $colsProperty -Wrap
            # Write this to a file.
            $StorageAccountsRolledBackFile = "$($backupFolderPath)\RolledBackStorageAccountForMinimumTls.csv"
            $StorageAccountsRolledBack| Export-CSV -Path $StorageAccountsRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to [$($StorageAccountsRolledBackFile)]"
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($StorageAccountsSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error occured while rolling back minimum TLS version for following Storage Account(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $StorageAccountsSkipped | Format-Table -Property $colsProperty -Wrap
            # Write this to a file.
            $StorageAccountsSkippedFile = "$($backupFolderPath)\RollbackSkippedStorageAccountForMinimumTls.csv"
            $StorageAccountsSkipped | Export-CSV -Path $StorageAccountsSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($StorageAccountsSkippedFile)]"
            Write-Host $([Constants]::DoubleDashLine)
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