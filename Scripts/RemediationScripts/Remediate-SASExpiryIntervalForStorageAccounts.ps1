<##########################################

# Overview:
    This script is used to set the SAS Expiry Interval for storage accounts less than the approved limit.

# ControlId: 
    Azure_Storage_AuthZ_Set_SAS_Expiry_Interval

# DisplayName:
    Shared Access Signature (SAS) expiry interval must be less than approved upper limit for Azure Storage

# Pre-requisites:
    1. You will need atleast contributor role on Storage Account(s) of subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script :
   To Remediate:
        1. Validate and/or install the modules required to run the script.
        2. Get list of Storage Account in a subscription which have SAS Expiry Interval not set and if set, then more than the apporved limit.
        3. Back up details of Storage Accounts that are to be remediated.
        4. Set the SAS Expiry Interval for the Storage Account(s) of subscription.

   To rollback:
        1. Validate and/or install the modules required to run the script.
        3. Get the list of Storage Accounts in a Subscription, the changes made to which previously, are to be rolled back.
        4. Reset the SAS Expiry Interval for the Storage Account(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script set SAS Expiry Interval on the Storage Account in the Subscription. Refer 'Examples', below.
   
    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to reset SAS Expiry Interval on the Storage Account in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Storage Account in a Subscription that will be remediated:
           Set-SASExpiryInterval -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        2. To enable encryption in transit on the Storage Account in a Subscription:
           Set-SASExpiryInterval -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 
       
       //TODO - change file name
        3. To enable encryption in transit on the Storage Account in a Subscription, from a previously taken snapshot:
           Set-SASExpiryInterval -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\Users\AppData\Local\AzTS\Remediation\Subscriptions\00000000_xxxx_0000_xxxx_000000000000\20211013_0608\EnableSecureTransit\StorageWithDisableHTTPS.csv
        
        4. To enable encryption in transit on the Storage Account in a Subscription without taking back up before actual remediation:
           Set-SASExpiryInterval -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Set-SASExpiryInterval -Detailed
   
    To rollback: 
        1. To disable  encryption in transit on the Storage Account in a Subscription, from a previously taken snapshot:
           Reset-SASExpiryInterval -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath  C:\Users\Documents\AzTS\Remediation\Subscriptions\00000000_xxxx_0000_xxxx_000000000000\20211013_0608\EnableSecureTransit\StorageWithDisableHTTPS.csv

        To know more about the options supported by the roll back command, execute:
        
        Get-Help Reset-SASExpiryInterval -Detailed 

#########################################>

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
            Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "$($_) module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host $([Constants]::SingleDashLine)
}

#function to perform remediation.
function Set-SASExpiryInterval
{
    <#
        .SYNOPSIS
        This command would help in remediating "Azure_Storage_AuthZ_Set_SAS_Expiry_Interval" control.

        .DESCRIPTION
        Set SAS Expiry Interval less than the apporved limit on the Storage Account in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
         
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER SkipBackup
        Specifies that no back up will be taken by the script before remediation.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .PARAMETER ExcludeResourceGroupNames
        Specifies the name of resource groups to be excluded from the remediation. To include this parameter please load the script form the file Helper.ps1 available in the Remediation script directory.
  
        .PARAMETER ExcludeResourceNames
        Specifies the name of resource  to be excluded from the remediation.To include this parameter please load the script form the file Helper.ps1 available in the Remediation script directory.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Set-SASExpiryInterval.

        .OUTPUTS
        None. Set-SASExpiryInterval does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        Set-SASExpiryInterval -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun
      
        .EXAMPLE
        Set-SASExpiryInterval -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 
      
      TODO: Change FilePath 
        .EXAMPLE
        PS> Set-SASExpiryInterval -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePathC:\Users\AppData\Local\AzTS\Remediation\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\20211013_0608\EnableSecureTransit\StorageWithDisableHTTPS.csv
         
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
        
        [string]
        [Parameter(ParameterSetName = "DryRun",  HelpMessage="Comma separated resource group name(s) to be excluded from remediation")]
        [Parameter(ParameterSetName = "WetRun",  HelpMessage="Comma separated resource group name(s) to be excluded from remediation")]
        $ExcludeResourceGroupNames,

        [string]
        [Parameter(ParameterSetName = "DryRun",  HelpMessage="Comma separated resource name(s) to be excluded from remediation")]
        [Parameter(ParameterSetName = "WetRun",  HelpMessage="Comma separated resource name(s) to be excluded from remediation")]
        $ExcludeResourceNames,

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
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 5] Validate the User" 
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

    Write-Host "To set SAS Expiry Interval for Storage Account(s) in a Subscription, Contributor or higher privileges on the Storage Account are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 2 of 5] Fetch Storage Account(s)"
    Write-Host $([Constants]::SingleDashLine)

    # Array to store Storage Account(s) list .
    $storageAccounts = @()

    $storageAccountsWithSasExpiryIntervalProperlySet = @()
    $storageAccountsWithoutSasExpiryIntervalProperlySet = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    $controlIds = "Azure_Storage_AuthZ_Set_SAS_Expiry_Interval"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "Fetching all Storage Account(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Storage Account(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            try
            {
                $storageAccount = Get-AzStorageAccount -StorageAccountName $_.ResourceName -ResourceGroupName $_.ResourceGroupName -ErrorAction SilentlyContinue
                $storageAccounts += $storageAccount
                # $sasExpiryInterval = $storageAccount.SasPolicy.SasExpirationPeriod
                # $storageAccounts += $storageAccount | Select-Object @{N = "ResourceName", E = {$_.ResourceName}},
                #                                                      {N = "ResourceGroupName", E = {$_.ResourceGroupName}},
                #                                                      {N = "ResourceId", E = {$_.ResourceId}},
                #                                                      {N = "SASExpiryInterval", E = {$sasExpiryInterval},
            }
            catch
            {
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..."
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Valid resource id(s) not found in input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
                return
            }
        }
    }
    else 
    {
        # No file path provided as input to the script. Fetch all Storage accounts in the Subscription.
        if([string]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all Storage Account(s) of the subscription: [$($SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            #Get all Storage Account in a Subscription
            $storageAccounts = Get-AzStorageAccount 
            Write-Host "Successfully fetched all the Storage Account(s) of the subscription." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {   #checking if the file path is correct.
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file path [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }

            Write-Host "Fetching all Storage Account(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $storageAccountDetails = Import-Csv -LiteralPath $FilePath
            $validStorageAccountDetails = $storageAccountDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
            
            $validStorageAccountDetails | ForEach-Object {
                $resourceId = $_.ResourceId

                try
                {
                    #storing the list of Storage Account .
                    $storageAccount = Get-AzStorageAccount -StorageAccountName $_.StorageAccountName -ResourceGroupName $_.ResourceGroupName -ErrorAction SilentlyContinue
                    $storageAccounts += $storageAccount
                }
                catch
                {
                    Write-Host "Error fetching Storage Account with resource ID: [$($resourceId)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Storage Account..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
            Write-Host "Completed fetching all the Storage Account(s) from the [$($FilePath)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
    }

    $totalStorageAccount = ($storageAccounts | Measure-Object).Count

    if($totalStorageAccount -eq 0)
    {  
        Write-Host "No Storage Account found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($totalStorageAccount)] Storage Account(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 3 of 5] Filter Storage Account(s) where SAS Expiry Interval is not properly set"
    Write-Host $([Constants]::SingleDashLine)

    $storageAccounts | ForEach-Object {
        if($null -eq $_.SasPolicy.SasExpirationPeriod)
        {
            $storageAccountsWithoutSasExpiryIntervalProperlySet += $_ | Select-Object @{ N = "ResourceName", E = {$_.ResourceName}},
                                                                                   @{ N = "ResourceGroupName", E = {$_.ResourceGroupName}},
                                                                                   @{ N = "ResourceId", E = {$_.ResourceId}},
                                                                                   @{ N = "SASExpiryInterval", E = {$([Constants]::TimeSpanWhenSASExpiryIntervalDisabled)}}
        }
        else if(-not(CheckifSASExpiryIntervalIsValid($_.SasPolicy.SasExpirationPeriod)))
        {
            $storageAccountsWithoutSasExpiryIntervalProperlySet += $_ | Select-Object @{ N = "ResourceName", E = {$_.ResourceName}},
                                                                                   @{ N = "ResourceGroupName", E = {$_.ResourceGroupName}},
                                                                                   @{ N = "ResourceId", E = {$_.ResourceId}},
                                                                                   @{ N = "SASExpiryInterval", E = {$_.SasPolicy.SasExpirationPeriod}}
        }
        else
        {
            $storageAccountsWithSasExpiryIntervalProperlySet += $_ | Select-Object @{ N = "ResourceName", E = {$_.ResourceName}},
                                                                                   @{ N = "ResourceGroupName", E = {$_.ResourceGroupName}},
                                                                                   @{ N = "ResourceId", E = {$_.ResourceId}},
                                                                                   @{ N = "SASExpiryInterval", E = {$_.SasPolicy.SasExpirationPeriod}}

            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason","SAS Expiry Interval is properly set.")    
            $logSkippedResources += $logResource
            Write-Host $([Constants]::SingleDashLine)
        }
    }

    if(($storageAccountsWithoutSasExpiryIntervalProperlySet | Measure-Object).Count -eq 0)
    {
        Write-Host "All Storage Account(s) have SAS Expiry Interval properly set. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
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

    Write-Host "Found [$(($storageAccountsWithoutSasExpiryIntervalProperlySet | Measure-Object).Count)] Storage Account(s) where SAS Expiry Interval is not properly set." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
                    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
                    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 100; Alignment = "left" },
                    @{Expression = { $_.SASExpiryInterval }; Label = "SASExpiryInterval"; Width = 100; Alignment = "left" }

    if (-not $AutoRemediation) 
    {
        Write-Host "Storage Account(s) where SAS Expiry Interval is not properly set are:"
        $storageAccountsWithoutSasExpiryIntervalProperlySet | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SASExpiryInterval"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "[Step 4 of 5] Back up Storage Account(s) details"
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        $backupFile = "$($backupFolderPath)\SetSASExpiryIntervalInStorageAccounts.csv"
        $storageAccountsWithoutSasExpiryIntervalProperlySet | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Storage Account(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "Skipped as -FilePath parameter is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 5 of 5] Set SAS Expiry Interval on Storage Account(s)" 
    Write-Host $([Constants]::SingleDashLine)
    if(-not $DryRun)
    {
        $userInputTimeSpan = $([Constants]::MaximumApprovedTimeSpanForSASExpiryInterval)
        if(-not $AutoRemediation)
        {
            if (-not $Force) {
                Write-Host "Do you want to set SAS Expiry Interval on all the Storage Account(s)? " -ForegroundColor $([Constants]::MessageType.Warning)

                $userInput = Read-Host -Prompt "(Y|N)"

                if ($userInput -ne "Y") {
                    Write-Host "SAS Expiry Interval will not be set on Storage Account(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::DoubleDashLine)	
                    return
                }

                Write-Host "User has provide consent to set SAS Expiry Interval on all the Storage Account(s)." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $userInputTimeSpan = UserInputTimeSpan
            }
            else {
                Write-Host "'Force' flag is provided. SAS Expiry Interval with maximum approved timespan of 7 days will be set on all the Storage Account(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        # List for storing remediated storage account(s)
        $storageAccountRemediated = @()

        # List for storing skipped storage account(s)
        $storageAccountSkipped = @()

        Write-Host "Setting SAS Expiry Interval on the storage accounts..." -ForegroundColor $([Constants]::MessageType.Info)
        #perform remediation
        $storageAccountsWithoutSasExpiryIntervalProperlySet | ForEach-Object {
            #Write-Host "Setting SAS Expiry Interval on the storage account: [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            try
            {
                Set-AzStorageAccount -StorageAccountName $_.ResourceName -ResourceGroupName $_.ResourceGroupName -ErrorAction SilentlyContinue -SasExpirationPeriod $_.SASExpiryInterval
                $output = Get-AzStorageAccount -StorageAccountName $_.ResourceName -ResourceGroupName $_.ResourceGroupName -ErrorAction SilentlyContinue
                if($output.SasPolicy.SasExpirationPeriod -eq $_.SASExpiryInterval)
                {
                    $storageAccountRemediated += $_
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logRemediatedResources += $logResource
                    #Write-Host "Successfully set SAS Expiry Interval on the storage account." -ForegroundColor $([Constants]::MessageType.Update)
                }
                else
                {
                    $storageAccountSkipped += $_
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Unable to set SAS Expiry Interval on the storage account.")
                    $logSkippedResources += $logResource
                    #Write-Host "Unable to set SAS Expiry Interval on the storage account." -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            catch
            {
                $storageAccountSkipped += $_
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason", "Error encountered while setting SAS Expiry Interval.")
                $logSkippedResources += $logResource
                #Write-Host "Error encountered while setting SAS Expiry Interval on the storage account." -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
        
        if($AutoRemediation)
        {
            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            if ($($storageAccountRemediated | Measure-Object).Count -gt 0) {
                Write-Host "Successfully set SAS Expiry Interval on the storage account(s): " -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)

                # Write this to a file.
                $storageAccountRemediatedFile = "$($backupFolderPath)\RemediatedSASExpiryIntervalStorageAccounts.csv"
                $storageAccountRemediated | Export-CSV -Path $storageAccountRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($storageAccountRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            }

            if ($($storageAccountSkipped | Measure-Object).Count -gt 0) {

                Write-Host "Error encountered while setting SAS Expiry Interval on the storage account(s): " -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)

                # Write this to a file.
                $storageAccountSkippedFile = "$($backupFolderPath)\SkippedSASExpiryIntervalStorageAcounts.csv"
                $storageAccountSkipped | Export-CSV -Path $storageAccountSkippedFile -NoTypeInformation

                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($storageAccountSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            }
        }
        else
        {
            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            if ($($storageAccountRemediated | Measure-Object).Count -gt 0) {
                Write-Host "Successfully set SAS Expiry Interval on the storage account(s): " -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $storageAccountRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $storageAccountRemediatedFile = "$($backupFolderPath)\RemediatedSASExpiryIntervalStorageAccounts.csv"
                $storageAccountRemediated | Export-CSV -Path $storageAccountRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($storageAccountRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            }

            if ($($storageAccountSkipped | Measure-Object).Count -gt 0) {

                Write-Host "Error encountered while setting SAS Expiry Interval on the storage account(s): " -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $storageAccountSkipped | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $storageAccountSkippedFile = "$($backupFolderPath)\SkippedSASExpiryIntervalStorageAcounts.csv"
                $storageAccountSkipped | Export-CSV -Path $storageAccountSkippedFile -NoTypeInformation

                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($storageAccountSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            }
        }

        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlId) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $storageAccountRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to set secure TLS version for Azure Service Bus Namespaces(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Reset-SASExpiryInterval
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_Storage_AuthZ_Set_SAS_Expiry_Interval' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_Storage_AuthZ_Set_SAS_Expiry_Interval' Control.
        Reset SAS expiry interval to previous value on storage account(s). 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER RollbackFilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to function Reset-SASExpiryInterval.

        .OUTPUTS
        None. function Reset-SASExpiryInterval does not return anything that can be piped and used as an input to another command.
        
        .EXAMPLE
        PS> Reset-SASExpiryInterval -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -RollbackFilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetSecureTLSVersionForServiceBusNamespaces\RemediatedServiceBusNamespaces.csv
        
        .LINK
        None
    #>
}

function CheckifSASExpiryIntervalIsValid
{
    param ([String] $SasExpiryInterval)

    if($SasExpiryInterval -le $[Constants]::MaximumApprovedTimeSpanForSASExpiryInterval )
    {
        return $true
    }
    return $false
}

function ValidUserInput
{
    param
    (
        [String] 
        $prompt,

        [int]
        $minimumValue,

        [int]
        $maximumValue
    )
    $validValue = $false
    do
    {
        try
        {
            $userInput = Read-Host -Prompt $prompt
            [int]$value = [int]::Parse($userInput)
            if($value -le $maximumValue -and $value -ge $minimumValue)
            {
                $validValue = $true
            }
            else
            {
                Write-Host "The entered value was not in valid range of ($($minimumValue), $($maximumValue)). Kindly re-enter the value." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
        catch
        {
            Write-Host "The entered value was not valid integer. Kindly re-enter the value." -ForegroundColor $([Constants]::MessageType.Warning)
        }
    }while($validValue -eq $false)
    return $value
}

function UserInputTimeSpan
{
    do
    {
        #take user input
        Write-Host "Enter the time span for SAS Expiry Interval. " -ForegroundColor $([Constants]::MessageType.Warning)
        $days = ValidUserInput "Days ( 0 - 7 )" 0 7
        $hours = ValidUserInput "Hours ( 0 - 24 )" 0 24
        $minutes = ValidUserInput "Minutes ( 0 - 60 )" 0 60
        $seconds = ValidUserInput "Seconds ( 0 - 60 )" 0 60
        if(($days -eq 0) -and ($hours -eq 0) -and ($minutes -eq 0) -and ($seconds -eq 0))
        {
            Write-Host "The time span can't be 0 days, 0 hours, 0 minutes, 0 seconds. Kindly re-enter the time span."
        }
        else
        {
            break;
        }
    }while($true)

    $daysInString = [string]$days
    $hoursInString = [string]$hours
    $minutesInString = [string]$minutes
    $secondsInString = [string]$seconds
    if($hours -lt 10)
    {
        $hoursInString = "0" + [string]$hours
    } 
    if($minutes -lt 10)
    {
        $minutesInString = "0" + [string]$minutes
    }
    if($seconds -lt 10)
    {
        $secondsInString = "0" + [string]$seconds
    }
    
    $timeSpanInString = "$($daysInString).$($hoursInString):$($minutesInString):$($secondsInString)"
    return $timeSpanInString
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
    static [String] $TimeSpanWhenSASExpiryIntervalDisabled = "0.00:00:00"
    static [String] $MaximumApprovedTimeSpanForSASExpiryInterval = "7.00:00:00"
    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}