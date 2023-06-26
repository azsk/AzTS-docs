<###
# Overview:
    This script is used for rotating key for Storage Account(s) in a Subscription.

# Control ID:
    Azure_Storage_SI_Rotate_Access_Keys

# Display Name:
    Azure Storage Account access keys should rotate on periodic basis.

# Prerequisites:
    Contributor or higher priviliged role on the Storage Account(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Storage Account(s) for a subsrciption where in keys are not rotated for past 90 days.
        3. Get the acesss keys for Storage Account(s).
        4. Regenerate key for Storage Account(s).


# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to rotate access key for storage account in the Subscription. Refer `Examples`, below.


# Examples:
    To remediate:
       1. To review the Storage Account(s) in a Subscription that will be remediated:
    
           Rotate-KeysForStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To rotate key on Storage Account(s) in the Subscription:
       
          Rotate-KeysForStorageAccount-SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To rotate key on Storage Account(s) in the Subscription, from a previously taken snapshot:
       
           Rotate-KeysForStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\StorageAccountKey\NonCompliantTStorageAccount.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help  Rotate-KeysForStorageAccount -Detailed
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
    $requiredModules = @("Az.Accounts", "Az.Storage")

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_) {
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module is installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host "All required modules are present." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
}


function Rotate-KeysForStorageAccount {
    <#
        .SYNOPSIS
        Remediates 'Azure_Storage_SI_Rotate_Access_Keys' Control.

        .DESCRIPTION
        Remediates 'Azure_Storage_SI_Rotate_Access_Keys' Control.
        Used for rotating access key in storage account. 
        
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
        
        .PARAMETER SkipBackup
        Specifies that no back up will be taken by the script before remediation.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Rotate-KeysForStorageAccount.

        .OUTPUTS
        None. Rotate-KeysForStorageAccount does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Rotate-KeysForStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Rotate-KeysForStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Rotate-KeysForStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\StorageAccountKey\NonCompliantTStorageAccountDetails.csv

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

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies no back up will be taken by the script before remediation")]
        $SkipBackup,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the path to the file to be used as input for the remediation")]
        $FilePath,

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
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }
    else {
        Write-Host "[Step 1 of 4] Validating the user... "
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context)) {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    if (-not($AutoRemediation)) {
        Write-Host "Current context has been set to below details: " -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    } 
    
    Write-Host "***To rotate keys on Storage Account(s) in a Subscription, Contributor or higher privileges on the Storage Account(s) are required..***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Storage Account(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    # Display the storage account details.
    $StorageAccountDetails = @()

    #Required retention period should be less than 90 days
    $requiredRetentionPeriod = 90

    #Display access key associated to that account
    $StorageAccountKey = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources = @()

    #Control id for the control
    $controlIds = "Azure_Storage_SI_Rotate_Access_Keys"

      
    # No file path provided as input to the script. Fetch all Storage Account in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        try {
            Write-Host "Fetching all Storage Account(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

            # Get all storage account in a Subscription
            $StorageAccountInfo = Get-AzStorageAccount -ErrorAction Stop
            #Get the access key associated with that Storage Account(s)
            $StorageAccountInfo | ForEach-Object {
                $StorageAccount = $_
                $keyDetails = New-Object System.Collections.Generic.Dictionary"[String,String]"
                $StorageAccountKeys = Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -ErrorAction Stop
                $StorageAccountKeys | ForEach-Object {
                    $key = $_
                    $keyDetails.Add($key.KeyName, $key.CreationTime)
                
                    # Seperating required properties
                    if($StorageAccountDetails.storageAccountName -notcontains $StorageAccount.StorageAccountName){
                    $StorageAccountDetails += $StorageAccount | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                    @{N = 'StorageAccountName'; E = { $_.StorageAccountName } },
                    @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName } },
                    @{N = 'KeyDetails'; E = { $keyDetails } }
                    }

                }
            }
        }
        catch {
            Write-Host "Error fetching Storage Account(s) from the subscription. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            $logResource = @{}
            $logResource.Add("Reason", "Error fetching Storage Account(s) information from the subscription.")    
            $logSkippedResources += $logResource
        }    
    }
    else {
        if (-not (Test-Path -Path $FilePath)) {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all Storage Account(s) from [$($FilePath)]..." 

        $StorageAccountResources = Import-Csv -LiteralPath $FilePath
        $validStorageAccountResources = $StorageAccountResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
        
        $validStorageAccountResources | ForEach-Object {
            
            try {
                $StorageAccountResources = Get-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName -ErrorAction SilentlyContinue
            
                $StorageAccountDetails += $StorageAccountResources | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceName'; E = { $_.StorageAccountName } },
                @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName } }

                $keyDetails = New-Object System.Collections.Generic.Dictionary"[String,String]"

                $StorageAccountKey = Get-AzStorageAccountKey -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName -ErrorAction Stop
                $StorageAccountKey | ForEach-Object {
                    $key = $_
                    $keyDetails.Add($key.KeyName, $key.CreationTime)
                }
                    
            }
            catch {
                Write-Host "Error fetching Storage Account(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                $logResource = @{}
                $logResource.Add("StorageAccountName", ($_.ResourceGroupName))
                $logResource.Add("ResourceGroupName", ($_.ResourceName))
                $logResource.Add("Reason", "Error fetching storage account information.")    
                $logSkippedResources += $logResource
            }
        }
    }

    $totalstorageaccount = ($StorageAccountDetails | Measure-Object).Count

    if ($totalstorageaccount -eq 0) {
        Write-Host "No Storage Account(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalstorageaccount)] Storage Account(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list Storage Account(s) where keys are not rotated within retention period
    $NonCompliantStorageAccounts = @()

    # Compliant Storage Account(s) where keys are within retention period
    $CompliantStorageAccounts = @()

    Write-Host "Separating Storage Account(s) for which keys are not rotated within specified retention period of 90 days..."

    $StorageAccountDetails | ForEach-Object {
        $Storage = $_
        $Storage.KeyDetails.Keys | ForEach-Object{
        $key=$_
        $value=$Storage.KeyDetails[$key]
        $date1=[DateTime]::ParseExact($value,"MM/dd/yyyy HH:mm:ss",$null)
        $time1 = Get-Date
        $days1 = (New-TimeSpan -Start $date1 -End $time1)
        if ($days1.Days -ge $requiredRetentionPeriod) {
           if($NonCompliantStorageAccounts.StorageAccountName -notcontains $Storage.StorageAccountName)
           {
           $NonCompliantStorageAccounts += $Storage
           }
            
        }
        else {
           if($CompliantStorageAccounts.StorageAccountName -notcontains $Storage.StorageAccountName)
           {
            $CompliantStorageAccounts+=$Storage
           }
        }
    }
    }
   
   
    $totalNonCompliantStorageAccount = ($NonCompliantStorageAccounts | Measure-Object).Count

    if ($totalNonCompliantStorageAccount -eq 0) {
        Write-Host "No Storage Account(s) found with keys are not rotated with specified [$($requiredRetentionPeriod)] days.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$($totalNonCompliantStorageAccount)] Storage Account(s) with non compliant required rentention period:" -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 50; Alignment = "left" },
    @{Expression = { $_.StorageAccountName }; Label = "StorageAccountName"; Width = 10; Alignment = "left" }
        
    $totalNonCompliantStorageAccount | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\AzStorageAccount"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up Storage Account(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Storage Account(s) details.
        $backupFile = "$($backupFolderPath)\NonCompliantStorageAccountDetails.csv"

        $NonCompliantStorageAccounts | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Storage Account(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remediating non compliant Storage Account(s)..." 
        Write-Host $([Constants]::SingleDashLine)
        
        if (-not $AutoRemediation) {
            if (-not $Force) {
                Write-Host "Found total [$($CompliantStorageAccounts.count)] Storage Account(s) acces key with default days. Access key for these resources can not be reverted back to default value after remediation." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "This step will rotate access keys for $CompliantStorageAccounts [$($requiredRetentionPeriod)] for all non-complaint [$($NonCompliantStorageAccounts.count)] Storage account access keys." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Do you want to Continue? " -ForegroundColor $([Constants]::MessageType.Warning)
            
                $userInput = Read-Host -Prompt "(Y|N)"

                if ($userInput -ne "Y") {
                    Write-Host "Access key  [$($requiredRetentionPeriod)] will not be rotated on Storage Account(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    break
                }
            }
            else {
                Write-Host "'Force' flag is provided.Key rotation is completed in Storage Account(s) without any prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }

        # List for storing remediated storage account keys
        $StorageAccountsRemediated = @()

        # List for storing skipped storage account keys
        $StorageAccountsSkipped = @()

        Write-Host "Rotating access keys [$($requiredRetentionPeriod)] on all listed Storage Account(s)." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)      
        try { 
            # Loop through the list of access keys which needs to be remediated.
            $NonCompliantStorageAccounts | ForEach-Object {
                $StorageAccount = $_
                $StorageAccount | Add-Member -NotePropertyName isStorageAccountKeySetPostRemediation -NotePropertyValue $false
                $StorageAccount.KeyDetails.Keys | ForEach-Object {
                    $key = $_
                    $time1 = Get-Date
                    $value= $StorageAccount.KeyDetails[$key]
                    $date1=[DateTime]::ParseExact($value,"MM/dd/yyyy HH:mm:ss",$null)
                    $days1 = (New-TimeSpan -Start $date1 -End $time1)
                    if ($days1.Days -ge $requiredRetentionPeriod) {
                        Write-Host "Rotating Access key [$($requiredRetentionPeriod)] on $key." -ForegroundColor $([Constants]::MessageType.Info)
                        New-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -KeyName $key
                    }
                }
                $logResource = @{}
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))
                $logResource.Add("ResourceName", ($_.ResourceName))
                $logRemediatedResources += $logResource
                Write-Host "Successfully rotated keys." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        catch {
            $StorageAccount.isStorageAccountKeySetPostRemediation = $false
            $StorageAccountsSkipped += $StorageAccount
            Write-Host $([Constants]::SingleDashLine)
            $logResource = @{}
            $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))
            $logResource.Add("ResourceName", ($_.ResourceName))
            $logResource.Add("Reason", "Error occured while rotating a key.")
            $logSkippedResources += $logResource
            Write-Host "Skipping this Access key resource." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
        $colsPropertyRemediated = @{Expression = { $_.StorageAccountName }; Label = "StorageAccountName"; Width = 30; Alignment = "left" },
        @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
        @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 50; Alignment = "left" },
        @{Expression = { $StorageAccountDetails.KeyDetails }; Label = "KeyDetails"; Width = 10; Alignment = "left" },
        @{Expression = { $_.isStorageAccountKeySetPostRemediation }; Label = "isStorageAccountKeySetPostRemediation"; Width = 10; Alignment = "left" }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)

        if ($($StorageAccountKeyRemediated | Measure-Object).Count -gt 0) {
            Write-Host "Access key on retention period [$($requiredRetentionPeriod)] days rotated on the following Storage Account(s)t in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
           
            $StorageAccountsRemediated | Format-Table -Property $colsPropertyRemediated -Wrap

            # Write this to a file.
            $StorageAccountKeyRemediatedFile = "$($backupFolderPath)\StorageAccountsRemediated.csv"
            $StorageAccountsRemediated | Export-CSV -Path $StorageAccountKeyRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($StorageAccountKeyRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($( $StorageAccountsSkipped | Measure-Object).Count -gt 0) {
            Write-Host "Error configuring on access key in the Storage Account(s): " -ForegroundColor $([Constants]::MessageType.Error)
            $StorageAccountsSkipped | Format-Table -Property $colsProperty -Wrap
            # Write this to a file.
            $StorageAccountKeyRemediatedFile = "$($backupFolderPath)\StorageAccountsSkipped.csv"
            $StorageAccountsSkipped | Export-CSV -Path  $StorageAccountKeyRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($StorageAccountKeyRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    else {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4]  Remediating non compliant ..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, configure Access keys in Storage Account(s) listed in the file."
    }
}

# Defines commonly used constants.
class Constants {
    # Defines commonly used colour codes, corresponding to the severity of the log.
    static [Hashtable] $MessageType = @{
        Error   = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info    = [System.ConsoleColor]::Cyan
        Update  = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}
