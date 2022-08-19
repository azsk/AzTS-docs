<##########################################

# Overview:
    This script is used to make the transit in Storage Account encrypted using the HTTPS.

# ControlId: 
    Azure_Storage_DP_Encrypt_In_Transit

# DisplayName:
    Enable Secure transfer to Storage Accounts

# Pre-requisites:
    1. You will need atleast contributor role on Storage Account(s) of subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script :
   To Remediate:
        1. Checking for prerequisites..
        2. Validating the Account type.
        3. Removing the excluded resource group(s) and resource from the list of subscription.
        4. Get list of Storage Account in a subscription which are having disable secure transfer.
        5. Exporting the Storage Account(s) to csv file so that it can be used to rollback.
        6. Enable secure transfer for the Storage Account(s) of subscription.

   To rollback:
        1. Checking for Prerequisites..
        2. Validating the Account type.
        3. Get the list of Storage Accounts in a Subscription, the changes made to which previously, are to be rolled back.
        4. Disable secure transfer on the Storage Account in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Load the script in the file Helper.ps1 available in the Remediation Script directory.
        4. Execute the script To enable encryption in transit on the Storage Account in the Subscription. Refer 'Examples', below.
   
    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable  encryption in transit" on the Storage Account in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Storage Account in a Subscription that will be remediated:
           Enable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        2. To enable encryption in transit on the Storage Account in a Subscription:
           Enable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 
       
        3. To enable encryption in transit on the Storage Account in a Subscription, from a previously taken snapshot:
           Enable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\Users\AppData\Local\AzTS\Remediation\Subscriptions\00000000_xxxx_0000_xxxx_000000000000\20211013_0608\EnableSecureTransit\StorageWithDisableHTTPS.csv
        
        4. To enable encryption in transit on the Storage Account in a Subscription without taking back up before actual remediation:
           Enable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Enable-StorageEncryptionInTransit -Detailed
   
    To rollback: 
        1. To disable  encryption in transit on the Storage Account in a Subscription, from a previously taken snapshot:
           Disable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath  C:\Users\Documents\AzTS\Remediation\Subscriptions\00000000_xxxx_0000_xxxx_000000000000\20211013_0608\EnableSecureTransit\StorageWithDisableHTTPS.csv

        To know more about the options supported by the roll back command, execute:
        
        Get-Help Disable-StorageEncryptionInTransit -Detailed 

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
function Enable-StorageEncryptionInTransit
{
     <#
        .SYNOPSIS
        This command would help in remediating "Azure_Storage_DP_Encrypt_In_Transit" control.

        .DESCRIPTION
        This command would help in remediating  "Azure_Storage_DP_Encrypt_In_Transit" control.
        Enables secure transfer on the Storage Account in the Subscription. 
        
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
        None. You cannot pipe objects to Enable-StorageEncryptionInTransit.

        .OUTPUTS
        None. Enable-StorageEncryptionInTransit does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        Enable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun
      
        .EXAMPLE
        Enable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 
      
        .EXAMPLE
        PS> Enable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePathC:\Users\AppData\Local\AzTS\Remediation\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\20211013_0608\EnableSecureTransit\StorageWithDisableHTTPS.csv
         
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

    Write-Host "To enable secure transfer for Storage Account(s) in a Subscription, Contributor or higher privileges on the Storage Account are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 2 of 5] Fetch Storage Account(s)"
    Write-Host $([Constants]::SingleDashLine)

    # Array to store Storage Account(s) list .
    $storageAccounts = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    $controlIds = "Azure_Storage_DP_Encrypt_In_Transit"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "Error: File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
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
            Write-Host "No Storage Account(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            try
            {
                $storageAccount = Get-AzStorageAccount -StorageAccountName $_.ResourceName -ResourceGroupName $_.ResourceGroupName -ErrorAction SilentlyContinue
                $storageAccounts += $storageAccount
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
                Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
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
                    Write-Host "Error fetching Storage Account: Resource ID: [$($resourceId)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
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

    $resourceSummary = @()
    # Adding property 'ResourceName' which will contain Storage Account name and being used by common helper method
    # Load the script in the helper.ps file in the Remediation Script directory.. to run -ExcludeResourceGroupNames and -ExcludeResourceNames Parameter .
    if(-not($AutoRemediation) -and (-not [string]::IsNullOrWhiteSpace($ExcludeResourceNames) -or -not [string]::IsNullOrWhiteSpace($ExcludeResourceGroupNames)))
    {
        Write-Host "Excluding these resources: [$($ExcludeResourceNames)] and these resource groups: [$($ExcludeResourceGroupNames)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        $storageAccounts | ForEach-Object {
            $_ | Add-Member -NotePropertyName ResourceName -NotePropertyValue $_.StorageAccountName -ErrorAction SilentlyContinue
        }
        # Apply resource or resource group exclusion logic
        try
        {
            $resourceResolver = [ResourceResolver]::new([string] $excludeResourceNames , [string] $excludeResourceGroupNames);
            $storageAccounts = $resourceResolver.ApplyResourceFilter([PSObject] $storageAccounts) 
        }
        catch
        {
            Write-Host "Please load Helper.ps1 file in current PowerShell session before executing the script." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }

        if($null -ne $resourceResolver.messageToPrint)
        {
            $resourceSummary += "Excluded resource/resource group summary:`n " 
            $resourceSummary += $resourceResolver.messageToPrint
        }  
        Write-Host $resourceSummary  
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "Total Storage Account(s) excluded from remediation:" [$($totalStorageAccount - ($storageAccounts | Measure-Object).Count)] -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "Total Storage Account(s) for remediation: [$(($storageAccounts | Measure-Object).Count)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 3 of 5] Fetch all Storage Account(s) Secure Transfer Configurations"
    Write-Host $([Constants]::SingleDashLine)

    #Storage Account with enabled Https only
    $stgWithEnableHTTPS = @()
    #Storage Account with disabled Https only
    $stgWithDisableHTTPS = @()

    $storageAccounts | ForEach-Object {
        try 
        {
            Write-Host "Fetching secure tranfer configuration of Storage Account: [$($_.StorageAccountName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            if ($_.EnableHttpsTrafficOnly)
            {
                $stgWithEnableHTTPS += $_ 
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Secure Transfer is already enabled.")    
                $logSkippedResources += $logResource
            }        
            else
            { 
                $stgWithDisableHTTPS += $_|Select-Object  @{N='ResourceId';E={$_.Id}},
                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                        @{N='StorageAccountName';E={$_.StorageAccountName}},
                                                        @{N='EnableHttpsTrafficOnly';E={$_.EnableHttpsTrafficOnly}}                                                                  
            }
            Write-Host "Successfully fetched secure tranfer configuration of Storage Account: [$($_.StorageAccountName)]" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch {
            Write-Host "Error encountered while fetching secure transfer configuration of the Storage Account: [$($_.StorageAccountName)]." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this Storage Account..." -ForegroundColor $([Constants]::MessageType.Warning)
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason","Error encountered while fetching secure transfer configuration of the Storage Account.")    
            $logSkippedResources += $logResource
            Write-Host $([Constants]::SingleDashLine)
        }
    }  
    $totalStgWithEnableHTTPS = ($stgWithEnableHTTPS | Measure-Object).Count
    $totalStgWithDisableHTTPS = ($stgWithDisableHTTPS | Measure-Object).Count

    if ($totalStgWithDisableHTTPS -eq 0)
    {
        Write-Host "No Storage Account found with Secure Transfer disabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation -and $totalStgWithEnableHTTPS -gt 0) 
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 100  | Out-File $logFile
        }
        return
    }

    Write-Host "Found [$($totalStgWithDisableHTTPS)] out of [$(($storageAccounts | Measure-Object).Count)] Storage Accounts(s) with Secure Transfer disabled." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
   
    Write-Host "[Step 4 of 5] Back up the Storage Account(s) details"
    Write-Host $([Constants]::SingleDashLine)

    if($SkipBackup)
    {
        Write-Host "Since -SkipBackup switch is provided, the storage account details are not backed up." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
    else 
    {
        $backupFolderPath = "$([Environment]::GetFolderPath("LocalApplicationData"))\AzTS\Remediation\Subscriptions\$($subscriptionid.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\EnableSecureTransit"
        if (-not (Test-Path -Path $backupFolderPath))
        {
            New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
        }

        # Backing up Storage Accounts details.
        $backupFile = "$($backupFolderPath)\EnableSecureTransferInStorageAccounts.csv"
        $StgWithDisableHTTPS | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Successfully backed up Storage Account details to [$($backupFolderPath)]." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 5 of 5] Enable Secure Transfer on the Storage Account(s)"
    Write-Host $([Constants]::SingleDashLine)

    if(-not $DryRun)
    {
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "Do you want to enable secure transfer on the storage account(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                $userInput = Read-Host -Prompt "(Y|N)"
                Write-Host $([Constants]::SingleDashLine)

                if($userInput -ne "Y")
                {
                    Write-Host "Secure transfer will not be enabled for any of the storage account. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
                Write-Host "User has provided consent to enable secure transfer on the storage account(s)." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                Write-Host "'Force' flag is provided. Secure transfer will be enabled on the storage account without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write=Host $([Constants]::SingleDashLine)
            }
        }

        #Storage Account passed from remediation
        $remediationSuccess = @() 
        #Storage Account failed from remediation
        $remediationFailure = @()

        $stgWithDisableHTTPS = $stgWithDisableHTTPS | Sort-Object -Property "ResourceGroupName"
        $stgWithDisableHTTPS | ForEach-Object {
            Write-Host "Enabling Secure Transfer on the Storage Account: [$($_.StorageAccountName)] in Resource Group [$($_.ResourceGroupName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            try
            {   
                $output = Set-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName -EnableHttpsTrafficOnly $true -ErrorAction SilentlyContinue
                $storageAccountResource = Get-AzStorageAccount -StorageAccountName $_.StorageAccountName -ResourceGroupName $_.ResourceGroupName -ErrorAction SilentlyContinue
                if($storageAccountResource.EnableHttpsTrafficOnly -eq $true)
                {
                    $_.EnableHttpsTrafficOnly = $true
                    $remediationSuccess += $_ 
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.StorageAccountName))
                    $logRemediatedResources += $logResource
                    Write-Host "Successfully enabled secure transfer on the Storage Account." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }   
                else
                {   
                    $remediationFailure += $_
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.StorageAccountName))
                    $logResource.Add("Reason","Unsuccessful in enabling secure transfer on the Storage Account.")    
                    $logSkippedResources += $logResource
                    Write-Host "Unsuccessful in enabling secure transfer on the Storage Account." -ForegroundColor $([Constants]::MessageType.Warning) 
                    Write-Host $([Constants]::SingleDashLine)
                }
            }        
            catch
            {
                Write-Host "Error occurred while enabling secure transfer on the Storage Account." -ForegroundColor $([Constants]::MessageType.Error) 
                Write-Host "Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $remediationFailure += $_
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.StorageAccountName))
                $logResource.Add("Reason","Error occurred while enabling secure transfer on the Storage Account.")    
                $logSkippedResources += $logResource
            }
        }
        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation)
        {
            if($($remediationSuccess|Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $storageAccountRemediatedFile = "$($backupFolderPath)\RemediateStorageAccountsEnableSecureTransfer.csv"
                $remediationSuccess | Export-CSV -Path $storageAccountRemediatedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($storageAccountRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "`nUse this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
            
            if($($remediationFailure|Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $storageAccountSkippedFile = "$($backupFolderPath)\SkippedStorageAccountsEnableSecureTransfer.csv"
                $remediationFailure | Export-CSV -Path $storageAccountSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($storageAccountSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else 
        {
            Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
            
            if($($remediationSuccess|Measure-Object).Count -gt 0)
            {
                Write-Host "Secure transfer successfully enabled for the following Storage Accounts(s):" -ForegroundColor $([Constants]::MessageType.Update)
                $remediationSuccess | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $storageAccountRemediatedFile = "$($backupFolderPath)\RemediateStorageAccountsEnableSecureTransfer.csv"
                $remediationSuccess | Export-CSV -Path $storageAccountRemediatedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($storageAccountRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "`nUse this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
            
            if($($remediationFailure|Measure-Object).Count -gt 0)
            {
                Write-Host "Secure transfer not enabled for the following Storage Accounts(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $remediationFailure | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $storageAccountSkippedFile = "$($backupFolderPath)\SkippedStorageAccountsEnableSecureTransfer.csv"
                $remediationFailure | Export-CSV -Path $storageAccountSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($storageAccountSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
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
                    $logControl.RollbackFile = $storageAccountRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else 
    {
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:`n" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to enable secure transfer on all the Storage Account resources listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)

    }
}

# Script to rollback changes done by remediation script
function Disable-StorageEncryptionInTransit
{
    <#
        .SYNOPSIS
        This command would help in performing rollback operation for '"Azure_Storage_DP_Encrypt_In_Transit" control.
      
        .DESCRIPTION
        This command would help in performing rollback operation for "Azure_Storage_DP_Encrypt_In_Transit" control. 
        Disables secure transfer on the Storage Account in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.

        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
          
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.
       
        .INPUTS
        None. You cannot pipe objects to Disable-StorageEncryptionInTransit.
       
        .OUTPUTS
        None. Disable-StorageEncryptionInTransit does not return anything that can be piped and used as an input to another command.
       
        .EXAMPLE
        Disable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath  C:\Users\Documents\AzTS\Remediation\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\20211013_0608\EnableSecureTransit\StorageWithDisableHTTPS.csv

        .LINK
        None
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id to perform rollback operation")]
        $SubscriptionId,

        [Switch]
        [Parameter(Mandatory = $false , HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [switch]
        [Parameter(Mandatory = $false, HelpMessage="Specifies a forceful remediation without any prompts")]
        $Force,
    
        [string]
        [Parameter(Mandatory = $true, HelpMessage="CSV file path which contain logs generated by remediation script to rollback remediation changes")]
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
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 3] Validate the User" 
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

    Write-Host "To disable secure transfer for Storage Accounts in a Subscription, Contributor or higher privileges on the Storge Accounts are required."
    Write-Host $([Constants]::SingleDashLine) 

    Write-Host "[Step 2 of 3] Fetch all the Storage Accounts"
    Write-Host $([Constants]::SingleDashLine)

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }
   
    # Fetching remediated log 
    Write-Host "Fetching all the Storage accounts from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $storageAccountDetails = Import-Csv -LiteralPath $FilePath
    $validStorageAccountDetails = $storageAccountDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.StorageAccountName) }
   
    $totalStorageAccounts = $($validStorageAccountDetails|Measure-Object).Count

    if($totalStorageAccounts -eq 0)
    {
        Write-Host "No Storage Account found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        return
    }
    Write-Host "Found [$($totalStorageAccounts)] Storage Account." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableSecureTransit"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "[Step 3 of 3] Disable Secure Transfer on Storage Accounts"
    Write-Host $([Constants]::SingleDashLine)


    if (-not $Force)
    {
        Write-Host "Do you want to disable secure transfer on the storage account(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "Secure transfer will not be disabled on the Storage Account(s)." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "Secure transfer will be disabled on all Storage Account(s)." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. Secure transfer will be disabled on the storage account without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
    
    $validStorageAccountDetails | ForEach-Object {
        $rollbackSuccess = @()
        $rollbackFailure = @()
        Write-Host "Enabling Secure Transfer on the Storage Account: [$($_.StorageAccountName)] in Resource Group [$($_.ResourceGroupName)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        try
        {   
            $output = Set-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName -EnableHttpsTrafficOnly $false -ErrorAction SilentlyContinue
            $storageAccountResource = Get-AzStorageAccount -StorageAccountName $_.StorageAccountName -ResourceGroupName $_.ResourceGroupName -ErrorAction SilentlyContinue
            if($storageAccountResource.EnableHttpsTrafficOnly -eq $false)
            {
                $_.EnableHttpsTrafficOnly = $false
                $rollbackSuccess += $_ | Select-Object -Property "StorageAccountName" , "ResourceGroupName" , "ResourceId"
                Write-Host "Successfully disabled secure transfer on the Storage Account." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }   
            else
            {   
                $rollbackFailure += $_ | Select-Object -Property "StorageAccountName" , "ResourceGroupName" , "ResourceId"
                Write-Host "Unsuccessful in disabling secure transfer on the Storage Account." -ForegroundColor $([Constants]::MessageType.Warning) 
                Write-Host $([Constants]::SingleDashLine)
            }
        }        
        catch
        {
            $rollbackFailure += $_ | Select-Object -Property "StorageAccountName" , "ResourceGroupName" , "ResourceId"
            Write-Host "Error occurred while disabling secure transfer on the Storage Account." -ForegroundColor $([Constants]::MessageType.Error) 
            Write-Host "Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
        }
    }

    if($($rollbackFailure|Measure-Object).Count -eq 0)
    {
        Write-Host "Secure Transfer successfully disabled for all [$($totalStorageAccounts)] Storage Account(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else 
    {
        Write-Host "Secure Transfer successfully disabled for [$($($rollbackSuccess | Measure-Object).Count)] out of [$($totalStorageAccounts)] Storage Account(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    Write-Host $([Constants]::DoubleDashLine)
    if ($($rollbackSuccess | Measure-Object).Count -gt 0 -or $($rollbackFailure | Measure-Object).Count -gt 0)
    {
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($rollbackSuccess | Measure-Object).Count -gt 0)
        {
            Write-Host "Secure transfer successfully disabled for the following Storage Accounts(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $rollbackSuccess | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)

            # Write this to a file.
            $storageAccountRolledBackFile = "$($backupFolderPath)\RolledBackStorageAccountSecureTransfer.csv"
            $rollbackSuccess | Export-CSV -Path $storageAccountRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to [$($storageAccountRolledBackFile)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($rollbackFailure | Measure-Object).Count -gt 0)
        {
            Write-Host "Error disabling Secure transfer for the following Storage Account(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $rollbackFailure | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $storageAccountSkippedFile = "$($backupFolderPath)\SkippedStorageAccountSecureTransfer.csv"
            $rollbackFailure | Export-CSV -Path $storageAccountSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($storageAccountSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
    }      
} 

# Defines commonly used constants.
class Constants
{
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