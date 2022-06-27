﻿<##########################################

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
    
    Write-Host "Required modules are: Az.Accounts, Az.Storage" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if required modules are present..."
   
    $availableModules = $(Get-Module -ListAvailable Az.Accounts,Az.Storage)
    $requiredModules = @("Az.Accounts" , "Az.Storage")

    # Check if the required modules are installed 
    $requiredModules | ForEach-Object { 
        if ($availableModules.Name -notcontains $_) 
        { 
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info) 
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop 
            Write-Host "$($_) module is installed." -ForegroundColor $([Constants]::MessageType.Update)
        } 
        else 
        { 
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update) 
        } 
    } 
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
        $ExcludeResourceNames
    )

    Write-Host " $([Constants]::DoubleDashLine)"
    Write-Host "[Step 1 of 4] : Checking for prerequisites..." 
    
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

    $isContextSet = Get-AzContext

    if ([string]::IsNullOrEmpty($isContextSet))
    {
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Metadata Details: `nSubscriptionName: $($currentSub.Subscription.Name) `nSubscriptionId: $($SubscriptionId) `nAccountName: $($currentSub.Account.Id) `nAccountType: $($currentSub.Account.Type)" 
    Write-Host $([Constants]::SingleDashLine)  
    Write-Host "Starting with subscription [$($SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::DoubleDashLine)

    Write-Host "*** To enable secure transfer for Storage Account(s) in a Subscription, Contributor or higher privileges on the Storage Account are required.***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Fetching Storage Account(s)..." 
   
    # Array to store Storage Account(s) list .
    $storageAccounts = @()

    # If CSV path not given fetch all Storage Account.
    if([string]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Storage Account(s) in subscription: [$($SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
        #Get all Storage Account in a Subscription
        $storageAccounts = Get-AzStorageAccount 
    }
    else
    {   #checking if the file path is correct.
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all Storage Account from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

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
                Write-Host "Error fetching Storage Account: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this Storage Account..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }
     
    $totalStorageAccount = ($storageAccounts | Measure-Object).Count

    if($totalStorageAccount -eq 0)
    {  
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Unable to fetch Storage Account or no Storage Account available." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    $folderPath = [Environment]::GetFolderPath("LocalApplicationData") 

    if (Test-Path -Path $folderPath)
    {  
        #creating a folder to store the csv file.
        $folderPath += "\AzTS\Remediation\Subscriptions\$($subscriptionid.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\EnableSecureTransit"
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }

    Write-Host "Total Storage Account found: [$($totalStorageAccount)] " -ForegroundColor $([Constants]::MessageType.update)
    Write-Host $([Constants]::DoubleDashLine)

    Write-Host "[Step 2 of 4] : Removing the excluded resource group and resource from the list of subscription." 
    $resourceSummary = @()
 
    # Adding property 'ResourceName' which will contain Storage Account name and being used by common helper method
    # Load the script in the helper.ps file in the Remediation Script directory.. to run -ExcludeResourceGroupNames and -ExcludeResourceNames Parameter .
    if(-not [string]::IsNullOrWhiteSpace($ExcludeResourceNames) -or -not [string]::IsNullOrWhiteSpace($ExcludeResourceGroupNames))
    {
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
            break
        }

        if($resourceResolver.messageToPrint -ne $null)
        {
            $resourceSummary += "Excluded resource/resource group summary:`n " 
            $resourceSummary += $resourceResolver.messageToPrint
        }  
        Write-Host $resourceSummary
    }
    
    Write-Host "Total Storage Account(s) excluded  from remediation:" [$($totalStorageAccount - ($storageAccounts | Measure-Object).Count)] -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "Total Storage Account(s) for remediation: [$(($storageAccounts | Measure-Object).Count)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "$([Constants]::DoubleDashLine)"

    $storageAccounts | ForEach-Object {
           if($_.Kind -eq "FileStorage"){
                $fileshares=@()
                $fileshares= Get-AzRMStorageShare -StorageAccountName $_.StorageAccountName -ResourceGroupName $_.ResourceGroupName
                if(($fileshares|Measure-Object).Count -gt 0)
                {
                    $SMBFileShares = @()
                    $NFSFileShares = @()
                    $SMBFileShares = $fileshares|Where-Object{$_.EnabledProtocols -contains "SMB"}
                    $NFSFileShares = $fileshares|Where-Object{$_.EnabledProtocols -contains "NFS"}
                    if($NFSFileShares.Count -gt 0 -and $SMBFileShares.Count -eq 0)
                    {
                        $storagewithOnlyNFSShares = $_.StorageAccountName
                        Write-Host "Excluding Storage Accounts $($_.StorageAccountName) with type FileStorage and having only NFS fileshares"
                        $storageAccounts=$storageAccounts|Where-Object{$_.StorageAccountName -ne $storagewithOnlyNFSShares}
                    }
                }
            }
     }


    try
    {
        #Storage Account with enabled Https only
        $stgWithEnableHTTPS = @()
        #Storage Account with disabled Https only
        $stgWithDisableHTTPS = @()
       
        Write-Host "[step 3 of 4] : Getting the Count of Storage Account in a subscription which are having disabled 'secure transfer'."
        $storageAccounts | ForEach-Object {
            if ($_.EnableHttpsTrafficOnly)
            {
                $stgWithEnableHTTPS += $_ 
            }        
            else
            { 
                 $stgWithDisableHTTPS += $_|Select-Object  @{N='ResourceId';E={$_.Id}},
                                                           @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                           @{N='StorageAccountName';E={$_.StorageAccountName}},
                                                           @{N='EnableHttpsTrafficOnly';E={$_.EnableHttpsTrafficOnly}}                                                                  
            }
        }                    
                              
        $totalStgWithEnableHTTPS = ($stgWithEnableHTTPS | Measure-Object).Count
        $totalStgWithDisableHTTPS = ($stgWithDisableHTTPS | Measure-Object).Count
    
        Write-Host "Storage Account(s) with enabled 'secure transfer': [$($totalStgWithEnableHTTPS)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "Storage Account(s) with disabled 'secure transfer': [$($totalStgWithDisableHTTPS)]" -ForegroundColor $([Constants]::MessageType.Update)

        # Start remediation Storage Account(s) with 'secure transfer' enabled.
        if ($totalStgWithDisableHTTPS -gt 0)
        {
            if (-not $DryRun)
            {
                if (-not $SkipBackup)
                {
                    Write-Host  $([Constants]::DoubleDashLine)
                    Write-Host "Exporting the Storage Account to csv file so that it can be used to rollback."
                    Write-Host "Backing up config of Storage Account(s) details. Please do not delete this file. Without this file you won't be able to rollback any changes done through remediation script." 
                    $stgWithDisableHTTPS | Export-CSV -Path "$($folderpath)\StorageWithDisableHTTPS.csv" -NoTypeInformation
                    Write-Host "Path: $($folderPath)\StorageWithDisableHTTPS.csv" -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }

                if (-not $Force)
                {
                    Write-Host "Do you want to enable secure transfer on the storage account(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                    $userInput = Read-Host -Prompt "(Y|N)"

                    if($userInput -ne "Y")
                    {
                        Write-Host "Secure transfer will not be enabled for any of the storage account. Exiting..." -ForegroundColor $([Constants]::MessageType.Info)
                        break
                    }
                }
                else
                {
                    Write-Host "'Force' flag is provided. Secure transfer will be enabled on the storage account without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                }
   
                Write-Host $([Constants]::DoubleDashLine)
                Write-Host "[step 4 of 4] : Enable 'secure transfer' for the Storage Account(s) of subscription."

                #Storage Account passed from remediation
                $remediationSuccess = @() 
                #Storage Account failed from remediation
                $remediationFailure = @()
    
                Write-Host "Enabling 'secure transfer' on [$($totalStgWithDisableHTTPS)] Storage Account(s)..."
                $stgWithDisableHTTPS = $stgWithDisableHTTPS | Sort-Object -Property "ResourceGroupName"
                $stgWithDisableHTTPS | ForEach-Object {
                    try
                    {   
                        $output = Set-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName -EnableHttpsTrafficOnly $true -ErrorAction SilentlyContinue
                        if($output -ne $null)
                        {
                            $remediationSuccess += $_ 
                        }   
                        else
                        {   
                            Write-Host "Remediation is not successful on [$($_.StorageAccountName)] : [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Warning) 
                            $remediationFailure += $_
                        }
                    }        
                    catch
                    {
                        Write-Host "Error occurred while remediating [$($_.StorageAccountName)] : [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Error) 
                        Write-Host  "Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                        $remediationFailure += $_
                    }
                }
                         
                Write-Host $([Constants]::SingleDashLine)
                if(($remediationSuccess| Measure-Object).Count -ne 0)
                {
                    Write-Host "Remediation is successful on following Storage Account(s)" -ForegroundColor $([Constants]::MessageType.Update)
                    $remediationSuccess |Select-Object -Property ResourceGroupName , StorageAccountName , ResourceId |ft
                    Write-Host $([Constants]::SingleDashLine)
                }

                if(($remediationFailure| Measure-Object).Count -ne 0)
                {
                    Write-Host "Remediation is not successful on following Storage Account(s):" -ForegroundColor $([Constants]::MessageType.Error)
                    $remediationFailure |Select-Object -Property ResourceGroupName , StorageAccountName , ResourceId |ft
                }
            }
            else
            {
                Write-Host " $([Constants]::SingleDashLine)"

                # Creating the log file
                Write-Host "Exporting configurations of Storage Account(s) that don't have secure transfer enabled. You may want to use this CSV as a pre-check before actual remediation." 
                $stgWithDisableHTTPS | Export-CSV -Path "$($folderpath)\StorageWithDisableHTTPS.csv" -NoTypeInformation
                Write-Host "Path: $($folderPath)\StorageWithDisableHTTPS.csv" -ForegroundColor $([Constants]::MessageType.Info)
            }          
        }     
        else
        {
            Write-Host "No Storage Account(s) found with disabled secure transfer." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            break
        }
    }
    catch
    {
        Write-Host "Error occurred while remediating changes.ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        break
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
    Write-Host "Starting rollback operation to disable secure transfer on Storage Account(s) from subscription [$($SubscriptionId)]...." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)
     
    Write-Host "[step 1 of 3] : Checking for prerequisites..." 

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
        
    # Connect to AzAccount
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet))
    {       
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force
    Write-Host "Metadata Details: `nSubscriptionId: $($SubscriptionId) `nAccountName: $($currentSub.Account.Id) `nAccountType: $($currentSub.Account.Type)" 
    Write-Host $([Constants]::SingleDashLine) 
    Write-Host "Starting with subscription [$($SubscriptionId)]..." 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host " ***To perform rollback operation for disabling secure transfer user must have atleast contributor access on Storage Account(s) of subscription: [$($SubscriptionId)]  ***" -ForegroundColor $([Constants]::MessageType.Info)

    Write-Host $([Constants]::SingleDashLine) 
    Write-Host "Fetching remediation log to perform rollback operation on  Storage Account(s) from subscription [$($SubscriptionId)]..." 
    Write-Host $([Constants]::DoubleDashLine)

    # Array to store Storage Accounts.
    $storageAccounts = @()

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Error: Control file path is not found." -ForegroundColor $([Constants]::MessageType.Error)
        break;        
    }
   
    # Fetching remediated log 
    Write-Host "[step 2 of 3] : Getting the list of resources for rollback."
    $remediatedResourceLog = Import-Csv -LiteralPath $FilePath
    
    Write-Host "Fetching remediation log..."
   
    Write-Host "Performing rollback operation to disable 'secure transfer' for Storage Account(s) of subscription [$($SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::DoubleDashLine)

    if (-not $Force)
    {
        Write-Host "Do you want to disable secure transfer on the storage account(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        $userInput = Read-Host -Prompt "(Y|N)"
    
        if($userInput -ne "Y")
        {
            Write-Host "Secure transfer will not be disabled for any of the storage account. Exiting..." -ForegroundColor $([Constants]::MessageType.Info)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. secure transfer will be disabled on the storage account without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[step 3 of 3] : Disable secure transfer on the Storage Account in the Subscription."
    
    try
    {
        if(($remediatedResourceLog | Measure-Object).Count -gt 0)
        {   $rollbackSuccess = @()
            $rollbackFailure = @()
                    
            Write-Host "Disabling secure transfer on [$(($remediatedResourceLog| Measure-Object).Count)] Storage Account(s) of subscription [$($SubscriptionId)]..." 
           
            $remediatedResourceLog | ForEach-Object {
                try
                {
                    $res = Get-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name _.StorageAccountName
                    if($_.Kind -eq "FileStorage"){
                    $fileshares=@()
                    $fileshares= Get-AzRMStorageShare -StorageAccountName $_.StorageAccountName -ResourceGroupName $_.ResourceGroupName
                    if(($fileshares|Measure-Object).Count -gt 0)
                    {
                        $SMBFileShares = @()
                        $NFSFileShares = @()
                        $SMBFileShares = $fileshares|Where-Object{$_.EnabledProtocols -contains "SMB"}
                        $NFSFileShares = $fileshares|Where-Object{$_.EnabledProtocols -contains "NFS"}
                        if($NFSFileShares.Count -gt 0 -and $SMBFileShares.Count -eq 0)
                        {
                            $storagewithOnlyNFSShares = $_.StorageAccountName
                            Write-Host "Excluding Storage Accounts $($_.StorageAccountName) with type FileStorage and having only NFS fileshares"
                            continue
                        }
                    }
                }
            

                    $output = Set-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName -EnableHttpsTrafficOnly $false -ErrorAction SilentlyContinue
                    if($output -ne $null)
                    {
                        $rollbackSuccess += $_ |Select-Object -Property "StorageAccountName" , "ResourceGroupName" , "ResourceId"
                    }
                    else
                    {  
                       Write-Host "Rollback is not successful on [$($_.StorageAccountName)] : [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Warning)    
                       $rollbackFailure += $_ |Select-Object -Property "StorageAccountName" , "ResourceGroupName" , "ResourceId"                              
                    }
                }             
                catch
                {
                    Write-Host "Error occurred while rollback on [$($_.StorageAccountName)] : [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host  "Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    $rollbackFailure += $_ |Select-Object -Property "StorageAccountName" , "ResourceGroupName" , "ResourceId"
                }
            }

            Write-Host $([Constants]::DoubleDashLine)

            if(($rollbackSuccess|Measure-Object).Count -ne 0)
            {   Write-Host "Rollback is successful on following  Storage Account(s):" -ForegroundColor ([Constants]::MessageType.Update)
                $rollbackSuccess | Select-Object -Property "ResourcegroupName", "storageAccountName" ,"ResourceId" | ft   
                Write-Host $([Constants]::SingleDashLine)
            } 
            
            if(($rollbackFailure|Measure-Object).Count -ne 0)
            {
                Write-Host "Rollback is not successful on following Storage Account(s):" -ForegroundColor ([Constants]::MessageType.Error)
                $rollbackFailure | Select-Object -Property "ResourcegroupName", "storageAccountName" ,"ResourceId"| ft        
            }         
        }
        else 
        {
            Write-Host "No Storage Account(s) found in remediation log to perform rollback operation." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            break
        }
    }   
    catch
    {
        Write-Host "Error occurred while performing rollback operation for remediating changes. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        break 
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

    static [string] $DoubleDashLine    = "================================================================================"
    static [string] $SingleDashLine    = "--------------------------------------------------------------------------------"
}