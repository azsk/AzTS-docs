<##########################################

# Overview:
    This script is used to make the transit in Storage Account encrpyted using the HTTPS.

# ControlId: 
    Azure_Storage_DP_Encrypt_In_Transit

# DisplayName:
    Enable Secure transfer to Storage Accounts

# Pre-requisites:
    You will need atleast contributor role on Storage Account(s) of subscription.

# Steps performed by the script :
   To Remediate:
        1. Checking for prerequisites.
        2. Validating the Account type.
        3. Removing   the excluded resource group(s) and resource  from the list of subscription.
        4. Get list of Storage Account in a subscription which are having 'EnableHttpsTrafficOnly' value set to false.
        5. Taking backup of Storage Account(s) having value of 'EnableHttpsTrafficOnly' set to false that are going to be remediated using remediation script.
        5. Set the value of 'EnableHttpsTrafficOnly' to true for the Storage Account(s) of subscription.

   To rollback:
        1. Validate and install the modules required to run the script.
        2. Get the list of Storage Accounts in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the value of 'EnableHttpsTrafficOnly'  to 'false' on the Storage Account in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable "EnableHTTPSTrafficOnly" on the Storage Account in the Subscription. Refer `Examples`, below.
   
    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable "EnableHTTPSTrafficOnly"  on the Storage Account in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Storage Account in a Subscription that will be remediated:
           Enable-StorageEncryptionInTransit  -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000  -DryRun

        2. To enable "EnableHTTPSTrafficOnly"  on the Storage Account in a Subscription:
           Enable-StorageEncryptionInTransit  -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 
       
        3. To enable "EnableHTTPSTrafficOnly"  on the Storage Account in a Subscription, from a previously taken snapshot:
           Enable-StorageEncryptionInTransit  -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\Users\Documents\AzTS\Remediation\Subscriptions\00000000_xxxx_0000_xxxx_000000000000\20211013_0608\EnableSecureTransit\StorageWithDisableHTTPs.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-StorageEncryptionInTransit -Detailed
   
    To rollback: 
        1. To disable "EnableHTTPSTrafficOnly"  on the Storage Account in a Subscription, from a previously taken snapshot:
           Disable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000  -FilePath  C:\Users\Documents\AzTS\Remediation\Subscriptions\00000000_xxxx_0000_xxxx_000000000000\20211013_0608\EnableSecureTransit\StorageWithDisableHTTPs.csv

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
    
    Write-Host "Required modules are: Az.Account, Az.Resources, Az.Storage" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking for required modules..."
    $availableModules = $(Get-Module -ListAvailable Az.Resources, Az.Accounts,Az.Storage)
    
    # Checking if 'Az.Accounts' module is available or not.
    if($availableModules.Name -notcontains 'Az.Accounts')
    {
        Write-Host "Installing module Az.Accounts..." -ForegroundColor $([Constants]::MessageType.Info)
        Install-Module -Name Az.Accounts -Scope CurrentUser -Repository 'PSGallery'
        Write-Host " Module Az.Accounts is installed." -ForegroundColor $([Constants]::MessageType.update)
    }
    else
    {
        Write-Host "Az.Accounts module is available." -ForegroundColor $([Constants]::MessageType.Update)
    }
    
    # Checking if 'Az.Storage' module with required version is available or not.
    if($availableModules.Name -notcontains 'Az.Storage')
    {
        Write-Host "Installing module Az.Storage..." -ForegroundColor $([Constants]::MessageType.Info)
        Install-Module -Name Az.Storage -Scope CurrentUser -Repository 'PSGallery'
        Write-Host "Module Az.Storage is installed." -ForegroundColor $([Constants]::MessageType.update)
    }
    else
    {
        Write-Host "Az.Storage module is available." -ForegroundColor $([Constants]::MessageType.Update)
        $currentModule = $availableModules | Where-Object { $_.Name -eq "Az.Storage" }
        $currentModuleVersion = ($currentModule.Version  | measure -Maximum).Maximum -as [string]
       
        if([version]('{0}.{1}.{2}' -f $currentModuleVersion.split('.')) -lt [version]('{0}.{1}.{2}' -f "3.5.0".split('.')))
        {
            Write-Host "Updating module Az.Storage..." -ForegroundColor Blue $([Constants]::MessageType.Info)
            Update-Module -Name "Az.Storage"
            Write-Host " Module Az.Storage is updated." -ForegroundColor $([Constants]::MessageType.update)
        }
    }

    # Checking if 'Az.Resources' module is available or not.
    if($availableModules.Name -notcontains 'Az.Resources')
    {
        Write-Host "Installing module Az.Resources..." -ForegroundColor $([Constants]::MessageType.Info)
        Install-Module -Name Az.Resources -Scope CurrentUser -Repository 'PSGallery'
        Write-Host "Module Az.resources is installed..." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Az.Resources module is available." -ForegroundColor $([Constants]::MessageType.Update)
    }
}





function Enable-StorageEncryptionInTransit
{
    
     <#
        .SYNOPSIS
        This command would help in remediating "Azure_Storage_DP_Encrypt_In_Transit" control.

        .DESCRIPTION
        This command would help in remediating  "Azure_Storage_DP_Encrypt_In_Transit" control.
        Enables HTTPS on the Storage Account in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
         
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .PARAMETER ExcludeResourceGroupNames
        Specifies the name of resource groups to be excluded from the remediation.
  
        .PARAMETER ExcludeResourceNames
        Specifies the name of resource  to be excluded from the remediation.

        .INPUTS
        None. You cannot pipe objects to Enable-StorageEncryptionInTransit.

        .OUTPUTS
        None. Enable-StorageEncryptionInTransit does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        Enable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000  -DryRun
      
        .EXAMPLE
        Enable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 
      
        .EXAMPLE
        PS> Enable-HttpsForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000  -FilePathC:\Users\Documents\AzTS\Remediation\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\20211013_0608\EnableSecureTransit\StorageWithDisableHTTPs.csv
         
        .LINK
        None
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id for remediation")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $false, HelpMessage="Enter path for the CSV file")]
        $FilePath,
   
        [string]
		[Parameter(Mandatory = $false, HelpMessage="Comma separated resource group name(s) to be excluded from remediation")]
		$ExcludeResourceGroupNames,

		[string]
		[Parameter(Mandatory = $false, HelpMessage="Comma separated resource name(s) to be excluded from remediation")]
		$ExcludeResourceNames,
        
        [switch]
        [Parameter(Mandatory = $false, HelpMessage="Specifies a forceful remediation without any prompts")]
        $Force,

        [switch]
        [Parameter(Mandatory = $false)]
        $DryRun
    )

    write-host " $([Constants]::DoubleDashLine)"

    try
    {   
        Write-Host "[Step 1 of 6]: Checking for pre-requisites..." 
        Setup-Prerequisites
        Write-Host $([Constants]::SingleDashLine)  
    }   
    catch 
    {
        Write-Host "Error occurred while checking pre-requisites. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)    
        break
    }
    
  
    #Connect to AzAccount
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet))
    {  
        Write-Host $([Constants]::SingleDashLine)    
        Write-Host "Connecting to AzAccount..."
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to AzAccount" -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force
  
    Write-Host "Metadata Details: `nSubscriptionName: $($currentSub.Subscription.Name) `nSubscriptionId: $($SubscriptionId) `nAccountName: $($currentSub.Account.Id) `nAccountType: $($currentSub.Account.Type)" 
  
    Write-Host $([Constants]::SingleDashLine)  
    Write-Host "Starting with subscription [$($SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Update)
    
    Write-Host $([Constants]::DoubleDashLine)

    write-host "[Step 2 of 6] : Validating the account type."
   
    Write-Host "*** To enable HTTPS for Storage Account in a Subscription, Contributor and higher privileges on the Storage Account are required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Validating whether the current user [$($currentSub.Account.Id)] has valid account type [User] to run the script for subscription [$($SubscriptionId)]..." 
    
    # Safe Check: Checking whether the current account is of type [User].
    if($currentSub.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
    
   
    Write-Host "Validation succeeded." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Fetching Storage Account(s)..." 
    
   
    # Array to store Storage Account(s) list .
    $resourceContext = @()

    # If CSV path not given fetch all Storage Account.
    if([string]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Storage Account(s) in subscription: [$($SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)

        #Get all Storage Account in a Subscription
        $resourceContext = Get-AzStorageAccount 
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
                $resourceContext += $storageAccount
            }
            catch
            {
                Write-Host "Error fetching Storage Account: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this Storage Account..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }

       
    $totalStorageAccount = ($resourceContext | Measure-Object).Count
   
    if($totalStorageAccount -eq 0)
    {  
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Unable to fetch Storage Account or no Storage Account available." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    $folderPath = [Environment]::GetFolderPath("MyDocuments") 

    if (Test-Path -Path $folderPath)
    {  
        #creating a folder to store the csv file.
        $folderPath += "\AzTS\Remediation\Subscriptions\$($subscriptionid.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\EnableSecureTransit"
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }

    Write-Host "Total Storage Account found: [$($totalStorageAccount)] " -ForegroundColor $([Constants]::MessageType.update)
    Write-Host $([Constants]::DoubleDashLine)

    write-host "[Step 3 of 6]: Removing the excluded resource group and resource from the list of subscription."
    
    $resourceSummary = @()
 
    # Adding property 'ResourceName' which will contain Storage Account name and being used by common helper method
    if(-not [string]::IsNullOrWhiteSpace($ExcludeResourceNames) -or -not [string]::IsNullOrWhiteSpace($ExcludeResourceGroupNames))
    {
        $resourceContext | ForEach-Object {
            $_ | Add-Member -NotePropertyName ResourceName -NotePropertyValue $_.StorageAccountName -ErrorAction SilentlyContinue
        }
    
        # Apply resource or resource group exclusion logic
        try
        {
            $resourceResolver = [ResourceResolver]::new([string] $excludeResourceNames , [string] $excludeResourceGroupNames);
            $resourceContext = $resourceResolver.ApplyResourceFilter([PSObject] $resourceContext) 
        }
        catch
        {
            Write-Host "Please load Helper.ps1 file in current PowerShell session before executing the script." -ForegroundColor $([Constants]::MessageType.Error)
            Break
        }

        if($resourceResolver.messageToPrint -ne $null)
        {
            $resourceSummary += "Excluded resource/resource group summary:`n " 
            $resourceSummary += $resourceResolver.messageToPrint
        }   
    }
    
    Write-Host $resourceSummary
    Write-Host "Total Storage Account(s) excluded  from remediation:" [$($totalStorageAccount - ($resourceContext | Measure-Object).Count)] -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "Total Storage Account(s) for remediation: [$(($resourceContext | Measure-Object).Count)]" -ForegroundColor $([Constants]::MessageType.Update)
    write-host "$([Constants]::DoubleDashLine)"

    try
    {
        #Storage Account with enabled HTTPs only
        $stgWithEnableHTTPs = @()
        #Storage Account with disabled HTTPs only
        $stgWithDisableHTTPs = @()
        #Storage Account skipped from remediation
        $skippedStorageAccountFromRemediation = @()

        Write-Host "[step 4 of 6] : Getting the Count of Storage Account in a subscription which are having 'EnableHttpsTrafficOnly' value set to false."
        $resourceContext | ForEach-Object {
            if ($_.EnableHttpsTrafficOnly)
            {
                $stgWithEnableHTTPs += $_ 
            }
        
            else
            { 
                 $stgWithDisableHTTPs += $_|Select-Object  @{N='ResourceId';E={$_.Id}},
                                                           @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                           @{N='StorageAccountName';E={$_.StorageAccountName}},
                                                           @{N='EnableHttpsTrafficOnly';E={$_.EnableHttpsTrafficOnly}}
                                                                              
            }
        }                    
                              
    
        $totalstgWithEnableHTTPs = ($stgWithEnableHTTPs | Measure-Object).Count
        $totalstgWithdisableHTTPs = ($stgWithDisableHTTPs | Measure-Object).Count
    
        Write-Host "Storage Account(s) with enabled 'EnablettpsTrafficOnly': [$($totalstgWithEnableHTTPs)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "Storage Account(s) with disabled 'EnableHttpsTrafficOnly'': [$($totalstgWithdisableHTTPs)]" -ForegroundColor $([Constants]::MessageType.Update)

        #Start remediation Storage Account(s) with 'EnableHttpsTrafficOnly' enabled.
            if ($totalstgWithDisableHTTPs -gt 0)
            {
                # Creating the log file
                if ($DryRun)
                {  
                    write-host " $([Constants]::SingleDashLine)"
                    Write-Host "Exporting configurations of Storage Account(s)  for which  the value of 'EnableHTTPsTrafficonly' is false.You may want to use this CSV as a pre-check before actual remediation." 
                    $stgWithDisableHTTPs | Export-CSV -Path "$($folderpath)\StorageWithDisableHTTPs.csv" -NoTypeInformation
                    Write-Host "Path: $($folderPath)\StorageWithDisableHTTPs.csv" -ForegroundColor $([Constants]::MessageType.Info)
                    return
                }
                else
                {  
                    write-host  $([Constants]::DoubleDashLine)
                    Write-Host "[step 5 of 6] : Exporting the Storage Account to csv file so that it can be used to rollback."
                    Write-Host "Backing up config of Storage Account(s) details. Please do not delete this file. Without this file you won't be able to rollback any changes done through remediation script." 
                    $stgWithDisableHTTPs | Export-CSV -Path "$($folderpath)\StorageWithdisableHTTPs.csv" -NoTypeInformation
                    Write-Host "Path: $($folderPath)\StorageWithdisableHTTPs.csv" -ForegroundColor $([Constants]::MessageType.Update)
                }

                write-host $([Constants]::SingleDashLine)
               
                if (-not $Force)
                {
                    Write-Host "Do you want to enable HTTPS on the storage account(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                    $userInput = Read-Host -Prompt "(Y|N)"
    
                    if($userInput -ne "Y")
                    {
                        Write-Host "HTTPS will not be enabled for any of the storage account. Exiting..." -ForegroundColor $([Constants]::MessageType.Info)
                        break
                    }
                }
                else
                {
                    Write-Host "'Force' flag is provided. HTTPS will be enabled on the storage account without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                }

              
                
                write-host $([Constants]::DoubleDashLine)
                Write-Host "[step 6 of 6] : Setting the value of 'EnableHttpsTrafficOnly' to 'true' for the Storage Account(s) of subscription."     
                $remediationSuccess = @() 
                    
                Write-Host "Enabling 'EnableHttpsTrafficOnly' on [$($totalstgWithdisableHTTPs)] Storage Account(s)..."
                $stgWithDisableHTTPs = $stgWithDisableHTTPs | Sort-Object -Property "ResourceGroupName"
                $stgWithDisableHTTPs | ForEach-Object {
                    try
                    {   
                        $output = Set-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName -EnableHttpsTrafficOnly $true -ErrorAction SilentlyContinue
                        if($output -ne $null)
                        {
                            $remediationSuccess += $_ 
                        }   
                        else
                        {   
                            $skippedStorageAccountFromRemediation += $_
                        }
                    }        
                    catch
                    {
                       $skippedStorageAccountFromRemediation += $_
                    }
                }
                    
                    
                write-host $([Constants]::DoubleDashLine)
                if(($skippedStorageAccountFromRemediation | Measure-Object).Count -eq 0)
                {
                    Write-Host "Remediation is successful on following Storage Account(s)" -ForegroundColor $([Constants]::MessageType.Update)
                    $remediationSuccess |Select-Object -Property ResourceGroupName , StorageAccountName , ResourceId |ft
                }

                elseif(($remediationSuccess | Measure-Object).Count -eq 0)
                {
                    Write-Host "Remediation is not successful on following Storage Account(s):" -ForegroundColor $([Constants]::MessageType.Error)
                    $skippedStorageAccountFromRemediation |Select-Object -Property ResourceGroupName , StorageAccountName , ResourceId |ft
                }
                   
                else 
                {
                    Write-Host "Remediation is successful on the following Storage Account(s):" -ForegroundColor $([Constants]::MessageType.Update)
                    $remediationSuccess |Select-Object -Property ResourceGroupName , StorageAccountName, ResourceId|ft
                    write-host $([Constants]::SingleDashLine)
                    Write-Host "Remediation is not successful on the following Storage Account(s):" -ForegroundColor $([Constants]::MessageType.Error)
                    $skippedStorageAccountFromRemediation |Select-Object -Property ResourceGroupName , StorageAccountName , ResourceId |ft
                }
            }     
            else
            {
                Write-Host "No Storage Account(s) found with disabled Https traffic only'." -ForegroundColor $([Constants]::MessageType.Update)
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
        Disables 'EnabledHttpsTrafficonly' on the Storage Account in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
          
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.
       
        .INPUTS
        None. You cannot pipe objects to Disable-StorageEncryptionInTransit.
       
        .OUTPUTS
        None. Disable-StorageEncryptionInTransit does not return anything that can be piped and used as an input to another command.
       
        .EXAMPLE
        Disable-StorageEncryptionInTransit -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath  C:\Users\Documents\AzTS\Remediation\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\20211013_0608\EnableSecureTransit\StorageWithDisableHTTPs.csv

        .LINK
        None
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id to perform rollback operation")]
        $SubscriptionId,

        [switch]
        [Parameter(Mandatory = $false, HelpMessage="Specifies a forceful remediation without any prompts")]
        $Force,

        
        [string]
        [Parameter(Mandatory = $true, HelpMessage="CSV file path which contain logs generated by remediation script to rollback remediation changes")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Starting rollback operation to disable 'EnableHttpsTrafficOnly' on Storage Account(s) from subscription [$($SubscriptionId)]...." -ForegroundColor $([Constants]::MessageType.Info)
    write-host "$([Constants]::DoubleDashLine)"

    try 
    {   Write-Host "[step 1 of 3 ] : Checking pre-requisites and validiating the user."
        Write-Host "Checking for pre-requisites..." 
        Setup-Prerequisites
        Write-Host $([Constants]::SingleDashLine)    
    }     
    catch 
    {
        Write-Host "Error occurred while checking pre-requisites. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)    
        break
    } 
         
    # Connect to AzAccount
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet))
    {       
        Write-Host "Connecting to AzAccount..."
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to AzAccount" -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force
    Write-Host "Metadata Details: `nSubscriptionId: $($SubscriptionId) `nAccountName: $($currentSub.Account.Id) `nAccountType: $($currentSub.Account.Type)" 
   
    Write-Host $([Constants]::SingleDashLine) 
    Write-Host "Starting with subscription [$($SubscriptionId)]..." 

    Write-Host " ***To perform rollback operation for enabling 'EnableHttpsTrafficonly' user must have atleast contributor access on Storage Account(s) of subscription: [$($SubscriptionId)]  ***" -ForegroundColor $([Constants]::MessageType.Info)

    Write-Host "Validating whether the current user [$($currentSub.Account.Id)] have valid account type [User] to run the script for subscription [$($SubscriptionId)]..." 

    # Safe Check: Checking whether the current account is of type User
    
    if($currentSub.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        break;
    }

    Write-Host "Successfully validated" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine) 
    Write-Host "Fetching remediation log to perform rollback operation on  Storage Account(s) from subscription [$($SubscriptionId)]..." 

    # Array to store resource context
    $resourceContext = @()

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Error: Control file path is not found." -ForegroundColor $([Constants]::MessageType.Error)
        break;        
    }
   
    Write-Host $([Constants]::DoubleDashLine)

    # Fetching remediated log 
    Write-Host "[step 2 of 3 ]: Getting the list of resources for rollback."
    $remediatedResourceLog = Import-Csv -LiteralPath $FilePath
    
    Write-Host "Fetching remedation log..."
    $resource =@()
  
                
            
    Write-Host "Performing rollback operation to disable  'EnableHttpsTrafficOnly' for Storage Account(s) of subscription [$($SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
    write-host $([Constants]::DoubleDashLine) 

    Write-Host $([Constants]::SingleDashLine)

    if (-not $Force)
    {
        Write-Host "Do you want to disable HTTPS on the storage account(s)? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        $userInput = Read-Host -Prompt "(Y|N)"
    
        if($userInput -ne "Y")
        {
            Write-Host "HTTPS will not be disabled for any of the storage account. Exiting..." -ForegroundColor $([Constants]::MessageType.Info)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. HTTPS will be disabled on the storage account without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    Write-Host "[step 3 of 3 ]: Performing rollback operation."
    
    try
    {
        if(($remediatedResourceLog | Measure-Object).Count -gt 0)
        {   $rollbackSuccess = @()
            $rollbackFailure = @()
                    
            Write-Host "Disabling 'EnableHttpsTrafficOnly' on [$(($remediatedResourceLog| Measure-Object).Count)] Storage Account(s) of subscription [$($SubscriptionId)]..." 
           
            $remediatedResourceLog | ForEach-Object {
                try
                {
                    $output = Set-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName -EnableHttpsTrafficOnly $false -ErrorAction SilentlyContinue
                    if($output -ne $null)
                    {
                        $rollbackSuccess += $_ |Select-Object -Property "StorageAccountName" , "ResourceGroupName" , "ResourceId"
                    }
                            
                    else
                    {         
                       $rollbackFailure += $_ |Select-Object -Property "StorageAccountName" , "ResourceGroupName" , "ResourceId"                              
                    }
                }   
                        
                catch
                {
                    $rollbackFailure += $_ |Select-Object -Property "StorageAccountName" , "ResourceGroupName" , "ResourceId"
                }
            }

            Write-Host $([Constants]::DoubleDashLine)

            if(($rollbackFailure|Measure-Object).Count -eq 0)
            {   Write-Host "Rollback is successful on following  Storage Account(s):" -ForegroundColor ([Constants]::MessageType.Update)
                $rollbackSuccess | Select-Object -Property "ResourcegroupName", "storageAccountName" ,"ResourceId" | ft
                    
            }          
            elseif(($rollbackSuccess|Measure-Object).Count -eq 0)
            {
                Write-Host "Rollback is not successful on following Storage Account(s):" -ForegroundColor ([Constants]::MessageType.Error)
                $rollbackFailure | Select-Object -Property "ResourcegroupName", "storageAccountName" ,"ResourceId"| ft
                    
            }         
            else
            {
                Write-Host "Rollback is successful on following Storage Account(s):" -ForegroundColor ([Constants]::MessageType.update)
                $rollbackSuccess | Select-Object -Property "ResourcegroupName", "storageAccountName" ,"ResourceId"| ft
                write-host $([Constants]::SingleDashLine)

                Write-Host "Rollback is not successful on following Storage Account(s):" -ForegroundColor ([Constants]::MessageType.Error)
                $rollbackFailure |Select-Object -Property "ResourcegroupName", "storageAccountName","ResourceId"|Format-Table
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
        Write-Host "Error occurred while performing rollback opeartion for remediating changes. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.error)
        break 
    }       
} 




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