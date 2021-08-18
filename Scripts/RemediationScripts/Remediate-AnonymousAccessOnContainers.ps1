<##########################################

# Overview:
    This script is used to remove anonymous access of storage account(s) containers that can lead to information disclosure.

ControlId: 
    Azure_Storage_AuthN_Dont_Allow_Anonymous

# Pre-requisites:
    You will need atleast contributor role on storage account(s) of subscription.

# Steps performed by the script
    1. Install and validate pre-requisites to run the script for subscription.

    2. Get anonymous access details of storage account(s).
        a. For given storage account(s) present in input json file.
                          ----OR----
        b. For all storage account(s) present in subscription.

    3. Taking backup of storage account(s) having anonymous access that are going to be remediated using remediation script.

    4. Removing anonymous access from storage account(s) of subscription as per selected remediation type.

# Step to execute script:
    Download and load remediation script in PowerShell session and execute below command.
    To know how to load script in PowerShell session refer link: https://aka.ms/AzTS-docs/RemediationscriptExcSteps.

# Command to execute:
    Examples:
        1. Run below command to remove anonymous access from all storage account(s) of subscription

        Remove-AnonymousAccessOnContainers -SubscriptionId '<Sub_Id>' -RemediationType '<DisableAnonymousAccessOnContainers>, <DisableAllowBlobPublicAccessOnStorage>' [-ExcludeResourceGroupNames <Comma separated resource group name(s) to be excluded from remediation>] [-ExcludeResourceNames <Comma separated resource name(s) to be excluded from remediation>]

        2. Run below command to remove anonymous access from given storage account(s) of subscription

        Remove-AnonymousAccessOnContainers -SubscriptionId '<Sub_Id>' -RemediationType '<DisableAnonymousAccessOnContainers>, <DisableAllowBlobPublicAccessOnStorage>'  -Path '<Json file path containing storage account(s) detail>' [-ExcludeResourceGroupNames <Comma separated resource group name(s) to be excluded from remediation>] [-ExcludeResourceNames <Comma separated resource name(s) to be excluded from remediation>]

    Note: 
        To rollback changes made by remediation script, execute below command
        Set-AnonymousAccessOnContainers -SubscriptionId '<Sub_Id>' -RollBackType '<EnableAnonymousAccessOnContainers>, <EnableAllowBlobPublicAccessOnStorage>'  -Path '<Json file path containing Remediated log>'   

To know more about parameter execute:
    a. Get-Help Remove-AnonymousAccessOnContainers -Detailed
    b. Get-Help Set-AnonymousAccessOnContainers -Detailed

########################################
#>

function Pre_requisites
{
    <#
    .SYNOPSIS
    This command would check pre requisites modules.
    .DESCRIPTION
    This command would check pre requisites modules to perform remediation.
	#>

    Write-Host "Required modules are: Az.Account, Az.Resources, Az.Storage" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking for required modules..."
    $availableModules = $(Get-Module -ListAvailable Az.Resources, Az.Accounts,Az.Storage)
    
    # Checking if 'Az.Accounts' module is available or not.
    if($availableModules.Name -notcontains 'Az.Accounts')
    {
        Write-Host "Installing module Az.Accounts..." -ForegroundColor $([Constants]::MessageType.Warning)
        Install-Module -Name Az.Accounts -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "Az.Accounts module is available." -ForegroundColor $([Constants]::MessageType.Update)
    }
    
    # Checking if 'Az.Storage' module with required version is available or not.
    if($availableModules.Name -notcontains 'Az.Storage')
    {
        Write-Host "Installing module Az.Storage..." -ForegroundColor $([Constants]::MessageType.Warning)
        Install-Module -Name Az.Storage -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "Az.Storage module is available." -ForegroundColor $([Constants]::MessageType.Update)
        $currentModule = $availableModules | Where-Object { $_.Name -eq "Az.Storage" }
        $currentModuleVersion = ($currentModule.Version  | measure -Maximum).Maximum -as [string]
        if([version]('{0}.{1}.{2}' -f $currentModuleVersion.split('.')) -lt [version]('{0}.{1}.{2}' -f "3.5.0".split('.')))
        {
            Write-Host "Updating module Az.Storage..." -ForegroundColor $([Constants]::MessageType.Update)
            Update-Module -Name "Az.Storage"
        }
    }

    # Checking if 'Az.Resources' module is available or not.
    if($availableModules.Name -notcontains 'Az.Resources')
    {
        Write-Host "Installing module Az.Resources..." -ForegroundColor $([Constants]::MessageType.Warning)
        Install-Module -Name Az.Resources -Scope CurrentUser -Repository 'PSGallery'
    }
    else
    {
        Write-Host "Az.Resources module is available." -ForegroundColor $([Constants]::MessageType.Update)
    }
}

function Remove-AnonymousAccessOnContainers
{
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_Storage_AuthN_Dont_Allow_Anonymous' control.
    .DESCRIPTION
    This command would help in remediating 'Azure_Storage_AuthN_Dont_Allow_Anonymous' control.
    .PARAMETER SubscriptionId
        Enter subscription id on which remediation need to perform.
    .PARAMETER RemediationType
        Select remediation type to perform from drop down menu.
    .PARAMETER Path
        Json file path which contain failed controls detail to remediate.
    .PARAMETER ExcludeResourceGroupNames
        Resource group name(s) which need to be excluded from remediation.
    .PARAMETER ExcludeResourceNames
        Resource name(s) which need to be excluded from remediation.
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id for remediation")]
        $SubscriptionId,

        [Parameter(Mandatory = $true, HelpMessage = "Select remediation type")]
        [ValidateSet("DisableAllowBlobPublicAccessOnStorage", "DisableAnonymousAccessOnContainers")]
        [string]
		$RemediationType,

        [string]
        [Parameter(Mandatory = $false, HelpMessage="Json file path which contain storage account(s) detail to remediate")]
        $Path,

        [string]
		[Parameter(Mandatory = $false, HelpMessage="Comma separated resource group name(s) to be excluded from remediation")]
		$ExcludeResourceGroupNames,

		[string]
		[Parameter(Mandatory = $false, HelpMessage="Comma separated resource name(s) to be excluded from remediation")]
		$ExcludeResourceNames
    )

    if($RemediationType -eq "DisableAnonymousAccessOnContainers" -and [string]::IsNullOrWhiteSpace($Path))
    {
        Write-Host "`n"
        Write-Host "Warning: Instead of disabling anonymous access on all containers of storage account, You can select to disable 'AllowBlobPublicAccess' at storage level." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Please execute same command with 'DisableAllowBlobPublicAccessOnStorage' remediation type parameter to disable anonymous access at storage level."
        Write-Host $([Constants]::DoubleDashLine)
        break; 
    }
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Starting to remediate anonymous access on containers of storage account(s) from subscription [$($SubscriptionId)]..."
    Write-Host $([Constants]::SingleDashLine)
    
    try 
    {
        Write-Host "Checking for pre-requisites..."
        Pre_requisites
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

    Write-Host "Metadata Details: `n SubscriptionName: $($currentSub.Subscription.Name) `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)  
    Write-Host "Starting with subscription [$($SubscriptionId)]..."

    Write-Host "`n"
    Write-Host "*** To perform remediation for disabling anonymous access on containers user must have atleast contributor access on storage account(s) of subscription: [$($SubscriptionId)] ***" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host "`n" 

    Write-Host "Validating whether the current user [$($currentSub.Account.Id)] has valid account type [User] to run the script for subscription [$($SubscriptionId)]..."
    
    # Safe Check: Checking whether the current account is of type User
    if($currentSub.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        break;
    }
    
    Write-Host "Successfully validated" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "`n"
    Write-Host "Fetching storage account(s)..."
    
    # Array to store resource context
    $resourceContext = @()
    $controlIds = "Azure_Storage_AuthN_Dont_Allow_Anonymous"
    
    # If json path not given fetch all storage account.
    if([string]::IsNullOrWhiteSpace($Path))
    {
        $resourceContext = Get-AzStorageAccount
    }
    else
    {
        if (-not (Test-Path -Path $Path))
        {
            Write-Host "Error: Json file containing storage account(s) detail not found for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            break;        
        }

        # Fetching storage accounts details for remediation.
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.FailedControlSet
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId};

        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($resourceDetails.ResourceDetails | Measure-Object).Count -eq 0)
        {
            Write-Host "No storage account(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
        $resourceDetails.ResourceDetails | ForEach-Object { 
            try
            {
                $resourceContext += Get-AzStorageAccount -Name $_.StorageAccountName -ResourceGroupName $_.ResourceGroupName
                $resourceContext | Add-Member -NotePropertyName AnonymousAccessContainer -NotePropertyValue $_.ContainersWithAnonymousAccess -ErrorAction SilentlyContinue
            }
            catch
            {
                Write-Host "Valid resource group(s) or resource name(s) not found in input json file. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                break
            }
        }
    }

    $totalStorageAccount = ($resourceContext | Measure-Object).Count
    if($totalStorageAccount -eq 0)
    {
        Write-Host "Unable to fetch storage account." -ForegroundColor $([Constants]::MessageType.Error);
        Write-Host $([Constants]::DoubleDashLine)
        break;
    }

    Write-Host "Total storage account(s): [$($totalStorageAccount)]"
    $folderPath = [Environment]::GetFolderPath("MyDocuments") 
    if (Test-Path -Path $folderPath)
    {
        $folderPath += "\AzTS\Remediation\Subscriptions\$($subscriptionid.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\DisableAnonymousAccessOnContainers"
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }
    $resourceSummary = @()
    $resourceSummary += "Total resource(s) for remediation: $($totalStorageAccount)"
    $resourceSummary += "$($resourceContext | Select-Object -Property "ResourceGroupName", "StorageAccountName"| Sort-Object -Property "ResourceGroupName" |Format-Table |Out-String)"
        

    # Adding property 'ResourceName' which will contain storage account name and being used by common helper method
    if(-not [string]::IsNullOrWhiteSpace($ExcludeResourceNames) -or -not [string]::IsNullOrWhiteSpace($ExcludeResourceGroupNames))
    {
        $resourceContext | ForEach-Object {
            $_ | Add-Member -NotePropertyName ResourceName -NotePropertyValue $_.StorageAccountName -ErrorAction SilentlyContinue
        }
    
        # Apply resource or resource group exclusion logic
    
        $resourceResolver = [ResourceResolver]::new([string] $excludeResourceNames , [string] $excludeResourceGroupNames);
        $resourceContext = $resourceResolver.ApplyResourceFilter([PSObject] $resourceContext) 
        
        if($resourceResolver.messageToPrint -ne $null)
        {
            $resourceSummary += $([Constants]::SingleDashLine)
            $resourceSummary += "Excluded resource/resource group summary: "
            $resourceSummary += $resourceResolver.messageToPrint
        }   
    }
    
    Write-Host "Total excluded storage account(s) from remediation:" [$($totalStorageAccount - ($resourceContext | Measure-Object).Count)]
    Write-Host "Checking config of storage account(s) for remediation: [$(($resourceContext | Measure-Object).Count)]"
    
    switch ($RemediationType)
    {
        "DisableAllowBlobPublicAccessOnStorage"
        {
            try
            {
                $stgWithEnableAllowBlobPublicAccess = @()
                $stgWithDisableAllowBlobPublicAccess = @()
                $skippedStorageAccountFromRemediation = @()
                $resourceContext | ForEach-Object {
                    if(($null -eq $_.allowBlobPublicAccess) -or ($_.allowBlobPublicAccess))
                    {
                        
                        $stgWithEnableAllowBlobPublicAccess += $_ | select -Property "StorageAccountName", "ResourceGroupName", "Id"
                    }
                    else
                    {
                        $stgWithDisableAllowBlobPublicAccess += $_
                    }   
                }
    
                $totalStgWithEnableAllowBlobPublicAccess = ($stgWithEnableAllowBlobPublicAccess | Measure-Object).Count
                $totalStgWithDisableAllowBlobPublicAccess = ($stgWithDisableAllowBlobPublicAccess | Measure-Object).Count
    
                Write-Host "Storage account(s) with enabled 'Allow Blob Public Access': [$($totalStgWithEnableAllowBlobPublicAccess)]"
                Write-Host "Storage account(s) with disabled 'Allow Blob Public Access': [$($totalStgWithDisableAllowBlobPublicAccess)]"

                Write-Host "`n"

                # Start remediation storage account(s) with 'Allow Blob Public Access' enabled.
                if ($totalStgWithEnableAllowBlobPublicAccess -gt 0)
                {
                    # Creating the log file
                    
                    Write-Host "Backing up config of storage account(s) details. Please do not delete this file without this file you won't be able to rollback any changes done through remediation script." -ForegroundColor $([Constants]::MessageType.Info)
                    $stgWithEnableAllowBlobPublicAccess | ConvertTo-json | out-file "$($folderpath)\DisabledAllowBlobPublicAccess.json"  
                    Write-Host "Path: $($folderpath)\DisabledAllowBlobPublicAccess.json"     
                    Write-Host "`n"
                    Write-Host "Disabling 'Allow Blob Public Access' on [$($totalStgWithEnableAllowBlobPublicAccess)] storage account(s)..."
                    $stgWithEnableAllowBlobPublicAccess = $stgWithEnableAllowBlobPublicAccess | Sort-Object -Property "ResourceGroupName"
                    $stgWithEnableAllowBlobPublicAccess | ForEach-Object {
                        try
                        {
                            $output = Set-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName -AllowBlobPublicAccess $false -ErrorAction SilentlyContinue
                            if($output -ne $null)
                            {
                                $_ | Select-Object @{Expression={($_.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$_.StorageAccountName};Label="StorageAccountName"}
                            }
                            else
                            {
                                $item =  New-Object psobject -Property @{  
                                    StorageAccountName = $_.StorageAccountName                
                                    ResourceGroupName = $_.ResourceGroupName
                                }

                                $skippedStorageAccountFromRemediation += $item
                            }
                        }
                        catch
                        {
                            $item =  New-Object psobject -Property @{  
                                StorageAccountName = $_.StorageAccountName                
                                ResourceGroupName = $_.ResourceGroupName
                            }
                            $skippedStorageAccountFromRemediation += $item
                        }
                    }

                    Write-Host "`n"
                    if(($skippedStorageAccountFromRemediation | Measure-Object).Count -eq 0)
                    {
                        Write-Host "Successfully disabled 'Allow Blob Public Access'." -ForegroundColor $([Constants]::MessageType.Update)
                    }
                    else 
                    {
                        Write-Host "Remediation was not successful on the following storage account(s)" -ForegroundColor $([Constants]::MessageType.Warning)
                        $skippedStorageAccountFromRemediation | Select-Object @{Expression={($_.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$_.StorageAccountName};Label="StorageAccountName"}
                        $resourceSummary += "Remediation was not successful on following storage account(s), due to insufficient permission"
                        $resourceSummary += "$($skippedStorageAccountFromRemediation | Select-Object -Property "ResourceGroupName", "StorageAccountName"| Sort-Object |Format-Table |Out-String)"
                    }
                }
                else
                {
                    Write-Host "No storage account(s) found with enabled 'Allow Blob Public Access'." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    break
                }
            }
            catch{
                Write-Host "Error occurred while remediating changes. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                break
            }
        }
        "DisableAnonymousAccessOnContainers" 
        {
            Write-Host "`n"
            Write-Host "Warning: Selected remediation type will disable anonymous access for specific containers, provided in input json file." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "`n"
           
            Write-Host "Disabling anonymous access on containers of storage account(s)..."

            # Performing remediation
            try
            {
                $ContainersWithAnonymousAccessOnStorage = @();
                $ContainersWithDisableAnonymousAccessOnStorage = @();
                $resourceContext = $resourceContext | Sort-Object -Property "ResourceGroupName"
                $resourceContext | ForEach-Object{
                    $flag = $true
                    $allContainers = @();
                    $containersWithAnonymousAccess = @();
                    $anonymousAccessContainersNameAndPublicAccess = @();
                    $context = $_.context;

                    # Taking containers details from input json file for remediation
                    $allContainers += Get-AzStorageContainer -Context $context -ErrorAction Stop
                    if((($allContainers | Measure-Object).Count -gt 0) -and (($null -ne $_.AnonymousAccessContainer) -and ($_.AnonymousAccessContainer | Measure-Object).Count -gt 0))
                    {
                        $containersToRemediate = $_.AnonymousAccessContainer;
                        $containersWithAnonymousAccess += $allContainers | Where-Object { $_.Name -in $containersToRemediate }
                        if(($containersWithAnonymousAccess | Measure-Object).Count -gt 0)
                        {
                            $containersWithAnonymousAccess | ForEach-Object {
                                try
                                {
                                    Set-AzStorageContainerAcl -Name $_.Name -Permission Off -Context $context | Out-Null
                                    
                                    # Creating objects with container name and public access type, It will help while doing rollback operation.
                                    $item =  New-Object psobject -Property @{  
                                            Name = $_.Name                
                                            PublicAccess = $_.PublicAccess
                                        }
                                        $anonymousAccessContainersNameAndPublicAccess += $item
                                }
                                catch
                                {
                                    # If not able to remove container public access due to insufficient permission or exception occurred.
                                    $flag = $false
                                    break;    
                                }
                            };
                        
                            # If successfully removed anonymous access from storage account's containers.
                            if($flag)
                            {
                                $_ | Select-Object @{Expression={($_.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$_.StorageAccountName};Label="StorageAccountName"}
                                $item =  New-Object psobject -Property @{  
                                        SubscriptionId = $SubscriptionId
                                        ResourceGroupName = $_.ResourceGroupName
                                        StorageAccountName = $_.StorageAccountName
                                        ResourceType = "Microsoft.Storage/storageAccounts"
                                        ResourceId = $_.id
                                    }

                                    # Adding array of container name and public access type
                                    $item | Add-Member -Name 'ContainersWithAnonymousAccess' -Type NoteProperty -Value $anonymousAccessContainersNameAndPublicAccess;
                                    $ContainersWithDisableAnonymousAccessOnStorage += $item
                            }
                            else
                            {
                                # Unable to disable containers anonymous access may be because of insufficient permission over storage account(s) or exception occurred.
                                Write-Host "Skipping to disable anonymous access on containers of storage account(s) due to insufficient access [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Warning);
                                $item =  New-Object psobject -Property @{
                                        SubscriptionId = $SubscriptionId  
                                        ResourceGroupName = $_.ResourceGroupName
                                        StorageAccountName = $_.StorageAccountName
                                        ResourceType = "Microsoft.Storage/storageAccounts"
                                        ResourceId = $_.id
                                    }

                                $ContainersWithAnonymousAccessOnStorage += $item
                            }
                        }
                        else {
                            Write-Host "There are no containers on storage account(s) which have anonymous access enabled [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Update);
                        }
                    }
                    else
                    {
                        Write-Host "No container(s) found to disable anonymous access for storage account(s) [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Update) ;
                    }	
                }
            }
            catch
            {
                Write-Host "Error occurred while remediating control. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                break
            }

            # Creating the log file
            if(($ContainersWithDisableAnonymousAccessOnStorage | Measure-Object).Count -gt 0)
            {
                Write-Host "Backing up config of storage account(s) details for subscription: [$($SubscriptionId)] on which remediation is successfully performed. Please do not delete this file without this file you won't be able to rollback any changes done through remediation script." -ForegroundColor $([Constants]::MessageType.Info)
                $ContainersWithDisableAnonymousAccessOnStorage | ConvertTo-Json -Depth 10| Out-File "$($folderPath)\ContainersWithDisableAnonymousAccess.json"
                Write-Host "Path: $($folderPath)\ContainersWithDisableAnonymousAccess.json"
                Write-Host $([Constants]::DoubleDashLine)
            }

            if(($ContainersWithAnonymousAccessOnStorage | Measure-Object).Count -gt 0)
            {
                Write-Host "`n"
                Write-Host "Generating the log file containing details of all the storage account(s) on which remediating script unable to disable containers with anonymous access due to error occurred or insufficient permission over storage account(s) for subscription: [$($SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
                $ContainersWithAnonymousAccessOnStorage | ConvertTo-Json -Depth 10 | Out-File "$($folderPath)\ContainersWithAnonymousAccessOnStorage.json"
                Write-Host "Path: $($folderPath)\ContainersWithAnonymousAccessOnStorage.json"
                Write-Host $([Constants]::DoubleDashLine)
            }
        }
        Default {

            Write-Host "No valid remediation type selected." -ForegroundColor $([Constants]::MessageType.Error)
            break;
        }
    }
    $resourceSummary += [Constants]::DoubleDashLine
    [ResourceResolver]::RemediationSummary($resourceSummary, $folderPath)
    Write-Host $([Constants]::DoubleDashLine)
}

# Script to rollback changes done by remediation script
function Set-AnonymousAccessOnContainers
{
    <#
    .SYNOPSIS
    This command would help in performing rollback operation for 'Azure_Storage_AuthN_Dont_Allow_Anonymous' control.
    .DESCRIPTION
    This command would help in performing rollback operation for 'Azure_Storage_AuthN_Dont_Allow_Anonymous' control.
    .PARAMETER SubscriptionId
        Enter subscription id on which rollback operation need to perform.
    .PARAMETER RollBackType
        Select rollback type to perform rollback operation from drop down menu.
    .PARAMETER Path
        Json file path which containing remediation log to perform rollback operation.
    #>
    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Enter subscription id to perform rollback operation")]
        $SubscriptionId,

        [Parameter(Mandatory = $true, HelpMessage = "Select rollback type")]
        [ValidateSet("EnableAllowBlobPublicAccessOnStorage", "EnableAnonymousAccessOnContainers")]
        [string]
		$RollBackType,

        [string]
        [Parameter(Mandatory = $true, HelpMessage="Json file path which contain logs generated by remediation script to rollback remediation changes")]
        $Path
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Starting rollback operation to enable anonymous access on containers of storage account(s) from subscription [$($SubscriptionId)]...."
    Write-Host $([Constants]::SingleDashLine)

    try 
        {
            Write-Host "Checking for pre-requisites..."
            Pre_requisites
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

    Write-Host "Metadata Details: `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host $([Constants]::SingleDashLine) 
    Write-Host "Starting with subscription [$($SubscriptionId)]..."

    Write-Host "`n"
    Write-Host "*** To perform rollback operation for enabling anonymous access on containers user must have atleast contributor access on storage account(s) of subscription: [$($SubscriptionId)] ***" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host "`n" 
    Write-Host "Validating whether the current user [$($currentSub.Account.Id)] have valid account type [User] to run the script for subscription [$($SubscriptionId)]..."

    # Safe Check: Checking whether the current account is of type User
    if($currentSub.Account.Type -ne "User")
    {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        break;
    }
    Write-Host "Successfully validated" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "`n"
    Write-Host "Fetching remediation log to perform rollback operation on containers of storage account(s) from subscription [$($SubscriptionId)]..."
 
    # Array to store resource context
    $resourceContext = @()
    if (-not (Test-Path -Path $Path))
    {
        Write-Host "Error: Control file path is not found." -ForegroundColor $([Constants]::MessageType.Error)
        break;        
    }

    switch ($RollBackType) 
    {
        "EnableAllowBlobPublicAccessOnStorage" 
        {  
            # Fetching remediated log for 'DisableAllowBlobPublicAccessOnStorage' remediation type.
            $remediatedResourceLog = Get-content -path $Path | ConvertFrom-Json
    
            Write-Host "Performing rollback operation to enable 'Allow Blob Public Access' for storage account(s) of subscription [$($SubscriptionId)]..."
        
            # Performing rollback operation
            try
            {
                if(($remediatedResourceLog | Measure-Object).Count -gt 0)
                {
                    Write-Host "Enabling 'Allow Blob Public Access' on [$(($remediatedResourceLog| Measure-Object).Count)] storage account(s) of subscription [$($SubscriptionId)]..."
                    $remediatedResourceLog | ForEach-Object {
                        try
                        {
                            $output = Set-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -StorageAccountName $_.StorageAccountName -AllowBlobPublicAccess $true -ErrorAction SilentlyContinue
                            if($output -ne $null)
                            {
                                $_ | Select-Object @{Expression={($_.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$_.StorageAccountName};Label="StorageAccountName"}    
                            }
                            else
                            {
                                Write-Host "Skipping rollback due to insufficient access [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Warning)                                
                            }
                        }
                        catch
                        {
                            Write-Host "Skipping rollback due to insufficient access or exception occurred [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Warning)
                        }
                    }
                    Write-Host $([Constants]::DoubleDashLine)
                }
                else 
                {
                    Write-Host "No storage account(s) found in remediation log to perform rollback operation." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    break
                }
            }   
            catch
            {
                Write-Host "Error occurred while performing rollback opeartion for remediating changes. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                break
            }
        }
        "EnableAnonymousAccessOnContainers" 
        {  
            # Fetching remediated log for 'DisableAnonymousAccessOnContainers' remediation type.
            $remediatedResourceLog = Get-content -path $Path | ConvertFrom-Json
            try
            {
                $remediatedResourceLog | ForEach-Object { 
                            $resourceContext += Get-AzStorageAccount -Name $_.StorageAccountName -ResourceGroupName $_.ResourceGroupName    
                            $resourceContext | Add-Member -NotePropertyName AnonymousAccessContainer -NotePropertyValue $_.ContainersWithAnonymousAccess -ErrorAction SilentlyContinue
                        }
            }
            catch
            {
                Write-Host "Input json file is not valid as per selected rollback type. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                break
            }

            $totalResourceToRollBack = ($resourceContext | Measure-Object).Count
            Write-Host "Found [$($totalResourceToRollBack)] storage account(s) to perform rollback operation."
            Write-Host "Performing rollback operation to enable anonymous access on containers of storage account(s) from subscription [$($SubscriptionId)]..."
        

            # Performing rollback
            try{
                if($totalResourceToRollBack -gt 0)
                {
                    $resourceContext | ForEach-Object{
                        $flag = $true
                        $context = $_.context;
                        $containerWithAnonymousAccess = @();
                        $containerWithAnonymousAccess += $_.AnonymousAccessContainer

                        # Checking 'Allow Blob Public Access' is enabled or not at storage level. If found enabled then we can rollback access otherwise not permitted.
                        if(($null -eq $_.AllowBlobPublicAccess) -or $_.AllowBlobPublicAccess)
                            {
                                if(($containerWithAnonymousAccess | Measure-Object).Count -gt 0)
                                {
                                    $containerWithAnonymousAccess | ForEach-Object {
                                        try
                                        {
                                            Set-AzStorageContainerAcl -Name $_.Name -Permission $_.PublicAccess -Context $context -ErrorAction SilentlyContinue | Out-Null
                                        }
                                        catch
                                        {
                                            $flag = $false
                                            break;
                                        }
                                    };

                                    if($flag)
                                    {
                                        $_ | Select-Object @{Expression={($_.ResourceGroupName)};Label="ResourceGroupName"},@{Expression={$_.StorageAccountName};Label="StorageAccountName"}
                                    }
                                    else 
                                    {
                                        Write-Host "Skipping to enable anonymous access on containers of storage [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Warning);
                                    }
                                }
                                else
                                {
                                    Write-Host "No containers found with enabled anonymous access [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Update);
                                }	
                            }
                            else 
                            {
                                Write-Host "Public access is not permitted on this storage account [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Warning);
                            }
                    }
                    Write-Host $([Constants]::DoubleDashLine)
                }
                else
                {
                    Write-Host "Unable to fetch storage account." -ForegroundColor $([Constants]::MessageType.Error);
                    break
                }
            }
            catch
            {
                Write-Host "Error occurred while performing rollback operation for remediating changes. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                break
            }
        }
        Default 
        {
            Write-Host "No valid rollback type selected." -ForegroundColor $([Constants]::MessageType.Error)
            break;
        }
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

# ***************************************************** #