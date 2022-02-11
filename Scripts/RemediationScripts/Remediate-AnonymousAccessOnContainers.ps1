<##########################################

# Overview:
    This script is used to remove anonymous access of Storage account(s) containers that can lead to information disclosure.

ControlId: 
    Azure_Storage_AuthN_Dont_Allow_Anonymous

DisplayName:
    Ensure secure access to Storage account containers.

# Pre-requisites:
    1. You will need atleast contributor role on Storage account(s) of subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script
    1. Install and validate pre-requisites to run the script for subscription.

    2. Get anonymous access details of Storage account(s).
        a. For given Storage account(s) present in input file.
                          ----OR----
        b. For all Storage account(s) present in subscription.

    3. Taking backup of Storage account(s) having anonymous access that are going to be remediated using remediation script.

    4. Removing anonymous access from Storage account(s) of subscription as per selected remediation type.

# Step to execute script:
    Download and load remediation script in PowerShell session and execute below command.
    To know how to load script in PowerShell session refer link: https://aka.ms/AzTS-docs/RemediationscriptExcSteps.
    Before running this script, make sure you load Helper.ps1 along with remediation script in current PowerShell session using below command:
        . ".\Helper.ps1"

# Examples:
    To remediate:
        1. Run below command to remove anonymous access from all Storage account(s) of subscription:
            Remove-AnonymousAccessOnContainers -SubscriptionId '<Sub_Id>' -RemediationType '<remediation_type>' [-ExcludeResourceGroupNames '<ExcludeRGNames>'] [-ExcludeResourceNames '<ExcludeResourceName>']

            Note:
                i. Supported two 'RemediationType':
                    a. DisableAllowBlobPublicAccessOnStorage, 
                    b. DisableAnonymousAccessOnContainers.
                ii. 'ExcludeResourceGroupNames' -> Comma separated resource group name(s) to be excluded from remediation.
                iii. 'ExcludeResourceNames' -> Comma separated resource name(s) to be excluded from remediation.

        2. Run below command to remove anonymous access at Storage account level from given csv file:
            Remove-AnonymousAccessOnContainers -SubscriptionId '<Sub_Id>' -RemediationType 'DisableAllowBlobPublicAccessOnStorage'  -FilePath '<csv file path containing Storage account(s) detail>' [-ExcludeResourceGroupNames '<ExcludeRGNames>'] [-ExcludeResourceNames '<ExcludeResourceName>']

        3. Run below command to remove anonymous access at container level from given json file:
            Remove-AnonymousAccessOnContainers -SubscriptionId '<Sub_Id>' -RemediationType 'DisableAnonymousAccessOnContainers'  -Path '<json file path containing Storage account(s) detail>' [-ExcludeResourceGroupNames '<ExcludeRGNames>'] [-ExcludeResourceNames '<ExcludeResourceName>']

            Note: You can refer sample json file 'FailedControlsSetForRemediation.json'

        Additional features supported while remediating at Storage account level (not at container level):
            i. [Recommended] Use -DryRun parameter to get details of Storage accounts in CSV for pre-check.
            ii. Use -SkipBackup, if you don't want to take backup before actual remediation.

        4. Run below command to review the Storage account(s) in a Subscription that will be remediated:
           Remove-AnonymousAccessOnContainers -SubscriptionId '<Sub_Id>' -DryRun

        5. Run below command to remove anonymous access from all Storage account(s) in a Subscription without taking back up before actual remediation:
           Remove-AnonymousAccessOnContainers -SubscriptionId '<Sub_Id>' -SkipBackup

    To rollback:
        1. Run below command to rollback changes made by remediation script at Storage account level:
           Set-AnonymousAccessOnContainers -SubscriptionId '<Sub_Id>' -RollBackType 'EnableAllowBlobPublicAccessOnStorage' -FilePath '<csv file path containing remediated log>'
           
        2. Run below command to rollback changes made by remediation script at Container level:
           Set-AnonymousAccessOnContainers -SubscriptionId '<Sub_Id>' -RollBackType 'EnableAnonymousAccessOnContainers>' -Path '<Json file path containing remediated log>'

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
        if([version]('{0}.{1}.{2}' -f $currentModuleVersion.split('.')) -lt [version]('{0}.{1}.{2}' -f "3.7.0".split('.')))
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
            Json file path which contain failed controls detail to remediate at container level.

        .PARAMETER ExcludeResourceGroupNames
            Resource group name(s) which need to be excluded from remediation.

        .PARAMETER ExcludeResourceNames
            Resource name(s) which need to be excluded from remediation.

        .PARAMETER DryRun
            Run pre-script before actual remediating Storage accounts in the subscription.

        .PARAMETER Force
        Specifies a forceful remediation without any prompts.

        .PARAMETER FilePath
            Specifies the path to the file to be used as input for the remediation at Storage account level.

        .PARAMETER SkipBackup
            Specifies no back up will be taken by the script before remediation
    #>

    param (
        [string]
        [Parameter(ParameterSetName = "RemediationAtStorageLevel", Mandatory = $true, HelpMessage="Enter subscription id for remediation")]
        [Parameter(ParameterSetName = "RemediationAtContainerLevel", Mandatory = $true, HelpMessage="Enter subscription id for remediation")]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Enter subscription id for remediation")]
        $SubscriptionId,

        [Parameter(ParameterSetName = "RemediationAtStorageLevel", Mandatory = $true, HelpMessage = "Select remediation type")]
        [Parameter(ParameterSetName = "RemediationAtContainerLevel", Mandatory = $true, HelpMessage = "Select remediation type")]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage = "Select remediation type")]
        [ValidateSet("DisableAllowBlobPublicAccessOnStorage", "DisableAnonymousAccessOnContainers")]
        [string]
        $RemediationType,

        [Switch]
        [Parameter(ParameterSetName = "RemediationAtStorageLevel", HelpMessage="Specifies a forceful remediation without any prompts")]
        [Parameter(ParameterSetName = "RemediationAtContainerLevel", HelpMessage="Specifies a forceful remediation without any prompts")]
        $Force,

        [string]
        [Parameter(ParameterSetName = "RemediationAtContainerLevel", Mandatory = $true, HelpMessage="Json file path which contain Storage account(s) detail to remediate")]
        $Path,

        [string]
        [Parameter(ParameterSetName = "RemediationAtStorageLevel", Mandatory = $false, HelpMessage="Comma separated resource group name(s) to be excluded from remediation")]
        [Parameter(ParameterSetName = "RemediationAtContainerLevel", Mandatory = $false, HelpMessage="Comma separated resource group name(s) to be excluded from remediation")]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $false, HelpMessage="Comma separated resource group name(s) to be excluded from remediation")]
        $ExcludeResourceGroupNames,

        [string]
        [Parameter(ParameterSetName = "RemediationAtStorageLevel", Mandatory = $false, HelpMessage="Comma separated resource name(s) to be excluded from remediation")]
        [Parameter(ParameterSetName = "RemediationAtContainerLevel", Mandatory = $false, HelpMessage="Comma separated resource name(s) to be excluded from remediation")]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $false, HelpMessage="Comma separated resource name(s) to be excluded from remediation")]
        $ExcludeResourceNames,

        [switch]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies a dry run of the actual remediation")]
        $DryRun,

        [Switch]
        [Parameter(ParameterSetName = "RemediationAtStorageLevel", HelpMessage="Specifies no back up will be taken by the script before remediation")]
        $SkipBackup,

        [String]
        [Parameter(ParameterSetName = "RemediationAtStorageLevel", HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath
    )

    if($RemediationType -eq "DisableAnonymousAccessOnContainers" -and [string]::IsNullOrWhiteSpace($Path))
    {
        Write-Host "`n"
        Write-Host "Warning: Instead of disabling anonymous access on all containers of Storage account, You can select to disable 'AllowBlobPublicAccess' at storage level." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Please execute same command with 'DisableAllowBlobPublicAccessOnStorage' remediation type parameter to disable anonymous access at storage level."
        Write-Host $([Constants]::DoubleDashLine)
        break; 
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Starting to remediate anonymous access on containers of Storage account(s) from subscription [$($SubscriptionId)]..."
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
    
    # Check current login context.
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet))
    {       
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force

    Write-Host "Metadata Details: `n SubscriptionName: $($currentSub.Subscription.Name) `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)  
    Write-Host "Starting with subscription [$($SubscriptionId)]..."

    Write-Host "`n"
    Write-Host "*** WARNING: To perform remediation for disabling anonymous access on containers user must have atleast contributor access on Storage account(s) of subscription: [$($SubscriptionId)] ***" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::DoubleDashLine) 
    
    # Array to store resource context
    $resourceContext = @()
    $controlIds = "Azure_Storage_AuthN_Dont_Allow_Anonymous"
    
    # If json path not given fetch all Storage account.
    if([string]::IsNullOrWhiteSpace($Path) -and [string]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Storage Account(s) in subscription: [$($SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
        $resourceContext = Get-AzStorageAccount
    }
    else
    {
        # Fetching Storage accounts details for remediation.
        if (![string]::IsNullOrWhiteSpace($Path))
        {
            if (-not (Test-Path -Path $Path))
            {
                Write-Host "Error: Json file containing Storage account(s) detail not found for remediation." -ForegroundColor $([Constants]::MessageType.Error)
                break;        
            }

            $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
            $controls = $controlForRemediation.FailedControlSet
            $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId};

            if(($resourceDetails | Measure-Object).Count -eq 0 -or ($resourceDetails.ResourceDetails | Measure-Object).Count -eq 0)
            {
                Write-Host "No Storage account(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
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

        elseif (![string]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all Storage Account from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

            $resourceContext = Import-Csv -LiteralPath $FilePath
        }
    }

    $totalStorageAccount = ($resourceContext | Measure-Object).Count
    if($totalStorageAccount -eq 0)
    {
        Write-Host "Unable to fetch Storage account or no Storage account available." -ForegroundColor $([Constants]::MessageType.Error);
        Write-Host $([Constants]::DoubleDashLine)
        break;
    }

    Write-Host "Total Storage account(s): [$($totalStorageAccount)]"
    $folderPath = [Environment]::GetFolderPath('LocalApplicationData') 
    if (Test-Path -Path $folderPath)
    {
        $folderPath += "\AzTS\Remediation\Subscriptions\$($subscriptionid.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\DisableAnonymousAccessOnContainers"
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }

    $resourceSummary = @()
    $resourceSummary += "Total resource(s) for remediation: $($totalStorageAccount)"
    $resourceSummary += "$($resourceContext | Select-Object -Property "ResourceGroupName", "StorageAccountName"| Sort-Object -Property "ResourceGroupName" |Format-Table |Out-String)"

    # Adding property 'ResourceName' which will contain Storage account name and being used by common helper method
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
            $resourceSummary += $([Constants]::SingleDashLine)
            $resourceSummary += "Excluded resource/resource group summary: "
            $resourceSummary += $resourceResolver.messageToPrint
        }   
    }
    
    Write-Host "Total excluded Storage account(s) from remediation:" [$($totalStorageAccount - ($resourceContext | Measure-Object).Count)]
    Write-Host "Checking config of Storage account(s) for remediation: [$(($resourceContext | Measure-Object).Count)]"
    
    switch ($RemediationType)
    {
        "DisableAllowBlobPublicAccessOnStorage"
        {
            try
            {
                $stgWithEnableAllowBlobPublicAccess = @()
                $stgWithDisableAllowBlobPublicAccess = @()
                $skippedStorageAccountsFromRemediation = @()
                $remediatedStorageAccounts = @()

                $resourceContext | ForEach-Object {
                    if(-not(Get-Member -InputObject $_ -MemberType Properties -Name allowBlobPublicAccess) -or ($_.allowBlobPublicAccess))
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

                # Start remediation Storage account(s) with 'Allow Blob Public Access' enabled.
                if ($totalStgWithEnableAllowBlobPublicAccess -gt 0)
                {
                    # Creating the log file
                    if ($DryRun)
                    {
                        Write-Host "Exporting configurations of Storage account(s) having 'Allow Blob Public Access' enabled. You may want to use this CSV as a pre-check before actual remediation." -ForegroundColor $([Constants]::MessageType.Info)
                        $stgWithEnableAllowBlobPublicAccess | Export-CSV -Path "$($folderpath)\StorageWithPublicAccess.csv" -NoTypeInformation
                        Write-Host "Path: $($folderPath)\StorageWithPublicAccess.csv"
                        Write-Host "Run the same command with -FilePath $($folderPath)\StorageWithPublicAccess.csv and without -DryRun, to enable 'Allow Blob Public Access' on Storage account(s) listed in the file."  -ForegroundColor $([Constants]::MessageType.Info)
                        return;
                    }
                    elseif (-not $SkipBackup)
                    {
                        $backupFile = "$($folderpath)\DisabledAllowBlobPublicAccess.csv"
                        Write-Host "Backing up configurations of Storage account(s)..." -ForegroundColor $([Constants]::MessageType.Info)
                        $stgWithEnableAllowBlobPublicAccess | Export-CSV -Path "$($backupFile)" -NoTypeInformation 
                        Write-Host "Configurations of Storage account(s) (having 'Allow Blob Public Access' enabled) have been backed up to $($backupFile)" -ForegroundColor $([Constants]::MessageType.Update)
                    }
                    
                    Write-Host "'Allow Blob Public Access' will be disabled for all Storage accounts." -ForegroundColor $([Constants]::MessageType.Info)

                    if (-not $Force)
                    {
                        Write-Host "Do you want to disable 'Allow Blob Public Access' for all Storage accounts? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
                        $userInput = Read-Host -Prompt "(Y|N)"

                        if($userInput -ne "Y")
                        {
                            Write-Host "'Allow Blob Public Access' will not be disabled for any Storage account. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                            exit
                        }
                    }
                    else
                    {
                        Write-Host "'Force' flag is provided. 'Allow Blob Public Access' will be disabled for all Storage accounts without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                    }
            
                    Write-Host "`n"
                    Write-Host "Disabling 'Allow Blob Public Access' on [$($totalStgWithEnableAllowBlobPublicAccess)] Storage account(s)..."
                    $stgWithEnableAllowBlobPublicAccess = $stgWithEnableAllowBlobPublicAccess | Sort-Object -Property "ResourceGroupName"
                    $stgWithEnableAllowBlobPublicAccess | ForEach-Object {
                        $item =  New-Object psobject -Property @{  
                            StorageAccountName = $_.StorageAccountName                
                            ResourceGroupName = $_.ResourceGroupName
                            ResourceId = $_.Id
                        }
                        
                        try
                        {
                            $output = Set-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName -AllowBlobPublicAccess $false -ErrorAction SilentlyContinue

                            if($output -ne $null)
                            {
                                $remediatedStorageAccounts += $item
                            }
                            else
                            {
                                $skippedStorageAccountsFromRemediation += $item
                            }
                        }
                        catch
                        {
                            $skippedStorageAccountsFromRemediation += $item
                        }
                    }

                    if(($skippedStorageAccountsFromRemediation | Measure-Object).Count -eq 0)
                    {
                        Write-Host "'Allow Blob Public Access' successfully disabled for all $($totalStgWithEnableAllowBlobPublicAccess) Storage account(s)." -ForegroundColor $([Constants]::MessageType.Update)
                    }
                    else
                    {
                        Write-Host "'Allow Blob Public Access' successfully disabled for $($($remediatedStorageAccounts | Measure-Object).Count) out of $($totalStgWithEnableAllowBlobPublicAccess) Storage account(s)." -ForegroundColor $([Constants]::MessageType.Warning)
                    }

                    Write-Host "`n"
                    if ($($remediatedStorageAccounts | Measure-Object).Count -gt 0 -or $($skippedStorageAccountsFromRemediation | Measure-Object).Count -gt 0)
                    {
                        Write-Host $([Constants]::DoubleDashLine)
                        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

                        if ($($remediatedStorageAccounts | Measure-Object).Count -gt 0)
                        {
                            Write-Host "'Allow Blob Public Access' successfully disabled for the following Storage account(s):" -ForegroundColor $([Constants]::MessageType.Update)
                            $remediatedStorageAccounts | Select-Object -Property ResourceGroupName , StorageAccountName , ResourceId | ft

                            # Write this to a file.
                            $storageAccountsRemediatedFile = "$($folderpath)\RemediatedStorageAccounts.csv"
                            $remediatedStorageAccounts | Export-CSV -Path $storageAccountsRemediatedFile -NoTypeInformation
                            Write-Host "This information has been saved to $($storageAccountsRemediatedFile)"
                            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
                        }

                        if ($($skippedStorageAccountsFromRemediation | Measure-Object).Count -gt 0)
                        {
                            Write-Host $([Constants]::SingleDashLine)
                            Write-Host "`nError disabling 'Allow Blob Public Access' for the following Storage account(s):" -ForegroundColor $([Constants]::MessageType.Error)
                            $skippedStorageAccountsFromRemediation | Select-Object -Property ResourceGroupName , StorageAccountName , ResourceId | ft
            
                            # Write this to a file.
                            $storageAccountsSkippedFile = "$($folderpath)\SkippedStorageAccountsFromRemediation.csv"
                            $skippedStorageAccountsFromRemediation | Export-CSV -Path $storageAccountsSkippedFile -NoTypeInformation
                            Write-Host "This information has been saved to $($storageAccountsSkippedFile)"
                        }
                        
                        return 
                    }
                }
                else
                {
                    Write-Host "No Storage account(s) found with enabled 'Allow Blob Public Access'." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    break
                }
            }
            catch
            {
                Write-Host "Error occurred while remediating changes. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                break
            }
        }

        "DisableAnonymousAccessOnContainers" 
        {
            Write-Host "`n"
            Write-Host "Warning: Selected remediation type will disable anonymous access for specific containers, provided in input json file." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "`n"
            Write-Host "Checking anonymous access on containers of Storage account(s)..."

            # Performing remediation
            try
            {
                $ContainersWithEnableAnonymousAccessOnStorage = @();
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
                                    # Creating objects with container name and public access type, It will help while doing rollback operation.
                                    $item =  New-Object psobject -Property @{  
                                            Name = $_.Name                
                                            PublicAccess = $_.PublicAccess
                                        }
                                    
                                    Set-AzStorageContainerAcl -Name $_.Name -Permission Off -Context $context | Out-Null
                                    $anonymousAccessContainersNameAndPublicAccess += $item 
                                }
                                catch
                                {
                                    # If not able to remove container public access due to insufficient permission or exception occurred.
                                    $flag = $false
                                    break;    
                                }
                            };
                        
                            # If successfully removed anonymous access from Storage account's containers.
                            if ($flag)
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
                                # Unable to disable containers anonymous access may be because of insufficient permission over Storage account(s) or exception occurred.
                                Write-Host "Skipping to disable anonymous access on containers of Storage account(s) due to insufficient access [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Warning);
                                $item =  New-Object psobject -Property @{
                                        SubscriptionId = $SubscriptionId  
                                        ResourceGroupName = $_.ResourceGroupName
                                        StorageAccountName = $_.StorageAccountName
                                        ResourceType = "Microsoft.Storage/storageAccounts"
                                        ResourceId = $_.id
                                    }

                                $ContainersWithEnableAnonymousAccessOnStorage += $item
                            }
                        }
                        else
                        {
                            Write-Host "There are no containers on Storage account(s) which have anonymous access enabled [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Update);
                        }
                    }
                    else
                    {
                        Write-Host "No container(s) found to disable anonymous access for Storage account(s) [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Update) ;
                    }                
                }
            }
            catch
            {
                Write-Host "Error occurred while remediating control. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                break
            }

            # Creating the log file
            if (($ContainersWithDisableAnonymousAccessOnStorage | Measure-Object).Count -gt 0)
            {               
                    Write-Host "Backing up config of Storage account(s) details for subscription: [$($SubscriptionId)] on which remediation is successfully performed. Please do not delete this file. Without this file you won't be able to rollback any changes done through remediation script." -ForegroundColor $([Constants]::MessageType.Info)
                    $ContainersWithDisableAnonymousAccessOnStorage | ConvertTo-Json -Depth 10| Out-File "$($folderPath)\ContainersWithDisableAnonymousAccess.json"
                    Write-Host "Path: $($folderPath)\ContainersWithDisableAnonymousAccess.json"
                    Write-Host $([Constants]::DoubleDashLine)
            }

            if (($ContainersWithEnableAnonymousAccessOnStorage | Measure-Object).Count -gt 0)
            {
                Write-Host "`n"
                Write-Host "Generating the log file containing details of all the Storage account(s) on which remediating script unable to disable containers with anonymous access due to error occurred or insufficient permission over Storage account(s) for subscription: [$($SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
                $ContainersWithEnableAnonymousAccessOnStorage | ConvertTo-Json -Depth 10 | Out-File "$($folderPath)\ContainersWithEnableAnonymousAccessOnStorage.json"
                Write-Host "Path: $($folderPath)\ContainersWithEnableAnonymousAccessOnStorage.json"
                Write-Host $([Constants]::DoubleDashLine)
            }
        }

        Default 
        {
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

        .PARAMETER Force
            Specifies a forceful roll back without any prompts.

        .PARAMETER FilePath
            CSV file path which containing remediation log to perform rollback operation at Storage level.

        .PARAMETER Path
            Json file path which contains remediated Storage account details to perform rollback operation at container level.
    #>
    param (
        [string]
        [Parameter(ParameterSetName = "RemediationAtStorageLevel", Mandatory = $true, HelpMessage="Enter subscription id to perform rollback operation")]
        [Parameter(ParameterSetName = "RemediationAtContainerLevel", Mandatory = $true, HelpMessage="Enter subscription id to perform rollback operation")]
        $SubscriptionId,

        [Parameter(ParameterSetName = "RemediationAtStorageLevel", Mandatory = $true, HelpMessage = "Select rollback type")]
        [Parameter(ParameterSetName = "RemediationAtContainerLevel", Mandatory = $true, HelpMessage = "Select rollback type")]
        [ValidateSet("EnableAllowBlobPublicAccessOnStorage", "EnableAnonymousAccessOnContainers")]
        [string]
		$RollBackType,

        [string]
        [Parameter(ParameterSetName = "RemediationAtContainerLevel", Mandatory = $true, HelpMessage="Json file path which contain Storage account(s) detail to remediate")]
        $Path,

        [Switch]
        [Parameter(ParameterSetName = "RemediationAtStorageLevel", Mandatory = $false, HelpMessage="Specifies a forceful roll back without any prompts")]
        $Force,

        [string]
        [Parameter(ParameterSetName = "RemediationAtStorageLevel", Mandatory = $true, HelpMessage="CSV file path which contain logs generated by remediation script to rollback remediation changes")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Starting rollback operation to enable anonymous access on containers of Storage account(s) from subscription [$($SubscriptionId)]...."
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
    
    # Check current login context.
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet))
    {       
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force

    Write-Host "Metadata Details: `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host $([Constants]::SingleDashLine) 
    Write-Host "Starting with subscription [$($SubscriptionId)]..."

    Write-Host "`n"
    Write-Host "*** To perform rollback operation for enabling anonymous access on containers user must have atleast contributor access on Storage account(s) of subscription: [$($SubscriptionId)] ***" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host "`n"
    Write-Host "Fetching remediation log to perform rollback operation on containers of Storage account(s) from subscription [$($SubscriptionId)]..."
    Write-Host "`n"

    # Array to store resource context
    $resourceContext = @()
    

    switch ($RollBackType) 
    {
        "EnableAllowBlobPublicAccessOnStorage" 
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Error: Control file path is not found." -ForegroundColor $([Constants]::MessageType.Error)
                break;        
            }
            # Fetching remediated log for 'DisableAllowBlobPublicAccessOnStorage' remediation type.
            $storageAccountDetails = Import-Csv -LiteralPath $FilePath
            $validStorageAccountDetails = $storageAccountDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.StorageAccountName) }

            $totalStorageAccounts = $(($validStorageAccountDetails | Measure-Object).Count)

            if ($totalStorageAccounts -eq 0)
            {
                Write-Host "No Storage account found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                break
            }

            Write-Host "Found $($totalStorageAccounts) Storage account(s)." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host "Performing rollback operation to enable 'Allow Blob Public Access' for Storage account(s) of subscription [$($SubscriptionId)]..."

            if (-not $Force)
            {
                Write-Host "Do you want to enable 'Allow Blob Public Access' for all Storage accounts?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
                $userInput = Read-Host -Prompt "(Y|N)"

                if($userInput -ne "Y")
                {
                    Write-Host "'Allow Blob Public Access' will not be enabled for any Storage account. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    exit
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. 'Allow Blob Public Access' will be enabled for all Storage accounts without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            }

            Write-Host "`n"
            Write-Host "Enabling 'Allow Blob Public Access' on [$($totalStorageAccounts)] Storage account(s) of subscription [$($SubscriptionId)]..."

            $rolledbackStorageAccounts = @()
            $skippedStorageAccounts = @()

            # Performing rollback operation
            $validStorageAccountDetails | ForEach-Object {
                $storageAccount = $_
                $resourceGroupName = $_.ResourceGroupName
                $storageAccountName = $_.StorageAccountName
                
                try
                {
                    $output = Set-AzStorageAccount -ResourceGroupName $resourceGroupName -StorageAccountName $storageAccountName -AllowBlobPublicAccess $true -ErrorAction SilentlyContinue
                    if($output -ne $null)
                    {
                        $rolledbackStorageAccounts = $storageAccount  
                    }
                    else
                    {
                        Write-Host "Skipping rollback due to insufficient access [StorageAccountName]: [$($storageAccountName)] [ResourceGroupName]: [$($resourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Warning)                                
                        $skippedStorageAccounts = $storageAccount
                    }
                }
                catch
                {
                    Write-Host "Skipping rollback due to insufficient access or exception occurred [StorageAccountName]: [$($storageAccountName)] [ResourceGroupName]: [$($resourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Warning)
                    $skippedStorageAccounts = $storageAccount
                }
                    
                Write-Host $([Constants]::DoubleDashLine)
            }

            if (($skippedStorageAccounts | Measure-Object).Count -eq 0)
            {
                Write-Host "'Allow Blob Public Access' successfully enabled for all $($totalStorageAccounts) Storage account(s)." -ForegroundColor $([Constants]::MessageType.Update)
            }
            else
            {
                Write-Host "'Allow Blob Public Access' successfully enabled for $($($rolledbackStorageAccounts | Measure-Object).Count) out of $($totalStorageAccounts) Storage account(s)." -ForegroundColor $([Constants]::MessageType.Warning)
            }

            if ($($rolledbackStorageAccounts | Measure-Object).Count -gt 0 -or $($skippedStorageAccounts | Measure-Object).Count -gt 0)
            {
                Write-Host $([Constants]::DoubleDashLine)
                # Back up snapshots to `%LocalApplicationData%'.
                $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($subscriptionid.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableAnonymousAccessOnContainers"

                if (-not (Test-Path -Path $backupFolderPath))
                {
                    New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
                }

                Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

                if ($($rolledbackStorageAccounts | Measure-Object).Count -gt 0)
                {
                    Write-Host "'Allow Blob Public Access' successfully enabled for the following Storage account(s):" -ForegroundColor $([Constants]::MessageType.Update)
                    $rolledbackStorageAccounts | Select-Object -Property ResourceGroupName , StorageAccountName , ResourceId | ft

                    # Write this to a file.
                    $storageAccountsRolledBackFile = "$($backupFolderPath)\RolledBackStorageAccounts.csv"
                    $rolledbackStorageAccounts | Export-CSV -Path $storageAccountsRolledBackFile -NoTypeInformation
                    Write-Host "This information has been saved to $($storageAccountsRolledBackFile)"
                }

                if ($($skippedStorageAccounts | Measure-Object).Count -gt 0)
                {
                    Write-Host "`nError enabling 'Allow Blob Public Access' for the following Storage account(s):" -ForegroundColor $([Constants]::MessageType.Error)
                    $skippedStorageAccounts | Select-Object -Property ResourceGroupName , StorageAccountName , ResourceId | ft
            
                    # Write this to a file.
                    $storageAccountsSkippedFile = "$($backupFolderPath)\SkippedStorageAccountsFromRollback.csv"
                    $skippedStorageAccounts | Export-CSV -Path $storageAccountsSkippedFile -NoTypeInformation
                    Write-Host "This information has been saved to $($storageAccountsSkippedFile)"
                }
            }
        }

        "EnableAnonymousAccessOnContainers" 
        {
            if (-not (Test-Path -Path $Path))
            {
                Write-Host "Error: Control file path is not found." -ForegroundColor $([Constants]::MessageType.Error)
                break;        
            }
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
            Write-Host "Found [$($totalResourceToRollBack)] Storage account(s) to perform rollback operation."
            Write-Host "Performing rollback operation to enable anonymous access on containers of Storage account(s) from subscription [$($SubscriptionId)]..."

            # Performing rollback
            try
            {
                if($totalResourceToRollBack -gt 0)
                {
                    $resourceContext | ForEach-Object{
                        $flag = $true
                        $context = $_.context;
                        $containerWithAnonymousAccess = @();
                        $containerWithAnonymousAccess += $_.AnonymousAccessContainer

                        # Checking 'Allow Blob Public Access' is enabled or not at storage level. If found enabled then we can rollback access otherwise not permitted.
                        if (($null -eq $_.AllowBlobPublicAccess) -or $_.AllowBlobPublicAccess)
                        {
                            if (($containerWithAnonymousAccess | Measure-Object).Count -gt 0)
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

                                if ($flag)
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
                            Write-Host "Public access is not permitted on this Storage account [StorageAccountName]: [$($_.StorageAccountName)] [ResourceGroupName]: [$($_.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Warning);
                        }
                    }

                    Write-Host $([Constants]::DoubleDashLine)
                }
                else
                {
                    Write-Host "Unable to fetch Storage account." -ForegroundColor $([Constants]::MessageType.Error);
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
