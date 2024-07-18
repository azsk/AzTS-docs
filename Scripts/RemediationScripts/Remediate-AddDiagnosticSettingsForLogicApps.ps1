<###
# Overview:
    This script is used to enable Dignostic setting for Azure Logic App resources in a subscription.

# Control ID:
    Azure_LogicApps_Audit_Enable_Diagnostic_Settings

# Display Name:
    Enable Security Logging in Azure Logic Apps

# Prerequisites:
    Contributor and higher privileges on the Logic Apps in a Subscription.
    

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of Logic Apps in a Subscription that do not have required Diagnostic settings configured.
        3. Add required Diagnostic settings for Logic Apps in a subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. 
        3. Execute the script to Add required Diagnostic settings for Logic Apps in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Logic Apps in a Subscription that will be remediated:

           Add-DiagnosticSettingsForLogicApps -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        2. To add required Diagnostic settings for Logic Apps in a subscription:

           Add-DiagnosticSettingsForLogicApps -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000

        3. To add required Diagnostic settings for Logic Apps in a subscription, from a previously taken snapshot:

           Add-DiagnosticSettingsForLogicApps -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\AddDiagnosticSettingsForLogicApps\LogicAppsWithoutDiagnosticSetting.csv

        To know more about the options supported by the remediation command, execute:

        Get-Help Add-DiagnosticSettingsForLogicApps -Detailed

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
    $requiredModules = @("Az.Storage", "Az.Resources")

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

function Add-DiagnosticSettingsForLogicApps
{
    <#
        .SYNOPSIS
        Remediates 'Azure_LogicApps_Audit_Enable_Diagnostic_Settings' Control.

        .DESCRIPTION
        Add DiagnosticSettings for LogicApps

        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .EXAMPLE
        PS> Add-DiagnosticSettingsForLogicApps -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Add-DiagnosticSettingsForLogicApps -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Add-DiagnosticSettingsForLogicApps -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\AddDiagnosticSettingsForLogicApps\LogicAppsWithoutDiagnosticSetting.csv
        
        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", HelpMessage="Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies a dry run of the actual remediation")]
        $DryRun,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Preparing to add diagnostic settings for Logic Apps in Subscription: $($SubscriptionId)"

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
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: $($context.Subscription.Name)"
    Write-Host "Subscription ID: $($context.Subscription.SubscriptionId)"
    Write-Host "Account Name: $($context.Account.Id)"
    Write-Host "Account Type: $($context.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if $($context.Account.Id) is allowed to run this script..."

    # # Checking if the current account type is "User"
    # if ($context.Account.Type -ne "User")
    # {
    #     Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of $($context.Account.Id) is: $($context.Account.Type)" -ForegroundColor $([Constants]::MessageType.Warning)
    #     break
    # }

    Write-Host "*** To add diagnostic seeting for Logic Apps in a Subscription, Contributor and higher privileges on thr Resource Groups containing Logic Apps in the Subscription is required. ***" -ForegroundColor $([Constants]::MessageType.Info)
    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Logic Apps..."

    $logicAppResources = @()

    # No file path provided as input to the script. Fetch all Logic Apps in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Logic Apps in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all Logic Apps in a Subscription.
        $logicApps = Get-AzResource -ResourceType "Microsoft.Logic/workflows" -ErrorAction Stop -ResourceGroupName "v-abbhanTestRG"
        
        $logicAppResources += $logicApps | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                     @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                     @{N='Name';E={$_.ResourceName}},
                                                                     @{N='ResourceType';E={$_.ResourceType}},
                                                                     @{N='Location';E={$_.Location}}
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all Logic Apps from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

        # Importing the list of Logic Apps to be remediated.
        $logicAppDetails = Import-Csv -LiteralPath $FilePath

        $logicAppResources = $logicAppDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
    }

    $totalLogicApps = $logicAppResources.Count

    if ($totalLogicApps -eq 0)
    {
        Write-Host "No Logic Apps found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalLogicApps) Logic Apps." -ForegroundColor $([Constants]::MessageType.Update)

    # Includes Logic Apps where required diagnostic settings are present.
    $logicAppsWithRequiredDiagnosticSetting = @()

    # Includes Logic Apps where required diagnostic settings are not present.
    $logicAppsWithoutRequiredDiagnosticSetting = @()

  # Check if required Diagnostic setting for Logic App is present

    $logicAppResources | ForEach-Object {
        try
        {
            Write-Host "Fetching diagnostic settings for Resource ID - $($_.ResourceId)"

            $settings= Get-AzDiagnosticSetting -ResourceId $_.ResourceId
            
            if ($null -eq $settings)
            {
                # No diagnostic setting is configured
                $logicAppsWithoutRequiredDiagnosticSetting += $_
            }
            #TODO: Add CategoryGroup Based check 
            else{
                if(($settings.Log|Where-Object {$_.Category -eq "WorkflowRuntime" -and $_.Enabled -eq "True"}|Measure-Object).Count -gt 0 ){
                    $logicAppsWithRequiredDiagnosticSetting += $_
                }
                else{
                    $logicAppsWithoutRequiredDiagnosticSetting += $_
                }
            }
        }
        catch
        {
            $logicAppsWithoutRequiredDiagnosticSetting += $_ 

            Write-Host "Error fetching diagnostic setting for Resource ID - $($_.ResourceId), Resource Group Name - $($_.ResourceGroupName), Resource Name - $($_.ServerName). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

    $totalLogicAppsWithoutRequiredDiagnosticSetting = ($logicAppsWithoutRequiredDiagnosticSetting | Measure-Object).Count

    if ($totalLogicAppsWithoutRequiredDiagnosticSetting -eq 0)
    {
        Write-Host "No Logic App found without required diagnostic setting. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalLogicAppsWithoutRequiredDiagnosticSetting) Logic Apps without required diagnostic setting." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\AddDiagnosticSettingForLogicApps"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    # Backing up Logic App details.
    $backupFile = "$($backupFolderPath)\LogicAppsWithoutRequiredDiagnosticSetting.csv"
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up Logic App details to $($backupFile)"

    $logicAppsWithoutRequiredDiagnosticSetting | Export-CSV -Path $backupFile -NoTypeInformation

    if (-not $DryRun)
    {
        Write-Host "*** There will be billing cost associated with adding Diagnostic Setting for Logic Apps. ***" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "*** In each resource group having Logic App resources, new Storage Accounts will be created to store diagnostic settings related data. ***" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Do you still want to proceed?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y")
        {
            Write-Host "Diagnostic setting will not be added to any Logic App. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Adding Diagnostic setting for Logic Apps..." -ForegroundColor $([Constants]::MessageType.Warning)

        # To hold results from the remediation.
        $remediatedLogicApps = @()

        # Includes Logic Apps that were skipped during remediation due to any errors.
        $skippedLogicApps = @()

        #Write-Host "Checking if Auditing and Advanced Threat Protection are configured for the individual SQL servers." -ForegroundColor $([Constants]::MessageType.Info)

        # Storage Account details
        [String] $storageAccountResourceGroupName = [String]::Empty
        [String] $storageAccountName = [String]::Empty
        $storageAccount = $null
        #$isStorageAccountPreferenceDecided = $false
        
        Write-Host "Adding diagnostic settng requires one or more of Storage Account, Log Analytics Workspace or Event Hub to be configured for storing diagnostic logs." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "*** This script supports only Storage Accounts as a destination for storing the diagnostic logs. ***" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Storage Accounts will be created per Resource Group and Location combination to store the diagnostic logs of all Logic Apps in the Resource Group" -ForegroundColor $([Constants]::MessageType.Info) 
        Write-Host "Do you still want to proceed?" -ForegroundColor $([Constants]::MessageType.Info) -NoNewline

        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y")
        {
            #Write-Host "If you prefer a different destination for storing the diagnostic logs, please configure them using Azure " -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host "Exiting as Storage Account is not chosen for storing the diagnostic logs..." -ForegroundColor $([Constants]::MessageType.Update)
            break
        }

        # Check Auditing and ATP settings at the SQL Server level.
        $logicAppsWithoutRequiredDiagnosticSetting  | ForEach-Object {
            Write-Host "Checking Logic App Resource ID: $($_.ResourceId)" -ForegroundColor $([Constants]::MessageType.Info)

            try
            {
                $logicAppInstance = $_

                $resourceGroup = $_.ResourceGroupName
                $location = $_.Location
                $storageAccountResourceGroupName= $ResourceGroup
                $storageAccountName = "diagn"
                 # Storage Account name will be a concatenation of "diaglogs" + name of the RG + Location.
                 # Only the first 5 characters of the Resource Group name and location will be considered, as there is a size limit of 20 characters for the name of a Storage Account.
                 # This will strip out non-alphanumeric characters as Storage Account names can only contain alphanumeric characters.
                 $storageAccountRGNameSuffix = $resourceGroup -replace "\W"
                 $storageAccountLocationSuffix = $location -replace "\W"

                        # This check is required, else, String::Substring() will throw an error for strings less than 15 characters.

                        if ($storageAccountLocationSuffix.Length -gt 15)
                        {
                            $storageAccountLocationSuffix = $storageAccountLocationSuffix.Substring(0, 15)
                        }

                        $storageAccountName = -join("diagn", $storageAccountLocationSuffix.ToLower() )

                        Write-Host "Creating a Storage Account for Resource Group: $($resourceGroup) and Location: $($location)"

                        $storageAccount = Create-StorageAccountIfNotExists $storageAccountResourceGroupName $storageAccountName $location

                            if (($storageAccount | Measure-Object).Count -ne 0)
                            {
                                Write-Host "Storage Account to store diagnostic logs already present or successfully created." -ForegroundColor $([Constants]::MessageType.Update)
                            }
                            else
                            {
                                Write-Host "Error creating a Storage Account to store the diagnostic logs." -ForegroundColor $([Constants]::MessageType.Error)
                                Write-Host "Please ensure that you have sufficient permissions to create a Storage Account in this Resource Group." -ForegroundColor $([Constants]::MessageType.Error)
                                Write-Host "Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                                break
                            }
                    #}


                    Write-Host "Adding diagnostic settings for Logic App: $($_.Name)"

                    $log = @()
                    $log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs
                    New-AzDiagnosticSetting -Name 'LogicApp-DiagnosticSetting' -ResourceId $_.ResourceId -Log $log -StorageAccountId $storageAccount.Id  

                    
                    $isDiagnosticSettingAdded= $true 

                    if ($isDiagnosticSettingAdded)
                    {
                        Write-Host "Diagnostic setting is successfully added for Logic App: $($_.Name)"
                    }
                    else
                    {
                        Write-Host "Error adding diagnostic setting for Logic App: $($__.Name)"
                    }
                

                if ($isDiagnosticSettingAdded -eq $true)
                {
                    $remediatedLogicApps += $logicAppInstance 
                }
                else
                {
                    $skippedLogicApps += $logicAppInstance 
                }
            }
            catch
            {
                $skippedLogicApps += $logicAppInstance
                Write-Host "Error adding diagnostic setting for Logic App. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this SQL Logic App. Diagnostic setting will not be added." -ForegroundColor $([Constants]::MessageType.Warning)
                return
            }
        }

        $colsProperty = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.Name};Label="Resource Name";Width=20;Alignment="left"}

        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

        if ($($remediatedLogicApps | Measure-Object).Count -gt 0)
        {
            Write-Host "Diagnostic setting added successfully for the following Logic Apps" -ForegroundColor $([Constants]::MessageType.Update)
            $remediatedLogicApps | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $remediatedLogicAppsFile = "$($backupFolderPath)\remediatedLogicApps.csv"
            $remediatedLogicApps | Export-CSV -Path $remediatedLogicAppsFile -NoTypeInformation
            Write-Host "This information has been saved to $($remediatedLogicAppsFile)"
        }

        if ($($skippedLogicApps | Measure-Object).Count -gt 0)
        {
            Write-Host "Error adding diagnostic setting for the following Logic Apps:" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedLogicApps | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $skippedLogicAppsFile = "$($backupFolderPath)\SkippedLogicApps.csv"
            $skippedLogicApps | Export-CSV -Path $skippedLogicAppsFile -NoTypeInformation
            Write-Host "This information has been saved to $($skippedLogicAppsFile)"
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Logic App details have been backed up to $($backupFile). Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`nRun the same command with -FilePath $($backupFile) and without -DryRun, to add diagnostic setting for all Logic Apps listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "`n*** It is recommended to keep this file and use it for any subsequent roll back post the remediation. ***" -ForegroundColor $([Constants]::MessageType.Info)
    }
}

function Check-HasRolesInScope
{
    <#
        .SYNOPSIS
        Checks if a sign-in address has any of the specified roles at the given scope.

        .DESCRIPTION
        Checks if a sign-in address has any of the specified roles at the given scope.

        .PARAMETER AccountId
        Specifies the sign-in address, the roles associated with which are to be evaluated.

        .PARAMETER Scope
        Specifies the scope that needs to be evaluated against.

        .Parameter RoleDefinitionNames
        Specifies the list of roles that need to be evaluated against.

        .INPUTS
        None. You cannot pipe objects to Check-HasRolesInScope.

        .OUTPUTS
        System.Boolean. Check-HasRolesInScope returns True, if the sign-in address has any of the specified roles at the given scope. False, otherwise.

        .EXAMPLE
        PS> Check-HasRolesInScope -AccountId "abc@xyz.com" -Scope "/subscriptions/00000000-xxxx-0000-xxxx-000000000000" -RoleDefinitionNames "Contributor", "Owner", "User Access Administrator"

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the sign-in address, the roles associated with which are to be evaluated.")]
        $AccountId,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the scope that needs to be evaluated against.")]
        $Scope,

        [String[]]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the list of roles that need to be evaluated against.")]
        $RoleDefinitionNames
    )

    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $AccountId -Scope $Scope -ErrorAction Continue

    return (($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -in $RoleDefinitionNames } | Measure-Object).Count -gt 0)
}

function Create-StorageAccountIfNotExists
{
    <#
        .SYNOPSIS
        Check and create a Storage Account if it does not exist.

        .DESCRIPTION
        Check and create a Storage Account if it does not exist.

        .PARAMETER ResourceGroupName
        Specifies the name of the Resource Group where the Storage Account needs to be created.

        .PARAMETER StorageAccountName
        Specifies the name of the Storage Account to be created.

        .PARAMETER Location
        Specifies the location of the Storage Account to be created.

        .INPUTS
        None. You cannot pipe objects to Create-StorageAccountIfNotExists.

        .OUTPUTS
        Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount.
        Create-StorageAccountIfNotExists checks if a Storage Account is present and returns the same. If not, creates and returns the newly created Storage Account instance.

        .EXAMPLE
        PS> Create-StorageAccountIfNotExists -ResourceGroupName "RGName" -StorageAccountName "storageaccountname"

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the name of the Resource Group where the Storage Account needs to be created.")]
        $ResourceGroupName,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the name of the Storage Account that needs to be created.")]
        $StorageAccountName,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the location of the Storage Account that needs to be created.")]
        $Location
    )

    Write-Host "Checking if Storage Account - $($StorageAccountName) is present in Resource Group - $($ResourceGroupName)..."

    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Continue

    if (($storageAccount | Measure-Object).Count -eq 0)
    {
        Write-Host "Storage Account does not exist. Creating a new Storage Account with the specified information..." -ForegroundColor $([Constants]::MessageType.Warning)
        $storageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -SkuName Standard_LRS -Location $Location -ErrorAction Continue
        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -EnableHttpsTrafficOnly true -AllowBlobPublicAccess false -MinimumTlsVersion TLS1_2 -AllowSharedKeyAccess false   
    }

    return $storageAccount
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

class StorageAcc {
    [string]$Id
    [string]$rgname
    [string]$location
}
