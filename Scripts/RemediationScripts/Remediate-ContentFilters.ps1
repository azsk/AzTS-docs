function Setup-Prerequisites 
{
    <#
    .SYNOPSIS
    This command would check pre requisites modules.
    
    .DESCRIPTION
    This command would check pre requisites modules to perform remediation.
    #>

    $requiredModules = @("Az.Resources", "Az.Accounts")
    
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
}

# Global list of exempted models that should be skipped during processing
$script:exemptedModels = @("tts", "tts-hd", "whisper")

# Global dictionary mapping parameter names to filter categories and sources
# This dictionary is used to evaluate content filter configurations based on user input parameters
# Based on Azure AI Foundry and OpenAI content filter controls (28 controls total)
$script:filterConfigMapping = @{
    # Azure AI Foundry - Output/Completion Filters
    "Azure_AIFoundry_SI_Apply_Sexual_Output_Content_Filter" = @{ FilterCategory = "Sexual"; FilterSource = "Completion"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_AIFoundry_SI_Apply_Violence_Output_Content_Filter" = @{ FilterCategory = "Violence"; FilterSource = "Completion"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_AIFoundry_SI_Apply_Hate_Output_Content_Filter" = @{ FilterCategory = "Hate"; FilterSource = "Completion"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_AIFoundry_SI_Apply_Selfharm_Output_Content_Filter" = @{ FilterCategory = "Selfharm"; FilterSource = "Completion"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    
    # Azure AI Foundry - Input/Prompt Filters
    "Azure_AIFoundry_SI_Apply_Violence_Input_Content_Filter" = @{ FilterCategory = "Violence"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_AIFoundry_SI_Apply_Hate_Input_Content_Filter" = @{ FilterCategory = "Hate"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_AIFoundry_SI_Apply_Sexual_Input_Content_Filter" = @{ FilterCategory = "Sexual"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_AIFoundry_SI_Apply_Selfharm_Input_Content_Filter" = @{ FilterCategory = "Selfharm"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }

    # Azure AI Foundry - Special Input Filters
    "Azure_AIFoundry_SI_Annotate_And_Block_Jailbreak_Input_Content_Filter" = @{ FilterCategory = "Jailbreak"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("NotApplicable") }
    "Azure_AIFoundry_SI_Annotate_And_Block_Indirect_Attack_Input_Content_Filter" = @{ FilterCategory = "Indirect Attack"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("NotApplicable") }
    
    # Azure AI Foundry - Protected Material and Ungrounded Filters
    "Azure_AIFoundry_SI_Annotate_Known_Text_Content" = @{ FilterCategory = "Protected Material Text"; FilterSource = "Completion"; Action = "Annotate only"; ReqThresholdLevels = @("NotApplicable") }
    "Azure_AIFoundry_SI_Annotate_Known_Code_Content" = @{ FilterCategory = "Protected Material Code"; FilterSource = "Completion"; Action = "Annotate only"; ReqThresholdLevels = @("NotApplicable") }
    "Azure_AIFoundry_SI_Annotate_Ungrounded_Output" = @{ FilterCategory = "Ungrounded Material"; FilterSource = "Completion"; Action = "Annotate only"; ReqThresholdLevels = @("NotApplicable") }
    
    # Azure OpenAI - Output/Completion Filters
    "Azure_OpenAI_SI_Apply_Violence_Output_Content_Filter" = @{ FilterCategory = "Violence"; FilterSource = "Completion"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_OpenAI_SI_Apply_Hate_Output_Content_Filter" = @{ FilterCategory = "Hate"; FilterSource = "Completion"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_OpenAI_SI_Apply_Sexual_Output_Content_Filter" = @{ FilterCategory = "Sexual"; FilterSource = "Completion"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_OpenAI_SI_Apply_Selfharm_Output_Content_Filter" = @{ FilterCategory = "Selfharm"; FilterSource = "Completion"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }

    # Azure OpenAI - Input/Prompt Filters
    "Azure_OpenAI_SI_Apply_Violence_Input_Content_Filter" = @{ FilterCategory = "Violence"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_OpenAI_SI_Apply_Hate_Input_Content_Filter" = @{ FilterCategory = "Hate"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_OpenAI_SI_Apply_Sexual_Input_Content_Filter" = @{ FilterCategory = "Sexual"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    "Azure_OpenAI_SI_Apply_Selfharm_Input_Content_Filter" = @{ FilterCategory = "Selfharm"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("Medium", "Low") }
    
    # Azure OpenAI - Special Input Filters
    "Azure_OpenAI_SI_Annotate_And_Block_Jailbreak_Input_Content_Filter" = @{ FilterCategory = "Jailbreak"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("NotApplicable") }
    "Azure_OpenAI_SI_Annotate_And_Block_Indirect_Attack_Input_Content_Filter" = @{ FilterCategory = "Indirect Attack"; FilterSource = "Prompt"; Action = "Annotate and block"; ReqThresholdLevels = @("NotApplicable") }
    
    # Azure OpenAI - Protected Material and Ungrounded Filters
    "Azure_OpenAI_SI_Annotate_Known_Text_Content" = @{ FilterCategory = "Protected Material Text"; FilterSource = "Completion"; Action = "Annotate only"; ReqThresholdLevels = @("NotApplicable") }
    "Azure_OpenAI_SI_Annotate_Known_Code_Content" = @{ FilterCategory = "Protected Material Code"; FilterSource = "Completion"; Action = "Annotate only"; ReqThresholdLevels = @("NotApplicable") }
    "Azure_OpenAI_SI_Annotate_Ungrounded_Output" = @{ FilterCategory = "Ungrounded Material"; FilterSource = "Completion"; Action = "Annotate only"; ReqThresholdLevels = @("NotApplicable") }
    
    # Azure OpenAI - Profanity Blocklist Filters
    "Azure_OpenAI_SI_Apply_Profanity_Blocklist_Output_Content_Filter" = @{ FilterCategory = "Profanity"; FilterSource = "Completion"; Action = "Annotate only"; ReqThresholdLevels = @("NotApplicable") }
    "Azure_OpenAI_SI_Apply_Profanity_Blocklist_Input_Content_Filter" = @{ FilterCategory = "Profanity"; FilterSource = "Prompt"; Action = "Annotate only"; ReqThresholdLevels = @("NotApplicable") }
}

function Fetch-API 
{
    param (
        [Parameter(Mandatory = $true)]
        [string]$Method,
        
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Body = @{},
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Headers = @{}
    )

    $cloudEnvironmentResourceManagerUrl = (Get-AzContext).Environment.ResourceManagerUrl
    $accessToken = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl -AsSecureString
    $credential = New-Object System.Net.NetworkCredential("", $accessToken.Token)
    $token = $credential.Password
    $authHeader = "Bearer " + $token
    $Headers["Authorization"] = $authHeader
    $Headers["Content-Type"] = "application/json"

    try {
        switch ($Method.ToUpper()) {
            "GET" {
                $response = Invoke-WebRequest -Uri $Uri -Method Get -Headers $Headers -UseBasicParsing -ErrorAction Stop
            }
            "PUT" {
                $jsonBody = $Body | ConvertTo-Json -Depth 10
                $response = Invoke-WebRequest -Uri $Uri -Method PUT -Headers $Headers -Body $jsonBody -UseBasicParsing -ErrorAction Stop
            }
            default {
                throw "Unsupported HTTP method: $Method"
            }
        }

        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201 -or $response.StatusCode -eq 202) {
            return $response.Content | ConvertFrom-Json
        }
        else {
            throw "API call failed with status code $($response.StatusCode)"
        }
    }
    catch {
        Write-Error "Error occurred: $_"
        throw $_
    }
}

function Validate-UserPermissions 
{
    <#
    .SYNOPSIS
    This command would check if user has required permissions.
    .DESCRIPTION
    This command would check if user has required permissions to perform remediation.
    #>
    param (
        [Parameter(Mandatory = $true)] [object] $context,
        [Parameter(Mandatory = $true)] [string] $SubscriptionId
    )

    Write-Host "Validating whether the current user [$($context.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."

    # Safe Check: Checking whether the current account is of type User
    if ($context.Account.Type -ine "User") {
        Write-Host "Error: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Error)
        return $false
    }
    else {
        Write-Host "User permission validation completed"
    }

    # Safe Check: Current user needs to be either Contributor or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)";
    $roles = $currentLoginRoleAssignments | Where-Object { 
        ($_.RoleDefinitionName -ieq "Owner" -or $_.RoleDefinitionName -ieq "Contributor") -and !($_.Scope -like "/subscriptions/$($SubscriptionId)/resourceGroups")
    }

    if (($roles | Measure-Object).Count -le 0) {
        Write-Host "Error: This script can only be run by Owner or Contributor of the subscription [$($SubscriptionId)] " -ForegroundColor $([Constants]::MessageType.Error)
        return $false
    }

    return $true
}

function Remediate-ContentFilters
{
    <#
    .SYNOPSIS
    Updates the RAI policy for a deployment to make it compliant.
    
    .DESCRIPTION
    This function makes an ARM API PUT call to update the RAI policy with corrected content filters.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$AccountName,
        
        [Parameter(Mandatory = $true)]
        [string]$RaiPolicyName,
        
        [Parameter(Mandatory = $true)]
        [object]$UpdatedRaiPolicy
    )
    
    try 
    {
        # Build the ARM API URI for updating the RAI policy
        $raiPolicyUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.CognitiveServices/accounts/$AccountName/raiPolicies/$RaiPolicyName`?api-version=2024-10-01"
        
        Write-Host "      Updating RAI policy [$($RaiPolicyName)] via ARM API..." -ForegroundColor $([Constants]::MessageType.Info)
        
        # Prepare the PUT request body
        $updateBody = @{
            properties = $UpdatedRaiPolicy.properties
        }
        
        # Make the PUT call to update the RAI policy
        $updateResponse = Fetch-API -Method "PUT" -Uri $raiPolicyUri -Body $updateBody
        
        if ($null -ne $updateResponse) {
            Write-Host "      Successfully updated RAI policy: [$($RaiPolicyName)]" -ForegroundColor $([Constants]::MessageType.Update)
            return $true
        }
        else {
            Write-Host "      Error: Failed to update RAI policy." -ForegroundColor $([Constants]::MessageType.Error)
            return $false
        }
    }
    catch {
        Write-Host "      Error occurred during remediation: $_" -ForegroundColor $([Constants]::MessageType.Error)
        return $false
    }
}

function Backup-RAIPolicyConfigurations
{
    <#
    .SYNOPSIS
    Backs up original RAI policy configurations to a CSV file before remediation.
    
    .DESCRIPTION
    This function exports all content filter configurations for non-compliant resources to a CSV file.
    The backup file can be used to revert changes if needed.
    
    .PARAMETER SubscriptionId
    The subscription ID
    
    .PARAMETER NonCompliantResources
    Array of non-compliant resources to backup
    
    .OUTPUTS
    Returns the backup file path if successful, $null if failed
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [array]$NonCompliantResources
    )
    
    try {
        $timestamp = Get-Date -Format "yyyyMMddhhmm"
        $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($SubscriptionId.replace('-','_'))\$($timestamp)\ContentFilters"
        
        if (-not (Test-Path -Path $backupFolderPath)) {
            New-Item -ItemType Directory -Path $backupFolderPath -Force | Out-Null
        }
        
        $backupFileName = "RAIPolicyBackup.csv"
        $backupFilePath = Join-Path -Path $backupFolderPath -ChildPath $backupFileName
        
        Write-Host "Creating backup file: [$($backupFilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
        
        $backupData = @()
        
        foreach ($nonCompliantResource in $NonCompliantResources) {
            $raiPolicy = $nonCompliantResource.RaiPolicyObject
            
            if ($null -eq $raiPolicy -or $null -eq $raiPolicy.properties -or $null -eq $raiPolicy.properties.contentFilters) {
                Write-Host "Warning: Invalid RAI policy object for deployment [$($nonCompliantResource.DeploymentName)]" -ForegroundColor $([Constants]::MessageType.Warning)
                continue
            }
            
            $contentFilters = $raiPolicy.properties.contentFilters
            
            foreach ($filter in $contentFilters) {
                $backupData += [PSCustomObject]@{
                    SubscriptionId = $SubscriptionId
                    ResourceGroupName = $nonCompliantResource.ResourceGroupName
                    AccountName = $nonCompliantResource.AccountName
                    DeploymentName = $nonCompliantResource.DeploymentName
                    ModelName = $nonCompliantResource.ModelName
                    RaiPolicyName = $nonCompliantResource.RaiPolicyName
                    FilterName = $filter.name
                    FilterSource = $filter.source
                    Enabled = $filter.enabled
                    Blocking = $filter.blocking
                    SeverityLevel = $filter.severityThreshold
                    AllowedContentTypes = if ($null -ne $filter.allowedContentTypes) { ($filter.allowedContentTypes -join ';') } else { '' }
                    BackupTimestamp = $timestamp
                }
            }
        }
        
        if ($backupData.Count -eq 0) {
            Write-Host "Error: No data to backup. Cannot proceed with remediation." -ForegroundColor $([Constants]::MessageType.Error)
            return $null
        }
        
        $backupData | Export-Csv -Path $backupFilePath -NoTypeInformation -Encoding UTF8
        
        if (Test-Path -Path $backupFilePath) {
            Write-Host "Successfully backed up original RAI policy configurations to: [$($backupFilePath)]" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host "Total filters backed up: [$($backupData.Count)]" -ForegroundColor $([Constants]::MessageType.Info)
            return $backupFilePath
        }
        else {
            Write-Host "Error: Backup file was not created successfully." -ForegroundColor $([Constants]::MessageType.Error)
            return $null
        }
    }
    catch {
        Write-Host "Error occurred while backing up RAI policy data: $_" -ForegroundColor $([Constants]::MessageType.Error)
        return $null
    }
}

function Rollback-ContentFilters
{
    <#
    .SYNOPSIS
    Rolls back RAI policy configurations to their original state using a backup CSV file.
    
    .DESCRIPTION
    This function reads a backup CSV file created by Backup-RAIPolicyConfigurations and restores
    the original content filter configurations for all RAI policies listed in the backup.
    
    .PARAMETER BackupFilePath
    The full path to the backup CSV file containing original RAI policy configurations
    
    .EXAMPLE
    Rollback-ContentFilters -BackupFilePath "C:\Backups\RAIPolicyBackup.csv"
    #>
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Enter the full path to the backup CSV file")]
        [string]$BackupFilePath
    )
    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Starting RAI Policy Rollback Process" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    
    # Validate backup file exists
    if (-not (Test-Path -Path $BackupFilePath)) {
        Write-Host "Error: Backup file not found at path: [$($BackupFilePath)]" -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }
    
    Write-Host "Reading backup file: [$($BackupFilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    
    try {
        $backupData = Import-Csv -Path $BackupFilePath -ErrorAction Stop
        
        if ($null -eq $backupData -or $backupData.Count -eq 0) {
            Write-Host "Error: Backup file is empty or invalid." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        
        Write-Host "Successfully loaded [$($backupData.Count)] filter configurations from backup." -ForegroundColor $([Constants]::MessageType.Update)
    }
    catch {
        Write-Host "Error: Failed to read backup file. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }
    
    # Extract unique subscription ID from backup data
    $subscriptionId = ($backupData | Select-Object -First 1).SubscriptionId
    
    if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
        Write-Host "Error: Could not determine Subscription ID from backup file." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }
    
    Write-Host "Subscription ID: [$($subscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
    
    # Connect to Azure account
    $context = Get-AzContext
    
    if ([String]::IsNullOrWhiteSpace($context)) {
        Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
        Connect-AzAccount -Subscription $subscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }
    
    # Set context to the subscription
    $context = Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop
    Write-Host "Context set to subscription: [$($context.Subscription.Name)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    
    # Group backup data by RAI policy (SubscriptionId + ResourceGroupName + AccountName + RaiPolicyName)
    $groupedByRaiPolicy = $backupData | Group-Object -Property @{Expression={
        "$($_.SubscriptionId)|$($_.ResourceGroupName)|$($_.AccountName)|$($_.RaiPolicyName)"
    }}
    
    $totalPolicies = $groupedByRaiPolicy.Count
    Write-Host "Found [$($totalPolicies)] unique RAI policies to rollback." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    
    $successfulRollbacks = 0
    $failedRollbacks = 0
    $policyCount = 0
    
    foreach ($policyGroup in $groupedByRaiPolicy) {
        $policyCount++
        
        # Parse the group key
        $keyParts = $policyGroup.Name -split '\|'
        $subId = $keyParts[0]
        $resourceGroupName = $keyParts[1]
        $accountName = $keyParts[2]
        $raiPolicyName = $keyParts[3]
        
        Write-Host "[$($policyCount)/$($totalPolicies)] Rolling back RAI policy: [$($raiPolicyName)]" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "  Account: [$($accountName)] | Resource Group: [$($resourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Info)
        
        try {
            # Fetch current RAI policy
            $raiPolicyUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$resourceGroupName/providers/Microsoft.CognitiveServices/accounts/$accountName/raiPolicies/$raiPolicyName`?api-version=2024-10-01"
            
            Write-Host "  Fetching current RAI policy..." -ForegroundColor $([Constants]::MessageType.Info)
            $currentRaiPolicy = Fetch-API -Method "GET" -Uri $raiPolicyUri
            
            if ($null -eq $currentRaiPolicy) {
                Write-Host "  Error: Failed to fetch current RAI policy." -ForegroundColor $([Constants]::MessageType.Error)
                $failedRollbacks++
                continue
            }
            
            # Reconstruct content filters from backup data
            $restoredContentFilters = @()
            
            foreach ($backupFilter in $policyGroup.Group) {
                $filterObj = @{
                    name = $backupFilter.FilterName
                    source = $backupFilter.FilterSource
                    enabled = [System.Convert]::ToBoolean($backupFilter.Enabled)
                    blocking = [System.Convert]::ToBoolean($backupFilter.Blocking)
                }
                
                # Add severity level if it exists and is not empty
                if (-not [string]::IsNullOrWhiteSpace($backupFilter.SeverityLevel)) {
                    $filterObj.severityThreshold = $backupFilter.SeverityLevel
                }
                
                # Add allowed content types if they exist
                if (-not [string]::IsNullOrWhiteSpace($backupFilter.AllowedContentTypes)) {
                    $filterObj.allowedContentTypes = $backupFilter.AllowedContentTypes -split ';'
                }
                
                $restoredContentFilters += $filterObj
            }
            
            Write-Host "  Restored [$($restoredContentFilters.Count)] filters from backup." -ForegroundColor $([Constants]::MessageType.Info)
            
            # Update RAI policy with restored filters
            $currentRaiPolicy.properties.contentFilters = $restoredContentFilters
            
            $updateBody = @{
                properties = $currentRaiPolicy.properties
            }
            
            Write-Host "  Updating RAI policy with restored configurations..." -ForegroundColor $([Constants]::MessageType.Info)
            $updateResponse = Fetch-API -Method "PUT" -Uri $raiPolicyUri -Body $updateBody
            
            if ($null -ne $updateResponse) {
                Write-Host "  Successfully rolled back RAI policy: [$($raiPolicyName)]" -ForegroundColor $([Constants]::MessageType.Update)
                $successfulRollbacks++
            }
            else {
                Write-Host "  Error: Failed to update RAI policy." -ForegroundColor $([Constants]::MessageType.Error)
                $failedRollbacks++
            }
        }
        catch {
            Write-Host "  Error occurred during rollback: $_" -ForegroundColor $([Constants]::MessageType.Error)
            $failedRollbacks++
        }
        
        Write-Host ""
    }
    
    # Rollback Summary
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Rollback Summary" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Total RAI Policies: [$($totalPolicies)]" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Successfully Rolled Back: [$($successfulRollbacks)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "Failed Rollbacks: [$($failedRollbacks)]" -ForegroundColor $(if($failedRollbacks -gt 0) {[Constants]::MessageType.Error} else {[Constants]::MessageType.Update})
    Write-Host $([Constants]::DoubleDashLine)
}



class Constants 
{
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

function Enable-ContentFilters
{
    param (
        [string]
        [Parameter(ParameterSetName = "EnableSelected",Mandatory = $true, HelpMessage = "Enter subscription id for remediation")]
        [Parameter(ParameterSetName = "EnableAll", Mandatory = $true, HelpMessage = "Enter subscription id for remediation")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "EnableAll", HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies a forceful remediation without any prompts")]
        [Parameter(ParameterSetName = "EnableAll", HelpMessage = "Specifies validation of prerequisites for the command")]
        $Force,

        # Azure AI Foundry - Output Filters
        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Sexual Output Content Filter for AI Foundry")]
        $Azure_AIFoundry_SI_Apply_Sexual_Output_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Violence Output Content Filter for AI Foundry")]
        $Azure_AIFoundry_SI_Apply_Violence_Output_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Hate Output Content Filter for AI Foundry")]
        $Azure_AIFoundry_SI_Apply_Hate_Output_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Selfharm Output Content Filter for AI Foundry")]
        $Azure_AIFoundry_SI_Apply_Selfharm_Output_Content_Filter,

        # Azure AI Foundry - Input Filters
        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Violence Input Content Filter for AI Foundry")]
        $Azure_AIFoundry_SI_Apply_Violence_Input_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Hate Input Content Filter for AI Foundry")]
        $Azure_AIFoundry_SI_Apply_Hate_Input_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Sexual Input Content Filter for AI Foundry")]
        $Azure_AIFoundry_SI_Apply_Sexual_Input_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Selfharm Input Content Filter for AI Foundry")]
        $Azure_AIFoundry_SI_Apply_Selfharm_Input_Content_Filter,

        # Azure AI Foundry - Special Filters
        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Jailbreak Input Content Filter for AI Foundry")]
        $Azure_AIFoundry_SI_Annotate_And_Block_Jailbreak_Input_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Indirect Attack Input Content Filter for AI Foundry")]
        $Azure_AIFoundry_SI_Annotate_And_Block_Indirect_Attack_Input_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Known Text Content annotation for AI Foundry")]
        $Azure_AIFoundry_SI_Annotate_Known_Text_Content,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Known Code Content annotation for AI Foundry")]
        $Azure_AIFoundry_SI_Annotate_Known_Code_Content,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Ungrounded Output annotation for AI Foundry")]
        $Azure_AIFoundry_SI_Annotate_Ungrounded_Output,

        # Azure OpenAI - Output Filters
        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Violence Output Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Apply_Violence_Output_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Hate Output Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Apply_Hate_Output_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Sexual Output Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Apply_Sexual_Output_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Selfharm Output Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Apply_Selfharm_Output_Content_Filter,

        # Azure OpenAI - Input Filters
        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Violence Input Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Apply_Violence_Input_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Hate Input Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Apply_Hate_Input_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Sexual Input Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Apply_Sexual_Input_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Selfharm Input Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Apply_Selfharm_Input_Content_Filter,

        # Azure OpenAI - Special Filters
        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Jailbreak Input Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Annotate_And_Block_Jailbreak_Input_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Indirect Attack Input Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Annotate_And_Block_Indirect_Attack_Input_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Known Text Content annotation for OpenAI")]
        $Azure_OpenAI_SI_Annotate_Known_Text_Content,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Known Code Content annotation for OpenAI")]
        $Azure_OpenAI_SI_Annotate_Known_Code_Content,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Ungrounded Output annotation for OpenAI")]
        $Azure_OpenAI_SI_Annotate_Ungrounded_Output,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Profanity Blocklist Output Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Apply_Profanity_Blocklist_Output_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Enable Profanity Blocklist Input Content Filter for OpenAI")]
        $Azure_OpenAI_SI_Apply_Profanity_Blocklist_Input_Content_Filter,

        [Switch]
        [Parameter(ParameterSetName = "EnableAll", Mandatory = $true, HelpMessage = "Specifies for all the resource provider to be enabled")]
        $EnableAllRequiredResourceTypes
    )
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script..."
    Write-Host $([Constants]::SingleDashLine)
    if ($PerformPreReqCheck) {
        try {
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }
    else {
        Write-Host "Skipped as -PerformPreReqCheck switch is not provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
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

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)


    Write-Host "Validating whether the current user [$($context.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."

    if (-not (Validate-UserPermissions -context $context -SubscriptionId $SubscriptionId)) 
    {
        return
    }
        
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3]: Checking Cognitive Services Accounts in Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    # Array to store non-compliant resources
    $nonCompliantResources = @()
    $compliantResources = @()
    $totalResourcesProcessed = 0

    # Get all Cognitive Services accounts in the subscription
    Write-Host "Fetching all Cognitive Services accounts in subscription [$($SubscriptionId)]..."
    
    try 
    {
        $cognitiveServicesAccounts = Get-AzResource -ResourceType "Microsoft.CognitiveServices/accounts" -ErrorAction Stop
        
        $totalAccounts = ($cognitiveServicesAccounts | Measure-Object).Count
        
        if ($totalAccounts -eq 0) {
            Write-Host "No Cognitive Services accounts found in the subscription." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        
        $accountSuffix = if($totalAccounts -ne 1) {'s'} else {''}
        Write-Host "Found [$($totalAccounts)] Cognitive Services account$($accountSuffix) in the subscription." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
    }
    catch {
        Write-Host "Error occurred while fetching Cognitive Services accounts. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    # Process each Cognitive Services account
    foreach ($account in $cognitiveServicesAccounts) {
        $totalResourcesProcessed++
        $resourceGroupName = $account.ResourceGroupName
        $accountName = $account.Name
        $resourceId = $account.ResourceId
        
        Write-Host "[$($totalResourcesProcessed)/$($totalAccounts)] Processing Cognitive Services account: [$($accountName)] in resource group: [$($resourceGroupName)]..."
        
        # Fetch deployments for this Cognitive Services account
        try 
        {
            $deploymentsUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.CognitiveServices/accounts/$accountName/deployments?api-version=2024-10-01"
            
            Write-Host "  Fetching deployments for account [$($accountName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            $deploymentsResponse = Fetch-API -Method "GET" -Uri $deploymentsUri
            
            $deployments = $deploymentsResponse.value
            $deploymentsCount = ($deployments | Measure-Object).Count
            
            if ($deploymentsCount -eq 0) {
                Write-Host "  No deployments found for account [$($accountName)]." -ForegroundColor $([Constants]::MessageType.Warning)
            }
            else {
                $deploymentSuffix = if($deploymentsCount -ne 1) {'s'} else {''}
                Write-Host "  Found [$($deploymentsCount)] deployment$($deploymentSuffix) in account [$($accountName)]." -ForegroundColor $([Constants]::MessageType.Info)
            }
        }
        catch {
            Write-Host "  Error occurred while fetching deployments for account [$($accountName)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            $deployments = @()
        }
        
        # Fetch RAI policies for this Cognitive Services account
        try {
            $raiPoliciesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.CognitiveServices/accounts/$accountName/raiPolicies?api-version=2024-10-01"
            
            Write-Host "  Fetching RAI policies for account [$($accountName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            $raiPoliciesResponse = Fetch-API -Method "GET" -Uri $raiPoliciesUri
            
            $raiPolicies = $raiPoliciesResponse.value
            $raiPoliciesCount = ($raiPolicies | Measure-Object).Count
            
            if ($raiPoliciesCount -eq 0) {
                Write-Host "  No RAI policies found for account [$($accountName)]." -ForegroundColor $([Constants]::MessageType.Warning)
            }
            else {
                $raiPolicySuffix = if($raiPoliciesCount -ne 1) {'ies'} else {'y'}
                Write-Host "  Found [$($raiPoliciesCount)] RAI polic$($raiPolicySuffix) in account [$($accountName)]." -ForegroundColor $([Constants]::MessageType.Info)
            }
        }
        catch {
            Write-Host "  Error occurred while fetching RAI policies for account [$($accountName)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            $raiPolicies = @()
        }
        
        # Skip if no deployments or RAI policies found
        if ($deploymentsCount -eq 0) {
            Write-Host "  Skipping account [$($accountName)] - no deployments found." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            continue
        }
        
        # Process each deployment
        if ($deploymentsCount -gt 0) {
            Write-Host "`n  Processing deployments:" -ForegroundColor $([Constants]::MessageType.Info)
            foreach ($deployment in $deployments) {
                $deploymentName = $deployment.name
                $modelName = $deployment.properties.model.name
                
                # Check if model is in exempted list
                if ($null -ne $script:exemptedModels -and $script:exemptedModels.Count -gt 0) {
                    $isExempted = $false
                    foreach ($exemptedModel in $script:exemptedModels) {
                        if ($modelName -ieq $exemptedModel) {
                            $isExempted = $true
                            break
                        }
                    }
                    
                    if ($isExempted) {
                        Write-Host "    - Deployment: [$($deploymentName)] (Model: [$($modelName)]) - Skipped (Exempted model)" -ForegroundColor Yellow
                        continue
                    }
                }
                
                # Get RAI policy name from deployment
                $raiPolicyName = $deployment.properties.raiPolicyName
                
                # Skip if RAI policy name is null, empty, or Microsoft.Nil
                if ([string]::IsNullOrWhiteSpace($raiPolicyName) -or $raiPolicyName -ieq "Microsoft.Nil") {
                    Write-Host "    - Deployment: [$($deploymentName)] (Model: [$($modelName)]) - Skipped (No valid RAI policy assigned)" -ForegroundColor Yellow
                    continue
                }
                
                Write-Host "    - Deployment: [$($deploymentName)] (Model: [$($modelName)]) (RAI Policy: [$($raiPolicyName)])" -ForegroundColor Cyan
                
                # Find the matching RAI policy from the list
                $matchingRaiPolicy = $null
                foreach ($raiPolicy in $raiPolicies) {
                    if ($raiPolicy.name -ieq $raiPolicyName) {
                        $matchingRaiPolicy = $raiPolicy
                        break
                    }
                }
                
                # Skip if matching RAI policy not found
                if ($null -eq $matchingRaiPolicy) {
                    Write-Host "      Warning: RAI policy [$($raiPolicyName)] not found in account's RAI policies list." -ForegroundColor $([Constants]::MessageType.Warning)
                    continue
                }
                
                Write-Host "      Found matching RAI policy: [$($matchingRaiPolicy.name)]" -ForegroundColor $([Constants]::MessageType.Update)

                # Check content filter configuration
                $contentFilters = $matchingRaiPolicy.properties.contentFilters
                
                if ($null -eq $contentFilters -or $contentFilters.Count -eq 0) {
                    Write-Host "      Warning: No content filters found in RAI policy [$($raiPolicyName)]." -ForegroundColor $([Constants]::MessageType.Warning)
                    continue
                }
                
                $isCompliant = $true
                $nonCompliantFilters = @()
                $isFilterActionReason = $false
                $isThresholdLevelReason = $false
                
                # Build list of filters to check based on enabled parameters using global mapping
                $filtersToCheck = @()
                
                # If EnableAllRequiredResourceTypes is specified, check all filters from the global mapping
                if ($EnableAllRequiredResourceTypes) {
                    foreach ($key in $script:filterConfigMapping.Keys) {
                        $filterConfig = $script:filterConfigMapping[$key]
                        $filtersToCheck += @{ 
                            Name = $filterConfig.FilterCategory
                            Source = $filterConfig.FilterSource
                            Action = $filterConfig.Action
                            ReqThresholdLevels = $filterConfig.ReqThresholdLevels
                        }
                    }
                }
                else {
                    # Check each parameter and add corresponding filter config from global mapping
                    foreach ($paramName in $script:filterConfigMapping.Keys) {
                        # Get the parameter value using Get-Variable
                        $paramValue = Get-Variable -Name $paramName -ValueOnly -ErrorAction SilentlyContinue
                        
                        if ($paramValue -eq $true) {
                            $filterConfig = $script:filterConfigMapping[$paramName]
                            $filtersToCheck += @{ 
                                Name = $filterConfig.FilterCategory
                                Source = $filterConfig.FilterSource
                                Action = $filterConfig.Action
                                ReqThresholdLevels = $filterConfig.ReqThresholdLevels
                            }
                        }
                    }
                }
                
                # Check each filter
                foreach ($filterToCheck in $filtersToCheck) {
                    $filterCategory = $filterToCheck.Name
                    $filterSource = $filterToCheck.Source
                    $requiredAction = $filterToCheck.Action
                    
                    # Find the matching filter in contentFilters array
                    $filter = $null
                    foreach ($cf in $contentFilters) {
                        if ($cf.name -ieq $filterCategory -and $cf.source -ieq $filterSource) {
                            $filter = $cf
                            break
                        }
                    }
                    
                    if ($null -ne $filter) {
                        # Content filter supports 3 actions:
                        # 1 - "Annotate and block": both blocking and enabled are true
                        # 2 - "Annotate only": only enabled is true
                        # 3 - "Off": both blocking and enabled are false
                        
                        # Reading the blocking and enabled flags from the filter configuration
                        $isFilterEnabled = $filter.enabled
                        $isFilterBlocked = $filter.blocking
                        
                        # Check if filter meets requirements based on required action
                        $meetsRequirements = $false
                        
                        if ($requiredAction -ieq "Annotate and block") {
                            # Both enabled and blocking must be true
                            $meetsRequirements = ($isFilterEnabled -eq $true -and $isFilterBlocked -eq $true)
                        }
                        elseif ($requiredAction -ieq "Annotate only") {
                            # Only enabled must be true
                            $meetsRequirements = ($isFilterEnabled -eq $true)
                        }
                        
                        if (-not $meetsRequirements) {
                            $isCompliant = $false
                            $nonCompliantFilters += "$filterCategory ($filterSource)"
                            $isFilterActionReason = $true
                        }
                        
                        # Check threshold level compliance (only if ReqThresholdLevels is not "NotApplicable")
                        $requiredThresholdLevels = $filterToCheck.ReqThresholdLevels
                        if ($null -ne $requiredThresholdLevels -and $requiredThresholdLevels.Count -gt 0 -and $requiredThresholdLevels[0] -ine "NotApplicable") {
                            $filterThresholdLevel = $filter.severityThreshold
                            
                            # Check if the filter's threshold level is in the required list
                            $thresholdLevelMatches = $false
                            foreach ($reqLevel in $requiredThresholdLevels) {
                                if ($filterThresholdLevel -ieq $reqLevel) {
                                    $thresholdLevelMatches = $true
                                    break
                                }
                            }
                            
                            if (-not $thresholdLevelMatches) {
                                $isCompliant = $false
                                if ($nonCompliantFilters -notcontains "$filterCategory ($filterSource)") {
                                    $nonCompliantFilters += "$filterCategory ($filterSource)"
                                }
                                $isThresholdLevelReason = $true
                            }
                        }
                    }
                    else {
                        # Filter not found in RAI policy
                        $isCompliant = $false
                        $nonCompliantFilters += "$filterCategory ($filterSource) - Not Found"
                        $isFilterActionReason = $true
                    }
                }
                
                # Add to appropriate array
                if ($isCompliant) {
                    Write-Host "      Status: Compliant" -ForegroundColor $([Constants]::MessageType.Update)
                    $compliantResources += $deployment
                }
                else {
                    Write-Host "      Status: Non-Compliant" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "      Non-compliant filters: $($nonCompliantFilters -join ', ')" -ForegroundColor $([Constants]::MessageType.Warning)
                    $nonCompliantResources += @{
                        DeploymentName = $deploymentName
                        ModelName = $modelName
                        AccountName = $accountName
                        ResourceGroupName = $resourceGroupName
                        RaiPolicyName = $raiPolicyName
                        RaiPolicyObject = $matchingRaiPolicy
                        FiltersToRemediate = $filtersToCheck
                        NonCompliantFilters = $nonCompliantFilters
                        IsFilterActionReason = $isFilterActionReason
                        IsThresholdLevelReason = $isThresholdLevelReason
                    }
                }
            }
        }
        
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Completed processing all Cognitive Services accounts."
    Write-Host $([Constants]::DoubleDashLine)
    
    # Summary of compliance check
    $totalNonCompliant = ($nonCompliantResources | Measure-Object).Count
    $totalCompliant = ($compliantResources | Measure-Object).Count
    
    Write-Host "`nCompliance Summary:" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "  Total Compliant Resources: [$($totalCompliant)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "  Total Non-Compliant Resources: [$($totalNonCompliant)]" -ForegroundColor $([Constants]::MessageType.Warning)
    
    if ($totalNonCompliant -eq 0) {
        Write-Host "`nAll resources are compliant. No remediation needed." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }
    
    # Export original RAI policy data to CSV for backup before remediation
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 5]: Backing up original RAI policy configurations..."
    Write-Host $([Constants]::SingleDashLine)
    
    $backupFilePath = Backup-RAIPolicyConfigurations -SubscriptionId $SubscriptionId -NonCompliantResources $nonCompliantResources
    
    if ($null -eq $backupFilePath) {
        Write-Host "`nBackup failed. Cannot proceed with remediation without a valid backup." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host "Please ensure you have write permissions in the current directory and try again." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }
    
    Write-Host $([Constants]::SingleDashLine)
    
    # Remediate non-compliant resources
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 4 of 5]: Remediating Non-Compliant Resources..."
    Write-Host $([Constants]::SingleDashLine)
    
    $remediatedResources = @()
    $failedRemediations = @()
    $remediationCount = 0
    
    foreach ($nonCompliantResource in $nonCompliantResources) {
        $remediationCount++
        $deploymentName = $nonCompliantResource.DeploymentName
        $accountName = $nonCompliantResource.AccountName
        $resourceGroupName = $nonCompliantResource.ResourceGroupName
        $raiPolicyName = $nonCompliantResource.RaiPolicyName
        $raiPolicy = $nonCompliantResource.RaiPolicyObject
        $filtersToRemediate = $nonCompliantResource.FiltersToRemediate
        $isFilterActionReason = $nonCompliantResource.IsFilterActionReason
        $isThresholdLevelReason = $nonCompliantResource.IsThresholdLevelReason
        
        Write-Host "[$($remediationCount)/$($totalNonCompliant)] Remediating deployment: [$($deploymentName)] in account: [$($accountName)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "  Reason: FilterAction=$($isFilterActionReason), ThresholdLevel=$($isThresholdLevelReason)" -ForegroundColor $([Constants]::MessageType.Info)
        
        try {
            if ($null -eq $raiPolicy -or $null -eq $raiPolicy.properties -or $null -eq $raiPolicy.properties.contentFilters) {
                Write-Host "  Error: RAI policy object is invalid or contentFilters not found." -ForegroundColor $([Constants]::MessageType.Error)
                $failedRemediations += $nonCompliantResource
                continue
            }
            
            $contentFilters = $raiPolicy.properties.contentFilters
            $modified = $false
            
            # Update filters in the RAI policy
            foreach ($filterToRemediate in $filtersToRemediate) {
                $filterCategory = $filterToRemediate.Name
                $filterSource = $filterToRemediate.Source
                $requiredAction = $filterToRemediate.Action
                $requiredThresholdLevels = $filterToRemediate.ReqThresholdLevels
                
                # Find the matching filter
                $matchingFilter = $null
                foreach ($cf in $contentFilters) {
                    if ($cf.name -ieq $filterCategory -and $cf.source -ieq $filterSource) {
                        $matchingFilter = $cf
                        break
                    }
                }
                
                if ($null -ne $matchingFilter) {
                    # Remediate filter action if needed
                    if ($isFilterActionReason) {
                        if ($requiredAction -ieq "Annotate and block") {
                            if ($matchingFilter.enabled -ne $true -or $matchingFilter.blocking -ne $true) {
                                $matchingFilter.enabled = $true
                                $matchingFilter.blocking = $true
                                Write-Host "    Updated [$($filterCategory)] ($($filterSource)): enabled=true, blocking=true" -ForegroundColor $([Constants]::MessageType.Update)
                                $modified = $true
                            }
                        }
                        elseif ($requiredAction -ieq "Annotate only" -or $requiredAction -ieq "Enabled") {
                            if ($matchingFilter.enabled -ne $true) {
                                $matchingFilter.enabled = $true
                                Write-Host "    Updated [$($filterCategory)] ($($filterSource)): enabled=true" -ForegroundColor $([Constants]::MessageType.Update)
                                $modified = $true
                            }
                        }
                    }
                    
                    # Remediate threshold level if needed
                    if ($isThresholdLevelReason -and $null -ne $requiredThresholdLevels -and $requiredThresholdLevels.Count -gt 0 -and $requiredThresholdLevels[0] -ine "NotApplicable") {
                        $currentSeverityLevel = $matchingFilter.severityThreshold
                        
                        $needsUpdate = $true
                        foreach ($reqLevel in $requiredThresholdLevels) {
                            if ($currentSeverityLevel -ieq $reqLevel) {
                                $needsUpdate = $false
                                break
                            }
                        }
                        
                        if ($needsUpdate) {
                            $newSeverityLevel = $requiredThresholdLevels[0]
                            $matchingFilter.severityThreshold = $newSeverityLevel
                            Write-Host "    Updated [$($filterCategory)] ($($filterSource)): severityLevel=$($newSeverityLevel)" -ForegroundColor $([Constants]::MessageType.Update)
                            $modified = $true
                        }
                    }
                }
                else {
                    # Filter not found - add it
                    Write-Host "    Adding missing filter: [$($filterCategory)] ($($filterSource))" -ForegroundColor $([Constants]::MessageType.Warning)
                    
                    $newFilter = @{
                        name = $filterCategory
                        source = $filterSource
                        enabled = $true
                        blocking = $false
                    }
                    
                    if ($requiredAction -ieq "Annotate and block") {
                        $newFilter.blocking = $true
                    }
                    
                    if ($null -ne $requiredThresholdLevels -and $requiredThresholdLevels.Count -gt 0 -and $requiredThresholdLevels[0] -ine "NotApplicable") {
                        $newFilter.severityThreshold = $requiredThresholdLevels[0]
                    }
                    
                    $contentFilters += $newFilter
                    $modified = $true
                }
            }   
            
            # Call Remediate-ContentFilters to update the RAI policy
            if ($modified) {
                $raiPolicy.properties.contentFilters = $contentFilters
                
                $success = Remediate-ContentFilters -SubscriptionId $SubscriptionId `
                                                     -ResourceGroupName $resourceGroupName `
                                                     -AccountName $accountName `
                                                     -RaiPolicyName $raiPolicyName `
                                                     -UpdatedRaiPolicy $raiPolicy
                
                if ($success) {
                    $remediatedResources += $nonCompliantResource
                    Write-Host "  Successfully remediated deployment: [$($deploymentName)]" -ForegroundColor $([Constants]::MessageType.Update)
                }
                else {
                    $failedRemediations += $nonCompliantResource
                    Write-Host "  Failed to remediate deployment: [$($deploymentName)]" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            else {
                Write-Host "  No modifications needed for deployment: [$($deploymentName)]" -ForegroundColor $([Constants]::MessageType.Info)
                $remediatedResources += $nonCompliantResource
            }
        }
        catch {
            Write-Host "  Error occurred during remediation: $_" -ForegroundColor $([Constants]::MessageType.Error)
            $failedRemediations += $nonCompliantResource
        }
        
        Write-Host ""
    }
    
    # Final Summary
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 5 of 5]: Remediation Summary" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    
    $totalRemediated = ($remediatedResources | Measure-Object).Count
    $totalFailed = ($failedRemediations | Measure-Object).Count
    
    Write-Host "Total Non-Compliant Resources: [$($totalNonCompliant)]" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Successfully Remediated: [$($totalRemediated)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "Failed Remediations: [$($totalFailed)]" -ForegroundColor $(if($totalFailed -gt 0) {[Constants]::MessageType.Error} else {[Constants]::MessageType.Update})
    
    if ($totalFailed -gt 0) {
        Write-Host "`nFailed Remediation Details:" -ForegroundColor $([Constants]::MessageType.Warning)
        foreach ($failed in $failedRemediations) {
            Write-Host "  - Deployment: [$($failed.DeploymentName)] | Account: [$($failed.AccountName)] | RG: [$($failed.ResourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }
    
    if ($totalRemediated -gt 0) {
        Write-Host "`nBackup file location: [$($backupFilePath)]" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Use this file to revert changes if needed." -ForegroundColor $([Constants]::MessageType.Info)
    }
    
    Write-Host $([Constants]::DoubleDashLine)
}