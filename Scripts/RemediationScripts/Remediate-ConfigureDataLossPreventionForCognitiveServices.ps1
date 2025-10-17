<##########################################

# Overview:
    This script is used to configure Data Loss Prevention for Azure Cognitive Services accounts in a subscription.
    It enables restrictOutboundNetworkAccess property for data loss prevention across multiple Cognitive Services kinds.
    Note: Only ONE Control ID can be remediated at a time per script execution.

# Supported Control IDs:
    - Azure_AIServices_DP_Data_Loss_Prevention
    - Azure_ComputerVision_DP_Data_Loss_Prevention
    - Azure_ContentSafety_DP_Data_Loss_Prevention
    - Azure_DocumentIntelligence_DP_Data_Loss_Prevention
    - Azure_FaceAPI_DP_Data_Loss_Prevention
    - Azure_LanguageService_DP_Data_Loss_Prevention
    - Azure_MultiServiceAccount_DP_Data_Loss_Prevention
    - Azure_OpenAI_DP_Data_Loss_Prevention
    - Azure_SpeechService_DP_Data_Loss_Prevention

# Display Name:
    Data Loss Prevention must be enabled in various Azure Cognitive Services

# Pre-requisites:
    1. You will need Contributor or higher role on the Cognitive Services accounts in the subscription.
    2. Must be connected to Azure with an authenticated account.
    3. Azure PowerShell modules (Az.Accounts, Az.Resources) must be installed.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script for subscription.
        2. Prompt user to select the Cognitive Services type (Control ID) to remediate if not provided while calling the script function.
        3. Get the list of Cognitive Services resources matching the selected type from subscription or input CSV file.
        4. Fetch current restrictOutboundNetworkAccess state for each resource.
        5. Take a backup or snapshot of resources that need remediation.
        6. Enable restrictOutboundNetworkAccess for non-compliant resources and backup the remediation details.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Prompt user to select the Cognitive Services type (Control ID) to rollback if not provided while calling the script function.
        3. Get the list of Cognitive Services resources from the remediation log file.
        4. Disable Data Loss Prevention for resources that were remediated.
        5. Rollback Summary and backup of files.

# Step to execute script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remediate Cognitive Services resources in the subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to rollback changes on all remediated Cognitive Services resources in the subscription. Refer `Examples`, below.

# Command to execute:
    To remediate:
        1. Run below command to enable Data Loss Prevention for Cognitive Services resources (Dry Run), asks for ControlID selection:

            Enable-DataLossPreventionForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Run below command to enable Data Loss Prevention for a specific Cognitive Services kind:

            Enable-DataLossPreventionForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ControlId "Azure_OpenAI_DP_Data_Loss_Prevention" -PerformPreReqCheck

        3. Run below command to enable Data Loss Prevention from a previously generated CSV file:

            Enable-DataLossPreventionForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202410071200\EnableDataLossPreventionForOpenAI\OpenAIResourcesWithoutDLP.csv -PerformPreReqCheck

        To know more about parameter execute:
            Get-Help Enable-DataLossPreventionForCognitiveServices -Detailed

    To roll back:
        1. Run below command to disable Data Loss Prevention for Cognitive Services resources:

            Disable-DataLossPreventionForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ControlId "Azure_OpenAI_DP_Data_Loss_Prevention" -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202410071200\EnableDataLossPreventionForOpenAI\RemediatedOpenAIResources.csv -PerformPreReqCheck

        To know more about parameter execute:
            Get-Help Disable-DataLossPreventionForCognitiveServices -Detailed

########################################
#>

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
    $requiredModules = @("Az.Accounts", "Az.Resources")

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

function Validate-UserPermissions {
    <#
        .SYNOPSIS
        Checks if user has required permissions.
        
        .DESCRIPTION
        Checks if user has required permissions to perform remediation.
        
        .PARAMETER context
        The Azure context object.
        
        .PARAMETER SubscriptionId
        The subscription ID to validate permissions for.
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

    # Safe Check: Current user needs to be either Owner, Contributor, or Security Admin for the subscription
    try {
        $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)" -ErrorAction Stop
        $roles = $currentLoginRoleAssignments | Where-Object { 
            ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor" -or $_.RoleDefinitionName -eq "Security Admin") -and 
            !($_.Scope -like "/subscriptions/$($SubscriptionId)/resourceGroups/*")
        }

        if (($roles | Measure-Object).Count -le 0) {
            Write-Host "Error: This script can only be run by an Owner or Contributor of subscription [$($SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Error)
            return $false
        }

        Write-Host "User has required permissions (Owner or Contributor) on subscription." -ForegroundColor $([Constants]::MessageType.Update)
        return $true
    }
    catch {
        Write-Host "Warning: Unable to validate role assignments. Error: $($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
        return $false
    }
}

function Enable-DataLossPreventionForCognitiveServices
{
    <#
        .SYNOPSIS
        Remediates Data Loss Prevention Controls for Azure Cognitive Services.

        .DESCRIPTION
        Remediates Data Loss Prevention Controls for Azure Cognitive Services.
        Enables restrictOutboundNetworkAccess for Cognitive Services resources.
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER ControlId
        Specifies the Control ID of the Cognitive Services type to remediate.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .INPUTS
        None. You cannot pipe objects to Enable-DataLossPreventionForCognitiveServices.

        .OUTPUTS
        None. Enable-DataLossPreventionForCognitiveServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-DataLossPreventionForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-DataLossPreventionForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ControlId "Azure_OpenAI_DP_Data_Loss_Prevention" -PerformPreReqCheck

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [String]
        [Parameter(ParameterSetName = "DryRun", HelpMessage="Specifies the Control ID of the Cognitive Services type")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the Control ID of the Cognitive Services type")]
        [ValidateSet("Azure_AIServices_DP_Data_Loss_Prevention", "Azure_ComputerVision_DP_Data_Loss_Prevention", 
                     "Azure_ContentSafety_DP_Data_Loss_Prevention", "Azure_DocumentIntelligence_DP_Data_Loss_Prevention",
                     "Azure_FaceAPI_DP_Data_Loss_Prevention", "Azure_LanguageService_DP_Data_Loss_Prevention",
                     "Azure_MultiServiceAccount_DP_Data_Loss_Prevention", "Azure_OpenAI_DP_Data_Loss_Prevention",
                     "Azure_SpeechService_DP_Data_Loss_Prevention")]
        $ControlId,

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

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 6] Prepare to enable Data Loss Prevention for Cognitive Services resources in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }
    else
    {
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
    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "To enable Data Loss Prevention for Azure Cognitive Services resources in a Subscription, Contributor or higher privileges on the resources are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)

    # Validate user permissions
    $hasPermissions = Validate-UserPermissions -context $context -SubscriptionId $SubscriptionId
    if (-not $hasPermissions) {
        Write-Host "Exiting due to insufficient permissions." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }
    Write-Host $([Constants]::SingleDashLine)

    # Handle Control ID selection
    $selectedControlId = $null
    $selectedKind = $null

    if ([String]::IsNullOrWhiteSpace($ControlId)) {
        # Prompt user to select a Control ID (regardless of FilePath)
        Write-Host "No Control ID specified. Please select ONE from the following:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        
        $availableControlIds = [CognitiveServicesMapping]::GetAllControlIds()
        for ($i = 0; $i -lt $availableControlIds.Count; $i++) {
            Write-Host "[$($i + 1)] $($availableControlIds[$i])"
        }
        Write-Host $([Constants]::SingleDashLine)
        
        $selection = Read-Host "Enter your selection (single number, e.g., 1 or 9)"
        
        # Parse the selection - only accept a single number
        if ($selection -match '^\d+$') 
        {
            $index = [int]$selection - 1
            
            if ($index -ge 0 -and $index -lt $availableControlIds.Count) {
                $selectedControlId = $availableControlIds[$index]
                Write-Host "Selected Control ID: $selectedControlId" -ForegroundColor $([Constants]::MessageType.Update)
            }
            else {
                Write-Host "Invalid selection. Please enter a number between 1 and $($availableControlIds.Count). Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                return
            }
        }
        else 
        {
            Write-Host "Invalid input. Please enter a number between 1 and $($availableControlIds.Count)." -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }
    else {
        $selectedControlId = $ControlId
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 6] Fetch all Cognitive Services resources"
    Write-Host $([Constants]::SingleDashLine)

    $cognitiveServicesResources = @()
    
    # No file path provided as input to the script. Fetch all Cognitive Services resources in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        # Get the Kind from ControlId
        $resourceKind = [CognitiveServicesMapping]::GetKindForControlId($selectedControlId)
        $displayName = [CognitiveServicesMapping]::GetDisplayName($selectedControlId)
        
        Write-Host "Fetching all [$displayName] resources in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Resource Kind: [$resourceKind]" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Get all Cognitive Services resources of the specified kind
        $resources = Get-AzResource -ResourceType "Microsoft.CognitiveServices/accounts" | Where-Object { $_.Kind -eq $resourceKind }

        $resources | ForEach-Object {
            $resource = $_
            $resourceId = $_.ResourceId
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.Name
            $location = $_.Location
            $kind = $_.Kind

            $cognitiveServicesResources += [PSCustomObject]@{
                ResourceId = $resourceId
                ResourceGroupName = $resourceGroupName
                ResourceName = $resourceName
                Location = $location
                Kind = $kind
                ControlId = $selectedControlId
            }
        }
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            return
        }

        Write-Host "Fetching all Cognitive Services resources from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $resourcesFromFile = Import-Csv -LiteralPath $FilePath

        # Validate CSV Kind matches Selected Control ID Kind
        # Use foreach to stop at first resource with Kind (efficient for large CSVs)
        $firstResourceWithKind = $null
        foreach ($resource in $resourcesFromFile) {
            if (![String]::IsNullOrWhiteSpace($resource.Kind)) {
                $firstResourceWithKind = $resource
                break
            }
        }
        
        if ($firstResourceWithKind) {
            $expectedKind = [CognitiveServicesMapping]::GetKindForControlId($selectedControlId)
            if ($firstResourceWithKind.Kind -ne $expectedKind) {
                Write-Host "Error: CSV file Kind mismatch detected!" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "  CSV file contains resources of Kind: [$($firstResourceWithKind.Kind)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "  Selected Control ID expects Kind: [$expectedKind]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Please ensure you are using the correct remediation file for the selected Control ID." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                return
            }
        }

        $resourcesFromFile | ForEach-Object {
            if (![String]::IsNullOrWhiteSpace($_.ResourceId)) {
                $cognitiveServicesResources += [PSCustomObject]@{
                    ResourceId = $_.ResourceId
                    ResourceGroupName = $_.ResourceGroupName
                    ResourceName = $_.ResourceName
                    Location = $_.Location
                    Kind = $_.Kind
                    ControlId = if (![String]::IsNullOrWhiteSpace($_.ControlId)) { $_.ControlId } else { $selectedControlId }
                    RestrictOutboundNetworkAccess = if (![String]::IsNullOrWhiteSpace($_.RestrictOutboundNetworkAccess)) { $_.RestrictOutboundNetworkAccess } else { "false" }
                }
            }
        }
    }

    $totalResources = $cognitiveServicesResources.Count

    if ($totalResources -eq 0) {
        Write-Host "No Cognitive Services resources found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        return
    }

    Write-Host "Found [$totalResources] Cognitive Services resource(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 3 of 6] Fetching Data Loss Prevention configuration for resources..."
    Write-Host $([Constants]::SingleDashLine)

    $nonCompliantResources = @()
    $compliantResources = @()
    $cognitiveServicesResourcesSkipped = @()

    $cognitiveServicesResources | ForEach-Object {
        $resource = $_
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.ResourceName
        $resourceId = $_.ResourceId
        $location = $_.Location
        
        Write-Host "Checking resource [$resourceName] in resource group [$resourceGroupName]..." -ForegroundColor $([Constants]::MessageType.Info)

        try {
            # Use Azure PowerShell to get resource details
            $resourceDetails = Get-AzResource -ResourceType "Microsoft.CognitiveServices/accounts" `
                -ResourceGroupName $resourceGroupName `
                -Name $resourceName `
                -ExpandProperties -ErrorAction Stop
            
            if ($resourceDetails) {
                $restrictOutbound = $resourceDetails.Properties.restrictOutboundNetworkAccess
                
                # Add the property to resource object for display
                $resourceDetails | Add-Member -NotePropertyName "RestrictOutboundNetworkAccess" -NotePropertyValue $restrictOutbound -Force

                # Check if Data Loss Prevention is not configured properly
                if ($restrictOutbound -ne $true) {
                    $nonCompliantResources += $resourceDetails
                }
                else {
                    $compliantResources += $resourceDetails
                }
            }
            else {
                Write-Host "  Error: Failed to retrieve resource details" -ForegroundColor $([Constants]::MessageType.Error)
                $cognitiveServicesResourcesSkipped += [PSCustomObject]@{
                    ResourceId = $resourceId
                    ResourceGroupName = $resourceGroupName
                    ResourceName = $resourceName
                    Location = $location
                    Kind = $resource.Kind
                    Error = "Failed to retrieve resource details"
                }
            }
        }
        catch {
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Error)
            $cognitiveServicesResourcesSkipped += [PSCustomObject]@{
                ResourceId = $resourceId
                ResourceGroupName = $resourceGroupName
                ResourceName = $resourceName
                Location = $location
                Kind = $resource.Kind
                Error = $_.Exception.Message
            }
        }
    }

    $totalNonCompliantResources = $nonCompliantResources.Count
    $totalCompliantResources = $compliantResources.Count
    $totalSkippedResources = $cognitiveServicesResourcesSkipped.Count

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Total resources compliant: [$totalCompliantResources]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "Total resources non-compliant: [$totalNonCompliantResources]" -ForegroundColor $([Constants]::MessageType.Warning)
    if ($totalSkippedResources -gt 0) {
        Write-Host "Total resources skipped due to errors: [$totalSkippedResources]" -ForegroundColor $([Constants]::MessageType.Error)
    }
    Write-Host $([Constants]::SingleDashLine)

    # Display skipped resources if any
    if ($totalSkippedResources -gt 0) {
        Write-Host "`nResources skipped due to errors:" -ForegroundColor $([Constants]::MessageType.Error)
        $colsPropertySkipped = @{Expression={$_.ResourceName};Label="Resource Name";Width=30;Alignment="left"},
                               @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=25;Alignment="left"},
                               @{Expression={$_.Kind};Label="Kind";Width=20;Alignment="left"},
                               @{Expression={$_.Error};Label="Error";Width=80;Alignment="left"}
        $cognitiveServicesResourcesSkipped | Format-Table -Property $colsPropertySkipped -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($totalNonCompliantResources -eq 0) {
        Write-Host "`nNo resources found without Data Loss Prevention enabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$totalNonCompliantResources] resource(s) without Data Loss Prevention enabled." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    $colsProperty = @{Expression={$_.ResourceName};Label="Resource Name";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=25;Alignment="left"},
                    @{Expression={$_.Kind};Label="Kind";Width=25;Alignment="left"},
                    @{Expression={$_.Location};Label="Location";Width=15;Alignment="left"},
                    @{Expression={$_.RestrictOutboundNetworkAccess};Label="DLP Enabled";Width=15;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="Resource ID";Width=120;Alignment="left"}

    Write-Host "Resources with Data Loss Prevention Disabled:"
    $nonCompliantResources | Format-Table -Property $colsProperty -Wrap
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 4 of 6] Take a backup of resources that need remediation"
    Write-Host $([Constants]::SingleDashLine)

    # Back up snapshots to `%LocalApplicationData%`
    $resourceKindForFolder = if ([String]::IsNullOrWhiteSpace($FilePath)) { [CognitiveServicesMapping]::GetKindForControlId($selectedControlId) } else { $cognitiveServicesResources[0].Kind }
    $folderName = "EnableDataLossPrevention$resourceKindForFolder"
    
    # If FilePath is provided, extract the timestamp from it to reuse the same folder
    if (-not [String]::IsNullOrWhiteSpace($FilePath))
    {
        if ($FilePath -match '\\(\d{12})\\')
        {
            $timestamp = $matches[1]
            $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($timestamp)\$($folderName)"
            Write-Host "Reusing existing backup folder from input file: [$($backupFolderPath)]" -ForegroundColor $([Constants]::MessageType.Info)
        }
        else
        {
            $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\$($folderName)"
            Write-Host "Could not extract timestamp from input file path. Creating new backup folder: [$($backupFolderPath)]" -ForegroundColor $([Constants]::MessageType.Warning)
        }
    }
    else
    {
        $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\$($folderName)"
    }

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    if (-not $DryRun)
    {
        Write-Host "[Step 5 of 6] Enabling Data Loss Prevention for resources..."
        Write-Host $([Constants]::SingleDashLine)
        
        $resourcesSkippedDuringRemediation = @()

        Write-Host "Data Loss Prevention will be enabled for all resource(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)

        if (-not $Force)
        {
            Write-Host "Do you want to enable Data Loss Prevention for all [$totalNonCompliantResources] resource(s) listed above? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            $userInput = Read-Host -Prompt "(Y|N)"
            Write-Host $([Constants]::SingleDashLine)

            if ($userInput.ToUpper() -ne "Y")
            {
                Write-Host "Data Loss Prevention will not be enabled for any resources. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                return
            }
            Write-Host "User has provided consent to enable Data Loss Prevention for all resource(s)." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "'Force' flag is provided. Data Loss Prevention will be enabled for all resource(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        # To hold results from the remediation.
        $resourcesRemediated = @()

        $nonCompliantResources | ForEach-Object {
            $resource = $_
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName

            Write-Host "Enabling Data Loss Prevention for resource [$resourceName]..." -ForegroundColor $([Constants]::MessageType.Info)

            try {
                # Store the previous value for rollback
                $previousValue = $resource.Properties.restrictOutboundNetworkAccess
                
                # Create a copy of the properties and update restrictOutboundNetworkAccess
                $updatedProperties = $resource.Properties.PSObject.Copy()
                
                # Add or update the restrictOutboundNetworkAccess property
                if ($updatedProperties.PSObject.Properties['restrictOutboundNetworkAccess']) {
                    $updatedProperties.restrictOutboundNetworkAccess = $true
                }
                else {
                    $updatedProperties | Add-Member -NotePropertyName "restrictOutboundNetworkAccess" -NotePropertyValue $true -Force
                }
                
                # Update the resource with updated properties
                $updateResult = Set-AzResource -ResourceId $resource.ResourceId `
                    -PropertyObject $updatedProperties `
                    -Force -ErrorAction Stop

                if ($updateResult) {
                    $resource | Add-Member -NotePropertyName "PreviousRestrictOutboundNetworkAccess" -NotePropertyValue $previousValue -Force
                    $resource | Add-Member -NotePropertyName "RestrictOutboundNetworkAccess" -NotePropertyValue $true -Force
                    
                    $resourcesRemediated += $resource
                    Write-Host "  Successfully enabled Data Loss Prevention for resource [$resourceName]" -ForegroundColor $([Constants]::MessageType.Update)
                }
                else {
                    $resourcesSkippedDuringRemediation += $resource
                    Write-Host "  Error: Failed to enable Data Loss Prevention." -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            catch {
                $resourcesSkippedDuringRemediation += $resource
                Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Error)
            }
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($resourcesRemediated.Count -eq $totalNonCompliantResources)
        {
            Write-Host "Data Loss Prevention enabled for all [$totalNonCompliantResources] resource(s)." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "Data Loss Prevention enabled for [$($resourcesRemediated.Count)] out of [$totalNonCompliantResources] resource(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsPropertyRemediated = @{Expression={$_.ResourceName};Label="Resource Name";Width=30;Alignment="left"},
                                   @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=25;Alignment="left"},
                                   @{Expression={$_.Kind};Label="Kind";Width=20;Alignment="left"},
                                   @{Expression={$_.Location};Label="Location";Width=15;Alignment="left"},
                                   @{Expression={$_.RestrictOutboundNetworkAccess};Label="DLP Enabled";Width=15;Alignment="left"},
                                   @{Expression={$_.ResourceId};Label="Resource ID";Width=120;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

        if ($resourcesRemediated.Count -gt 0)
        {
            Write-Host "Data Loss Prevention enabled for the following resource(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $resourcesRemediated | Format-Table -Property $colsPropertyRemediated -Wrap
            Write-Host $([Constants]::SingleDashLine)

            # Write this to a file.
            $resourcesRemediatedFile = "$($backupFolderPath)\RemediatedResources.csv"
            $resourcesRemediated | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                  @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                  @{N='ResourceName';E={$_.ResourceName}},
                                                  @{N='Kind';E={$_.Kind}},
                                                  @{N='Location';E={$_.Location}},
                                                  @{N='RestrictOutboundNetworkAccess';E={$_.RestrictOutboundNetworkAccess}},
                                                  @{N='PreviousRestrictOutboundNetworkAccess';E={$_.PreviousRestrictOutboundNetworkAccess}} |
                Export-CSV -Path $resourcesRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($resourcesRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($resourcesSkippedDuringRemediation.Count -gt 0)
        {
            Write-Host "Error enabling Data Loss Prevention for the following resource(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $resourcesSkippedDuringRemediation | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)

            # Write this to a file.
            $resourcesSkippedFile = "$($backupFolderPath)\SkippedResources.csv"
            $resourcesSkippedDuringRemediation | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                @{N='ResourceName';E={$_.ResourceName}},
                                                                @{N='Kind';E={$_.Kind}},
                                                                @{N='Location';E={$_.Location}},
                                                                @{N='RestrictOutboundNetworkAccess';E={$_.RestrictOutboundNetworkAccess}} |
                Export-CSV -Path $resourcesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($resourcesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
        Write-Host "[Step 5 of 6] Back up resource details..."
        Write-Host $([Constants]::SingleDashLine)
        
        # Backing up non-compliant resource details.
        $backupFile = "$($backupFolderPath)\ResourceWithDataLossPreventionDisabled.csv"
        $nonCompliantResources | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                @{N='ResourceName';E={$_.ResourceName}},
                                                @{N='Kind';E={$_.Kind}},
                                                @{N='Location';E={$_.Location}},
                                                @{N='RestrictOutboundNetworkAccess';E={$_.RestrictOutboundNetworkAccess}} |
            Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Resource(s) details have been backed up to [$($backupFile)]." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "[Step 6 of 6] Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun to enable Data Loss Prevention for all resource(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Disable-DataLossPreventionForCognitiveServices
{
    <#
        .SYNOPSIS
        Rolls back remediation done for Data Loss Prevention Controls for Azure Cognitive Services.

        .DESCRIPTION
        Rolls back remediation done for Data Loss Prevention Controls.
        Disables restrictOutboundNetworkAccess for resources that were previously remediated.
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER ControlId
        Specifies the Control ID of the Cognitive Services type.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-DataLossPreventionForCognitiveServices.

        .OUTPUTS
        None. Disable-DataLossPreventionForCognitiveServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-DataLossPreventionForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ControlId "Azure_OpenAI_DP_Data_Loss_Prevention" -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202410071200\EnableDataLossPreventionForOpenAI\RemediatedResources.csv -PerformPreReqCheck

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the path to the file to be used as input for the roll back")]
        $FilePath,

        [String]
        [Parameter(HelpMessage="Specifies the Control ID of the Cognitive Services type")]
        [ValidateSet("Azure_AIServices_DP_Data_Loss_Prevention", "Azure_ComputerVision_DP_Data_Loss_Prevention", 
                     "Azure_ContentSafety_DP_Data_Loss_Prevention", "Azure_DocumentIntelligence_DP_Data_Loss_Prevention",
                     "Azure_FaceAPI_DP_Data_Loss_Prevention", "Azure_LanguageService_DP_Data_Loss_Prevention",
                     "Azure_MultiServiceAccount_DP_Data_Loss_Prevention", "Azure_OpenAI_DP_Data_Loss_Prevention",
                     "Azure_SpeechService_DP_Data_Loss_Prevention")]
        $ControlId,

        [Switch]
        [Parameter(HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 5] Prepare to disable Data Loss Prevention for Cognitive Services resources in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }
    else
    {
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

    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "To restore Data Loss Prevention configuration for Azure Cognitive Services resources in a Subscription, Contributor or higher privileges on the resources are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)

    # Validate user permissions
    $hasPermissions = Validate-UserPermissions -context $context -SubscriptionId $SubscriptionId
    if (-not $hasPermissions) {
        Write-Host "Exiting due to insufficient permissions." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }
    Write-Host $([Constants]::SingleDashLine)

    # Handle Control ID selection
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 5] Cognitive Services type to rollback"
    Write-Host $([Constants]::SingleDashLine)

    $selectedControlId = $null
    $selectedKind = $null

    if ([String]::IsNullOrWhiteSpace($ControlId)) {
        # Prompt user to select a Control ID
        Write-Host "No Control ID specified. Please select ONE from the following:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        
        $availableControlIds = [CognitiveServicesMapping]::GetAllControlIds()
        for ($i = 0; $i -lt $availableControlIds.Count; $i++) {
            Write-Host "[$($i + 1)] $($availableControlIds[$i])"
        }
        Write-Host $([Constants]::SingleDashLine)
        
        $selection = Read-Host "Enter your selection (single number, e.g., 1 or 9)"
        
        # Parse the selection - only accept a single number
        if ($selection -match '^\d+$') 
        {
            $index = [int]$selection - 1
            
            if ($index -ge 0 -and $index -lt $availableControlIds.Count) {
                $selectedControlId = $availableControlIds[$index]
                Write-Host "Selected Control ID: $selectedControlId" -ForegroundColor $([Constants]::MessageType.Update)
            }
            else {
                Write-Host "Invalid selection. Please enter a number between 1 and $($availableControlIds.Count). Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                return
            }
        }
        else 
        {
            Write-Host "Invalid input. Please enter a number between 1 and $($availableControlIds.Count)." -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }
    else {
        $selectedControlId = $ControlId
    }

    Write-Host "Selected Control ID: $selectedControlId" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Get corresponding Kind for selected Control ID
    $selectedKind = [CognitiveServicesMapping]::GetKindForControlId($selectedControlId)
    Write-Host "Targeting Cognitive Services kind: $selectedKind" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 5] Fetch remediation log to perform rollback operation"
    Write-Host $([Constants]::SingleDashLine)

    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "Error: Rollback file [$FilePath] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }

    Write-Host "Fetching resources from [$FilePath]..." -ForegroundColor $([Constants]::MessageType.Info)
    $remediatedResources = Import-Csv -LiteralPath $FilePath
    $totalRemediatedResources = $remediatedResources.Count

    if ($totalRemediatedResources -eq 0) {
        Write-Host "No resources found in the remediation log file. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        return
    }

    # Validate CSV Kind matches Selected Control ID Kind
    $firstResourceWithKind = $null
    foreach ($resource in $remediatedResources) {
        if (![String]::IsNullOrWhiteSpace($resource.Kind)) {
            $firstResourceWithKind = $resource
            break
        }
    }
    
    if ($firstResourceWithKind) {
        $expectedKind = [CognitiveServicesMapping]::GetKindForControlId($selectedControlId)
        if ($firstResourceWithKind.Kind -ne $expectedKind) {
            Write-Host "Error: CSV file Kind mismatch detected!" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "  CSV file contains resources of Kind: [$($firstResourceWithKind.Kind)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "  Selected Control ID expects Kind: [$expectedKind]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Please ensure you are using the correct rollback file for the selected Control ID." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
    }

    Write-Host "Found [$totalRemediatedResources] resource(s) to rollback." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 4 of 5] Disable Data Loss Prevention for resources which were previously remediated"
    Write-Host $([Constants]::SingleDashLine)

    $rolledBackResources = @()
    $failedRollbacks = @()

    foreach ($resource in $remediatedResources) {
        $resourceGroupName = $resource.ResourceGroupName
        $resourceName = $resource.ResourceName
        $previousValue = $resource.PreviousRestrictOutboundNetworkAccess
        
        # Default to false if previous value is not available
        if ([String]::IsNullOrWhiteSpace($previousValue)) {
            $previousValue = $false
        }
        else {
            # Convert string to boolean
            $previousValue = [System.Convert]::ToBoolean($previousValue)
        }

        Write-Host "`nRolling back resource [$resourceName] to restrictOutboundNetworkAccess=[$previousValue]..." -ForegroundColor $([Constants]::MessageType.Info)
        
        try {
            # Get the current resource with all properties
            $currentResourceDetails = Get-AzResource -ResourceType "Microsoft.CognitiveServices/accounts" `
                -ResourceGroupName $resourceGroupName `
                -Name $resourceName `
                -ExpandProperties -ErrorAction Stop
            
            if ($currentResourceDetails) {
                # Create a copy of the properties
                $updatedProperties = $currentResourceDetails.Properties.PSObject.Copy()
                
                # Add or update the restrictOutboundNetworkAccess property
                if ($updatedProperties.PSObject.Properties['restrictOutboundNetworkAccess']) {
                    $updatedProperties.restrictOutboundNetworkAccess = $previousValue
                }
                else {
                    $updatedProperties | Add-Member -NotePropertyName "restrictOutboundNetworkAccess" -NotePropertyValue $previousValue -Force
                }
                
                # Update the resource with updated properties
                $updateResult = Set-AzResource -ResourceId $currentResourceDetails.ResourceId `
                    -PropertyObject $updatedProperties `
                    -Force -ErrorAction Stop

                if ($updateResult) {
                    Write-Host "  Successfully rolled back resource [$resourceName]" -ForegroundColor $([Constants]::MessageType.Update)
                    $rolledBackResources += $resource | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                       @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                       @{N='ResourceName';E={$_.ResourceName}},
                                                                       @{N='Location';E={$_.Location}},
                                                                       @{N='RestrictOutboundNetworkAccess';E={$previousValue}},
                                                                       @{N='PreviousRestrictOutboundNetworkAccess';E={$_.PreviousRestrictOutboundNetworkAccess}},
                                                                       @{N='RolledBackOn';E={$(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')}}
                }
                else {
                    Write-Host "  Error: Failed to rollback resource." -ForegroundColor $([Constants]::MessageType.Error)
                    $failedRollbacks += $resource | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                   @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                   @{N='ResourceName';E={$_.ResourceName}},
                                                                   @{N='Location';E={$_.Location}},
                                                                   @{N='Error';E={"Update failed"}}
                }
            }
            else {
                Write-Host "  Error: Failed to retrieve resource details." -ForegroundColor $([Constants]::MessageType.Error)
                $failedRollbacks += $resource | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                               @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                               @{N='ResourceName';E={$_.ResourceName}},
                                                               @{N='Location';E={$_.Location}},
                                                               @{N='Error';E={"Failed to retrieve resource details"}}
            }
        }
        catch {
            Write-Host "  Error: Failed to rollback resource [$resourceName]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            $failedRollbacks += $resource | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                           @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                           @{N='ResourceName';E={$_.ResourceName}},
                                                           @{N='Location';E={$_.Location}},
                                                           @{N='Error';E={$_.Exception.Message}}
        }
    }

    $totalRolledBack = $rolledBackResources.Count
    $totalFailed = $failedRollbacks.Count

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 5 of 5] Rollback summary"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Total resources rolled back: [$totalRolledBack]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "Total resources failed: [$totalFailed]" -ForegroundColor $([Constants]::MessageType.Error)
    Write-Host $([Constants]::SingleDashLine)

    # Extract backup folder path from input file path
    $backupFolderPath = Split-Path -Path $FilePath -Parent

    if ($totalRolledBack -gt 0) {
        Write-Host "`nData Loss Prevention configuration successfully restored for the following resource(s):" -ForegroundColor $([Constants]::MessageType.Update)
        
        $colsProperty = @{Expression={$_.ResourceName};Label="Resource Name";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=25;Alignment="left"},
                        @{Expression={$_.Location};Label="Location";Width=15;Alignment="left"},
                        @{Expression={$_.RestrictOutboundNetworkAccess};Label="DLP Enabled";Width=15;Alignment="left"},
                        @{Expression={$_.RolledBackOn};Label="Rolled Back On";Width=25;Alignment="left"}
        
        $rolledBackResources | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
        
        # Write this to a file.
        $rolledBackResourcesFile = "$($backupFolderPath)\RolledBackResources.csv"
        $rolledBackResources | Export-CSV -Path $rolledBackResourcesFile -NoTypeInformation
        Write-Host "This information has been saved to [$($rolledBackResourcesFile)]." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($totalFailed -gt 0) {
        Write-Host "Error restoring Data Loss Prevention configuration for the following resource(s):" -ForegroundColor $([Constants]::MessageType.Error)
        
        $colsPropertyFailed = @{Expression={$_.ResourceName};Label="Resource Name";Width=30;Alignment="left"},
                              @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=25;Alignment="left"},
                              @{Expression={$_.Location};Label="Location";Width=15;Alignment="left"},
                              @{Expression={$_.Error};Label="Error";Width=80;Alignment="left"}
        
        $failedRollbacks | Format-Table -Property $colsPropertyFailed -Wrap
        Write-Host $([Constants]::SingleDashLine)
        
        # Write this to a file.
        $failedRollbacksFile = "$($backupFolderPath)\RollbackFailedResources.csv"
        $failedRollbacks | Export-CSV -Path $failedRollbacksFile -NoTypeInformation
        Write-Host "This information has been saved to [$($failedRollbacksFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "Rollback operation completed." -ForegroundColor $([Constants]::MessageType.Update)

    Write-Host $([Constants]::DoubleDashLine)
}

# Class to define constants
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

# Mapping of Control IDs to Cognitive Services 'kind' values
class CognitiveServicesMapping {
    static [Hashtable] $ControlIdToKindMap = @{
        "Azure_AIServices_DP_Data_Loss_Prevention"            = "AIServices"
        "Azure_ComputerVision_DP_Data_Loss_Prevention"        = "ComputerVision"
        "Azure_ContentSafety_DP_Data_Loss_Prevention"         = "ContentSafety"
        "Azure_DocumentIntelligence_DP_Data_Loss_Prevention"  = "FormRecognizer"
        "Azure_FaceAPI_DP_Data_Loss_Prevention"               = "Face"
        "Azure_LanguageService_DP_Data_Loss_Prevention"       = "TextAnalytics"
        "Azure_MultiServiceAccount_DP_Data_Loss_Prevention"   = "CognitiveServices"
        "Azure_OpenAI_DP_Data_Loss_Prevention"                = "OpenAI"
        "Azure_SpeechService_DP_Data_Loss_Prevention"         = "SpeechServices"
    }

    static [Hashtable] $DisplayNames = @{
        "Azure_AIServices_DP_Data_Loss_Prevention"            = "AI Services"
        "Azure_ComputerVision_DP_Data_Loss_Prevention"        = "Computer Vision"
        "Azure_ContentSafety_DP_Data_Loss_Prevention"         = "Content Safety"
        "Azure_DocumentIntelligence_DP_Data_Loss_Prevention"  = "Document Intelligence"
        "Azure_FaceAPI_DP_Data_Loss_Prevention"               = "Face API"
        "Azure_LanguageService_DP_Data_Loss_Prevention"       = "Language Service"
        "Azure_MultiServiceAccount_DP_Data_Loss_Prevention"   = "Multi-Service Account"
        "Azure_OpenAI_DP_Data_Loss_Prevention"                = "Azure OpenAI"
        "Azure_SpeechService_DP_Data_Loss_Prevention"         = "Speech Service"
    }

    static [string[]] GetAllControlIds() {
        return [CognitiveServicesMapping]::ControlIdToKindMap.Keys
    }

    static [string] GetKindForControlId([string] $ControlId) {
        if ([CognitiveServicesMapping]::ControlIdToKindMap.ContainsKey($ControlId)) {
            return [CognitiveServicesMapping]::ControlIdToKindMap[$ControlId]
        }
        return $null
    }

    static [string] GetDisplayName([string] $ControlId) {
        if ([CognitiveServicesMapping]::DisplayNames.ContainsKey($ControlId)) {
            return [CognitiveServicesMapping]::DisplayNames[$ControlId]
        }
        return $ControlId
    }
}
