<##########################################

# Overview:
    This script is used to configure Managed Service Identity for Azure Cognitive Services accounts in a subscription.
    It enables System-Assigned Managed Identity for authentication across multiple Cognitive Services types.

# Supported Control IDs:
    - Azure_AIServices_AuthN_Use_Managed_Service_Identity
    - Azure_AIServicesMultiServiceAccount_AuthN_Use_Managed_Service_Identity
    - Azure_ComputerVision_AuthN_Use_Managed_Service_Identity
    - Azure_ContentSafety_AuthN_Use_Managed_Service_Identity
    - Azure_DocumentIntelligence_AuthN_Use_Managed_Service_Identity
    - Azure_FaceAPI_AuthN_Use_Managed_Service_Identity
    - Azure_HealthInsights_AuthN_Use_Managed_Service_Identity
    - Azure_ImmersiveReader_AuthN_Use_Managed_Service_Identity
    - Azure_LanguageService_AuthN_Use_Managed_Service_Identity
    - Azure_OpenAI_AuthN_Use_Managed_Service_Identity
    - Azure_SpeechService_AuthN_Use_Managed_Service_Identity
    - Azure_Translator_AuthN_Use_Managed_Service_Identity

# Display Name:
    Managed Service Identity (MSI) must be used in Azure Cognitive Services

# Pre-requisites:
    1. You will need Contributor or higher role on the Cognitive Services accounts in the subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script for subscription.
        2. Prompt user to select the Cognitive Services type (Control ID) to remediate if not provided while calling the script function.
        3. Get the list of Cognitive Services resources matching the selected type from subscription or input CSV file.
        4. Fetch current Managed Identity state for each resource..
        5. Take a backup or snapshot of resources that need remediation.
        6. Enable System-Assigned Managed Identity for non-compliant resources and backup the remediation details.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Cognitive Services resources from the remediation log file.
        3. Validate CSV file Kind matches the selected Control ID.
        4. Restore original Managed Identity configuration for each resource.

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
        1. Run below command to enable Managed Service Identity for Cognitive Services resources (Dry Run):

            Enable-ManagedIdentityForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Run below command to enable Managed Service Identity for a specific Cognitive Services type:

            Enable-ManagedIdentityForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ControlId "Azure_OpenAI_AuthN_Use_Managed_Service_Identity" -PerformPreReqCheck

        3. Run below command to enable Managed Service Identity from a previously generated CSV file:

            Enable-ManagedIdentityForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202410071200\EnableManagedIdentityForOpenAI\OpenAIResourcesWithoutMSI.csv -PerformPreReqCheck

        To know more about parameter execute:
            Get-Help Enable-ManagedIdentityForCognitiveServices -Detailed

    To roll back:
        1. Run below command to disable Managed Service Identity for Cognitive Services resources:

            Disable-ManagedIdentityForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ControlId "Azure_OpenAI_AuthN_Use_Managed_Service_Identity" -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202410071200\EnableManagedIdentityForOpenAI\RemediatedOpenAIResources.csv -PerformPreReqCheck

        To know more about parameter execute:
            Get-Help Disable-ManagedIdentityForCognitiveServices -Detailed

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

function Fetch-API {
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
    $authHeader = "Bearer $token"
    $Headers["Authorization"] = $authHeader
    $Headers["Content-Type"] = "application/json"

    try {
        switch ($Method.ToUpper()) {
            "GET" {
                $response = Invoke-WebRequest -Uri $Uri -Method Get -Headers $Headers -UseBasicParsing -ErrorAction Stop
            }
            "PATCH" {
                $jsonBody = $Body | ConvertTo-Json
                $response = Invoke-WebRequest -Uri $Uri -Method PATCH -Headers $Headers -Body $jsonBody -UseBasicParsing -ErrorAction Stop
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

function Enable-ManagedIdentityForCognitiveServices
{
    <#
        .SYNOPSIS
        Remediates Cognitive Services Managed Identity Controls.

        .DESCRIPTION
        Remediates Cognitive Services Managed Identity Controls.
        Azure Cognitive Services resources must have System-Assigned Managed Identity configured for secure authentication.
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER ControlIds
        Specifies the Control IDs to remediate. If not specified, user will be prompted to select.
        Valid values: Azure_AIFoundry_AuthN_Use_Managed_Service_Identity, Azure_AIServices_AuthN_Use_Managed_Service_Identity, etc.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .INPUTS
        None. You cannot pipe objects to Enable-ManagedIdentityForCognitiveServices.

        .OUTPUTS
        None. Enable-ManagedIdentityForCognitiveServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-ManagedIdentityForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-ManagedIdentityForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ControlIds "Azure_OpenAI_AuthN_Use_Managed_Service_Identity" -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-ManagedIdentityForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202201011212\EnableManagedIdentityForCognitiveServices\ResourcesWithoutMSI.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [String]
        [Parameter(ParameterSetName = "DryRun", HelpMessage="Specifies the Control ID to remediate (only one Control ID allowed at a time)")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the Control ID to remediate (only one Control ID allowed at a time)")]
        [ValidateSet(
            "Azure_AIServices_AuthN_Use_Managed_Service_Identity",
            "Azure_AIServicesMultiServiceAccount_AuthN_Use_Managed_Service_Identity",
            "Azure_ComputerVision_AuthN_Use_Managed_Service_Identity",
            "Azure_ContentSafety_AuthN_Use_Managed_Service_Identity",
            "Azure_DocumentIntelligence_AuthN_Use_Managed_Service_Identity",
            "Azure_FaceAPI_AuthN_Use_Managed_Service_Identity",
            "Azure_HealthInsights_AuthN_Use_Managed_Service_Identity",
            "Azure_ImmersiveReader_AuthN_Use_Managed_Service_Identity",
            "Azure_LanguageService_AuthN_Use_Managed_Service_Identity",
            "Azure_OpenAI_AuthN_Use_Managed_Service_Identity",
            "Azure_SpeechService_AuthN_Use_Managed_Service_Identity",
            "Azure_Translator_AuthN_Use_Managed_Service_Identity"
        )]
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

    $apiVersion = '2023-05-01'

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 6] Prepare to enable Managed Identity for Azure Cognitive Services resources in Subscription: [$($SubscriptionId)]"
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

    Write-Host "To enable Managed Identity for Azure Cognitive Services resources in a Subscription, Contributor or higher privileges on the resources are required." -ForegroundColor $([Constants]::MessageType.Warning)

    
    # Validate user permissions
    $hasPermissions = Validate-UserPermissions -context $context -SubscriptionId $SubscriptionId
    if (-not $hasPermissions) {
        Write-Host "Exiting due to insufficient permissions." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }

    # Step 2: Control ID Selection
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 6] Cognitive Services type to remediate"
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
        
        $selection = Read-Host "Enter your selection (single number, e.g., 1 or 11)"
        
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

    Write-Host "[Step 3 of 6] Fetch all Azure Cognitive Services resources"
    Write-Host $([Constants]::SingleDashLine)

    $cognitiveServicesResourcesType = "Microsoft.CognitiveServices/accounts"
    $cognitiveServicesResources = @()

    # No file path provided as input to the script. Fetch all Azure Cognitive Services resources in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Cognitive Services resources in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        # Get all Cognitive Services accounts in a Subscription
        $allCognitiveServicesAccounts = Get-AzResource -ResourceType $cognitiveServicesResourcesType -ExpandProperties -ErrorAction Stop
        $cognitiveServicesResources = $allCognitiveServicesAccounts | Where-Object { ![String]::IsNullOrWhiteSpace($_.Kind) -and $_.Kind -eq $selectedKind }
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
        $resourceDetails = Import-Csv -LiteralPath $FilePath
        
        # Validate CSV Kind matches Selected Control ID Kind
        # Use foreach to stop at first resource with Kind (efficient for large CSVs)
        $firstResourceWithKind = $null
        foreach ($resource in $resourceDetails) {
            if (![String]::IsNullOrWhiteSpace($resource.Kind)) {
                $firstResourceWithKind = $resource
                break
            }
        }
        
        if ($firstResourceWithKind -and $firstResourceWithKind.Kind -ne $selectedKind) {
            Write-Host "Error: CSV file Kind mismatch detected!" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "  CSV file contains resources of Kind: [$($firstResourceWithKind.Kind)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "  Selected Control ID expects Kind: [$selectedKind]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Please ensure you are using the correct remediation file for the selected Control ID." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }

        foreach ($resource in $resourceDetails) {
            if (![String]::IsNullOrWhiteSpace($resource.ResourceId) -and 
                ![String]::IsNullOrWhiteSpace($resource.Kind) -and 
                $resource.Kind -eq $selectedKind) {
                
                $cognitiveServicesResources += [PSCustomObject]@{
                    ResourceId = $resource.ResourceId
                    ResourceGroupName = $resource.ResourceGroupName
                    ResourceName = $resource.ResourceName
                    Kind = $resource.Kind
                    Location = $resource.Location
                }
            }
        }
    }
    
    $totalCognitiveServicesResources = ($cognitiveServicesResources | Measure-Object).Count

    if ($totalCognitiveServicesResources -eq 0) 
    { 
        Write-Host "No Cognitive Services resource(s) found for selected types. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        return
    }
    
    Write-Host "Found [$($totalCognitiveServicesResources)] Cognitive Services resource(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Targeting Cognitive Services kind: $selectedKind" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $cognitiveServicesResourcesWithoutMSI = @()
    $cognitiveServicesResourcesSkipped = @()

    Write-Host "[Step 4 of 6] Fetching Cognitive Services resource configurations..."
    Write-Host $([Constants]::SingleDashLine)

    $cognitiveServicesResources | ForEach-Object {
        $resource = $_
        $resourceId = $_.ResourceId
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.ResourceName
        $location = $_.Location

        try {
            $identityState = Get-CognitiveServicesManagedIdentityState -ResourceId $resourceId -ApiVersion $apiVersion

            $stateObj = [PSCustomObject]@{
                ResourceId                = $resourceId
                ResourceGroupName         = $resourceGroupName
                ResourceName              = $resourceName
                Kind                      = $_.Kind
                Location                  = $location
                IdentityType              = $identityState.IdentityType
                HasSystemAssignedIdentity = $identityState.HasSystemAssignedIdentity
            }

            if ($stateObj.HasSystemAssignedIdentity -eq $false) {
                $cognitiveServicesResourcesWithoutMSI += $stateObj
            } else {
                $cognitiveServicesResourcesSkipped += $stateObj
            }
        }
        catch {
            Write-Host "Error fetching Cognitive Services resource configuration. Resource Name: [$($resourceName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            $cognitiveServicesResourcesSkipped += [PSCustomObject]@{
                ResourceId = $resourceId
                ResourceGroupName = $resourceGroupName
                ResourceName = $resourceName
                Kind = $_.Kind
                Location = $location
                IdentityType = $null
                HasSystemAssignedIdentity = $null
                Error = $_.Exception.Message
            }
        }
    }

    $totalCognitiveServicesResourcesWithoutMSI = ($cognitiveServicesResourcesWithoutMSI | Measure-Object).Count

    if ($totalCognitiveServicesResourcesWithoutMSI -eq 0) 
    {
        Write-Host "No Cognitive Services resource found without Managed Identity. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        return
    }

    Write-Host "Found [$($totalCognitiveServicesResourcesWithoutMSI)] Cognitive Services resource(s) without Managed Identity." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    $colsProperty = @{Expression={$_.ResourceName};Label="Resource Name";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=25;Alignment="left"},
                    @{Expression={$_.Location};Label="Location";Width=15;Alignment="left"},
                    @{Expression={$_.IdentityType};Label="Identity Type";Width=15;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="Resource ID";Width=120;Alignment="left"}

    Write-Host "Cognitive Services resource(s) without System-Assigned Managed Identity:"
    $cognitiveServicesResourcesWithoutMSI | Format-Table -Property $colsProperty -Wrap
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 5 of 6] Take a backup of resources that need remediation"
    Write-Host $([Constants]::SingleDashLine)

    # Back up snapshots to `%LocalApplicationData%'.
    # Create a dynamic folder name based on the selected Control ID
    $folderName = "EnableManagedIdentityFor$($selectedKind)"
    
    # If FilePath is provided, extract the timestamp from it to reuse the same folder
    # Otherwise, create a new timestamp-based folder
    if (-not [String]::IsNullOrWhiteSpace($FilePath))
    {
        # Extract timestamp from the input file path (e.g., C:\...\202410061430\EnableManagedIdentityForOpenAI\file.csv)
        # Look for pattern: \<12-digit-timestamp>\EnableManagedIdentityFor<Kind>\
        if ($FilePath -match '\\(\d{12})\\EnableManagedIdentityFor\w+\\')
        {
            $timestamp = $matches[1]
            $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($timestamp)\$($folderName)"
            Write-Host "Reusing existing backup folder from input file: [$($backupFolderPath)]" -ForegroundColor $([Constants]::MessageType.Info)
        }
        else
        {
            # Fallback: couldn't extract timestamp, create new one
            $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\$($folderName)"
            Write-Host "Could not extract timestamp from input file path. Creating new backup folder: [$($backupFolderPath)]" -ForegroundColor $([Constants]::MessageType.Warning)
        }
    }
    else
    {
        # No FilePath provided, create new timestamp-based folder
        $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\$($folderName)"
    }

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }


    if (-not $DryRun)
    {
        Write-Host "[Step 6 of 6] Enabling System-Assigned Managed Identity for $($selectedKind) resource(s)..."
        Write-Host $([Constants]::SingleDashLine)
        # Includes Cognitive Services accounts that were skipped during remediation. There were errors remediating them.
        $cognitiveServicesResourcesSkippedDuringRemediation = @()

        Write-Host "System-Assigned Managed Identity will be enabled for all $($selectedKind) resource(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)

        if (-not $Force)
        {
            Write-Host "Do you want to enable System-Assigned Managed Identity for all $($selectedKind) resource(s) listed above? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            $userInput = Read-Host -Prompt "(Y|N)"
            Write-Host $([Constants]::SingleDashLine)

            if ($userInput.ToUpper() -ne "Y")
            {
                Write-Host "System-Assigned Managed Identity will not be enabled for any $($selectedKind) resource. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                return
            }
            Write-Host "User has provided consent to enable System-Assigned Managed Identity for all $($selectedKind) resource(s)." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "'Force' flag is provided. System-Assigned Managed Identity will be enabled for all $($selectedKind) resource(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        # To hold results from the remediation.
        $cognitiveServicesResourcesRemediated = @()

        $cognitiveServicesResourcesWithoutMSI | ForEach-Object {
            $preState = $_
            $resourceId = $_.ResourceId
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName
            $location = $_.Location

            Write-Host "Enabling System-Assigned Managed Identity for $($selectedKind) resource: Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            try {
                $updateResult = Update-CognitiveServicesManagedIdentityState -ResourceId $resourceId -Location $location -EnableSystemAssignedIdentity $true -ApiVersion $apiVersion

                $remediatedResource = [PSCustomObject]@{
                    ResourceId         = $resourceId
                    ResourceGroupName  = $resourceGroupName
                    ResourceName       = $resourceName
                    Kind               = $preState.Kind
                    Location           = $location
                    IdentityType       = $updateResult.IdentityType
                    PrincipalId        = $updateResult.PrincipalId
                }
                $cognitiveServicesResourcesRemediated += $remediatedResource

                Write-Host "Successfully enabled System-Assigned Managed Identity for $($selectedKind) resource: Resource Name: [$($resourceName)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "Principal ID: [$($updateResult.PrincipalId)]" -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }
            catch {
                $cognitiveServicesResourcesSkippedDuringRemediation += $preState

                Write-Host "Error enabling System-Assigned Managed Identity for $($selectedKind) resource: Resource Name: [$($resourceName)]. Error: [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        if (($cognitiveServicesResourcesRemediated | Measure-Object).Count -eq $totalCognitiveServicesResourcesWithoutMSI)
        {
            Write-Host "System-Assigned Managed Identity enabled for all [$($totalCognitiveServicesResourcesWithoutMSI)] $($selectedKind) resource(s)." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "System-Assigned Managed Identity enabled for [$($($cognitiveServicesResourcesRemediated | Measure-Object).Count)] out of [$($totalCognitiveServicesResourcesWithoutMSI)] $($selectedKind) resource(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsPropertyRemediated = @{Expression={$_.ResourceName};Label="Resource Name";Width=30;Alignment="left"},
                                   @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=25;Alignment="left"},
                                   @{Expression={$_.Location};Label="Location";Width=15;Alignment="left"},
                                   @{Expression={$_.IdentityType};Label="Identity Type";Width=20;Alignment="left"},
                                   @{Expression={$_.PrincipalId};Label="Principal ID";Width=40;Alignment="left"},
                                   @{Expression={$_.ResourceId};Label="Resource ID";Width=120;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

        if ($($cognitiveServicesResourcesRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "System-Assigned Managed Identity enabled for the following $($selectedKind) resource(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $cognitiveServicesResourcesRemediated | Format-Table -Property $colsPropertyRemediated -Wrap
            Write-Host $([Constants]::SingleDashLine)

            # Write this to a file.
            $cognitiveServicesResourcesRemediatedFile = "$($backupFolderPath)\Remediated$($selectedKind)Resources.csv"
            $cognitiveServicesResourcesRemediated | Export-CSV -Path $cognitiveServicesResourcesRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to $($cognitiveServicesResourcesRemediatedFile)." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($cognitiveServicesResourcesSkippedDuringRemediation | Measure-Object).Count -gt 0)
        {
            Write-Host "Error enabling System-Assigned Managed Identity for the following $($selectedKind) resource(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $cognitiveServicesResourcesSkippedDuringRemediation | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)

            # Write this to a file.
            $cognitiveServicesResourcesSkippedFile = "$($backupFolderPath)\Skipped$($selectedKind)Resources.csv"
            $cognitiveServicesResourcesSkippedDuringRemediation | Export-CSV -Path $cognitiveServicesResourcesSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($cognitiveServicesResourcesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
        Write-Host "Back up $($selectedKind) resource details..."
        Write-Host $([Constants]::SingleDashLine)
        
        # Backing up Cognitive Services resource details.
        $backupFile = "$($backupFolderPath)\$($selectedKind)ResourcesWithoutMSI.csv"
        $cognitiveServicesResourcesWithoutMSI | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "$($selectedKind) resource(s) details have been backed up to [$($backupFile)]." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun to enable System-Assigned Managed Identity for all $($selectedKind) resource(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Disable-ManagedIdentityForCognitiveServices
{
    <#
        .SYNOPSIS
        Rolls back remediation done for Cognitive Services Managed Identity Controls.

        .DESCRIPTION
        Rolls back remediation done for Cognitive Services Managed Identity Controls.
        Restores the original Managed Identity configuration for Azure Cognitive Services resources in a Subscription as per input file.
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER ControlId
        Specifies the Control ID to rollback. If not specified, user will be prompted to select.
        Valid values: Azure_OpenAI_AuthN_Use_Managed_Service_Identity, Azure_ComputerVision_AuthN_Use_Managed_Service_Identity, etc.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-ManagedIdentityForCognitiveServices.

        .OUTPUTS
        None. Disable-ManagedIdentityForCognitiveServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-ManagedIdentityForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableManagedIdentityForOpenAI\RemediatedOpenAIResources.csv

        .EXAMPLE
        PS> Disable-ManagedIdentityForCognitiveServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ControlId "Azure_OpenAI_AuthN_Use_Managed_Service_Identity" -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableManagedIdentityForOpenAI\RemediatedOpenAIResources.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

        [String]
        [Parameter(HelpMessage="Specifies the Control ID to rollback (only one Control ID allowed at a time)")]
        [ValidateSet(
            "Azure_AIServices_AuthN_Use_Managed_Service_Identity",
            "Azure_AIServicesMultiServiceAccount_AuthN_Use_Managed_Service_Identity",
            "Azure_ComputerVision_AuthN_Use_Managed_Service_Identity",
            "Azure_ContentSafety_AuthN_Use_Managed_Service_Identity",
            "Azure_DocumentIntelligence_AuthN_Use_Managed_Service_Identity",
            "Azure_FaceAPI_AuthN_Use_Managed_Service_Identity",
            "Azure_HealthInsights_AuthN_Use_Managed_Service_Identity",
            "Azure_ImmersiveReader_AuthN_Use_Managed_Service_Identity",
            "Azure_LanguageService_AuthN_Use_Managed_Service_Identity",
            "Azure_OpenAI_AuthN_Use_Managed_Service_Identity",
            "Azure_SpeechService_AuthN_Use_Managed_Service_Identity",
            "Azure_Translator_AuthN_Use_Managed_Service_Identity"
        )]
        $ControlId,

        [Switch]
        [Parameter(HelpMessage="Specifies a forceful roll back without any prompts")]
        $Force,

        [Switch]
        [Parameter(HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the path to the file to be used as input for the roll back")]
        $FilePath
    )

    $apiVersion = '2023-05-01'

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Prepare to restore Managed Identity configuration for Azure Cognitive Services resources in Subscription: [$($SubscriptionId)]"
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

    # Connect to Azure account
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

    Write-Host "To restore Managed Identity configuration for Azure Cognitive Services resources in a Subscription, Contributor or higher privileges on the resources are required." -ForegroundColor $([Constants]::MessageType.Warning)
    
    # Validate user permissions
    Write-Host "Validating whether the current user [$($context.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."
    $hasPermissions = Validate-UserPermissions -context $context -SubscriptionId $SubscriptionId
    if (-not $hasPermissions) {
        Write-Host "Exiting due to insufficient permissions." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }

    # Step 2: Control ID Selection
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Cognitive Services type to rollback"
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
        
        $selection = Read-Host "Enter your selection (single number, e.g., 1 or 11)"
        
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

    Write-Host "[Step 3 of 4] Fetch all $($selectedKind) resources from input file"
    Write-Host $([Constants]::SingleDashLine)

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }

    Write-Host "Fetching all $($selectedKind) resources from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $cognitiveServicesResourceDetails = Import-Csv -LiteralPath $FilePath
    
    # Validate CSV Kind matches Selected Control ID Kind
    # Use foreach to stop at first resource with Kind (efficient for large CSVs)
    $firstResourceWithKind = $null
    foreach ($resource in $cognitiveServicesResourceDetails) {
        if (![String]::IsNullOrWhiteSpace($resource.Kind)) {
            $firstResourceWithKind = $resource
            break
        }
    }
    
    if ($firstResourceWithKind -and $firstResourceWithKind.Kind -ne $selectedKind) {
        Write-Host "Error: CSV file Kind mismatch detected!" -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host "  CSV file contains resources of Kind: [$($firstResourceWithKind.Kind)]" -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host "  Selected Control ID expects Kind: [$selectedKind]" -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host "Please ensure you are using the correct rollback file for the selected Control ID." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::SingleDashLine)
        return
    }
    
    $validCognitiveServicesResourceDetails = $cognitiveServicesResourceDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalCognitiveServicesResources = ($validCognitiveServicesResourceDetails | Measure-Object).Count

    if ($totalCognitiveServicesResources -eq 0)
    {
        Write-Host "No $($selectedKind) resources found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }

    Write-Host "Found [$($totalCognitiveServicesResources)] $($selectedKind) resource(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DisableManagedIdentityFor$($selectedKind)"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
    
    if (-not $Force)
    {
        Write-Host "Do you want to restore the original Managed Identity configuration for all $($selectedKind) resources? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "Managed Identity configuration will not be restored for any $($selectedKind) resource. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "User has provided consent to restore Managed Identity configuration for all $($selectedKind) resources." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. Managed Identity configuration will be restored for all $($selectedKind) resources without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 4 of 4] Restore Managed Identity configuration for $($selectedKind) resources"
    Write-Host $([Constants]::SingleDashLine)
    
    # Includes Cognitive Services resources, to which, previously made changes were successfully rolled back.
    $cognitiveServicesResourcesRolledBack = @()

    # Includes Cognitive Services resources that were skipped during roll back. There were errors rolling back the changes made previously.
    $cognitiveServicesResourcesSkipped = @()

    $validCognitiveServicesResourceDetails | ForEach-Object {
        $cognitiveServicesResource = $_
        $resourceId = $cognitiveServicesResource.ResourceId
        $resourceGroupName = $cognitiveServicesResource.ResourceGroupName
        $resourceName = $cognitiveServicesResource.ResourceName
        $originalIdentityType = $cognitiveServicesResource.IdentityType
        $location = $cognitiveServicesResource.Location

        try {
            Write-Host "Restoring Managed Identity configuration for $($selectedKind) resource: Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host "Original Identity Type: [$($originalIdentityType)]" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            $enableMSI = $false
            $updateResult = Update-CognitiveServicesManagedIdentityState -ResourceId $resourceId -Location $location -EnableSystemAssignedIdentity $enableMSI -ApiVersion $apiVersion

            $cognitiveServicesResourcesRolledBack += [PSCustomObject]@{
                ResourceID                    = $resourceId
                ResourceGroupName             = $resourceGroupName
                ResourceName                  = $resourceName
                Location                      = $location
                IdentityTypePostRollback      = $updateResult.IdentityType
                OriginalIdentityType          = $originalIdentityType
            }
            Write-Host "Successfully restored Managed Identity configuration for $($selectedKind) resource." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch {
            $cognitiveServicesResourcesSkipped += [PSCustomObject]@{
                ResourceID                    = $resourceId
                ResourceGroupName             = $resourceGroupName
                ResourceName                  = $resourceName
                Location                      = $location
                IdentityTypePostRollback      = 'Unknown'
                OriginalIdentityType          = $originalIdentityType
                Error                         = $_.Exception.Message
            }
            Write-Host "Error restoring Managed Identity configuration for $($selectedKind) resource: [$($resourceName)]. Error: [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
        }
    }

    if (($cognitiveServicesResourcesSkipped | Measure-Object).Count -eq 0)
    {
        Write-Host "Managed Identity configuration successfully restored for all [$($totalCognitiveServicesResources)] $($selectedKind) resource(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Managed Identity configuration successfully restored for [$($($cognitiveServicesResourcesRolledBack | Measure-Object).Count)] out of [$($totalCognitiveServicesResources)] $($selectedKind) resource(s)." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    $colsProperty = @{Expression={$_.ResourceName};Label="Resource Name";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=25;Alignment="left"},
                    @{Expression={$_.Location};Label="Location";Width=15;Alignment="left"},
                    @{Expression={$_.OriginalIdentityType};Label="Original Identity";Width=20;Alignment="left"},
                    @{Expression={$_.IdentityTypePostRollback};Label="Post-Rollback Identity";Width=25;Alignment="left"},
                    @{Expression={$_.ResourceID};Label="Resource ID";Width=120;Alignment="left"}

    
    Write-Host $([Constants]::DoubleDashLine)
    if($($cognitiveServicesResourcesRolledBack | Measure-Object).Count -gt 0 -or $($cognitiveServicesResourcesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
    }
    
    if ($($cognitiveServicesResourcesRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "Managed Identity configuration successfully restored for the following $($selectedKind) resource(s):" -ForegroundColor $([Constants]::MessageType.Update)
        $cognitiveServicesResourcesRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
        # Write this to a file.
        $cognitiveServicesResourcesRolledBackFile = "$($backupFolderPath)\RolledBack$($selectedKind)Resources.csv"
        $cognitiveServicesResourcesRolledBack | Export-CSV -Path $cognitiveServicesResourcesRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to [$($cognitiveServicesResourcesRolledBackFile)]." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($($cognitiveServicesResourcesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error restoring Managed Identity configuration for the following $($selectedKind) resource(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $cognitiveServicesResourcesSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
        # Write this to a file.
        $cognitiveServicesResourcesSkippedFile = "$($backupFolderPath)\RollbackSkipped$($selectedKind)Resources.csv"
        $cognitiveServicesResourcesSkipped | Export-CSV -Path $cognitiveServicesResourcesSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to [$($cognitiveServicesResourcesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Get-CognitiveServicesManagedIdentityState {
    <#
        .SYNOPSIS
        Returns the Managed Identity state for a given Azure Cognitive Services account.
        .OUTPUTS
        [PSCustomObject] Object with IdentityType, HasSystemAssignedIdentity, and PrincipalId properties.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ResourceId,
        
        [Parameter(Mandatory=$false)]
        [string]$ApiVersion = '2023-05-01'
    )
    
    $base = (Get-AzContext).Environment.ResourceManagerUrl.TrimEnd('/')
    $uri = "$($base)$($ResourceId)?api-version=$($ApiVersion)"
    
    try {
        $response = Fetch-API -Method "GET" -Uri $uri
        
        $identityType = $null
        $principalId = $null
        $hasSystemAssignedIdentity = $false

        if ($response.identity) {
            $identityType = $response.identity.type
            $principalId = $response.identity.principalId
            # Check if identity type contains "SystemAssigned" OR "UserAssigned"
            # Valid values: "SystemAssigned", "SystemAssigned,UserAssigned", "UserAssigned"
            # All three should return TRUE as they indicate Managed Identity is configured
            if (![String]::IsNullOrWhiteSpace($identityType)) {
                $trimmedType = $identityType.Trim()
                $hasSystemAssignedIdentity = ($trimmedType -match '\b(SystemAssigned|UserAssigned)\b')
            }
        }

        return [PSCustomObject]@{
            IdentityType              = $identityType
            HasSystemAssignedIdentity = $hasSystemAssignedIdentity
            PrincipalId               = $principalId
        }
    }
    catch {
        throw "Failed to read Managed Identity state for [$ResourceId]. Error: $($_.Exception.Message)"
    }
}

function Update-CognitiveServicesManagedIdentityState {
    <#
        .SYNOPSIS
        Updates the Managed Identity configuration on an Azure Cognitive Services account.
        .DESCRIPTION
        Enables or disables System-Assigned Managed Identity on a Cognitive Services resource.
        Returns the updated state for verification.
        .OUTPUTS
        [PSCustomObject] Object with IdentityType, PrincipalId, and Succeeded properties.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ResourceId,

        [Parameter(Mandatory=$true)]
        [string]$Location,

        [Parameter(Mandatory=$true)]
        [bool]$EnableSystemAssignedIdentity,

        [Parameter(Mandatory=$false)]
        [string]$ApiVersion = '2023-05-01'
    )

    $base = (Get-AzContext).Environment.ResourceManagerUrl.TrimEnd('/')
    $uri = "$($base)$($ResourceId)?api-version=$($ApiVersion)"

    try {
        # Construct the payload with location and identity
        if ($EnableSystemAssignedIdentity) {
            $payload = @{
                location = $Location
                identity = @{
                    type = "SystemAssigned"
                }
            }
        } else {
            $payload = @{
                location = $Location
                identity = @{
                    type = "None"
                }
            }
        }

        # Update the resource
        $response = Fetch-API -Method "PATCH" -Uri $uri -Body $payload
        
        # Return the new state
        return [PSCustomObject]@{
            IdentityType = $response.identity.type
            PrincipalId  = $response.identity.principalId
            Succeeded    = $true
        }
    }
    catch {
        throw "Failed to update Managed Identity for [$ResourceId]. Error: $($_.Exception.Message)"
    }
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

# Mapping of Control IDs to Cognitive Services 'kind' values
class CognitiveServicesMapping {
    static [Hashtable] $ControlIdToKindMap = @{
        "Azure_AIServices_AuthN_Use_Managed_Service_Identity"                     = "AIServices"
        "Azure_AIServicesMultiServiceAccount_AuthN_Use_Managed_Service_Identity"  = "CognitiveServices"
        "Azure_ComputerVision_AuthN_Use_Managed_Service_Identity"                 = "ComputerVision"
        "Azure_ContentSafety_AuthN_Use_Managed_Service_Identity"                  = "ContentSafety"
        "Azure_DocumentIntelligence_AuthN_Use_Managed_Service_Identity"           = "FormRecognizer"
        "Azure_FaceAPI_AuthN_Use_Managed_Service_Identity"                        = "Face"
        "Azure_HealthInsights_AuthN_Use_Managed_Service_Identity"                 = "HealthInsights"
        "Azure_ImmersiveReader_AuthN_Use_Managed_Service_Identity"                = "ImmersiveReader"
        "Azure_LanguageService_AuthN_Use_Managed_Service_Identity"                = "TextAnalytics"
        "Azure_OpenAI_AuthN_Use_Managed_Service_Identity"                         = "OpenAI"
        "Azure_SpeechService_AuthN_Use_Managed_Service_Identity"                  = "SpeechServices"
        "Azure_Translator_AuthN_Use_Managed_Service_Identity"                     = "TextTranslation"
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
}
