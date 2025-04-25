<##########################################

# Overview:
    This script is used to configure Managed Service Identity for Azure Machine Learning Workspace on subscription.

# ControlId: 
    Azure_MachineLearningWorkspace_AuthN_Use_Managed_Service_Identity

# Pre-requisites:
    1. You will need Owner or Contributor role on subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Install and validate pre-requisites to run the script for subscription.
        2. Get the list of compute resources for each resource group from subscription.
        3. Take a backup of these non-compliant resource types.
    
    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of compute resources in a Subscription, the changes made to which previously, are to be rolled back.
        3. Roll back resource type in the Subscription.

# Step to execute script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remediate resource type in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to rollback on all resource type in the Subscription. Refer `Examples`, below.

# Command to execute:
    To remediate:
        1. Run below command to enable Managed Service Identity for computes in machine learning workspace. 
           
            Enable-ManagedIdentityForMachineLearningWorkpace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck
        
        To know more about parameter execute:
            Get-Help Enable-ManagedIdentityForMachineLearningWorkpace -Detailed
            
        To roll back:
        1. Run below command to disable Managed Service Identity for computes in machine learning workspace. 
           
            Disable-ManagedIdentityForMachineLearningSpace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath  C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\MachineLearningWorkspace\nonCompliantComputes.json
        
        To know more about parameter execute:
   
            Get-Help Disable-ManagedIdentityForMachineLearningSpace -Detailed

########################################
#>
function Setup-Prerequisites {
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
    $accessToken = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl
    $authHeader = "Bearer " + $accessToken.Token
    $Headers["Authorization"] = $authHeader
    $Headers["Content-Type"] = "application/json"

    try {
        switch ($Method.ToUpper()) {
            "GET" {
                $response = Invoke-WebRequest -Uri $Uri -Method Get -Headers $Headers -UseBasicParsing -ErrorAction Stop
            }
            "PATCH" {
                $jsonBody = $Body | ConvertTo-Json
                $response = Invoke-WebRequest -Uri $Uri -Method Patch -Headers $Headers -Body $jsonBody -UseBasicParsing -ErrorAction Stop
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
    }
}



function Enable-ManagedIdentityForMachineLearningWorkpace {
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_MachineLearningWorkspace_AuthN_Use_Managed_Service_Identity' control.
    
    .DESCRIPTION
    This command would help in remediating 'Azure_MachineLearningWorkspace_AuthN_Use_Managed_Service_Identity' control.
    
    .PARAMETER SubscriptionId
    Enter subscription id on which remediation needs to be performed.

    .PARAMETER Force
    Specifies a forceful remediation without any prompts.
    
   
    .INPUTS
    None. You cannot pipe objects to  Enable-MicrosoftDefender.

    .OUTPUTS
    None. Configure-ManagedIdentityForMachineLearningWorkpace does not return anything that can be piped and used as an input to another command.

    .EXAMPLE
    PS> Configure-ManagedIdentityForMachineLearningWorkpace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck
    #>

    param (
        [string]
        [Parameter(ParameterSetName = "EnableSelected", Mandatory = $true, HelpMessage = "Enter subscription id for remediation")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "EnableSelected", HelpMessage = "Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "EnableAll", HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck
    )
   
    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script..."
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
        Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script..."
        Write-Host $([Constants]::SingleDashLine)
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

    # Safe Check: Checking whether the current account is of type User
    if ($context.Account.Type -ne "User") {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    # Safe Check: Current user needs to be either or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)";
    $roles = $currentLoginRoleAssignments | Where { ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Security Admin" ) -and !($_.Scope -like "/subscriptions/$($SubscriptionId)/resourceGroups") }

    if (($roles | Measure-Object).Count -le 0) {
        Write-Host "Warning: This script can only be run by an Owner of subscription [$($SubscriptionId)] " -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }
    
    

    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3]: Checking compute resources in each machine learning workspace..."
    Write-Host $([Constants]::SingleDashLine)






    $nonCompliantComputes = @()
    # Get All Resource Groups
    $resourceGroups = Get-AzResourceGroup | Select ResourceGroupName

    foreach ($rg in $resourceGroups) {
        $ResourceGroupName = $rg.ResourceGroupName
        $assessmentUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.MachineLearningServices/workspaces?api-version=2021-04-01"
        $workspaceList = Fetch-API -Method "GET" -Uri $assessmentUri
        foreach ($workspace in $workspaceList.Value) {
            $WorkspaceName = $workspace.Name
            $assessmentUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.MachineLearningServices/workspaces/$WorkspaceName/computes?api-version=2021-04-01"
            $computeResources = Fetch-API -Method "GET" -Uri $assessmentUri
            foreach ($compute in $computeResources.Value) {
                if($compute.identity.type -ne "SystemAssigned"){
                    $ComputeName = $compute.name
                    $assessmentUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.MachineLearningServices/workspaces/$WorkspaceName/computes/" + "$ComputeName" + "?api-version=2021-04-01"
                    $body = @{
                        identity   = @{
                            type = "SystemAssigned"
                        }
                        properties = @{
                            computeLocation = $compute.location
                        }
                    }
                    $resBody = Fetch-API -Method "PATCH" -Uri $assessmentUri -Body $body
                    $backupCompute = @{
                        ResourceGroupName = $ResourceGroupName
                        WorkspaceName = $WorkspaceName
                        ComputeName   = $ComputeName
                        Location      = $compute.location
                    }
                    $nonCompliantComputes += $backupCompute
                    }
                
            }
        }
    }

    $nonCompliantComputesCount = ($nonCompliantComputes | Measure-Object).Count

    # If control is already in Passed state (i.e. 'Microsoft.Security' provider is already registered and no non-compliant resource types are found) then no need to execute below steps.
    if ($nonCompliantComputesCount -eq 0) {
        Write-Host "All Computes already assigned a Managed Identity or no any compute found"  -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($nonCompliantComputesCount)] computes to be remediated"

    $colsProperty = @{Expression = { $_.Name }; Label = "Name"; Width = 40; Alignment = "left" },
    @{Expression = { $_.Location }; Label = "Location"; Width = 40; Alignment = "left" },
    @{Expression = { $_.WorkspaceName }; Label = "Workspace Name"; Width = 80; Alignment = "left" }
       
       

    $nonCompliantComputes | Format-Table -Property $colsProperty -Wrap
    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Backing up resource type details..."
    Write-Host $([Constants]::SingleDashLine)
   
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\MachineLearningWorkspace"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    $backup = New-Object psobject -Property @{
        SubscriptionId = $SubscriptionId
    }
    $backup | Add-Member -Name "nonCompliantComputes" -Type NoteProperty -Value $nonCompliantComputes

    # Backing up resource type details.
    $backupFile = "$($backupFolderPath)\NonCompliantComputes.json"
    $backup | ConvertTo-Json | Out-File -FilePath $backupFile

    Write-Host "Resource type details have been backed up to" -NoNewline
    Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Remediation successfull" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
}


function Disable-ManagedIdentityForMachineLearningSpace {
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_MachineLearningWorkspace_AuthN_Use_Managed_Service_Identity' control.
    
    .DESCRIPTION
    This command would help in remediating 'Azure_MachineLearningWorkspace_AuthN_Use_Managed_Service_Identity' control.
    
    .PARAMETER SubscriptionId
    Specifies the ID of the Subscription that was previously remediated.
    
    .Parameter PerformPreReqCheck
    Specifies validation of prerequisites for the command.
    
    .PARAMETER FilePath
    Specifies the path to the file to be used as input for the roll back.

    .EXAMPLE
    PS> Disable-ManagedIdentityForMachineLearningSpace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath  C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\MachineLearningWorkspace\nonCompliantComputes.json
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Enter subscription id to perform rollback operation")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "File path which contain logs generated by remediation script to rollback remediation changes")]
        $FilePath,

        [Switch]
        [Parameter(HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck
    )

    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script..."
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
        Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script..."
        Write-Host $([Constants]::SingleDashLine)
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

    # Safe Check: Checking whether the current account is of type User
    if ($context.Account.Type -ne "User") {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    # Safe Check: Current user needs to be either  or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    if (($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Security Admin" -or $_.RoleDefinitionName -eq "Contributor" -and !($_.Scope -like "/subscriptions/$($SubscriptionId)/resourceGroups") } | Measure-Object).Count -le 0) {
        Write-Host "Warning: This script can only be run by an Owner or Contributor of subscription [$($SubscriptionId)] " -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3]: Fetching remediation log to perform rollback operation to workspaces for subscription [$($SubscriptionId)]..."
    Write-Host $([Constants]::SingleDashLine)

    # Array to store resource context
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "Warning: Rollback file is not found. Please check if the initial Remediation script has been run from the same machine. Exiting the process" -ForegroundColor $([Constants]::MessageType.Warning)
        break;        
    }

    $remediatedLog = Get-Content -Raw -Path $FilePath | ConvertFrom-Json

    Write-Host "Step 3 of 3: Performing rollback operation to Disable Managed Service Identity for subscription [$($SubscriptionId)]..."
        

    Write-Host $([Constants]::SingleDashLine)
    foreach($compute in $remediatedLog.nonCompliantComputes) {
    Write-Host $compute.ComputeName -ForegroundColor Red
        $ResourceGroupName = $compute.ResourceGroupName
        $ComputeName = $compute.ComputeName
        $WorkspaceName = $compute.WorkspaceName
        Write-Host "Rolling back [$($ComputeName)] compute in [$($ResourceGroupName)] resource group..." -ForegroundColor $([Constants]::MessageType.Update)
        $assessmentUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.MachineLearningServices/workspaces/$WorkspaceName/computes/" + "$ComputeName" + "?api-version=2021-04-01"
        $body = @{
            identity   = @{
                type = "None"
            }
            properties = @{
                computeLocation = $compute.Location
            }
        }
        try {
            Fetch-API -Method "PATCH" -Uri $assessmentUri -Body $body
        }
        catch {
            Write-Host "Error occurred while rolling back [$($ComputeName)] compute in [$($ResourceGroupName)] resource group. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Rollback operation completed successfully." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
}

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