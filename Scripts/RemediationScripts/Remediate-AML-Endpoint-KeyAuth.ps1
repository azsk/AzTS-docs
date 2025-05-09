<##########################################

# Overview:
    This script is used to configure AAD Token Authentication for Azure Machine Learning Workspace Online Endpoints on a subscription.

# ControlId: 
    Azure_MachineLearningWorkspace_AuthN_Restrict_Key_Based_AuthType_OnlineEndPoints

# Pre-requisites:
    1. You will need Owner or Contributor role on subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Install and validate pre-requisites to run the script for subscription.
        2. Get the list of online endpoints for each resource group from subscription.
        3. Take a backup of these non-compliant resource types.
    
    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of online endpoints in a Subscription, the changes made to which previously, are to be rolled back.
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
        1. Run below command to setup AAD Token auth for online endpoints in machine learning workspace. 
           
            Enable-AADTokenBasedAuthForMLWorkspaceOnlineEndpoint -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck
        
        To know more about parameter execute:
            Get-Help Enable-AADTokenBasedAuthForMLWorkspaceOnlineEndpoint -Detailed
            
        To roll back:
        1. Run below command to roll back AAD Token auth for online endpoints in machine learning workspace. 
           
            Disable-AADTokenBasedAuthForMLWorkspaceOnlineEndpoint -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath  C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\MachineLearningWorkspace\nonCompliantOnlineEndpoints.json
        
        To know more about parameter execute:
   
            Get-Help Disable-AADTokenBasedAuthForMLWorkspaceOnlineEndpoint -Detailed

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
                $jsonBody = $Body | ConvertTo-Json
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

function Enable-AADTokenBasedAuthForMLWorkspaceOnlineEndpoint {
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_MachineLearningWorkspace_AuthN_Restrict_Key_Based_AuthType_OnlineEndPoints' control.
    
    .DESCRIPTION
    This command would help in remediating 'Azure_MachineLearningWorkspace_AuthN_Restrict_Key_Based_AuthType_OnlineEndPoints' control.
    
    .PARAMETER SubscriptionId
    Enter subscription id on which remediation needs to be performed.


    .OUTPUTS
    None. Enable-AADTokenBasedAuthForMLWorkspaceOnlineEndpoint does not return anything that can be piped and used as an input to another command.

    .EXAMPLE
    PS> Enable-AADTokenBasedAuthForMLWorkspaceOnlineEndpoint -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Enter subscription id for remediation")]
        $SubscriptionId,

        [Switch]
        [Parameter(HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck
    )
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script..."
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck) {
        try {
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
            Write-Host $([Constants]::SingleDashLine)
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

    # Safe Check: Checking whether the current account is of type User
    if ($context.Account.Type -ne "User") {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    # Safe Check: Current user needs to be either or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/$($SubscriptionId)";
    $roles = $currentLoginRoleAssignments | Where { ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor" -or $_.RoleDefinitionName -eq "Security Admin" ) -and !($_.Scope -like "/subscriptions/$($SubscriptionId)/resourceGroups") }

    if (($roles | Measure-Object).Count -le 0) {
        Write-Host "Warning: This script can only be run by Owner or Contributor or Security Admin of the subscription [$($SubscriptionId)] " -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }
        
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3]: Checking Machine Learning Workspaces in each resource group..."
    Write-Host $([Constants]::SingleDashLine)

    $nonCompliantEndpoints = @()
    # Get All Resource Groups
    $resourceGroups = Get-AzResourceGroup | Select ResourceGroupName
    $resourceGroups = @(@{ ResourceGroupName = "RahulJTestRG" })

    foreach ($rg in $resourceGroups) {
        $ResourceGroupName = $rg.ResourceGroupName
        $workspacesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.MachineLearningServices/workspaces?api-version=2023-04-01"
        $workspaceList = Fetch-API -Method "GET" -Uri $workspacesUri

        foreach ($workspace in $workspaceList.Value) {
            $WorkspaceName = $workspace.Name
            Write-Host "`nChecking Online Endpoints in [$WorkspaceName] workspace..."

            $endpointUri   = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.MachineLearningServices/workspaces/$WorkspaceName/onlineEndpoints?api-version=2023-04-01"
            $onlineEndpoints = Fetch-API -Method "GET" -Uri $endpointUri
            $endpointsCount = $onlineEndpoints.Value.Count

            if($endpointsCount -ge 1){
                $endpointSuffix = if($endpointsCount -ne 1) {'s'} else {''}
                Write-Host "[$($endpointsCount)] Online Endpoint$($endpointSuffix) found in [$($ResourceGroupName)] resource group." -ForegroundColor $([Constants]::MessageType.Info)
            }else{
                Write-Host "No Online Endpoints found in [$($ResourceGroupName)] resource group." -ForegroundColor $([Constants]::MessageType.Info)
                continue
            }
            foreach ($endpoint in $onlineEndpoints.Value) {
                if($endpoint.properties.authMode -eq "Key"){
                    $endpointName = $endpoint.name
                    $endpointLocation = $endpoint.location
                    $resolutionUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.MachineLearningServices/workspaces/$WorkspaceName/onlineEndpoints/$endpointName" + "?api-version=2023-04-01"

                    $body = @{
                                location = $endpointLocation
                                properties = @{
                                    authMode = "AADToken"
                                }
                            }

                    try {
                        Write-Host "`nSetting auth type as AAD Token for [$endpointName] endpoint..." -ForegroundColor Cyan
                        $resBody = Fetch-API -Method "PUT" -Uri $resolutionUri -Body $body
                        Write-Host "`nSuccessfully set auth type for [$endpointName] endpoint." -ForegroundColor Green
                        $backupEndpoint = @{
                            ResourceGroupName = $ResourceGroupName
                            WorkspaceName = $WorkspaceName
                            EndpointName   = $endpointName
                            Location      = $endpoint.location
                        }
                        $nonCompliantEndpoints += $backupEndpoint
                    }
                    catch {
                        Write-Host "Error occurred while setting auth type for [$($endpointName)] endpoint in [$($ResourceGroupName)] resource group. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    }
                    Write-Host $([Constants]::SingleDashLine)
                }
                else{
                    Write-Host "[$($endpoint.name)] endpoint already does not use Key Auth." -ForegroundColor Green
                }
            }
        }
    }

    $nonCompliantEndpointsCount = ($nonCompliantEndpoints | Measure-Object).Count

    # If control is already in Passed state (i.e. no non-compliant online endpoints are found) then no need to execute below steps.
    if ($nonCompliantEndpointsCount -eq 0) {
        Write-Host "`n`nNo online endpoints using key-based authentication were found or no endpoint resource exist."  -ForegroundColor Cyan
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "`n[$($nonCompliantEndpointsCount)] endpoints remediated." -ForegroundColor Green
    
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "`n[Step 3 of 3] Backing up resource type details..."
    Write-Host $([Constants]::SingleDashLine)
   
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\MachineLearningWorkspace"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    $backup = New-Object psobject -Property @{
        SubscriptionId = $SubscriptionId
    }
    $backup | Add-Member -Name "nonCompliantEndpoints" -Type NoteProperty -Value $nonCompliantEndpoints

    # Backing up resource type details.
    $backupFile = "$($backupFolderPath)\nonCompliantEndpoints.json"
    $backup | ConvertTo-Json | Out-File -FilePath $backupFile

    Write-Host "Resource type details have been backed up to" -NoNewline
    Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Remediation successfull" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
}

function Disable-AADTokenBasedAuthForMLWorkspaceOnlineEndpoint {
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_MachineLearningWorkspace_AuthN_Restrict_Key_Based_AuthType_OnlineEndPoints' control.
    
    .DESCRIPTION
    This command would help in remediating 'Azure_MachineLearningWorkspace_AuthN_Restrict_Key_Based_AuthType_OnlineEndPoints' control.
    
    .PARAMETER SubscriptionId
    Specifies the ID of the Subscription that was previously remediated.
    
    .Parameter PerformPreReqCheck
    Specifies validation of prerequisites for the command.
    
    .PARAMETER FilePath
    Specifies the path to the file to be used as input for the roll back.

    .EXAMPLE
    PS> Disable-AADTokenBasedAuthForMLWorkspaceOnlineEndpoint -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath  C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\MachineLearningWorkspace\nonCompliantEndpoints.json -PerformPreReqCheck
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
    Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script..."
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck) {
        try {
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
            Write-Host $([Constants]::SingleDashLine)
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

    # Safe Check: Checking whether the current account is of type User
    if ($context.Account.Type -ne "User") {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor $([Constants]::MessageType.Warning)
        return;
    }

    # Safe Check: Current user needs to be either Contributor or Owner or Security Admin for the subscription
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

    $TotalEndpoints = $remediatedLog.nonCompliantEndpoints.Count
    $RollbackSuccess = 0
    $RollbackFailed = 0

    foreach($endpoint in $remediatedLog.nonCompliantEndpoints) {
        $ResourceGroupName = $endpoint.ResourceGroupName
        $EndpointName = $endpoint.EndpointName
        $WorkspaceName = $endpoint.WorkspaceName
        $EndpointLocation = $endpoint.Location
        Write-Host "Rolling back [$($EndpointName)] endpoint in [$($ResourceGroupName)] resource group..." -ForegroundColor $([Constants]::MessageType.Info)
        $rollbackUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.MachineLearningServices/workspaces/$WorkspaceName/onlineEndpoints/$endpointName" + "?api-version=2023-04-01"

        $body = @{
                    location = $EndpointLocation
                    properties = @{
                        authMode = "Key"
                    }
                }

        try {
            Fetch-API -Method "PUT" -Uri $rollbackUri -Body $body
            $RollbackSuccess++
        }
        catch {
            Write-Host "Error occurred while rolling back [$($EndpointName)] endpoint in [$($ResourceGroupName)] resource group. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            $RollbackFailed++
        }
    }

    Write-Host $([Constants]::DoubleDashLine)
    if($RollbackFailed -eq $TotalEndpoints) {
        Write-Host "Rollback operation Failed." -ForegroundColor $([Constants]::MessageType.Error)
    }
    else{
        if($RollbackSuccess -eq $TotalEndpoints) {
            Write-Host "Rollback operation Completed Successfully." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else{
            Write-Host "Rollback operation Completed partially." -ForegroundColor $([Constants]::MessageType.Warning)
        }
    }
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