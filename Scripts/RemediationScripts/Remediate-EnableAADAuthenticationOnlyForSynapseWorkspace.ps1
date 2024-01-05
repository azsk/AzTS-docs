<###
# Overview:
    This script is used to Enable Azure AD Only Authentication for Synapse workspace in a Subscription.

# Control ID:
    Azure_SynapseWorkspace_AuthN_SQL_Pools_Use_AAD_Only_Trial

# Display Name:
    Use AAD Only Authentication for Synapse workspace

# Prerequisites:
    Contributor and higher privileges on the Synapse workspace in a Subscription.

# NOTE: Please run the script using -DryRun Switch and provide the output file of -DryRun switch as input for actual remediation.
    
# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script and validate the user.
        2. Get the list of Synapse workspaces in a Subscription that do not have Azure AD Only Authentication enabled.
        3. Back up details of Synapse workspace that are going to be remediated.
        4. Enable Azure AD Only Authentication on the Synapse workspaces in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Synapse workspace in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable Azure AD Only Authentication on the Synapse workspace in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable Azure AD Only Authentication on the Synapse workspaces in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable Azure AD Only Authentication on the Synapse workspaces in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Synapse workspace details in a Subscription that will be remediated:

           Enable-AADOnlyAuthenticationForSynapseWorkspace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        2. To review the Synapse workspace details in a Subscription that will be remediated with pre-requisites check:

           Enable-AADOnlyAuthenticationForSynapseWorkspace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun -PerformPreReqCheck

        3. To enable Azure AD Only Authentication on the Synapse workspaces in a Subscription, from a previously taken snapshot:

           Enable-AADOnlyAuthenticationForSynapseWorkspace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForsynapseWorkspaces\SynapseWorkspaceWithADAdminDisabled.csv

        To know more about the options supported by the remediation command, execute:

        Get-Help Enable-AADOnlyAuthenticationForSynapseWorkspace -Detailed

    To roll back:
        1. To disable Azure AD Only Authentication on the Synapse workspaces in a Subscription, from a previously taken snapshot:

           Disable-AADOnlyAuthenticationForSynapseWorkspaces -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForsynapseWorkspaces\RemediatedSynapseWorkspace.csv

        To know more about the options supported by the roll back command, execute:

        Get-Help Disable-AADOnlyAuthenticationForSynapseWorkspaces -Detailed
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
    $requiredModules = @("Az.Accounts", "Az.Resources")

    Write-Host "Required modules: $($requiredModules -join ', ')", "Az.Synapse" -ForegroundColor $([Constants]::MessageType.Info)
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

    # Checking if 'Az.Synapse' module >=1.5.0 is available and installing otherwisee.
    Write-Host "Checking if Az.Synapse>=1.5.0 is present..."

    $azSynapse = Get-InstalledModule -Name "Az.Synapse" -MinimumVersion 1.5.0 -ErrorAction SilentlyContinue
    if(($azSynapse|Measure-Object).Count -eq 0)
    {
        Write-Host "Installing module Az.Synapse with version 1.5.0..." -ForegroundColor $([Constants]::MessageType.Warning)
        Install-Module -Name Az.Synapse -Scope CurrentUser -Repository 'PSGallery' -MinimumVersion 1.5.0 -Force
    }
    else
    {
        Write-Host "Az.Synapse module of required version is available." -ForegroundColor $([Constants]::MessageType.Update)
    }
}

function Enable-AADOnlyAuthenticationForSynapseWorkspace
{
    <#
        .SYNOPSIS
        Remediates 'Azure_SynapseWorkspace_AuthN_SQL_Pools_Use_AAD_Only_Trial' Control.

        .DESCRIPTION
        Remediates 'Azure_SynapseWorkspace_AuthN_SQL_Pools_Use_AAD_Only_Trial' Control.
        Azure AD Only Authentication must be enabled.

        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .EXAMPLE
        PS> Enable-AADOnlyAuthenticationForSynapseWorkspace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-AADOnlyAuthenticationForSynapseWorkspace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -DryRun

        .EXAMPLE
        PS> Enable-AADOnlyAuthenticationForSynapseWorkspace -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForsynapseWorkspaces\SynapseWorkspaceWithADAdminDisabled.csv

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
    
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 4] Validating and install the modules required to run the script and validating the user..."
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }
    else
    {
        Write-Host "[Step 1 of 4] validating the user..."
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..."

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of $($context.Account.Id) is: $($context.Account.Type)" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run this script..." -ForegroundColor $([Constants]::MessageType.Update)
    }

    Write-Host "*** To enable Azure AD Only Authentication for Synapse workspace(s) in a Subscription, Contributor and higher privileges on the Synapse workspace(s) in the Subscription are required. ***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Synapse workspace(s)..."

    $synapseWorkspaceResources = @()

    # No file path provided as input to the script. Fetch all Synapse workspaces in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
         
         # Get all Synapse Workspaces in a Subscription
         $synapseWorkspaces = Get-AzResource -ResourceType "Microsoft.Synapse/workspaces" -ErrorAction Stop

                                         
         # Add Synapse Workspaces to this list.
         $synapseWorkspaceResources += $synapseWorkspaces | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                   @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                   @{N='WorkSpaceName';E={$_.Name}},
                                                                   @{N='ResourceType';E={$_.ResourceType}},                                                                  
                                                                   @{N='IsAADAdminPreviouslyConfigured';E={$false}}
                                                                  
    }  
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all Synapse workspace(s) from:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "$($FilePath)" 

        # Importing the list of Synapse workspaces to be remediated.
        $synapseWorkspaceDetails = Import-Csv -LiteralPath $FilePath

        $synapseWorkspaceResources = $synapseWorkspaceDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
    }

    $totalsynapseWorkspace = ($synapseWorkspaceResources|Measure-Object).Count

    if ($totalsynapseWorkspace -eq 0)
    {
        Write-Host "No Synapse workspaces found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalsynapseWorkspace) Synapse workspace(s)." -ForegroundColor $([Constants]::MessageType.Update)

    # Includes Synapse workspaces where Azure AD Only Authentication is enabled.
    $synapseWorkspaceWithAADOnlyAuthEnabled = @()

    # Includes Synapse workspaces where Azure AD Only Authentication is disabled.
    $synapseWorkspaceWithAADOnlyAuthDisabled = @()

    # Includes Synapse workspaces Skipped
    $synapseWorkspaceWithAADOnlyAuthEvaluationSkipped = @()
    Write-Host "Checking if Azure AD Only Authentication is enabled on Synapse workspace(s)..."

    $synapseWorkspaceResources | ForEach-Object {
        try
        {
            $synapseWorkspaceInstance = Get-AzSynapseActiveDirectoryOnlyAuthentication -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.WorkSpaceName -ErrorAction Ignore

             
            # Check if Azure AD Only Authentication are enabled on the Synapse workspace.
            if (($synapseWorkspaceInstance|Measure-Object).Count -ne 0)
            {             
               
                if ($synapseWorkspaceInstance.AzureADOnlyAuthenticationProperty -eq $true)
                {
                    $synapseWorkspaceWithAADOnlyAuthEnabled += $_
                }
                else
                {
                    $synapseWorkspaceWithAADOnlyAuthDisabled += $_
                }
            }
            else
            {
                $synapseWorkspaceWithAADOnlyAuthDisabled += $_                                           
            }
        }
        catch
        {
            $synapseWorkspaceWithAADOnlyAuthEvaluationSkipped += $_ 
        }
    }

    $colsProperty3 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.WorkSpaceName};Label="WorkSpace Name ";Width=20;Alignment="left"} 

    if (($synapseWorkspaceWithAADOnlyAuthEvaluationSkipped | Measure-Object).Count -ne 0)
    {
        Write-Host "`nError checking if AAD Only Authenticaton is enabled for the following Synapse workspace(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $synapseWorkspaceWithAADOnlyAuthEvaluationSkipped | Format-Table -Property $colsProperty3 -Wrap
    }

    $totalsynapseWorkspaceWithAADOnlyAuthDisabled = ($synapseWorkspaceWithAADOnlyAuthDisabled | Measure-Object).Count

    if ($totalsynapseWorkspaceWithAADOnlyAuthDisabled -eq 0)
    {
        Write-Host "`nNo Synapse workspace found with Azure AD Only Authentication disabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "`nFound $($totalsynapseWorkspaceWithAADOnlyAuthDisabled) Synapse workspace(s) with Azure AD Only Authentication disabled." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableAADOnlyAuthForSynapseWorkspaces"
   
    $synapseWorkspaceWithAADOnlyAuthDisabled | Format-Table -Property $colsProperty3 -Wrap
    
    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    # Backing up Synapse workspace details.
    $backupFile = "$($backupFolderPath)\SynapseWorkspaceWithAADOnlyAuthDisabled.csv"
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up Synapse workspace details..."
   
    $synapseWorkspaceWithAADOnlyAuthDisabled | Export-CSV -Path $backupFile -NoTypeInformation -ErrorAction Stop
    Write-Host "Synapse workspace(s) details have been backed up to:" -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "$($backupFile)"
    Write-Host $([Constants]::DoubleDashLine)

    if (-not $DryRun)
    {
        Write-Host "[Step 4 of 4] Enabling Azure AD Only Authentication for Synapse Workspace(s)..." 
        Write-Host "Do you want to enable AAD Only Authentication for Synapse Workspace(s)?`n" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y")
        {
            Write-Host "Azure AD Only Authentication will not be enabled for any Synapse Workspace. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }

        # To hold results from the remediation.
        $remediatedSynapseWorkspaces = @()

        # Includes Synapse Workspace that were skipped during remediation. There were errors remediating them.
        $skippedSynapseWorkspaces = @()
       
        Write-Host "Enabling Azure AD Only Authentication for Synapse workspace(s)..." -ForegroundColor $([Constants]::MessageType.Info)
         
        $synapseWorkspaceWithAADOnlyAuthDisabled  | ForEach-Object {
            $SynapseWorkspacesInstance = $_
            try {
            $aadOnlyAuth  =@()
            if($_.WorkspaceName -ieq 'v-rahkuma')
            {                # To enable AAD Only, AAD Admin should be set. We are first checking if it is previously set on the resource and proceeding for AAD Only.                   
                $aadOnlyAuth = Enable-AzSynapseActiveDirectoryOnlyAuthentication -ResourceGroupName  $_.ResourceGroupName -WorkspaceName $_.WorkspaceName
                
                }
                 
                if (($aadOnlyAuth | Measure-Object).Count -ne 0) {
                    $remediatedSynapseWorkspaces += $SynapseWorkspacesInstance 
                }
                else {
                    $skippedSynapseWorkspaces += $SynapseWorkspacesInstance                   
                }
               
            } 
            catch {
                $skippedSynapseWorkspaces += $SynapseWorkspacesInstance
            }
        }

        $colsProperty1 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.WorkSpaceNameName};Label="Server Name";Width=20;Alignment="left"}
               
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

        if ($($remediatedSynapseWorkspaces | Measure-Object).Count -gt 0)
        {
            Write-Host "Azure AD Only Authentication successfully enabled for the following Synapse workspace(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $remediatedSynapseWorkspaces | Format-Table -Property $colsProperty1 -Wrap

            # Write this to a file.
            $remediatedSynapseWorkspacesFile = "$($backupFolderPath)\RemediatedSynapseWorkspaces.csv"
            $remediatedSynapseWorkspaces | Export-CSV -Path $remediatedSynapseWorkspacesFile -NoTypeInformation
            Write-Host "This information has been saved to $($remediatedSynapseWorkspacesFile)"
            Write-Host "Use this file only for rollback.`n" -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($skippedSynapseWorkspaces | Measure-Object).Count -gt 0)
        {
            Write-Host "Error enabling AAD Only Authenticaton for the following Synapse workspace(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedSynapseWorkspaces | Format-Table -Property $colsProperty1 -Wrap

            # Write this to a file.
            $skippedSynapseWorkspacesFile = "$($backupFolderPath)\SkippedSynapseWorkspaces.csv"
            $skippedSynapseWorkspaces | Export-CSV -Path $skippedSynapseWorkspacesFile -NoTypeInformation
            Write-Host "This information has been saved to $($skippedSynapseWorkspacesFile)"
        }
        Write-Host $([Constants]::DoubleDashLine)

    }
    else
    {
        Write-Host "[Step 4 of 4] Enabling Azure AD Only Authentication for Synapse workspaces..."
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
       
        Write-Host "`nNext steps:"  -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun switch, to enable Azure AD Only Authentication for all Synapse workspaces listed in the file."
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function Disable-AADOnlyAuthenticationForSynapseWorkspaces
{
    <#
        .SYNOPSIS
        Rolls back remediation done for Azure_SynapseWorkspace_AuthN_SQL_Pools_Use_AAD_Only_Trial' Control.

        .DESCRIPTION
        Rolls back remediation done for Azure_SynapseWorkspace_AuthN_SQL_Pools_Use_AAD_Only_Trial' Control.
        Disables Azure AD Only Authentication on the Synapse workspaces in the Subscription.

        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.

        .PARAMETER Force
        Specifies a forceful roll back without any prompts.

        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .EXAMPLE
        PS> Disable-AADOnlyAuthenticationForSynapseWorkspaces -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202101010930\EnableADAdminForSynapseWorkspaces\SynapseWorkspacesWithADAdminDisabled.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

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

    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 3] Validating and install the modules required to run the script and validating the user..."
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }
    else
    {
        Write-Host "[Step 1 of 3] Validating the user..."
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host $([Constants]::SingleDashLine)  
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]" 
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..."

    # Checking if the current account type is "User"
    if ($context.Account.Type -ne "User")
    {
        Write-Host "WARNING: This script can only be run by `User` Account Type. Account Type of $($context.Account.Id) is: $($context.Account.Type)" -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
    else
    {
        Write-Host "[$($context.Account.Id)] is allowed to run this script."  -ForegroundColor $([Constants]::MessageType.Update)
    }

    Write-Host "*** To disable Azure AD Only Authentication for Synapse workspace(s) in a Subscription, Contributor and higher privileges on the Synapse workspace(s) in the Subscription are required. ***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Synapse workspace details..."

    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Synapse workspace(s) details from:" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "$($FilePath)"

    $synapseWorkspaceDetails = Import-Csv -LiteralPath $FilePath
    $validSynapseWorkspaceDetails = $synapseWorkspaceDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.WorkSpaceName)}
    $totalsynapseWorkspaces = $(($validSynapseWorkspaceDetails|measure-object).Count)

    if ($totalsynapseWorkspaces -eq 0)
    {
        Write-Host "No Synapse workspace found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalsynapseWorkspaces) Synapse workspace(s)." -ForegroundColor $([Constants]::MessageType.Update)
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableADAdminForsynapseWorkspaces"

    $colsProperty3 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.ServerName};Label="Server Name";Width=20;Alignment="left"},
                         @{Expression={$_.IsSynapseWorkspace};Label="Is Synapse Workspace?";Width=25;Alignment="left"}

   
    $validSynapseWorkspaceDetails | Format-Table -Property $colsProperty3 -Wrap

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Disabling Azure AD Only Authentication for Synapse workspace(s)..." 
   
    if (-not $Force)
    {
        Write-Host "Do you want to disable Azure AD Only Authentication for all Synapse workspace(s)?`n" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline

        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Azure AD Only Authentication will not be disabled for Synapse workspace(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Azure AD Only Authentication will be disabled for Synapse workspace(s)." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
    }

    # Includes Synapse workspaces, to which, previously made changes were successfully rolled back.
    $rolledBackSynapseWorkspaces = @()

    Write-Host "Disabling Azure AD Only Authentication for Synapse workspace(s)..." -ForegroundColor $([Constants]::MessageType.Info)

    # Includes Synapse workspaces that were skipped during roll back. There were errors rolling back the changes made previously.
    $skippedSynapseWorkspaces = @()
    $validSynapseWorkspaceDetails | ForEach-Object {
        $SynapseWorkspacesInstance = $_
        try {
        $aadOnlyAuth  =@()
        if($_.WorkspaceName -ieq 'v-rahkuma')
        {                # To enable AAD Only, AAD Admin should be set. We are first checking if it is previously set on the resource and proceeding for AAD Only.                   
            $aadOnlyAuth = Disable-AzSynapseActiveDirectoryOnlyAuthentication -ResourceGroupName  $_.ResourceGroupName -WorkspaceName $_.WorkspaceName
            
            }
             
            if (($aadOnlyAuth | Measure-Object).Count -ne 0) {
                $rolledBackSynapseWorkspaces += $SynapseWorkspacesInstance 
            }
            else {
                $skippedSynapseWorkspaces += $SynapseWorkspacesInstance                   
            }           
        } 
        catch {
            $skippedSynapseWorkspaces += $SynapseWorkspacesInstance
        }
    }

    $colsProperty1 = @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=25;Alignment="left"},
                         @{Expression={$_.WorkSpaceNameName};Label="Server Name";Width=20;Alignment="left"}

    Write-Host $([Constants]::SingleDashLine)

    Write-Host "RollBack Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

    if ($($rolledBackSynapseWorkspaces | Measure-Object).Count -gt 0)
    {
        Write-Host "Azure AD Only Authentication successfully disabled for the following Synapse workspace(s):" -ForegroundColor $([Constants]::MessageType.Update)
        $rolledBackSynapseWorkspaces | Format-Table -Property $colsProperty1 -Wrap

        # Write this to a file.
        $rolledBackSynapseWorkspacesFile = "$($backupFolderPath)\RolledBackSynapseWorkspaces.csv"
        $rolledBackSynapseWorkspaces | Export-CSV -Path $rolledBackSynapseWorkspacesFile -NoTypeInformation
        Write-Host "This information has been saved to $($rolledBackSynapseWorkspacesFile)"
    }

    if ($($skippedSynapseWorkspaces | Measure-Object).Count -gt 0)
    {
        Write-Host "Error disabling Azure AD Only Authentication for the following Synapse workspace(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $skippedSynapseWorkspaces |  Format-Table -Property $colsProperty1 -Wrap

        # Write this to a file.
        $skippedSynapseWorkspacesFile = "$($backupFolderPath)\SkippedSynapseWorkspaces.csv"
        $skippedSynapseWorkspaces | Export-CSV -Path $skippedSynapseWorkspacesFile -NoTypeInformation
        Write-Host "This information has been saved to $($skippedSynapseWorkspacesFile)"
    }
    Write-Host $([Constants]::DoubleDashLine)
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

