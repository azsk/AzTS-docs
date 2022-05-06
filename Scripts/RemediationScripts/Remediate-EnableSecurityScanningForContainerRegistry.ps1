<###
# Overview:
    This script is used to grant access to security scanner identities for image scans on Container Registry(s) in a Subscription.

# Control ID:
    Azure_ContainerRegistry_Config_Enable_Security_Scanning

# Display Name:
    Security scanner identity must be granted access to Container Registry(s) for image scans.

# Prerequisites:
    Owner and higher privileges on the Container Registry(s) in a Subscription.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Container Registry(s) in a Subscription that do not have access to security scanner identities for image scan.
        3. Back up details of Container Registry(s) that are to be remediated.
        4. Grant access to security scanner identities for image scans on Container Registry(s) in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Container Registry(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Remove access to security scanner identities on all Container Registry(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to grant access to security scanner identities for image scans on Container Registry(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remove access to security scanner identities on all Container Registry(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Container Registry(s) in a Subscription that will be remediated:
    
           Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To grant access to security scanner identities for image scans on Container Registry(s) in the Subscription:
       
           Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To grant access to security scanner identities for image scans on Container Registry(s) in the Subscription, from a previously taken snapshot:
       
           Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableSecurityScanningIdentityForContainerRegistry\ContainerRegistryWithoutSecurityScanningEnabled.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-SecurityScanningIdentityForContainerRegistry -Detailed

    To roll back:
        1. To remove access from security scanner identities for image scans on Container Registry(s) in the Subscription, from a previously taken snapshot:
           Disable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableSecurityScanningIdentityForContainerRegistry\RemediatedContainerRegistry.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Disable-SecurityScanningIdentityForContainerRegistry -Detailed        
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

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
             Write-Host "[$($_)] module is installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
}


function Enable-SecurityScanningIdentityForContainerRegistry
{
    <#
        .SYNOPSIS
        Remediates 'Azure_ContainerRegistry_Config_Enable_Security_Scanning' Control.

        .DESCRIPTION
        Remediates 'Azure_ContainerRegistry_Config_Enable_Security_Scanning' Control.
        Grant access to security scanner identities for image scans on Container Registry(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .INPUTS
        None. You cannot pipe objects to Enable-SecurityScanningIdentityForContainerRegistry.

        .OUTPUTS
        None. Enable-SecurityScanningIdentityForContainerRegistry does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableSecurityScanningIdentityForContainerRegistry\ContainerRegistryWithoutSecurityScanningEnabled.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

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

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script and validating the user..."
            Write-Host $([Constants]::SingleDashLine)
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
        Write-Host "[Step 1 of 4] Validating the user... "
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
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

    Write-Host "*** To grant access to security scanner identities for image scans on Container Registry(s) in the Subscription, Owner and higher privileges on the Subscription are required. ***" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Container Registry(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Container details.
    $containerRegistryDetails = @()

    # No file path provided as input to the script. Fetch all Container Registry(s) in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Container Registry(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all Container Registry(s) in a Subscription
        $containerRegistryDetails = Get-AzContainerRegistry -ErrorAction Stop
    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all Container Registry(s) from $($FilePath)" -ForegroundColor $([Constants]::MessageType.Info)

        $containerRegistryResources = Import-Csv -LiteralPath $FilePath
        $validcontainerRegistryResources = $containerRegistryResources| Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
        
        $validcontainerRegistryResources| ForEach-Object {
            $resourceId = $_.ResourceId

            try
            {
                Write-Host "Fetching Container Registry(s) resource: Resource ID - $($resourceId)"
                $containerRegistryResource = Get-AzContainerRegistry -ResourceGroupName $_.ResourcegroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                $containerRegistryDetails += $containerRegistryResource
            }
            catch
            {
                Write-Host "Error fetching Container Registry(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping this Container Registry(s) resource..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }
    }

    $totalContainerRegistry = ($containerRegistryDetails| Measure-Object).Count

    if ($totalContainerRegistry -eq 0)
    {
        Write-Host "No Container Registry(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }
  
    Write-Host "Found [$($totalContainerRegistry)] Container Registry(s)." -ForegroundColor $([Constants]::MessageType.Update)
    
    # Seperating required properties
    $containerRegistryDetails = $containerRegistryDetails | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                          @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                          @{N='ResourceName';E={$_.Name}}
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    # List for storing role assignment details.
    $roleAssignmentDetails = @()

    # List for storing sub level scanning identity role assignment details.
    $subLevelRoleAssignmentDetails = @()

    Write-Host "Fetching central reader security scanner role assignments..."

    # Fetching all role assignment.
    $roleAssignmentDetails = Get-AzRoleAssignment 


    # Seperating the central account. 
    $centralReaderAccounts = $roleAssignmentDetails | Where-Object {$_.ObjectType -eq "ServicePrincipal" -and $_.RoleDefinitionName -eq "Reader" -and $_.DisplayName -eq "aqua-csp-dsre" -and $_.ObjectId -eq "933b2294-7959-4e6f-a006-3e75ab109a4e"} 

    Write-Host "Found [$(($centralReaderAccounts| Measure-Object).Count)] central reader security scanner role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)

    # list for storing Container Registry(s) for which central reader role is not assigned.
    $containerRegistryWithoutSecurityScanningEnabled = @()

    Write-Host "Separating Container Registry(s) for which access is not granted to security scanning identities..."

    #seperating the sub level role assignments.
    $subLevelRoleAssignmentDetails = $centralReaderAccounts | Where-Object {$_.Scope -eq "/subscriptions/$($SubscriptionId)"}

    if(($subLevelRoleAssignmentDetails| Measure-Object).Count  -eq 0)
    {
        $containerRegistryDetails | ForEach-Object {
            $containerRegistry = $_
            $CentralReaderAccount = $centralReaderAccounts | Where-Object {$_.Scope -eq $containerRegistry.ResourceId -or ($_.Scope).Split('/')[4] -eq $containerRegistry.ResourceGroupName}

            if(($centralReaderAccount | Measure-Object).count -eq 0)
            {
                $containerRegistryWithoutSecurityScanningEnabled += $containerRegistry
            }
        }
        
    }
   
    
    $totalContainerRegistryWithoutSecurityScanningEnabled  = ($containerRegistryWithoutSecurityScanningEnabled | Measure-Object).Count

    if ($totalContainerRegistryWithoutSecurityScanningEnabled  -eq 0)
    {
        Write-Host "No Container Registry(s) found for granting access to security scanner identities for image scans. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found $($totalContainerRegistryWithoutSecurityScanningEnabled) Container Registry(s) for which access is not granted to security scanning identities." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=40;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"}
        
    $containerRegistryWithoutSecurityScanningEnabled | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableSecurityScanningIdentityForContainerRegistry"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up Container Registry(s) details..."
    Write-Host $([Constants]::SingleDashLine)
    
    # Backing up Container Registry(s) details.
    $backupFile = "$($backupFolderPath)\ContainerRegistryWithoutSecurityScanningEnabled.csv"

    $containerRegistryWithoutSecurityScanningEnabled | Export-CSV -Path $backupFile -NoTypeInformation

    Write-Host "Container Registry(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Grant access to security scanner identities for image scans on Container Registry(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)
        

        if (-not $Force)
        {
            Write-Host "Do you want to grant access to security scanner identities for image scans on Container Registry(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Access is not granted to security scanner identities for image scans on Container Registry(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
        }
        else
        {
            Write-Host "'Force' flag is provided. Access will be granted to security scanner identities for image scans on Container Registry(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        # List for storing remediated Container Registry(s)
        $containerRegistryRemediated = @()

        # List for storing skipped Container Registry(s)
        $containerRegistrySkipped = @()

        Write-Host "Creating Reader role for security scanner identities for image scanning on Container Registry(s)." -ForegroundColor $([Constants]::MessageType.Info)

        # Loop through the list of Container Registry(s) which needs to be remediated.
        $containerRegistryWithoutSecurityScanningEnabled | ForEach-Object {
            $containerRegistry = $_
            try
            {
                $roleAssignment = New-AzRoleAssignment -Scope $_.ResourceId -ObjectId "933b2294-7959-4e6f-a006-3e75ab109a4e" -RoleDefinitionName "Reader" -ObjectType 'ServicePrincipal'
                if($roleAssignment -ne $null)
                {
                    $containerRegistryRemediated += $containerRegistry
                }
                else
                {
                    $containerRegistrySkipped += $containerRegistry
                }
            }
            catch
            {
                $containerRegistrySkipped += $containerRegistry
            }
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($ContainerRegistryRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Access is successfully granted to security scanner identities for image scans on the following Container Registry(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
           
            $ContainerRegistryRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $ContainerRegistryRemediatedFile = "$($backupFolderPath)\RemediatedContainerRegistry.csv"
            $ContainerRegistryRemediated | Export-CSV -Path $ContainerRegistryRemediatedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($ContainerRegistryRemediatedFile)]"
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($ContainerRegistrySkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError granting access to security scanner identities for image scans on the following Container Registry(s)in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
            $ContainerRegistrySkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $ContainerRegistrySkippedFile = "$($backupFolderPath)\SkippedContainerRegistry.csv"
            $ContainerRegistrySkipped | Export-CSV -Path $ContainerRegistrySkippedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($ContainerRegistrySkippedFile)]"
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Grant access to security scanner identities for image scans on Container Registry(s) in the Subscription..."
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "`nNext steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "*    Run the same command with -FilePath $($backupFile) and without -DryRun, to grant access to security scanner identities for image scans on Container Registry(s) listed in the file."
    }
}

function Disable-SecurityScanningIdentityForContainerRegistry
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_ContainerRegistry_Config_Enable_Security_Scanning' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_ContainerRegistry_Config_Enable_Security_Scanning' Control.
        Remove access to security scanner identities for image scans on Container Registry(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .Parameter ExcludeNonProductionSlots
        Specifies exclusion of non-production slots from roll back.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-SecurityScanningIdentityForContainerRegistry.

        .OUTPUTS
        None. Disable-SecurityScanningIdentityForContainerRegistry does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableSecurityScanningIdentityForContainerRegistry\RemediatedContainerRegistry.csv

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

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script and validating the user..."
            Write-Host $([Constants]::SingleDashLine)
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

    Write-Host "*** To grant access to security scanner identities for image scans on Container Registry(s) in the Subscription, Owner and higher privileges on the subscription are required. ***" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Container Registry(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Container Registry(s) from [$($FilePath)]" -ForegroundColor $([Constants]::MessageType.Info)

    $containerRegistryDetails = Import-Csv -LiteralPath $FilePath

    $validcontainerRegistryDetails = $containerRegistryDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalContainerRegistry = $(($validcontainerRegistryDetails|Measure-Object).Count)

    if ($totalContainerRegistry -eq 0)
    {
        Write-Host "No Container Registry(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        break
    }

    Write-Host "Found [$(($validcontainerRegistryDetails|Measure-Object).Count)] Container Registry(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=40;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"}
        
    $validcontainerRegistryDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableSecurityScanningIdentityForContainerRegistry"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Remove access to security scanner identities on all Container Registry(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        
        Write-Host "Do you want to remove access from security scanner identities on all Container Registry(s) mentioned the file in the ?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "Access is not removed from security scanner identities for image scans on Container Registry(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
            Write-Host "Removing access for security scanner identities for image scans on Container Registry(s) in the Subscription."

    }
    else
    {
        Write-Host "'Force' flag is provided. Access will be removed from security scanner identities for image scans on Container Registry(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    # List for storing rolled back Container Registry resource.
    $ContainerRegistryRolledBack = @()

    # List for storing skipped rolled back Container Registry resource.
    $ContainerRegistrySkipped = @()

    $validcontainerRegistryDetails | ForEach-Object {
        $containerRegistry = $_
        try
        {
            Remove-AzRoleAssignment -Scope $_.ResourceId -ObjectId "933b2294-7959-4e6f-a006-3e75ab109a4e"  -RoleDefinitionName "Reader" 
            $RoleAssignment = Get-AzRoleAssignment -Scope $_.ResourceId -ObjectId "933b2294-7959-4e6f-a006-3e75ab109a4e" -RoleDefinitionName "Reader"
            
            if($RoleAssignment -eq $null)
            {
                $ContainerRegistryRolledBack += $containerRegistry    
            }
            else
            {
                $containerRegistrySkipped += $containerRegistry
            }
        }
        catch
        {
            $containerRegistrySkipped += $containerRegistry
        }
    }

    if ($($ContainerRegistryRolledBack | Measure-Object).Count -gt 0 -or $($ContainerRegistrySkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($ContainerRegistryRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Access is successfully removed for security scanner identities on following Container Registry(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
            $ContainerRegistryRolledBack | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $ContainerRegistryRolledBackFile = "$($backupFolderPath)\RolledBackContainerRegistry.csv"
            $ContainerRegistryRolledBack | Export-CSV -Path $ContainerRegistryRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to [$($ContainerRegistryRolledBackFile)]"
        }

        if ($($ContainerRegistrySkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError removing access for security scanner identities on following Container Registry(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
            $ContainerRegistrySkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $ContainerRegistrySkippedFile = "$($backupFolderPath)\RollbackSkippedContainerRegistry.csv"
            $ContainerRegistrySkipped | Export-CSV -Path $ContainerRegistrySkippedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($ContainerRegistrySkippedFile)]"
        }
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
