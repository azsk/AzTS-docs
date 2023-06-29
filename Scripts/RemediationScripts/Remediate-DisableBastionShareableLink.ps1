<###
# Overview:
    This script is used to disable Bastion Shareable Link in a Subscription.

# Control ID:
    Azure_Bastion_AuthZ_Disable_Shareable_Link

# Display Name:
    Azure Bastion Shareable links must not be used.

# Prerequisites:
    1)Contributor or higher priviliged role on the Bastion(s) is required for remediation.
    2)Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of Bastion(s) in a Subscription.
        3. Back up details of Bastion(s) that are to be remediated.
        4. Remediate Shareable Link on Bastion(s) in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Bastion(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Roll back port on all Bastion(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remediate Shareable Link on Bastion(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to rollback on all Bastion(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Bastion(s) in a Subscription that will be remediated:
    
           Disable-BastionShareableLink -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Disable Shareable Link on Bastion(s) in the Subscription:
       
           Disable-BastionShareableLink -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Disable Shareable Link on Bastion(s) in the Subscription, from a previously taken snapshot:
       
           Disable-BastionShareableLink -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\ShareableLinkForBastion\NonCompliantBastion.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Disable-BastionShareableLink -Detailed

    To roll back:
        1. Enable Shareable Link on Bastion(s) in the Subscription, from a previously taken snapshot:
           Enable-BastionShareableLink -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\ShareableLinkForBastion\RemediatedBastion.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Enable-BastionShareableLink-Detailed        
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
    Write-Host "All required modules are present." -ForegroundColor $([Constants]::MessageType.Update)
}

function Disable-BastionShareableLink
{
    <#
        .SYNOPSIS
        Remediates 'Azure_Bastion_AuthZ_Disable_Shareable_Link' Control.

        .DESCRIPTION
        Remediates 'Azure_Bastion_AuthZ_Disable_Shareable_Link' Control.
        Disable Shareable Link on Bastion. 
        
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
        
        .PARAMETER SkipBackup
        Specifies that no back up will be taken by the script before remediation.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Disable-BastionShareableLink.

        .OUTPUTS
        None. Disable-BastionShareableLink does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-BastionShareableLink -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Disable-BastionShareableLink -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Disable-BastionShareableLink -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\ShareableLinkForBastion\NonCompliantBastion.csv

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

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies no back up will be taken by the script before remediation")]
        $SkipBackup,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used")]
        $Path,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies script is run as a subroutine of AutoRemediation Script")]
        $AutoRemediation,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used")]
        $TimeStamp
    )

    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script..."
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
        Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -PerformPreReqCheck switch is not provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
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
    
    if(-not($AutoRemediation))
    {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Current context has been set to below details: " -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    } 
    
    Write-Host "***To disable Shareable Link on Bastion in a Subscription, Contributor or higher privileges on the Bastion are required.***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Bastion(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store resource details.
    $BastionDetails = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    $ConfigureShareableLink = [ConfigureShareableLink]::new()

    #Control id for the control
    $controlIds = "Azure_Bastion_AuthZ_Disable_Shareable_Link"

    # No file path provided as input to the script. Fetch all Bastion(s) in the Subscription.
    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }

        Write-Host "Fetching all Bastion(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        $BastionResources = $ConfigureShareableLink.GetBastions($SubscriptionId)

        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Bastion(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }

        $validResources | ForEach-Object { 
            try
            {
                $BastionDetail = $BastionResources | Where-Object {$_.Id -eq $resourceId}
                $BastionDetails += $BastionDetail
            }
            catch
            {
                Write-Host "Valid resource information not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..."
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Valid ResourceName(s)/ResourceGroupName not found in input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }
    else
    {
        # No file path provided as input to the script. Fetch all Bastion(s) in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            try
            {
                Write-Host "Fetching all Bastion(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)    
                
                # Get all Bastion(s) in a Subscription
                $BastionDetails =  $ConfigureShareableLink.GetBastions($SubscriptionId)
            }
            catch
            {
                Write-Host "Error fetching Bastion(s) from the subscription. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                $logResource = @{}
                $logResource.Add("SubscriptionID",($SubscriptionId))
                $logResource.Add("Reason","Error fetching Bastion(s) information from the subscription.")    
                $logSkippedResources += $logResource
            }    
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                break
            }

            Write-Host "Fetching all Bastion(s) from [$($FilePath)]..." 

            $BastionResources = Import-Csv -LiteralPath $FilePath
            $validBastionResources = $BastionResources| Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
            $BastionResources = $ConfigureShareableLink.GetBastions($SubscriptionId)
        
            $validBastionResources| ForEach-Object {
            $resourceId = $_.ResourceId
                $BastionDetail = $BastionResources | Where-Object {$_.ResourceId -eq $resourceId}
                if(($BastionDetail| Measure-Object).Count -gt 0)
                {
                    $BastionDetails += $BastionDetail
                }
                else
                {
                    Write-Host "Error fetching Bastion(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason","Error fetching Bastion(s) information.")    
                    $logSkippedResources += $logResource
                }
            }
        }
    }

    $totalBastion = ($BastionDetails| Measure-Object).Count

    if ($totalBastion -eq 0)
    {
        Write-Host "No Bastion(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalBastion)] Bastion(s)." -ForegroundColor $([Constants]::MessageType.Update)                                                       
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Bastion(s) where Shareable Link is enabled
    $NonCompliantBastion = @()

    Write-Host "Separating Bastion(s) for which Shareable Link is enabled..."

    $BastionDetails | ForEach-Object {
        $Bastion = $_
        if($_.SKU -eq "Standard" -and $_.IsShareableLinkEnabled -eq $true)
        {
            $NonCompliantBastion += $Bastion
        }
        else
        {
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason","Shareable link is disabled on the bastion.")    
            $logSkippedResources += $logResource
        }
    }
   
    $totalNonCompliantBastion  = ($NonCompliantBastion | Measure-Object).Count

    if ($totalNonCompliantBastion  -eq 0)
    {
        Write-Host "No Bastion(s) found with Shareable Link enabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$($totalNonCompliantBastion)] Bastion(s) with Shareable Link enabled:" -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.IsShareableLinkEnabled};Label="IsShareableLinkEnabled";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"}
                    
        
    $NonCompliantBastion | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ShareableLinkForBastion"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up Bastion(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        # Backing up Bastion(s) details.
        $backupFile = "$($backupFolderPath)\NonCompliantBastion.csv"
        $NonCompliantBastion | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Bastion(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remediating non compliant Azure Bastions..." 
        Write-Host $([Constants]::SingleDashLine)
        
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "This step will disable Shareable Link for all non-complaint [$($NonCompliantBastion.count)] Bastion(s)." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Do you want to continue? " -ForegroundColor $([Constants]::MessageType.Warning)
            
                $userInput = Read-Host -Prompt "(Y|N)"

                if($userInput -ne "Y")
                {
                    Write-Host "Shareable Link will not be disabled on Bastion(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    break
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. Shareable Link will be disabled on Bastion(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }

        # List for storing remediated Bastion(s)
        $BastionRemediated = @()

        # List for storing skipped Bastion(s)
        $BastionSkipped = @()

        Write-Host "Disabling Shareable Link on all listed Bastion(s)..." -ForegroundColor $([Constants]::MessageType.Info)

        # Loop through the list of Bastion(s) which needs to be remediated.
        $NonCompliantBastion | ForEach-Object {
            $Bastion = $_
            try
            {
                $BastionResource = $ConfigureShareableLink.DisableBastionShareableLink($subscriptionId,$_.ResourceName,$_.ResourceGroupName,"Disable")
                if($BastionResource.properties.enableShareableLink -eq $false)
                {
                    $Bastion.IsShareableLinkEnabled = $false
                    $BastionRemediated += $Bastion
                    
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logRemediatedResources += $logResource
                }
                else
                {
                    $Bastion.isMinTLSVersionSetPostRemediation = $false
                    $BastionSkipped += $Bastion
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Error occured while disabling Shareable Link on Bastion.")
                    $logSkippedResources += $logResource
                }  
            }
            catch
            {
                $BastionSkipped += $Bastion
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason", "Error while disabling Shareable Link on Bastion.")
                $logSkippedResources += $logResource
            }
        }

        $colsPropertyRemediated = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                                  @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                                  @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                                  @{Expression={$_.IsShareableLinkEnabled};Label="IsShareableLinkEnabled";Width=10;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)


        if ($($BastionRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Successfully disabled Shareable Link on the following Bastion(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            $BastionRemediated | Format-Table -Property $colsPropertyRemediated -Wrap

            # Write this to a file.
            $BastionRemediatedFile = "$($backupFolderPath)\RemediatedBastion.csv"
            $BastionRemediated | Export-CSV -Path $BastionRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($BastionRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($BastionSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Error occured while disabling Shareable Link on the following Bastion(s)in the subscription: " -ForegroundColor $([Constants]::MessageType.Error)
            $BastionSkipped | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $BastionSkippedFile = "$($backupFolderPath)\SkippedBastion.csv"
            $BastionSkipped | Export-CSV -Path $BastionSkippedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($BastionSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }

        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $BastionRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4]  Remediating non compliant Azure Bastion..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, disable Shareable Link on Bastion(s) listed in the file."
    }
}

function Enable-BastionShareableLink
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_Bastion_AuthZ_Disable_Shareable_Link' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_Bastion_AuthZ_Disable_Shareable_Link' Control.
        Enable shareable link on Azure Bastion. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Enable-BastionShareableLink.

        .OUTPUTS
        None. Enable-BastionShareableLink does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-BastionShareableLink -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ShareableLinkForBastion\RemediatedBastion.csv

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
            Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script...."
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
        Write-Host "[Step 1 of 3] Validate and install the modules required to run the script..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -PerformPreReqCheck switch is not provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
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

    Write-Host "*** To enable Shareable Link on Bastion in a Subscription, Contributor or higher privileges on the Bastion are required.***" -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Bastion(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Bastion(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $BastionDetails = Import-Csv -LiteralPath $FilePath

    $validBastionDetails = $BastionDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalBastion = $(($validBastionDetails|Measure-Object).Count)

    if ($totalBastion -eq 0)
    {
        Write-Host "No Bastion(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($validBastionDetails|Measure-Object).Count)] Bastion(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.IsShareableLinkEnabled};Label="IsShareableLinkEnabled";Width=50;Alignment="left"}

    $validBastionDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableShareableLinkOnBastion"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Rolling back Shareable Link for all Bastion(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        Write-Host "This step will enable Shareable Link for all non-complaint [$($validBastionDetails.count)] Bastion(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Do you want to continue? " -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Shareable Link will not be enabled for any Bastion(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Shareable Link will be disabled on Bastion(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    # List for storing rolled back Bastion resource.
    $BastionRolledBack = @()

    # List for storing skipped rolled back Bastion resource.
    $BastionSkipped = @()

    $ConfigureShareableLink = [ConfigureShareableLink]::new()

    Write-Host "Enabling shareable link on all listed Bastion(s)..." -ForegroundColor $([Constants]::MessageType.Info)

    $validBastionDetails | ForEach-Object {
        $Bastion = $_
        try
        {
            $BastionResource = $ConfigureShareableLink.DisableBastionShareableLink($subscriptionId,$_.ResourceName,$_.ResourceGroupName,"Enable")
            if($BastionResource.properties.enableShareableLink -eq $true)
            {
                $Bastion.IsShareableLinkEnabled = $true
                $BastionRolledBack += $Bastion    
            }
            else
            {
                $Bastion.isMinTLSVersionRolledback = $false
                $BastionSkipped += $Bastion
            }
        }
        catch
        {
            $BastionSkipped += $Bastion
        }
    }

    $colsPropertyRollBack = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"},
                    @{Expression={$_.IsShareableLinkEnabled};Label="IsShareableLinkEnabled";Width=50;Alignment="left"}

    if ($($BastionRolledBack | Measure-Object).Count -gt 0 -or $($BastionSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($BastionRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Successfully enabled Shareable Link on following Bastion(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Update)
            $BastionRolledBack | Format-Table -Property $colsPropertyRollBack -Wrap
            
            # Write this to a file.
            $BastionRolledBackFile = "$($backupFolderPath)\RolledBackBastion.csv"
            $BastionRolledBack | Export-CSV -Path $BastionRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($BastionRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($BastionSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Error occured while enabling Shareable Link on following Bastion(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Warning)
            $BastionSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $BastionSkippedFile = "$($backupFolderPath)\RollbackSkippedBastion.csv"
            $BastionSkipped | Export-CSV -Path $BastionSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($BastionSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)
        }
    }
}

class ConfigureShareableLink
{
    [PSObject] GetAuthHeader()
    {
        [psobject] $headers = $null
        try 
        {
            $resourceAppIdUri = "https://management.azure.com/"
            $rmContext = Get-AzContext
            $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $rmContext.Account,
            $rmContext.Environment,
            $rmContext.Tenant,
            [System.Security.SecureString] $null,
            "Never",
            $null,
            $resourceAppIdUri); 

            $header = "Bearer " + $authResult.AccessToken
            $headers = @{"Authorization"=$header;"Content-Type"="application/json";}
        }
        catch 
        {
            Write-Host "Error occurred while fetching auth header. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)   
        }
        return($headers)
    }

    [PSObject] GetBastions([string] $subscriptionId)
    {
        $content = $null
        $bastions = @()
        try
        {
            $armUri = "https://management.azure.com/subscriptions/$($subscriptionId)/providers/Microsoft.Network/bastionHosts?api-version=2022-11-01"
            $headers = $this.GetAuthHeader()
            $method = "GET"
            # API to set local accounts Profile config to Bastion
            $response = Invoke-WebRequest -Method $method -Uri $armUri -Headers $headers -UseBasicParsing
            $content = ConvertFrom-Json $response.Content

            $content.value | ForEach-Object {
                    $resId = $_.id.Split('/')
                    $resourceGroupName = $resId[4]
                    $bastions += $_ | Select-Object   @{N='ResourceId';E={$_.id}},
                                                                @{N='ResourceName';E={$_.Name}},
                                                                @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                @{N='SKU';E={$_.sku.name}},
                                                                @{N='IsShareableLinkEnabled';E={$_.properties.enableShareableLink}}
            }
        }
        catch
        {
            Write-Host "Error occurred while fetching Bastions configurations. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        }
        return($bastions)
    }

    [PSObject] GetBastion([string] $subscriptionId, [string] $resourceGroup,[string] $resourceName)
    {
        $content = $null
        try
        {
            $armUri = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroup)/providers/Microsoft.Network/bastionHosts/$($resourceName)?api-version=2022-11-01"
            $headers = $this.GetAuthHeader()
            $method = "GET"
            
            $response = Invoke-WebRequest -Method $method -Uri $armUri -Headers $headers -UseBasicParsing
            $content = $response.Content
        }
        catch
        {
            Write-Host "Error occurred while fetching Bastion configurations. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        }
        
        return($content)
    }

    [PSObject] DisableBastionShareableLink([string] $subscriptionId, [string] $resourceName, [string] $resourceGroup, [string] $operationType)
    {
        $content = $null
        $result = $null
        
        try
        {
            $response =  $this.GetBastion($subscriptionId,$resourceGroup,$resourceName)
            $armUri = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroup)/providers/Microsoft.Network/bastionHosts/$($resourceName)?api-version=2022-11-01"
            $headers = $this.GetAuthHeader()
            $method = "Put"
            
            if($operationType -eq "Enable")
            {
                $response = $response.Replace('"enableShareableLink":false','"enableShareableLink":true')  
            }
            else 
            {
              $response = $response.Replace('"enableShareableLink":true','"enableShareableLink":false')
            
            }  
            $result = Invoke-WebRequest -Method $method -Uri $armUri -Headers $headers -Body $response -UseBasicParsing
            $content = ConvertFrom-Json $result.Content
        }
        catch
        {
            Write-Host "Error occurred while updating Bastion Shareable Link. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        }
        return($content)
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






