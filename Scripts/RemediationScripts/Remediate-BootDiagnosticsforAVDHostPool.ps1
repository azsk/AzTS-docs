<###
# Overview:
    This script is used to enable  boot diagnostic with managed storage account for AVD Host pool(s) VMs in a Subscription.

# Control ID:
    Azure_AVD_Audit_Enable_HostPool_BootDiagnostics

# Display Name:
    Boot Diagnostic must be enabled with Managed Storage Account on Azure AVD Host pool VMs.

# Prerequisites:
    1)Contributor or higher priviliged role on the AVD Host pool(s) VMs is required for remediation.
    2)Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of AVD Host pool(s) in a Subscription.
        3. Back up details of AVD Host pool(s) that are to be remediated.
        4. Remediate AVD Host pool(s) in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of AVD Host pool(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Roll back AVD Host pool(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remediate on AVD Host pool(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to rollback on all AVD Host pool(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the AVD Host pool(s) in a Subscription that will be remediated:
    
           Enable-AVDHostPoolBootDiagnosticWithManagedStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Enable boot diagnostic with managed storage account on AVD Host pool(s) in the Subscription:
       
           Enable-AVDHostPoolBootDiagnosticWithManagedStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Enable boot diagnostic with managed storage account on AVD Host pool(s) in the Subscription, from a previously taken snapshot:
       
           Enable-AVDHostPoolBootDiagnosticWithManagedStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\BootDiagnosticsWithManagedStorageAccountForAVDHostPool\NonCompliantAVDHostPool.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-AVDHostPoolBootDiagnosticWithManagedStorageAccount -Detailed

    To roll back:
        1. Disable boot diagnostic with managed storage account on AVD Host pool(s) in the Subscription, from a previously taken snapshot:
           Disable-AVDHostPoolBootDiagnosticWithManagedStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\BootDiagnosticsWithManagedStorageAccountForAVDHostPool\RemediatedAVDHostPool.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Disable-AVDHostPoolBootDiagnosticWithManagedStorageAccount -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.DesktopVirtualization","Az.Compute")

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

function Enable-AVDHostPoolBootDiagnosticWithManagedStorageAccount
{
    <#
        .SYNOPSIS
        Remediates 'Azure_AVD_Audit_Enable_HostPool_BootDiagnostics' Control.

        .DESCRIPTION
        Remediates 'Azure_AVD_Audit_Enable_HostPool_BootDiagnostics' Control.
        Enable boot diagnostic with managed storage account on AVD Host pool. 
        
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
        None. You cannot pipe objects to Enable-AVDHostPoolBootDiagnosticWithManagedStorageAccount.

        .OUTPUTS
        None. Enable-AVDHostPoolBootDiagnosticWithManagedStorageAccount does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-AVDHostPoolBootDiagnosticWithManagedStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-AVDHostPoolBootDiagnosticWithManagedStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-AVDHostPoolBootDiagnosticWithManagedStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\BootDiagnosticsWithManagedStorageAccountForAVDHostPool\NonCompliantAVDHostPool.csv

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
    
    Write-Host "***To Enable boot diagnostic with managed storage account on AVD Host pool(s) in a Subscription, Contributor or higher privileges on the AVD Host pool(s) are required.***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all AVD Host pool(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store resource details.
    $AVDHostPoolDetails = @()

    # list to store resource details.
    $SessionHostDetails = @()
    

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    #Control id for the control
    $controlIds = "Azure_AVD_Audit_Enable_HostPool_BootDiagnostics"

    # No file path provided as input to the script. Fetch all AVD Host pool(s) in the Subscription.
    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }

        Write-Host "Fetching all AVD Host pool(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
          
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No AVD Host pool(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }

        $validResources | ForEach-Object { 
            try
            {
                $AVDHostPool = $_
                $AVDHostPoolDetail =  Get-AzWvdHostPool -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction Stop
                $AVDHostPoolDetails += $AVDHostPoolDetail
            }
            catch
            {
                Write-Host "Valid resource information not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..."
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($AVDHostPool.ResourceGroupName))
                $logResource.Add("ResourceName",($AVDHostPool.ResourceName))
                $logResource.Add("Reason","Valid ResourceName(s)/ResourceGroupName not found in input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }
    else
    {
        # No file path provided as input to the script. Fetch all AVD Host pool(s) in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            try
            {
                Write-Host "Fetching all AVD Host pool(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)    
                
                # Get all AVD Host pool(s) in a Subscription
                $AVDHostPoolDetails =  Get-AzWvdHostPool -ErrorAction Stop
            }
            catch
            {
                Write-Host "Error fetching AVD Host pool(s) from the subscription. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                $logResource = @{}
                $logResource.Add("SubscriptionID",($SubscriptionId))
                $logResource.Add("Reason","Error fetching AVD Host pool(s) information from the subscription.")    
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

            Write-Host "Fetching all AVD Host pool(s) from [$($FilePath)]..." 

            $AVDHostPoolResources = Import-Csv -LiteralPath $FilePath
            $validAVDHostPoolResources = $AVDHostPoolResources| Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
        
            $validAVDHostPoolResources| ForEach-Object {
                $resourceId = $_.ResourceId
                $avdHostPool = $_
                $AVDHostPoolDetail =  Get-AzWvdHostPool -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName
                if(($AVDHostPoolDetail| Measure-Object).Count -gt 0)
                {
                    $AVDHostPoolDetails += $AVDHostPoolDetail
                }
                else
                {
                    Write-Host "Error fetching AVD Host pool(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($avdHostPool.ResourceGroupName))
                    $logResource.Add("ResourceName",($avdHostPool.ResourceName))
                    $logResource.Add("Reason","Error fetching AVD Host pool(s) information.")    
                    $logSkippedResources += $logResource
                }
            }
        }
    }

    $totalAVDHostPool = ($AVDHostPoolDetails| Measure-Object).Count

    if ($totalAVDHostPool -eq 0)
    {
        Write-Host "No AVD Host pool(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalAVDHostPool)] AVD Host pool(s)." -ForegroundColor $([Constants]::MessageType.Update)                                                       
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing AVD Host pool(s) where boot diagnostic with managed storage account is enabled
    $NonCompliantAVDHostPool = @()

    $AVDHostPools = @()

    Write-Host "Separating AVD Host pool(s) for which boot diagnostic with managed storage account is not enabled..."

    $AVDHostPoolDetails | ForEach-Object {
        try {
        
            $ListOfNonCompliantSessionHost = @()
            $SessionHostDetails = @()
            $avdHostPool = $_
            $resourceName = $_.Name
            $resourceGroupName = $_.Id.Split("/")[4]
            $sessionHostDetail =   Get-AzWvdSessionHost -ResourceGroupName $resourceGroupName -HostPoolName $resourceName -ErrorAction Stop
            $sessionHostDetail | ForEach-Object {
                $sessionHost = $_
                $sessionHostName = $sessionHost.Name.Split("/")[1]
                $sessionHostRG = $sessionHost.Id.Split("/")[4]
                $virtualMachine = get-AzVM -ResourceGroupName $sessionHostRG -Name $sessionHostName
                
                $BootDiagnostic = $virtualMachine.DiagnosticsProfile.BootDiagnostics.Enabled
                $StorageURI = $virtualMachine.DiagnosticsProfile.BootDiagnostics.StorageUri
                
                $SessionHostDetails += $virtualMachine | Select-Object @{N='ResourceName';E={$virtualMachine.Name}},
                @{N='ResourceGroupName';E={$virtualMachine.ResourceGroupName}},
                @{N='BootDiagnostic';E={$BootDiagnostic}},
                @{N='StorageURI';E={$StorageURI}}
            }

            $ListOfNonCompliantSessionHost = $SessionHostDetails | Where-Object {!($_.BootDiagnostic -and [String]::IsNullOrWhiteSpace($StorageURI))}
            $AVDHostPools += $avdHostPool | Select-Object   @{N='ResourceId';E={$_.Id}},
            @{N='ResourceName';E={$resourceName}},
            @{N='ResourceGroupName';E={$resourceGroupName}},
            @{N='ListofSessionHost';E={$SessionHostDetails}},
            @{N='ListOfNonCompliantSessionHost';E={$ListOfNonCompliantSessionHost}}

        }                 
        catch {
            Write-Host "Error fetching AVD Host pool configuration: Resource ID: [$($avdHostPool.ResourceId)], Resource Group Name: [$($resourceName)], Resource Name: [$($resourceName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($resourceName))
            $logResource.Add("ResourceName",($resourceGroupName))
            $logResource.Add("Reason","Encountered error while fetching AVD Host pool configuration")    
            $logSkippedResources += $logResource
            Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)   
        }
    }

    $AVDHostPools | ForEach-Object {
        $AVDHostPool = $_
        if(($_.ListOfNonCompliantSessionHost| Measure-Object).Count -gt 0)
        {
            $NonCompliantAVDHostPool += $AVDHostPool
        }
        else
        {
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($AVDHostPool.ResourceGroupName))
            $logResource.Add("ResourceName",($AVDHostPool.ResourceName))
            $logResource.Add("Reason","boot diagnostic with managed storage account is enabled on the AVD Host pool.")    
            $logSkippedResources += $logResource
        }
    }
   
    $totalNonCompliantAVDHostPool  = ($NonCompliantAVDHostPool | Measure-Object).Count

    if ($totalNonCompliantAVDHostPool  -eq 0)
    {
        Write-Host "No AVD Host pool(s) found with boot diagnostic with managed storage account is disabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$($totalNonCompliantAVDHostPool)] AVD Host pool(s) with boot diagnostic with managed storage account is disabled:" -ForegroundColor $([Constants]::MessageType.Update)
    
    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={($_.ListOfNonCompliantSessionHost | Select-Object -ExpandProperty ResourceName) -join ','};Label="NonCompliantSessionHost";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"}
                    
    $NonCompliantAVDHostPool | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\BootDiagnosticsWithManagedStorageAccountForAVDHostPool"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up AVD Host pool(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        $ExportedHostPoolDetails = $NonCompliantAVDHostPool | Select-Object   @{N='ResourceId';E={$_.ResourceId}},
            @{N='ResourceName';E={$_.ResourceName}},
            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
            @{N='ListofSessionHost';E={($_.ListofSessionHost | Select-Object -ExpandProperty ResourceName) -join ','}},
            @{N='ListOfNonCompliantSessionHost';E={($_.ListOfNonCompliantSessionHost | Select-Object -ExpandProperty ResourceName) -join ','}}
        
            # Backing up AVD Host pool(s) details.
        $backupFile = "$($backupFolderPath)\NonCompliantAVDHostPool.csv"
        $ExportedHostPoolDetails | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "AVD Host pool(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remediating non compliant Azure AVD Host pool(s)..." 
        Write-Host $([Constants]::SingleDashLine)
        
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "This step will enable boot diagnostic with managed storage account for all non-complaint [$($NonCompliantAVDHostPool.count)] AVD Host pool(s)." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Do you want to continue? " -ForegroundColor $([Constants]::MessageType.Warning)
            
                $userInput = Read-Host -Prompt "(Y|N)"

                if($userInput -ne "Y")
                {
                    Write-Host "Boot diagnostic with managed storage account will not be enabled on AVD Host pool(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    break
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. boot diagnostic with managed storage account will be enabled on AVD Host pool(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
            }
        }

        # List for storing remediated AVD Host pool(s)
        $AVDHostPoolRemediated = @()

        # List for storing skipped AVD Host pool(s)
        $AVDHostPoolSkipped = @()

        Write-Host "Enabling boot diagnostic with managed storage account on all listed AVD Host pool(s)..." -ForegroundColor $([Constants]::MessageType.Info)

        # Loop through the list of AVD Host pool(s) which needs to be remediated.
        $NonCompliantAVDHostPool | ForEach-Object {

            $AVDHostPool = $_
            $listOfRemediatedSessionHost = @()
            $listOfSkippedSessionHost = @()
            Write-Host "Enabling boot diagnostic with managed storage account on resource:  ResourceName - [$($AVDHostPool.ResourceName)], ResourceGroupName - [$($AVDHostPool.ResourceGroupName)]."
                
            $AVDHostPool.ListOfNonCompliantSessionHost | ForEach-Object {
                try {
                    $SessionHost = $_
                    $SessionHostDetail = Get-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName
                    
                    if(($SessionHostDetail|Measure-Object).Count -gt 0)
                    {
                        $SessionHostDetail.DiagnosticsProfile.BootDiagnostics.Enabled = $true
                        $SessionHostDetail.DiagnosticsProfile.BootDiagnostics.StorageUri = $null
                        $result = Update-AzVM -ResourceGroupName $_.ResourceGroupName -VM $SessionHostDetail 
                        
                        if(($result|Measure-Object).count -gt 0)
                        {
                            $listOfRemediatedSessionHost +=  $SessionHost | Select-Object  @{N='ResourceName';E={$SessionHost.ResourceName}},
                            @{N='ResourceGroupName';E={$SessionHost.ResourceGroupName}},
                            @{N='BootDiagnostic';E={$true}},
                            @{N='StorageURI';E={$StorageURI}}
                        }
                        else {
                            $listOfSkippedSessionHost +=  $SessionHost | Select-Object  @{N='ResourceName';E={$SessionHost.ResourceName}},
                            @{N='ResourceGroupName';E={$SessionHost.ResourceGroupName}},
                            @{N='BootDiagnostic';E={$SessionHost.BootDiagnostic}},
                            @{N='StorageURI';E={$SessionHost.StorageURI}}
                        }
                    }
                    else {
                        $listOfSkippedSessionHost +=  $SessionHost | Select-Object  @{N='ResourceName';E={$SessionHost.ResourceName}},
                            @{N='ResourceGroupName';E={$SessionHost.ResourceGroupName}},
                            @{N='BootDiagnostic';E={$SessionHost.BootDiagnostic}},
                            @{N='StorageURI';E={$SessionHost.StorageURI}}
                    }
                }
                catch {
                    $listOfSkippedSessionHost +=  $SessionHost | Select-Object  @{N='ResourceName';E={$SessionHost.ResourceName}},
                        @{N='ResourceGroupName';E={$SessionHost.ResourceGroupName}},
                        @{N='BootDiagnostic';E={$SessionHost.BootDiagnostic}},
                        @{N='StorageURI';E={$SessionHost.StorageURI}}
                }         
            }

            if(($listOfRemediatedSessionHost|Measure-Object).Count -gt 0 )
            {
                $AVDHostPoolRemediated += $AVDHostPool | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                @{N='ResourceName';E={$_.ResourceName}},
                @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                @{N='ListOfNonCompliantSessionHost';E={($_.ListOfNonCompliantSessionHost | Select-Object -ExpandProperty ResourceName) -join ','}},
                @{N='ListOfRemediatedSessionHost';E={($listOfRemediatedSessionHost|Select-Object -ExpandProperty ResourceName) -join ','}}

                $logResource = @{}
                $logResource.Add("ResourceGroupName",($AVDHostPool.ResourceGroupName))
                $logResource.Add("ResourceName",($AVDHostPool.ResourceName))
                $logRemediatedResources += $logResource
                Write-Host "Successfully enabled boot diagnostic with managed storage account on resource:  ResourceName - [$($AVDHostPool.ResourceName)], ResourceGroupName - [$($AVDHostPool.ResourceGroupName)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }

            if(($listOfSkippedSessionHost|Measure-Object).Count -gt 0 )
            {
                $AVDHostPoolSkipped += $AVDHostPool | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                @{N='ResourceName';E={$_.ResourceName}},
                @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                @{N='ListOfNonCompliantSessionHost';E={($_.ListOfNonCompliantSessionHost| Select-Object -ExpandProperty ResourceName) -join ','}},
                @{N='ListOfSkippedSessionHost';E={($listOfSkippedSessionHost| Select-Object -ExpandProperty ResourceName) -join ','}}
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($AVDHostPool.ResourceGroupName))
                $logResource.Add("ResourceName",($AVDHostPool.ResourceName))
                $logResource.Add("Reason", "Error occured while disabling boot diagnostic with managed storage account on AVD Host pool.")
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }               
        }

        $colsPropertyRemediated = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
            @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
            @{Expression={$_.ListOfRemediatedSessionHost};Label="ListOfRemediatedSessionHost";Width=30;Alignment="left"},
            @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"}

        $colsPropertySkipped = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
            @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
            @{Expression={$_.ListOfSkippedSessionHost};Label="ListOfSkippedSessionHost";Width=30;Alignment="left"},
            @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)

        if ($($AVDHostPoolRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Successfully enabled boot diagnostic with managed storage account on the following AVD Host pool(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            $AVDHostPoolRemediated | Format-Table -Property $colsPropertyRemediated -Wrap

            # Write this to a file.
            $AVDHostPoolRemediatedFile = "$($backupFolderPath)\RemediatedAVDHostPool.csv"
            $AVDHostPoolRemediated | Export-CSV -Path $AVDHostPoolRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($AVDHostPoolRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($AVDHostPoolSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Error occured while enabling boot diagnostic with managed storage account on the following AVD Host poolin the subscription: " -ForegroundColor $([Constants]::MessageType.Error)
            $AVDHostPoolSkipped | Format-Table -Property $colsPropertySkipped -Wrap

            # Write this to a file.
            $AVDHostPoolSkippedFile = "$($backupFolderPath)\SkippedAVDHostPool.csv"
            $AVDHostPoolSkipped | Export-CSV -Path $AVDHostPoolSkippedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($AVDHostPoolSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }

        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $AVDHostPoolRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4]  Remediating non compliant AVD Host pool(s)..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath [$($backupFile)] and without -DryRun, to enable boot diagnostic with managed storage account on AVD Host pool(s) listed in the file."
    }
}

function Disable-AVDHostPoolBootDiagnosticWithManagedStorageAccount
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_AVD_Audit_Enable_HostPool_BootDiagnostics' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_AVD_Audit_Enable_HostPool_BootDiagnostics' Control.
        Disable boot diagnostic with managed storage account on Azure AVD Host pool. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-AVDHostPoolBootDiagnosticWithManagedStorageAccount.

        .OUTPUTS
        None. Disable-AVDHostPoolBootDiagnosticWithManagedStorageAccount does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-AVDHostPoolBootDiagnosticWithManagedStorageAccount -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\BootDiagnosticsWithManagedStorageAccountForAVDHostPool\RemediatedAVDHostPool.csv

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

    Write-Host "*** To disable boot diagnostic with managed storage account on AVD Host pool(s) in a Subscription, Contributor or higher privileges on the AVD Host pool(s) are required.***" -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all AVD Host pool(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    $AVDHostPoolDetails = @()
    $AVDHostPools = @()

    Write-Host "Fetching all AVD Host pool(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $AVDHostPoolDetail = Import-Csv -LiteralPath $FilePath

    $validAVDHostPoolDetails = $AVDHostPoolDetail | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }
    
    $validAVDHostPoolDetails| ForEach-Object {
        $resourceId = $_.ResourceId
        $avdHostPool = $_
        $AVDHostPoolDetail =  Get-AzWvdHostPool -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName
        if(($AVDHostPoolDetail| Measure-Object).Count -gt 0)
        {
            $AVDHostPoolDetails += $AVDHostPoolDetail
        }
        else
        {
            Write-Host "Error fetching AVD Host pool(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($avdHostPool.ResourceGroupName))
            $logResource.Add("ResourceName",($avdHostPool.ResourceName))
            $logResource.Add("Reason","Error fetching AVD Host pool(s) information.")    
            $logSkippedResources += $logResource
        }
    }

    $AVDHostPoolDetails | ForEach-Object {
        try {

            $SessionHostDetails = @()
            $avdHostPool = $_
            $resourceName = $_.Name
            $resourceGroupName = $_.Id.Split("/")[4]
            $sessionHostDetail =   Get-AzWvdSessionHost -ResourceGroupName $resourceGroupName -HostPoolName $resourceName -ErrorAction Stop
            $sessionHostDetail | ForEach-Object {
                $sessionHost = $_
                $sessionHostName = $sessionHost.Name.Split("/")[1]
                $sessionHostRG = $sessionHost.Id.Split("/")[4]
                $virtualMachine = get-AzVM -ResourceGroupName $sessionHostRG -Name $sessionHostName
                
                $BootDiagnostic = $virtualMachine.DiagnosticsProfile.BootDiagnostics.Enabled
                $StorageURI = $virtualMachine.DiagnosticsProfile.BootDiagnostics.StorageUri
                
                $SessionHostDetails += $virtualMachine | Select-Object @{N='ResourceName';E={$virtualMachine.Name}},
                @{N='ResourceGroupName';E={$virtualMachine.ResourceGroupName}},
                @{N='BootDiagnostic';E={$BootDiagnostic}},
                @{N='StorageURI';E={$StorageURI}}
               

            }

            $ListofOriginalRemediatedSessionHost = $validAVDHostPoolDetails | Where-Object {$_.ResourceId -eq $avdHostPool.Id} 
            $ListOfRemediatedSessionHost = $SessionHostDetails | Where-Object {$ListofOriginalRemediatedSessionHost.ListOfRemediatedSessionHost -split "," -contains $_.ResourceName}
            
            $AVDHostPools += $avdHostPool | Select-Object   @{N='ResourceId';E={$_.Id}},
            @{N='ResourceName';E={$resourceName}},
            @{N='ResourceGroupName';E={$resourceGroupName}},
            @{N='ListofSessionHost';E={$SessionHostDetails}},
            @{N='ListOfRemediatedSessionHost';E={$ListOfRemediatedSessionHost}}

        }                 
        catch {
            Write-Host "Error fetching AVD Host pool configuration: Resource ID: [$($avdHostPool.ResourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($resourceGroupName))
            $logResource.Add("ResourceName",($resourceName))
            $logResource.Add("Reason","Encountered error while fetching AVD Host pool configuration")    
            $logSkippedResources += $logResource
            Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning) 
        }
    }

    $totalAVDHostPool = $(($AVDHostPools|Measure-Object).Count)

    if ($totalAVDHostPool -eq 0)
    {
        Write-Host "No AVD Host pool(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($validAVDHostPoolDetails|Measure-Object).Count)] AVD Host pool(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsPropertyRemediated = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
        @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
        @{Expression={($_.ListOfRemediatedSessionHost | Select-Object -ExpandProperty ResourceName) -join ','};Label="ListOfRemediatedSessionHost";Width=30;Alignment="left"},
        @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"}

    $AVDHostPools | Format-Table -Property $colsPropertyRemediated -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DisableBootDiagnosticWithManagedStorageAccountOnAVDHostPool"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Rolling back boot diagnostic with managed storage account for all AVD Host pool(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        Write-Host "This step will disable boot diagnostic with managed storage account for all non-complaint [$($validAVDHostPoolDetails.count)] AVD Host pool(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Do you want to continue? " -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Boot diagnostic with managed storage account will not be disabled for any AVD Host pool(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. boot diagnostic with managed storage account will be disabled on AVD Host pool(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    # List for storing rolled back AVD Host pool resource.
    $AVDHostPoolRolledBack = @()

    # List for storing skipped rolled back AVD Host pool resource.
    $AVDHostPoolSkipped = @()

    Write-Host "Disabling boot diagnostic with managed storage account on all listed AVD Host pool(s)..." -ForegroundColor $([Constants]::MessageType.Info)

    $AVDHostPools | ForEach-Object {

        $AVDHostPool = $_
        $ListOfRolledBackSessionHost = @()
        $listOfSkippedSessionHost = @()
        Write-Host "Disabling boot diagnostic with managed storage account on resource:  ResourceName - [$($AVDHostPool.ResourceName)], ResourceGroupName - [$($AVDHostPool.ResourceGroupName)]."
              
        $AVDHostPool.ListOfRemediatedSessionHost | ForEach-Object {
            try {
                $SessionHost = $_
                $SessionHostDetail = Get-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName
                if(($SessionHostDetail|Measure-Object).Count -gt 0)
                {
                    $SessionHostDetail.DiagnosticsProfile.BootDiagnostics.Enabled = $false
                    $SessionHostDetail.DiagnosticsProfile.BootDiagnostics.StorageUri = $null
                    
                    $result = Update-AzVM -ResourceGroupName $_.ResourceGroupName -VM $SessionHostDetail 
                    if(($result|Measure-Object).count -gt 0)
                    {
                        $ListOfRolledBackSessionHost +=  $SessionHost | Select-Object @{N='ResourceName';E={$SessionHost.ResourceName}},
                            @{N='ResourceGroupName';E={$SessionHost.ResourceGroupName}},
                            @{N='BootDiagnostic';E={$false}},
                            @{N='StorageURI';E={$null}}
                    }
                    else {
                        $listOfSkippedSessionHost +=  $SessionHost | Select-Object @{N='ResourceName';E={$SessionHost.ResourceName}},
                            @{N='ResourceGroupName';E={$SessionHost.ResourceGroupName}},
                            @{N='BootDiagnostic';E={$SessionHost.BootDiagnostic}},
                            @{N='StorageURI';E={$SessionHost.StorageURI}}
                    }
                }
                else {
                    $listOfSkippedSessionHost +=  $SessionHost | Select-Object  @{N='ResourceName';E={$SessionHost.ResourceName}},
                        @{N='ResourceGroupName';E={$SessionHost.ResourceGroupName}},
                        @{N='SecurityType';E={"TrustedLaunch"}},
                        @{N='BootDiagnostic';E={$SessionHost.BootDiagnostic}},
                        @{N='StorageURI';E={$SessionHost.StorageURI}}
                }
            }
            catch {
                $listOfSkippedSessionHost +=  $SessionHost | Select-Object @{N='ResourceName';E={$SessionHost.ResourceName}},
                    @{N='ResourceGroupName';E={$SessionHost.ResourceGroupName}},
                    @{N='BootDiagnostic';E={$SessionHost.BootDiagnostic}},
                    @{N='StorageURI';E={$SessionHost.StorageURI}}
            }
        }

        if(($ListOfRolledBackSessionHost|Measure-Object).Count -gt 0 )
        {
            $AVDHostPoolRolledBack += $AVDHostPool | Select-Object   @{N='ResourceId';E={$_.ResourceId}},
            @{N='ResourceName';E={$_.ResourceName}},
            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
            @{N='ListOfRemediatedSessionHost';E={($_.ListOfRemediatedSessionHost | Select-Object -ExpandProperty ResourceName) -join ','}},
            @{N='ListOfRolledBackSessionHost';E={($ListOfRolledBackSessionHost | Select-Object -ExpandProperty ResourceName) -join ','}}
        }

        if(($listOfSkippedSessionHost|Measure-Object).Count -gt 0 )
        {
            $AVDHostPoolSkipped += $AVDHostPool | Select-Object   @{N='ResourceId';E={$_.ResourceId}},
            @{N='ResourceName';E={$_.ResourceName}},
            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
            @{N='ListOfRemediatedSessionHost';E={($_.ListOfRemediatedSessionHost| Select-Object -ExpandProperty ResourceName) -join ','}},
            @{N='ListOfSkippedSessionHost';E={($listOfSkippedSessionHost| Select-Object -ExpandProperty ResourceName) -join ','}}
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason", "Error occured while disabling boot diagnostic with managed storage account  on AVD Host pool.")
            $logSkippedResources += $logResource
        }
    }

    $colsPropertyRollBack = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
        @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
        @{Expression={$_.ListOfRolledBackSessionHost};Label="ListOfRolledBackSessionHost";Width=30;Alignment="left"},
        @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"}

    $colsPropertySkipped = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
        @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
        @{Expression={$_.ListOfSkippedSessionHost };Label="ListOfSkippedSessionHost";Width=30;Alignment="left"},
        @{Expression={$_.ResourceId};Label="ResourceId";Width=50;Alignment="left"}

    if ($($AVDHostPoolRolledBack | Measure-Object).Count -gt 0 -or $($AVDHostPoolSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($AVDHostPoolRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Successfully disabled boot diagnostic with managed storage account on following AVD Host pool(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Update)
            $AVDHostPoolRolledBack | Format-Table -Property $colsPropertyRollBack -Wrap
            
            # Write this to a file.
            $AVDHostPoolRolledBackFile = "$($backupFolderPath)\RolledBackAVDHostPool.csv"
            $AVDHostPoolRolledBack | Export-CSV -Path $AVDHostPoolRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($AVDHostPoolRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($AVDHostPoolSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Error occured while disabling boot diagnostic with managed storage account on following AVD Host pool(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Warning)
            $AVDHostPoolSkipped | Format-Table -Property $colsPropertySkipped -Wrap
            
            # Write this to a file.
            $AVDHostPoolSkippedFile = "$($backupFolderPath)\RollbackSkippedAVDHostPool.csv"
            $AVDHostPoolSkipped | Export-CSV -Path $AVDHostPoolSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($AVDHostPoolSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)
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






