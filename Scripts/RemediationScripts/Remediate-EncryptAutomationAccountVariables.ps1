<###
# Overview:
    This script is used to encrypt variables associated with the Automation Account(s) in a Subscription.

# Control ID:
    Azure_AutomationAccounts_DP_Encrypt_Variables

# Display Name:
    Automation account variables must be encrypted.

# Prerequisites:
    1. Contributor or higher privileges on the Automation Account(s) in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of Automation Accounts in a Subscription that has more than one unencrypted variables.
        3. Back up details of Automation Accounts along with the variables, that are to be remediated.
        4. Encrypt the unencrypted variables associated with the Automation Accounts in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to encrypt the unencrypted variables associated with the Automation Accounts in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Automation Accounts in a Subscription that will be remediated:
           Encrypt-AutomationAccountVariables -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To encrypt all the unencrypted variables associated with the Automation Accounts in a Subscription:
           Encrypt-AutomationAccountVariables -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To encrypt all the unencrypted variables associated with the Automation Accounts in a Subscription, from a previously taken snapshot:
           Encrypt-AutomationAccountVariables -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EncryptAutomationAccountVariables\AutomationAccountsWithUnencryptedVariables.csv

        4. To encrypt all the unencrypted variables associated with the Automation Accounts in a Subscription without taking back up before actual remediation:
           Encrypt-AutomationAccountVariables -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Encrypt-AutomationAccountVariables -Detailed
      
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
    $requiredModules = @("Az.Accounts", "Az.Automation")

    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)    
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)
    
    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "[$($_)] module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host $([Constants]::SingleDashLine)
}

function Encrypt-AutomationAccountVariables
{
    <#
        .SYNOPSIS
        Remediates 'Azure_AutomationAccounts_DP_Encrypt_Variables' Control.

        .DESCRIPTION
        Remediates 'Azure_AutomationAccounts_DP_Encrypt_Variables' Control.
        Encrypt all the unencrypted variables associated with the Automation Accounts in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER SkipBackup
        Specifies that no back up will be taken by the script before remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Encrypt-AutomationAccountVariables.

        .OUTPUTS
        None. Encrypt-AutomationAccountVariables does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Encrypt-AutomationAccountVariables -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Encrypt-AutomationAccountVariables -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Encrypt-AutomationAccountVariables -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EncryptAutomationAccountVariables\AutomationAccountsWithUnencryptedVariables.csv

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
    Write-Host "[Step 1 of 5] Validate and install the modules required to run the script"
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
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)            
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "Skipped as '-PerformPreReqCheck' is not provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)        
        Write-Host $([Constants]::SingleDashLine)
    }
    
    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    

    if(-not($AutoRemediation))	
    {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "To encrypt the unencrypted variables associated with the Automation Accounts in a Subscription, Contributor or higher privileges on the Automation Accounts are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 2 of 5] Fetch all Automation Accounts"
    Write-Host $([Constants]::SingleDashLine)
    $automationAccountResources = @()
    $requiredMinTLSVersion = 1.2

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()
    
    # Control Id
    $controlIds = "Azure_AutomationAccounts_DP_Encrypt_Variables"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "Fetching all Automation Accounts failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}

        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Automation Account found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        } 

        $allAutomationAccountResources = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        $validResources | ForEach-Object { 
            try
            {
                $name = $_.ResourceName
                $resourceGroupName = $_.ResourceGroupName
                $automationAccountResource = $allAutomationAccountResources | Where-Object {$_.AutomationAccountName -eq $name -and $_.ResourceGroupName -eq $resourceGroupName}
                if($automationAccountResource -ne $null)
                {
                    $automationAccountResources += $automationAccountResource
                }
                else
                {
                    Write-Host "Automation Account not found. Automation Account: [$($name)] - Resource Group: [$($resourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Automation Account..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason","Resource not found.")    
                    $logSkippedResources += $logResource
                }
                
            }
            catch
            {
                Write-Host "Valid resource group name and resource name not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($name)]..." -ForegroundColor $([Constants]::MessageType.Warning)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Valid resource group name and resource name not found in input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }
    else
    {
        # No file path provided as input to the script. Fetch all Automation Accounts in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all Automation Accounts in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all Automation Accounts in the Subscription
            $automationAccountResources = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }

            Write-Host "Fetching all Automation Accounts from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $automationAccountResourcesFromFile = Import-Csv -LiteralPath $FilePath
            $validAutomationAccountResources = $automationAccountResourcesFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.AutomationAccountName) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) }
            $allAutomationAccountResources = Get-AzAutomationAccount -ErrorAction SilentlyContinue
            $validAutomationAccountResources | ForEach-Object {
                $resourceGroupName = $_.ResourceGroupName        
                $name = $_.AutomationAccountName               

                try
                {
                    $automationAccountResource = $allAutomationAccountResources | Where-Object {$_.AutomationAccountName -eq $name -and $_.ResourceGroupName -eq $resourceGroupName}
                    if($automationAccountResource -ne $null)
                    {
                        $automationAccountResources += $automationAccountResource
                    }
                    else
                    {
                        Write-Host "Automation Account not found. Automation Account: [$($name)] - Resource Group: [$($resourceGroupName)]" -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "Skipping this Automation Account..." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                }
                catch
                {
                    Write-Host "Error fetching Automation Account: [$($name)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Automation Account..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
        }
    }

    $totalAutomationAccountResources = ($automationAccountResources | Measure-Object).Count

    if ($totalAutomationAccountResources -eq 0)
    {
        Write-Host "No Automation Account found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($totalAutomationAccountResources)] Automation Account(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
     
    Write-Host "[Step 3 of 5] Fetching unencrypted variables associated with the Automation Accounts"
    Write-Host $([Constants]::SingleDashLine)

     # Automation Accounts having non-zero unencrypted variable.
    $automationAccountsWithUnEncryptedVariables = @()

    $automationAccountResources | ForEach-Object {
        $automationAccount = $_
        $automationAccountName =  $automationAccount.AutomationAccountName
        $resourceGroupName = $automationAccount.ResourceGroupName

        try
        {
            $variables = Get-AzAutomationVariable -AutomationAccountName $automationAccountName  -ResourceGroupName $resourceGroupName  
            $unencryptedVariables = @()
            $unencryptedVariablesName = @()
            $variables | ForEach-Object {
                $variable = $_
                $name = $variable.Name
                $encrypted = $variable.Encrypted
                $value = $variable.value

                if($encrypted -eq $false)
                {
                    $unencryptedVariables +=  $variable | Select-Object @{N='Name';E={$name}},
                                                                    @{N='Value';E={$value}}
                    
                    $unencryptedVariablesName += $name
                }
            }

            $unencryptedVariablesCount = ($unencryptedVariables | Measure-Object).Count
            $unencryptedVariablesNameStr = $unencryptedVariablesName -join ', '
            if($unencryptedVariablesCount -gt 0)
            {
                $automationAccountsWithUnEncryptedVariables += $automationAccount | Select-Object @{N="AutomationAccountName";E={$automationAccountName}},
                                                                                                @{N="ResourceGroupName";E={$resourceGroupName}},
                                                                                                @{N="UnencryptedVariables";E={$unencryptedVariables}},
                                                                                                @{N="UnencryptedVaribalesNameStr"; E={$unencryptedVariablesNameStr}}
            }
            else
            {
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($resourceGroupName))
                $logResource.Add("ResourceName",($automationAccountName))
                $logResource.Add("Reason","All the variables associated with the automation account is encrypted.")    
                $logSkippedResources += $logResource
            }
        }
        catch
        {
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($resourceGroupName))
            $logResource.Add("ResourceName",($automationAccountName))
            $logResource.Add("Reason","Error occured while fetching variables associated with the Automation Account.")    
            $logSkippedResources += $logResource
        }
    }

    $totalAutomationAccountsWithUnEncryptedVariables = ($automationAccountsWithUnEncryptedVariables | Measure-Object).Count

    $automationAccountsWithUnEncryptedVariablesBackup = @()
    $automationAccountsWithUnEncryptedVariables | ForEach-Object {
        $automationAccountsWithUnEncryptedVariablesBackup += $_ | Select-Object @{N="AutomationAccountName";E={$_.AutomationAccountName}},
                                                                                    @{N="ResourceGroupName";E={$_.ResourceGroupName}},
                                                                                    @{N="UnencryptedVaribalesNameStr"; E={$_.UnencryptedVaribalesNameStr}}
    }
     
    if ($totalAutomationAccountsWithUnEncryptedVariables  -eq 0)
    {
        Write-Host "No Automation Account found with unencrypted variables. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        if($AutoRemediation) 
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }	
        return
    }

    Write-Host "Found [$($totalAutomationAccountsWithUnEncryptedVariables)] Automation Accounts with unencrypted variables." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
     
    $colsProperty = @{Expression={$_.AutomationAccountName};Label="Automation Account Name";Width=35;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"},
                    @{Expression={$_.UnencryptedVaribalesNameStr};Label="Unencrypted Variables Name";Width=30;Alignment="left"}

    if(-not($AutoRemediation))
    {
        $automationAccountsWithUnEncryptedVariables | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EncryptAutomationAccountVariables"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 4 of 5] Backing up Automation Account details"
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
        if(-not $SkipBackup)
        {
            # Backing up Automation Account details.
            $backupFile = "$($backupFolderPath)\AutomationAccountsWithUnencryptedVariables.csv"
            $automationAccountsWithUnEncryptedVariablesBackup | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "Automation Account details have been successfully backed up to [$($backupFolderPath)]" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
        Write-Host "Skipped as '-FilePath' is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
  

    Write-Host "[Step 5 of 5] Encrypt the unencrypted variables associated with the Automation Accounts"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not $DryRun)
    {  
        # Here AutoRemediation switch is used as there is no need to take user input at BRS level if user has given consent to proceed with the remediation in AutoRemediation Script.
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "Do you want to encrypt the unencrypted variables associated with the Automation Accounts? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                $userInput = Read-Host -Prompt "(Y|N)"

                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "User has not provided consent to encrypt the unencrypted variables associated with the Automation Accounts. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    return
                }
                else
                {
                    Write-Host "User has provided consent to encrypt the unencrypted variables associated with the Automation Accounts." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. All the unencrypted variables associated with the Automation Account will be encrypted without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        # To hold results from the remediation.
        $automationAccountsRemediated = @()
        $automationAccountsSkipped = @()

        Write-Host "Encrypting the unencypted variables associated with the Automation Accounts..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Remediate Controls by encrypting the unencrypted variables.
        $automationAccountsWithUnEncryptedVariables | ForEach-Object {
            $automationAccount = $_
            $automationAccountName = $automationAccount.AutomationAccountName;
            $resourceGroupName = $automationAccount.ResourceGroupName; 
            $unencryptedVariables = $automationAccount.UnencryptedVariables;
            $remediatedVariables = @()
            $skippedVariables = @()
            $unencryptedVariables | ForEach-Object {
                $variable = $_
                $name = $variable.Name
                $value = $variable.Value
                try
                {
                    Remove-AzAutomationVariable -AutomationAccountName $automationAccountName -ResourceGroupName $resourceGroupName -Name $name
                    $output = New-AzAutomationVariable -AutomationAccountName $automationAccountName -ResourceGroupName $resourceGroupName -Name $name -Encrypted $true -Value $value 
                    if($output.Encrypted -eq $true)
                    {
                        $remediatedVariables += $variable
                    }
                    else
                    {
                        $skippedVariables += $variable
                    }
                }
                catch
                {
                    $skippedVariables += $variable
                }
            }
            $totalVariables = ($unencryptedVariables | Measure-Object).Count
            $totalRemediatedVariables = ($remediatedVariables | Measure-Object).Count
            $totalSkippedVariables = ($skippedVariables | Measure-Object).Count
            
            if($totalRemediatedVariables -eq $totalVariables)
            {
                $automationAccountsRemediated += $automationAccount | Select-Object @{N="AutomationAccountName";E={$automationAccountName}},
                                                                                    @{N="ResourceGroupName";E={$resourceGroupName}},
                                                                                    @{N="UnencryptedVaribalesNameStr"; E={$_.UnencryptedVaribalesNameStr}}
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($resourceGroupName))
                $logResource.Add("ResourceName",($automationAccountName))
                $logRemediatedResources += $logResource
            }
            else
            {
                $automationAccountsSkipped += $automationAccount | Select-Object @{N="AutomationAccountName";E={$automationAccountName}},
                                                                                @{N="ResourceGroupName";E={$resourceGroupName}},
                                                                                @{N="UnencryptedVaribalesNameStr"; E={$_.UnencryptedVaribalesNameStr}}
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($resourceGroupName))
                $logResource.Add("ResourceName",($automationAccountName))
                $logResource.Add("Reason", "These variables were not succesfully encrypted: [$($skippedVariables)]")
                $logSkippedResources += $logResource 
            }
        }

        $totalAutomationAccountsRemediated = ($automationAccountsRemediated | Measure-Object).Count
        $totalAutomationAccountsSkipped = ($automationAccountsSkipped | Measure-Object).Count
        Write-Host "[$($totalAutomationAccountsRemediated)] out of [$($totalAutomationAccountResources)] Automation Accounts remediated." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)

        $colsProperty = @{Expression={$_.AutomationAccountName};Label="Automation Account Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)

        if($AutoRemediation)
        {
            if ($totalAutomationAccountsRemediated -gt 0)
            {
                # Write this to a file.
                $automationAccountsRemediatedFile = "$($backupFolderPath)\RemediatedEncryptAutomationAccountsVariables.csv"
                $automationAccountsRemediated | Export-CSV -Path $automationAccountsRemediatedFile -NoTypeInformation
                Write-Host "The information related to Automation Accounts, where all the associated unencrypted variables are encrypted successfully, has been saved to [$($automationAccountsRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($totalAutomationAccountsSkipped -gt 0)
            {   
                # Write this to a file.
                $automationAccountsSkippedFile = "$($backupFolderPath)\SkippedEncryptAutomationAccountsVariables.csv"
                $automationAccountsSkipped | Export-CSV -Path $automationAccountsSkippedFile -NoTypeInformation
                Write-Host "The information related to Automation Accounts, where all the associated unencrypted variables are not encrypted successfully, has been saved to [$($automationAccountsSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)

            if ($totalAutomationAccountsRemediated -gt 0)
            {
                Write-Host "Successfully encrypted all the associated unencrypted variables in the following Automation Accounts in the Subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $automationAccountsRemediated | Format-Table -Property $colsProperty -Wrap
                # Write this to a file.
                $automationAccountsRemediatedFile = "$($backupFolderPath)\RemediatedEncryptAutomationAccountsVariables.csv"
                $automationAccountsRemediated | Export-CSV -Path $automationAccountsRemediatedFile -NoTypeInformation
                Write-Host "The information related to Automation Accounts, where all the associated unencrypted variables are encrypted successfully, has been saved to [$($automationAccountsRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($totalAutomationAccountsSkipped -gt 0)
            {   
                Write-Host "Unable to encrypted all the associated unencrypted variables in the following Automation Accounts in the Subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $automationAccountsSkipped | Format-Table -Property $colsProperty -Wrap
                # Write this to a file.
                $automationAccountsSkippedFile = "$($backupFolderPath)\SkippedEncryptAutomationAccountsVariables.csv"
                $automationAccountsSkipped | Export-CSV -Path $automationAccountsSkippedFile -NoTypeInformation
                Write-Host "The information related to Automation Accounts, where all the associated unencrypted variables are not encrypted successfully, has been saved to [$($automationAccountsSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        if($AutoRemediation)
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources 
                }
            }
            
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps: " -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, encrypt all the unencrypted variables associated with the Automation Accounts listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

# Rollback not possible.

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