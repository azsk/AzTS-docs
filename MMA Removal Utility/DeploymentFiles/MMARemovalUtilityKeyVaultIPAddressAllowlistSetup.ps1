function Set-AzTSMMARemovalUtilityRunbook {
    Param(      
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Subscription id in which automation account and key vault are present.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Name of the resource group in which automation account and key vault are present.")]
        $ResourceGroupName,

        [string]
        [Parameter(Mandatory = $false, HelpMessage = "Location where automation account should be created.")]
        $Location = "EastUS2",

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Location for which dynamic ip addresses should be allowed on keyvault. Default location is EastUS2.")]
        $FunctionAppUsageRegion,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Resource id of the keyvault on which ip addresses should be allowed.")]
        $KeyVaultResourceId
    )

    Begin {
        # Step 1: Set context to subscription and resource group where monitoring dashboard needs to be created.
        $currentContext = $null
        $contextHelper = [ContextHelper]::new()
        $currentContext = $contextHelper.SetContext($SubscriptionId)
        if (-not $currentContext) {
            return;
        }
    }

    Process {
        try {
            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "Running MMA Removal utility runbook setup..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Step 2: Create Automation Account.
            $AutomationAccountName = "MMARemovalUtility-AutomationAccount-{0}"
            $ResourceId = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroupName
            $ResourceIdHash = get-hash($ResourceId)
            $ResourceHash = $ResourceIdHash.Substring(0, 5).ToString().ToLower()
            $AutomationAccountName = $AutomationAccountName -f $ResourceHash 

            $DeploymentName = "AzTSMMAenvironmentautomationaccountsetup-$([datetime]::Now.ToString("yyyymmddThhmmss"))"
            $DeploymentOutput = New-AzResourceGroupDeployment -Name  $DeploymentName `
                -Mode Incremental `
                -ResourceGroupName $ResourceGroupName  `
                -TemplateFile ".\MMARemovalUtilityAutomationAccountTemplate.bicep" `
                -automationAccountName $AutomationAccountName `
                -location $Location

            Write-Host "Automation account [$($AutomationAccountName)] has been successfully created in the resource group [$($ResourceGroupName)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            # Step 3: Grant access for Automation Account System assigned managed identity on KeyVault.
            Write-Host "Assigning the identity on KeyVault..." -ForegroundColor $([Constants]::MessageType.Info)    
            $identity = $DeploymentOutput.Outputs.automationAccountManagedIdentity.Value
            Write-Host $([Constants]::SingleDashLine) 
            $identity
            Write-Host $([Constants]::SingleDashLine) 
            try {
                New-AzRoleAssignment -ObjectId $identity -Scope $KeyVaultResourceId -RoleDefinitionName "Key Vault Contributor" -ErrorAction Stop
            }
            catch {
                if ($_.Exception.Body.Code -eq "RoleAssignmentExists") {
                    Write-Host "$($_.Exception.Message)" -ForegroundColor $([Constants]::MessageType.Warning)
                            
                }
                else {
                    Write-Host "Error occurred while granting permission. ErrorMessage [$($_.Exception.Message)]" -ForegroundColor $([Constants]::MessageType.Error)
                               
                }
            }
           
            Write-Host "Assigned the identity on KeyVault successfully." -ForegroundColor $([Constants]::MessageType.Update)    
            Write-Host $([Constants]::SingleDashLine)

            # Step 4: Setup runbook.
            $RunbookName = 'UpdateDynamicIPAddresses'
            Write-Host "Setting the runbook [$($RunbookName)] in the automation account [$($AutomationAccountName)]..." -ForegroundColor $([Constants]::MessageType.Info)    
            
            $UpdateDynamicIPAddressesScriptFilePath = ".\MMARemovalUtilityUpdateDynamicIPAddresses.ps1"
            $UpdateDynamicIPAddressesScriptModifiedFilePath = ".\MMARemovalUtilityUpdateDynamicIPAddressesModified.ps1"
            $RemoveExistingIPRanges = $true

            $Content = Get-Content -Path $UpdateDynamicIPAddressesScriptFilePath -Raw
            $Content = $Content -replace '<SubscriptionId>', $SubscriptionId
            $Content = $Content -replace '<KeyVaultResourceId>', $KeyVaultResourceId
            $Content = $Content -replace '<FunctionAppUsageRegion>', $FunctionAppUsageRegion
            $Content = $Content -replace '<RemoveExistingIPRanges>', $RemoveExistingIPRanges
            $Content | Out-File -FilePath $UpdateDynamicIPAddressesScriptModifiedFilePath -Force

            Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName -Path $UpdateDynamicIPAddressesScriptModifiedFilePath -Published -Type PowerShell -Force
            Start-Sleep -Seconds 10
            Write-Host "Runbook [$($RunbookName)] has been successfully created in the automation account [$($AutomationAccountName)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            # Step 5: Triggering runbook.
            Write-Host "Triggering the runbook [$($RunbookName)] in the automation account [$($AutomationAccountName)]..." -ForegroundColor $([Constants]::MessageType.Info)   
            $TriggerRunbook = Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName
            Write-Host "Runbook [$($RunbookName)] has been successfully triggered in the automation account [$($AutomationAccountName)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            # Step 6: Setup the recurring schedule for running the script every week.
            [System.DayOfWeek[]]$WeekDays = @([System.DayOfWeek]::Monday)
            $ScheduleName = "UpdateDynamicIPAddressesScheduleRecurring"
            Write-Host "Setting up the recurring schedule for [$($RunbookName)] in the automation account [$($AutomationAccountName)]..." -ForegroundColor $([Constants]::MessageType.Info)   
            $CreateSchedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ScheduleName -StartTime $(Get-Date).AddMinutes(6) -WeekInterval 1 -DaysOfWeek $WeekDays
            Start-Sleep -Seconds 10
            $RegisterSchedule = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName $RunbookName -ScheduleName $ScheduleName
            Write-Host "Recurring schedule for [$($RunbookName)] has been successfully created in the automation account [$($AutomationAccountName)]." -ForegroundColor $([Constants]::MessageType.Update)                            
            Write-Host $([Constants]::SingleDashLine)
        }
        catch {
            Write-Host "Error occurred while setting up MMA Removal Utility runbook. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return;
        }
    }
}

class ContextHelper {
    $currentContext = $null;

    [PSObject] SetContext([string] $SubscriptionId) {
        $this.currentContext = $null
        if (-not $SubscriptionId) {

            Write-Host "The argument 'SubscriptionId' is null. Please specify a valid subscription id." -ForegroundColor $([Constants]::MessageType.Error)
            return $null;
        }

        # Login to Azure and set context
        try {
            if (Get-Command -Name Get-AzContext -ErrorAction Stop) {
                $this.currentContext = Get-AzContext -ErrorAction Stop
                $isLoginRequired = (-not $this.currentContext) -or (-not $this.currentContext | GM Subscription) -or (-not $this.currentContext | GM Account)
                    
                # Request login if context is empty
                if ($isLoginRequired) {
                    Write-Host "No active Azure login session found. Initiating login flow..." -ForegroundColor $([Constants]::MessageType.Warning)
                    $this.currentContext = Connect-AzAccount -ErrorAction Stop # -SubscriptionId $SubscriptionId
                }
            
                # Switch context if the subscription in the current context does not the subscription id given by the user
                $isContextValid = ($this.currentContext) -and ($this.currentContext | GM Subscription) -and ($this.currentContext.Subscription | GM Id)
                if ($isContextValid) {
                    # Switch context
                    if ($this.currentContext.Subscription.Id -ne $SubscriptionId) {
                        $this.currentContext = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force
                    }
                }
                else {
                    Write-Host "Invalid PS context. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            else {
                Write-Host "Az command not found. Please run the following command 'Install-Module Az -Scope CurrentUser -Repository 'PSGallery' -AllowClobber -SkipPublisherCheck' to install Az module." -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
        catch {
            Write-Host "Error occurred while logging into Azure. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            return $null;
        }

        return $this.currentContext;
    
    }
    
}
class Constants {
    static [Hashtable] $MessageType = @{
        Error   = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info    = [System.ConsoleColor]::Cyan
        Update  = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [string] $DoubleDashLine = "================================================================================"
    static [string] $SingleDashLine = "--------------------------------------------------------------------------------"
}
function get-hash([string]$textToHash) {
    $hasher = new-object System.Security.Cryptography.MD5CryptoServiceProvider
    $toHash = [System.Text.Encoding]::UTF8.GetBytes($textToHash.ToLower())
    $hashByteArray = $hasher.ComputeHash($toHash)
    $result = [string]::Empty;
    foreach ($byte in $hashByteArray) {
        $result += "{0:X2}" -f $byte
    }
    return $result;
}