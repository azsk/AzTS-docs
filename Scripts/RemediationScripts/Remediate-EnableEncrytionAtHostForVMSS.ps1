<##########################################

# Overview:
    This script is used to Enable Encryption at Host for Virtual machine scale sets and underlying Virtual machines in flexible orchestration mode.

# ControlId:
    Azure_VirtualMachineScaleSet_DP_Enable_Encryption_At_Host

# Pre-requisites:
    You will need Owner or Contributor role on subscription.

# Steps performed by the script:
    1. Install and validate pre-requisites to run the script for subscription.

    2. Get the list of resource groups and check for Virtual machine scale sets and Virtual machines, from subscription.

    3. Take a backup of these non-compliant resource types.


# Step to execute script:
    Download and load remediation script in PowerShell session and execute below command.
    To know how to load script in PowerShell session refer link: https://aka.ms/AzTS-docs/RemediationscriptExcSteps.

# Command to execute:
    Examples:
        1. Run below command to Enable Encrytion at Host for vmss

        Enable-EncrytionAtHost -SubscriptionId '<Sub_Id>' -PerformPreReqCheck: $true

    Note: 
        To rollback changes made by remediation script, execute below command
        Disable-EncrytionAtHost -SubscriptionId '<Sub_Id>' -Path '<Json file path containing Remediated log>' -PerformPreReqCheck: $true

To know more about parameter execute:
    a. Get-Help Enable-EncrytionAtHost -Detailed
    b. Get-Help Disable-EncrytionAtHost -Detailed

########################################
#>

function Pre_requisites {
    <#
    .SYNOPSIS
    This command would check pre requisites modules.
    .DESCRIPTION
    This command would check pre requisites modules to perform remediation.
    #>

    Write-Host "Required modules are: Az.Resources, Az.Security, Az.Accounts" -ForegroundColor Cyan
    Write-Host "Checking for required modules..."
    $availableModules = $(Get-Module -ListAvailable Az.Resources, Az.Security, Az.Accounts)
    
    # Checking if 'Az.Accounts' module is available or not.
    if ($availableModules.Name -notcontains 'Az.Accounts') {
        Write-Host "Installing module Az.Accounts..." -ForegroundColor Yellow
        Install-Module -Name Az.Accounts -Scope CurrentUser -Repository 'PSGallery'
    }
    else {
        Write-Host "Az.Accounts module is available." -ForegroundColor Green
    }

    # Checking if 'Az.Resources' module is available or not.
    if ($availableModules.Name -notcontains 'Az.Resources') {
        Write-Host "Installing module Az.Resources..." -ForegroundColor Yellow
        Install-Module -Name Az.Resources -Scope CurrentUser -Repository 'PSGallery'
    }
    else {
        Write-Host "Az.Resources module is available." -ForegroundColor Green
    }

    # Checking if 'Az.Security' module is available or not.
    if ($availableModules.Name -notcontains 'Az.Security') {
        Write-Host "Installing module Az.Security..." -ForegroundColor Yellow
        Install-Module -Name Az.Security -Scope CurrentUser -Repository 'PSGallery'
    }
    else {
        Write-Host "Az.Security module is available." -ForegroundColor Green
    }
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
            default {
                throw "Unsupported HTTP method: $Method"
            }
        }

        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
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
function Enable-EncrytionAtHost {
    <#
    .SYNOPSIS
    This command would help in remediating 'Azure_VirtualMachineScaleSet_DP_Enable_Encryption_At_Host' control.
    .DESCRIPTION
    This command would help in remediating 'Azure_VirtualMachineScaleSet_DP_Enable_Encryption_At_Host' control.
    .PARAMETER SubscriptionId
        Enter subscription id on which remediation needs to be performed.
    .PARAMETER PerformPreReqCheck
        Perform pre requisites check to ensure all required modules to perform remediation operation are available.
    #>
    param(
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Enter subscription id for remediation")]
        $SubscriptionId,

        [switch]
        $PerformPreReqCheck    
    )
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Starting operation for subscription [$($SubscriptionId)]...`n"
    if ($PerformPreReqCheck) {
        try {
            Write-Host "Checking for pre-requisites..."
            Pre_requisites
            Write-Host $([Constants]::SingleDashLine)
        }
        catch {
            Write-Host "Error occurred while checking pre-requisites. ErrorMessage [$($_)]" -ForegroundColor Red    
            break
        }
    }
    # Connect to AzAccount
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet)) {       
        Write-Host "Connecting to AzAccount..."
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to AzAccount" -ForegroundColor Green
    }
    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force
    
    Write-Host "Metadata Details: `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Starting with Subscription [$($SubscriptionId)]..."
    
    Write-Host "Step 1 of 3: Validating whether the current user [$($currentSub.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."

    # Safe Check: Checking whether the current account is of type User
    if ($currentSub.Account.Type -ne "User") {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor Yellow
        return;
    }

    # Safe Check: Current user needs to be either Contributor or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $currentSub.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    if (($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq 'Contributor' -or $_.RoleDefinitionName -eq "Security Admin" } | Measure-Object).Count -le 0) {
        Write-Host "Warning: This script can only be run by an Owner or Contributor of subscription [$($SubscriptionId)] " -ForegroundColor Yellow
        return;
    }

    # Get All Resource Groups
    $resourceGroups = Get-AzResourceGroup | Select ResourceGroupName
    Get-AzProviderFeature -FeatureName "EncryptionAtHost" -ProviderNamespace "Microsoft.Compute"
    $vmScaleSetBackup = @()
    $vmBackup = @()

    Write-Host "Authentication successfull!!`n" -ForegroundColor Cyan
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Step 2 of 3: Started operation on Virtual machine scale set and underlying Virtual machines..."
    $reqOrchestrationMode = "Flexible"

    Write-Host "Checking Virtual Machine Scale Sets and underlying virtual machines in each Resource Groups..."
    foreach ($rg in $resourceGroups) {
        $ResourceGroupName = $rg.ResourceGroupName
        $virtualMachineScaleSets = Get-AzVmss -ResourceGroupName $ResourceGroupName | Select-Object Name, Type, OrchestrationMode
   
        $colsProperty = @{Expression = { $_.Name }; Label = "Virtual Machine Scale Set Name"; Width = 60; Alignment = "left" },
        @{Expression = { $_.Location }; Label = "Location"; Width = 40; Alignment = "left" },
        @{Expression = { $_.ProvisioningState }; Label = "Provisioning State"; Width = 80; Alignment = "left" }
        $virtualMachineScaleSets | Format-Table -Property $colsProperty -Wrap    

        if (($virtualMachineScaleSets | Measure-Object).Count -gt 0) {
            Write-Host "Found [$($virtualMachineScaleSets.Count)] Virtual Machine Scale Sets"
            foreach ($ele in $virtualMachineScaleSets) {
                if ($ele.OrchestrationMode -eq $reqOrchestrationMode) {
                    $VMScaleSetName = $ele.Name
                    $VMSS = Get-AzVmss -ResourceGroupName $ResourceGroupName -Name $VMScaleSetName
                    $isEncrytionSet = $VMSS.VirtualMachineProfile.SecurityProfile.EncryptionAtHost
                    if ($isEncrytionSet) {
                        Write-Host "Encryption at Host already enabled for [$($VMScaleSetName)] VM Scale Set.`n" -ForegroundColor Cyan
                    }
                    else {
                        try {
                            Write-Host "Enabling Encrytion at Host for [$($VMScaleSetName)] VM Scale Set..."
                            $VMSS = Get-AzVmss -ResourceGroupName $ResourceGroupName -Name $VMScaleSetName
                            Update-AzVmss -VirtualMachineScaleSet $VMSS -Name $VMScaleSetName -ResourceGroupName $ResourceGroupName -EncryptionAtHost $true
                            $vmScaleSetBackup += [PSCustomObject]@{
                                ResourceGroupName = $ResourceGroupName
                                VMSSName          = $VMScaleSetName
                            }
                        }
                        catch {
                            Write-Host "Operation Failed : Enable Encryption at Host for [$($VMScaleSetName)].`n"
                        }
                        Write-Host "Successfully enabled Encrytion at Host property for [$($VMScaleSetName)] VM Scale Set!!!`n"
                
                    }
                    $Uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachineScaleSets/$VMScaleSetName/virtualMachines?api-version=2024-11-01"
                    $virtualMachines = Fetch-API -Method "GET" -Uri $Uri
                    foreach ($virtualMachine in $virtualMachines.Value) {
                        $VMName = $virtualMachine.Name
                        $VM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
                        if ($VM.SecurityProfile.EncryptionAtHost -ne $true) {
                            try {
                                Write-Host "This step will stop and restart [$($VMName)] Virtual Machine." -ForegroundColor Yellow
                                Write-Host "It may take few minutes..." -ForegroundColor Yellow
                                Write-Host "Do you want to continue? " -ForegroundColor Yellow
                                
                                $userInput = Read-Host -Prompt "(Y|N)"
                                
                                if ($userInput -eq "Y" -or $userInput -eq "y") {
                                    Write-Host "Enabling Encryption at Host for [$($VMName)] Virtual Machine..."
                                    Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Force
                                    Update-AzVM -VM $VM -ResourceGroupName $ResourceGroupName -EncryptionAtHost $true
                                    $vmBackup += [PSCustomObject]@{
                                        ResourceGroupName = $ResourceGroupName
                                        VMName            = $VMName
                                    }
                                    Write-Host "Successfully set Encrytion at Host for [$($VMName)] Virtual machine.`n" -ForegroundColor Cyan
                                    Write-Host "Restarting [$($VMName)] Virtual machine...."
                                    Start-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
                                    Write-Host "Successfully re-started [$($VMName)] Virtual machine.`n" -ForegroundColor Cyan
                                }
                                else {
                                    Write-Host "User cancelled the operation for [$($VMName)] Virtual machine." -ForegroundColor Yellow
                                }
                            }
                            catch {
                                Write-Host "Enabling Encryption at Host for [$($VMName)] Virtual machine operation failed" -ForegroundColor Red
                            }
                        }
                        else {
                            Write-Host "Encrytion at Host already enabled for [$($VMName)] virtual machine.`n" -ForegroundColor Cyan
                        }
                    }
                }
                      
            }
            Write-Host $([Constants]::SingleDashLine)
        }
    }

    # Creating the log file
    $folderPath = [Environment]::GetFolderPath("MyDocuments") 
    if (Test-Path -Path $folderPath) {
        $folderPath += "\AzTS\Remediation\Subscriptions\$($SubscriptionId.replace("-","_"))\$((Get-Date).ToString('yyyyMMdd_hhmm'))\VirtualMachine"
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }

    $backup = New-Object psobject -Property @{
        SubscriptionId = $SubscriptionId
    }
    $backup | Add-Member -Name 'VMSS' -Type NoteProperty -Value $vmScaleSetBackup
    $backup | Add-Member -Name 'VM' -Type NoteProperty -Value $vmBackup

    Write-Host "Step 3 of 3: Taking backup of resource types provider registration status. Please do not delete this file. Without this file you won't be able to rollback any changes done through Remediation script." -ForegroundColor Cyan
    $backup | ConvertTo-json | out-file "$($folderpath)\Vmss.json"  
    Write-Host "Path: $($folderpath)\Vmss.json"     
    Write-Host "`n"
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Successfully completed remediation of Virtual machine scale set and underlying Virtual machines on subscription [$($SubscriptionId)]" -ForegroundColor Green
    Write-Host $([Constants]::DoubleDashLine)

}



function Disable-EncrytionAtHost {
    <#
    .SYNOPSIS
    This command would help in rollback the changes made by 'Azure_VirtualMachineScaleSet_DP_Enable_Encryption_At_Host' control script.
    .DESCRIPTION
    This command would help in rollback the changes made by 'Azure_VirtualMachineScaleSet_DP_Enable_Encryption_At_Host' control script.
    .PARAMETER SubscriptionId
        Enter subscription id on which remediation needs to be performed.
    .PARAMETER PerformPreReqCheck
        Perform pre requisites check to ensure all required modules to perform rollback operation are available.
    #>

    param (
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Enter subscription id to perform rollback operation")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Json file path which contain logs generated by remediation script to rollback remediation changes")]
        $Path,

        [switch]
        $PerformPreReqCheck
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Started rollback operation on subscription [$($SubscriptionId)]..."
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck) {
        try {
            Write-Host "Checking for pre-requisites..."
            Pre_requisites
            Write-Host $([Constants]::SingleDashLine)     
        }
        catch {
            Write-Host "Error occurred while checking pre-requisites. ErrorMessage [$($_)]" -ForegroundColor Red    
            break
        }
    }

    # Connect to AzAccount
    $isContextSet = Get-AzContext
    if ([string]::IsNullOrEmpty($isContextSet)) {       
        Write-Host "Connecting to AzAccount..."
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to AzAccount" -ForegroundColor Green
    }
    # Setting context for current subscription.
    $currentSub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force
    
    Write-Host "Metadata Details: `n SubscriptionId: $($SubscriptionId) `n AccountName: $($currentSub.Account.Id) `n AccountType: $($currentSub.Account.Type)"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Starting with Subscription [$($SubscriptionId)]..."
    
    Write-Host "Validating whether the current user [$($currentSub.Account.Id)] has the required permissions to run the script for subscription [$($SubscriptionId)]..."

    # Safe Check: Checking whether the current account is of type User
    if ($currentSub.Account.Type -ne "User") {
        Write-Host "Warning: This script can only be run by user account type." -ForegroundColor Yellow
        return;
    }

    # Safe Check: Current user needs to be either Contributor or Owner for the subscription
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $currentSub.Account.Id -Scope "/subscriptions/$($SubscriptionId)";

    if (($currentLoginRoleAssignments | Where { $_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq 'Contributor' -or $_.RoleDefinitionName -eq "Security Admin" } | Measure-Object).Count -le 0) {
        Write-Host "Warning: This script can only be run by an Owner or Contributor of subscription [$($SubscriptionId)] " -ForegroundColor Yellow
        return;
    }
 
    # Array to store resource context
    if (-not (Test-Path -Path $Path)) {
        Write-Host "Warning: Rollback file is not found. Please check if the initial Remediation script has been run from the same machine. Exiting the process" -ForegroundColor Yellow
        break;        
    }

    $remediatedLog = Get-Content -Raw -Path $Path | ConvertFrom-Json

    Write-Host "`nPerforming rollback operation to disable encryption at host for subscription [$($SubscriptionId)]...`n"

    # Rollback Virtual Machine Scale Set
    if ($null -ne $remediatedLog.VMSS -and ($remediatedLog.VMSS | Measure-Object).Count -gt 0) {
        foreach ($ele in $remediatedLog.VMSS) {
            $VMScaleSetName = $ele.VMSSName
            $ResourceGroupName = $ele.ResourceGroupName
            $VMSS = Get-AzVmss -ResourceGroupName $ResourceGroupName -Name $VMScaleSetName           
            try {
                Write-Host "Disabling Encrytion at Host property for [$($VMScaleSetName)] VM Scale Set..."
                $VMSS = Get-AzVmss -ResourceGroupName $ResourceGroupName -Name $VMScaleSetName
                Update-AzVmss -VirtualMachineScaleSet $VMSS -Name $VMScaleSetName -ResourceGroupName $ResourceGroupName -EncryptionAtHost $false
                    
            }
            catch {
                Write-Host "Operation Failed : Disable Encryption at Host for [$($VMScaleSetName)]."
            }
            Write-Host "Successfully disabled Encrytion at Host property for [$($VMScaleSetName)] VM Scale Set!!!`n"


        }
        
         
    }
    else {
        Write-Host "No virtual machine scale sets found to perform rollback operation." -ForegroundColor Green                
    }

    # Rollback Virtual machines
    if ($null -ne $remediatedLog.VM -and ($remediatedLog.VM | Measure-Object).Count -gt 0) {
        
        foreach ($remediatedVm in $remediatedLog.VM) {
            try {
                $VMName = $remediatedVm.VMName

                Write-Host "This step will stop and restart [$($VMName)] Virtual Machine." -ForegroundColor Yellow
                Write-Host "It may take few minutes..." -ForegroundColor Yellow
                Write-Host "Do you want to continue? " -ForegroundColor Yellow
            
                $userInput = Read-Host -Prompt "(Y|N)"
            
                if ($userInput -eq "Y" -or $userInput -eq "y") {
                    Write-Host "Disabling Encryption at Host for [$($VMName)] Virtual Machine."
                    $VM = Get-AzVM -ResourceGroupName $remediatedVm.ResourceGroupName -Name $VMName

                    Stop-AzVM -ResourceGroupName $remediatedVm.ResourceGroupName -Name $VMName -Force
                    
                    Update-AzVM -VM $VM -ResourceGroupName $remediatedVm.ResourceGroupName -EncryptionAtHost $false

                    Write-Host "Successfully disabled Encrytion at Host for [$($VMName)] Virtual machine."
                    Write-Host "Restarting [$($VMName)] Virtual machine..."

                    Start-AzVM -ResourceGroupName $remediatedVm.ResourceGroupName -Name $VMName
                    Write-Host "Successfully re-started [$($VMName)] Virtual machine.`n"
                    Write-Host $([Constants]::SingleDashLine)
                }
                else {
                    Write-Host "User cancelled the operation for [$($VMName)] Virtual machine." -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "Error occurred while performing rollback operation to disable Encrytion at Host. ErrorMessage [$($_)]" -ForegroundColor Red  
            }
        }
        
    }
    else {
        Write-Host "No Virtual Machine records found to perform rollback operation." -ForegroundColor Green                
    }

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "`nRollback operation completed......." -ForegroundColor Green
}


class Constants {
    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}
