<###
# Overview:
    This script is used to enable the DDOS on virtual network available in the App Gateway in a Subscription.

# Control ID:
    Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial

# Display Name:
    DDoS must be configured.

# Prerequisites:    
    Owner or higher priviliged role on the Virtual Network(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Virtual Network(s) in a Subscription that have DDoS Protection Plan is not enabled.
        3. Back up details of Virtual Network(s) that are to be remediated.
        4. Enable the DDoS Protection Plan on the Virtual Network(s) in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Virtual Network(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Disable the DDoS Protection Plan on the Virtual Network(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable the DDoS Protection Plan on the Virtual Network(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable the DDoS Protection Plan on the Virtual Network(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Virtual Network(s) in a Subscription that will be remediated:
    
           File has already been generated using the previous script.

        2. Enable the DDoS Protection Plan on the Virtual Network(s)(s) in the Subscription:
       
           Enable-DDoSProtectionPlanOnVirtualNetwork -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Enable the DDoS Protection Plan on the Virtual Network(s) in the Subscription, from a previously taken snapshot:
       
           Enable-DDoSProtectionPlanOnVirtualNetwork -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableDDoSProtectionPlan\VirtualNetworkDetailsBackUp.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-DDoSProtectionPlanOnVirtualNetwork -Detailed

    To roll back:
        1. Disable the DDoS Protection Plan on the Virtual Network(s) in the Subscription, from a previously taken snapshot:
           Disable-DDoSProtectionPlanOnVirtualNetwork -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\DisableDDoSProtectionPlan\RemediatedVirtualNetworkDetails.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Disable-DDoSProtectionPlanOnVirtualNetwork -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Network")

    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)    
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
}


function Enable-DDoSProtectionPlanOnVirtualNetwork
{
    <#
        .SYNOPSIS
        Remediates 'Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial' Control.

        .DESCRIPTION
        Remediates 'Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial' Control.
        Enable the DDoS Protection Plan on the Virtual Network(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .INPUTS
        None. You cannot pipe objects to Enable-DDoSProtectionPlanOnVirtualNetwork.

        .OUTPUTS
        None. Enable-DDoSProtectionPlanOnVirtualNetwork does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-DDoSProtectionPlanOnVirtualNetwork -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-DDoSProtectionPlanOnVirtualNetwork -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableDDoSProtectionPlan\VirtualNetworkDetailsBackUp.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 4] Validate and install the modules required to run the script and validate the user..."
            Write-Host $([Constants]::SingleDashLine)
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
        Write-Host "[Step 1 of 4] Validate the user... "
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
    Write-Host " To Enable the DDOS on the Virtual Network in a Subscription, Contributor or higher privileged role assignment on the Virtual Network(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)  

    Write-Host "[Step 2 of 4] Fetch all Virtual Network(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Container details.
    $VirtualNetworkDetails = @()

     # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources=@()	

    # Control Id	
    $controlIds = "Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial"
    
      
     
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)	
            return
        }

        Write-Host "Fetch all Virtual Network(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $VirtualNetworkResources = Import-Csv -LiteralPath $FilePath

        $validVirtualNetworkResources = $VirtualNetworkResources| Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

        $validVirtualNetworkResources| ForEach-Object {
            $resourceId = $_.ResourceId

            try
            {                
                $VirtualNetworkResource =  Get-AzVirtualNetwork -ResourceGroupName $_.ResourceVNetRGName -Name $_.ResourceVNetName -ErrorAction SilentlyContinue
            
                $VirtualNetworkDetails += $VirtualNetworkResource  | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                          @{N='ResourceGroupName';E={$_.Id.Split("/")[4]}},
                                                                          @{N='ResourceName';E={$_.Name}},
                                                                          @{N='IsDDOSEnabled';E={$_.EnableDdosProtection}}
                                                                         

             }
            catch
            {
                Write-Host "Error fetching Virtual Network(s) resource: Resource ID:  [$($ResourceVNetName)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }
            
        }
                                                                
    
    
    $totalVirtualNetwork = ($VirtualNetworkDetails| Measure-Object).Count

    if ($totalVirtualNetwork -eq 0)
    {
        Write-Host "No Virtual Network(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }
  
    Write-Host "Found [$($totalVirtualNetwork)] Virtual Network(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Virtual Network(s) for which DDoS Protection Plan is not enabled.
    $VirtualNetworkWithoutDDoSEnabled = @()

    Write-Host "Separating Virtual Network(s) for which DDoS is not enabled..." -ForegroundColor $([Constants]::MessageType.Info)

    $VirtualNetworkDetails | ForEach-Object {
        $VirtualNetwork = $_        
            if($_.IsDDOSEnabled -eq $false)
            {
                $VirtualNetworkWithoutDDoSEnabled += $VirtualNetwork
            }
    }
   
    $totalVirtualNetworkWithoutDDoSEnabled  = ($VirtualNetworkWithoutDDoSEnabled | Measure-Object).Count

    if ($totalVirtualNetworkWithoutDDoSEnabled  -eq 0)
    {
        Write-Host "No Virtual Network(s) found with where DDOS is not enabled.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalVirtualNetworkWithoutDDoSEnabled)] Virtual Network(s) for which DDoS is not enabled ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"},
                    @{Expression={$_.IsDDOSEnabled};Label="IsDDOSEnabled";Width=100;Alignment="left"}

      if(-not $AutoRemediation)
      {
        Write-Host "Virtual Network(s) without DDOS enabled are as follows:"
        $VirtualNetworkWithoutDDoSEnabled | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
      }    
    

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableDDoSProtectionOnVNet"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 3 of 4] Back up Virtual Network(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        # Backing up Virtual Network(s) details.
        $backupFile = "$($backupFolderPath)\VirtualNetworkDetailsBackUp.csv"
        $VirtualNetworkWithoutDDoSEnabled | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Virtual Network(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enable the DDoS Protection Plan on Virtual Network(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)
        

        if (-not $Force)
        {
            Write-Host "Do you want to enable DDoS Protection Plan on the Virtual Network(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "we are starting the procedure to enable the DDoS Protection Plan on Virtual Network(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
        }
      

        # List for storing remediated Virtual Network(s)
        $VirtualNetworkRemediated = @()

        # List for storing skipped Virtual Network(s)
        $VirtualNetworkSkipped = @()

        Write-Host "Enabling the DDoS on Virtual Network(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of Virtual Network(s) which needs to be remediated.
        $VirtualNetworkWithoutDDoSEnabled | ForEach-Object {
            $VirtualNetwork = $_
            try
            {
                
                    Write-Host "To Start enabling the DDoS on Virtual Network(s), Please enter the DDoS Protection Plan Name..." -ForegroundColor $([Constants]::MessageType.Info)

                    # Ask about the DDoS Plan Name
                    $DDoSPlanName = Read-Host -Prompt "Please enter DDoS Plan Name"
                    # Ask about the DDoS Plan RG Name
                    $DDoSPlanRGName = Read-Host -Prompt "Please enter the name of Resource Group where this DDoS Plan is available"
                    if($DDoSPlanName -ne $null -and $DDoSPlanRGName -ne $null)
                    {
                        
                        $ddosProtectionPlanID = Get-AzDdosProtectionPlan -Name $DDoSPlanName -ResourceGroupName $DDoSPlanRGName
                        if($DDoSPlanName -ne $null -and $DDoSPlanRGName -ne $null)
                        {
                            $vnet = Get-AzVirtualNetwork -Name $_.ResourceName -ResourceGroupName $_.ResourceGroupName
                            $vnet.DdosProtectionPlan = New-Object Microsoft.Azure.Commands.Network.Models.PSResourceId

                            # Update the properties and enable DDoS protection
                            $vnet.DdosProtectionPlan.Id = $ddosProtectionPlanID.Id
                            $vnet.EnableDdosProtection = $true
                            $vnet = Set-AzVirtualNetwork -VirtualNetwork $vnet
                            # $vnet | Set-AzVirtualNetwork
                        }
                        else
                        {
                            Write-Host "Could not find the DDoS Plan with the given details..." -ForegroundColor $([Constants]::MessageType.Info)
                            $VirtualNetworkSkipped += $VirtualNetwork                                    
                            return
                        }
                        
                    }
                    else
                    {
                        Write-Host "DDoS Protection Plan Name/RG Name can not be empty..." -ForegroundColor $([Constants]::MessageType.Info)
                        $VirtualNetworkSkipped += $VirtualNetwork                                    
                        return
                    }

                    
                   
                    if($vnet.EnableDdosProtection -eq $true)
                    {
                        $VirtualNetwork.IsDDOSEnabled = $true
                        $VirtualNetworkRemediated += $VirtualNetwork
                        $logResource = @{}	
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                        $logResource.Add("ResourceName",($_.ResourceName))	
                        $logRemediatedResources += $logResource	
                    }
                    else
                    {
                        $VirtualNetworkSkipped += $VirtualNetwork
                        $logResource = @{}	
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                        $logResource.Add("ResourceName",($_.ResourceName))
                        $logResource.Add("Reason", "Error Enabling the DDoS Plan: [$($VirtualNetwork)]")      
                        $logSkippedResources += $logResource	

                    }
                
            }
            catch
            {
                $VirtualNetworkSkipped += $VirtualNetwork
                $logResource = @{}	
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                $logResource.Add("ResourceName",($_.ResourceName))	
                $logResource.Add("Reason","Encountered error Enabling DDoS Plan")    	
                $logSkippedResources += $logResource	
                Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)	
                Write-Host $([Constants]::SingleDashLine)
            }
         }

        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        if ($($VirtualNetworkRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Successfully enabled the DDoS on Virtual Network(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            $VirtualNetworkRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $VirtualNetworkRemediatedFile = "$($backupFolderPath)\RemediatedVirtualNetwork.csv"
            $VirtualNetworkRemediated | Export-CSV -Path $VirtualNetworkRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VirtualNetworkRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

           
        
        if ($($VirtualNetworkSkipped | Measure-Object).Count -gt 0)
        {

            Write-Host "Error while enabling DDoS Protection Plan On Virtual Network(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            $VirtualNetworkSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $VirtualNetworkSkippedFile = "$($backupFolderPath)\SkippedVirtualNetwork.csv"
            $VirtualNetworkSkipped | Export-CSV -Path $VirtualNetworkSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($VirtualNetworkSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
        
       
    }
}

function Disable-DDoSProtectionPlanOnVirtualNetwork
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial' Control.
        Disable DDoS Protecion Plan on Virtual Network(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-DDoSProtectionPlanOnVirtualNetwork.

        .OUTPUTS
        None. Disable-DDoSProtectionPlanOnVirtualNetwork does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-DDoSProtectionPlanOnVirtualNetwork -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableDDoSOnVNet\RemediatedVirtualNetwork.csv

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
            Write-Host "[Step 1 of 3] Validate and install the modules required to run the script and validate the user..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites"	
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
        Write-Host "[Step 1 of 3] Validate the user..." 
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
    else
    {
        # Setting up context for the current Subscription.
        $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    }

    
    
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

     # Note about the required access required for remediation

 Write-Host "To disable DDoS Protection Plan on Virtual Network(s) in a Subscription, Contributor or higher privileged role assignment on the Virtual Network(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Virtual Network(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file:  [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Fetching all Virtual Network(s) from" -NoNewline
    Write-Host " [$($FilePath)\...]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $VirtualNetworkDetails = Import-Csv -LiteralPath $FilePath

    $validVirtualNetworkDetails = $VirtualNetworkDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalVirtualNetwork = $(($validVirtualNetworkDetails|Measure-Object).Count)

    if ($totalVirtualNetwork -eq 0)
    {
        Write-Host "No Virtual Network(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$(($validVirtualNetworkDetails|Measure-Object).Count)] Virtual Network(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"},
                    @{Expression={$_.IsDDOSEnabled};Label="IsDDOSEnabled";Width=100;Alignment="left"}
                    
        
    $validVirtualNetworkDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DisableDDoSOnVNet"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Disable DDoS Protection Plan on all remediated Virtual Network(s) in the Subscription"
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        
        Write-Host "Do you want to disable DDoS Protection Plan on Virtual Network(s) mentioned in the file?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "DDoS Protection Plan will not be rolled back on Virtual Network(s) mentioned in the file. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }
            Write-Host "DDoS Protection Plan will be rolled back on Virtual Network(s) mentioned in the file." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. DDoS Protection Plan will be rolled back on Virtual Network(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Virtual Network resource.
    $VirtualNetworkRolledBack = @()

    # List for storing skipped rolled back Virtual Network resource.
    $VirtualNetworkSkipped = @()


    $validVirtualNetworkDetails | ForEach-Object {
        $VirtualNetwork = $_
        try
        {   
            
            $vnet =  Get-AzVirtualNetwork -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
            $vnet.DdosProtectionPlan = $null
            $vnet.EnableDdosProtection = $false
            $vnet = Set-AzVirtualNetwork -VirtualNetwork $vnet
            # $vnet | Set-AzVirtualNetwork
            
            if($vnet.EnableDdosProtection -eq $false)
            {
                $VirtualNetwork.IsDDOSEnabled = $false
                $VirtualNetworkRolledBack += $VirtualNetwork
            }
            else
            {
                $VirtualNetworkSkipped += $VirtualNetwork
            }
            
        }
        catch
        {
            $VirtualNetworkSkipped += $VirtualNetwork
        }
    }


    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
    if ($($VirtualNetworkRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "DDoS Protection Plan has been disabled on the following Virtual Network(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
        $VirtualNetworkRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $VirtualNetworkRolledBackFile = "$($backupFolderPath)\RolledBackVirtualNetwork.csv"
        $VirtualNetworkRolledBack | Export-CSV -Path $VirtualNetworkRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($VirtualNetworkRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }

    if ($($VirtualNetworkSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error while disabling DDoS Protection Plan on Virtual Network(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
        $VirtualNetworkSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

            
        # Write this to a file.
        $VirtualNetworkSkippedFile = "$($backupFolderPath)\RollbackSkippedVirtualNetwork.csv"
        $VirtualNetworkSkipped | Export-CSV -Path $VirtualNetworkSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($VirtualNetworkSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }
}


# Defines commonly used constants.
class Constants
{
    # Defines commonly used colour codes, corresponding to the severity of the log...
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
