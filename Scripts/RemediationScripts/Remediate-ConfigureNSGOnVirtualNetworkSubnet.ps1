<###
# Overview:
    This script is used to configure the NSG on subnet of virtual network available in the App Gateway in a Subscription.

# Control ID:
    Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial

# Display Name:
    NGS must be configured on the Subnet.

# Prerequisites:    
    Owner or higher priviliged role on the Virtual Network(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Subnet(s) in a Subscription that have NSG is not configured.
        3. Back up details of Subnet(s) that are to be remediated.
        4. Configure the NSG on the Subnet(s) of Virtual Network in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Subnet(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Remove the NSG configuration from the Subnet(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to configure NSG on the Subnet(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to Remove the NSG configuration on the Subnet(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Subnet(s) in a Subscription that will be remediated:
    
           File has already been generated using the previous script.

        2. Configure the NSG on the Subnet(s)(s) in the Subscription:
       
           Add-NSGConfigurationOnSubnet -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Configure the NSG on the Subnet(s) in the Subscription, from a previously taken snapshot:
       
           Add-NSGConfigurationOnSubnet -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ConfigureNSG\SubnetDetailsBackUp.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Add-NSGConfigurationOnSubnet -Detailed

    To roll back:
        1. Remove the NSG configuration on the Subnet(s) in the Subscription, from a previously taken snapshot:
           Remove-NSGConfigurationOnSubnet -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\DisableDDoSProtectionPlan\RemediatedSubnetDetails.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Remove-NSGConfigurationOnSubnet -Detailed        
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


function Add-NSGConfigurationOnSubnet
{
    <#
        .SYNOPSIS
        Remediates 'Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial' Control.

        .DESCRIPTION
        Remediates 'Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial' Control.
        Add the NSG configuration on the Subnet(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .INPUTS
        None. You cannot pipe objects to Add-NSGConfigurationOnSubnet.

        .OUTPUTS
        None. Add-NSGConfigurationOnSubnet does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Add-NSGConfigurationOnSubnet -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Add-NSGConfigurationOnSubnet -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ConfigureNSG\SubnetDetailsBackUp.csv

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
    Write-Host " To configure the NSG on the Subnet in a Subscription, Contributor or higher privileged role assignment on the Virtual Network(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)  

    Write-Host "[Step 2 of 4] Fetch all Subnets(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Container details.
    $SubnetDetails = @()

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

        Write-Host "Fetch all Subnet(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $SubnetResources = Import-Csv -LiteralPath $FilePath

        $validSubnetResources = $SubnetResources| Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

        $validSubnetResources| ForEach-Object {
            $resourceId = $_.ResourceId

            try
            {    
                $VNetResource = Get-AzVirtualNetwork -ResourceGroupName $_.ResourceVirtualNetworkRGName -Name $_.ResourceVirtualNetworkName -ErrorAction SilentlyContinue
                $SubnetResource =  Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNetResource -Name $_.ResourceSubNetName
                $SubnetDetails += $SubnetResource  | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                          @{N='ResourceGroupName';E={$_.Id.Split("/")[4]}},
                                                                          @{N='ResourceName';E={$_.Name}},
                                                                          @{N='ResourceVirtualNetworkName';E={$_.Id.Split("/")[8]}},
                                                                          @{N='IsNSGConfigured';E={
                                                                            if($_.NetworkSecurityGroup -eq $null)
                                                                            { 
                                                                                $false
                                                                            }
                                                                            else
                                                                            {
                                                                                $true
                                                                            }
                                                                          }}
                                                                         

             }
            catch
            {
                Write-Host "Error fetching subnet of Virtual Network(s) resource: Resource ID:  [$($ResourceVNetName)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }
            
        }
                                                                
    
    
    $totalSubnet = ($SubnetDetails| Measure-Object).Count

    if ($totalSubnet -eq 0)
    {
        Write-Host "No Subnet(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }
  
    Write-Host "Found [$($totalSubnet)] Subnet(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Subnet(s) for which NSG is not configured.
    $SubnetWithoutNSGConfigured = @()

    Write-Host "Separating Subnet(s) for which NSG is not configured..." -ForegroundColor $([Constants]::MessageType.Info)

    $SubnetDetails | ForEach-Object {
        $Subnet = $_        
            if($_.IsNSGConfigured -eq $false)
            {
                $SubnetWithoutNSGConfigured += $Subnet
            }
    }
   
    $totalSubnetWithoutNSGConfigured  = ($SubnetWithoutNSGConfigured | Measure-Object).Count

    if ($totalSubnetWithoutNSGConfigured  -eq 0)
    {
        Write-Host "No Subnet(s) found with where NSG is not configured.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalSubnetWithoutNSGConfigured)] Subnet(s) for which NSG is not configured ." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"},
                    @{Expression={$_.VirtualNetworkName};Label="VirtualNetworkName";Width=100;Alignment="left"}
                    @{Expression={$_.IsNSGConfigured};Label="IsNSGConfigured";Width=100;Alignment="left"}

      if(-not $AutoRemediation)
      {
        Write-Host "Subnet(s) without NSG configuration are as follows:"
        $SubnetWithoutNSGConfigured | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
      }    
    

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ConfiguredNSGOnSubnet"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 3 of 4] Back up Subnet(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        # Backing up Subnet(s) details.
        $backupFile = "$($backupFolderPath)\SubnetDetailsBackUp.csv"
        $SubnetWithoutNSGConfigured | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Subnet(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
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
        Write-Host "[Step 4 of 4] Enable the DDoS Protection Plan on Subnet(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)
        

        if (-not $Force)
        {
            Write-Host "Do you want to configure NSG on the Subnet(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "we are starting the procedure to configure the NSG on the Subnet(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
        }
      

        # List for storing remediated Subnet(s)
        $SubnetRemediated = @()

        # List for storing skipped Subnet(s)
        $SubnetSkipped = @()

        Write-Host "Enabling the NSG on Subnet(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of Subnet(s) which needs to be remediated.
        $SubnetWithoutNSGConfigured | ForEach-Object {
            $subnet = $_
            try
            {
                
                    Write-Host "To Start configuring the NSG on the Subnet(s), Please enter the Network Security Group Name..." -ForegroundColor $([Constants]::MessageType.Info)
                    $NSGName = Read-Host -Prompt "Please enter name of Network Security Group"
                    $NSGRGName = Read-Host -Prompt "Please enter Resource Group of Network Security Group"
                    if($NSGName -ne $null -and $NSGRGName -ne $null)
                    {
                        $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $NSGRGName -Name $NSGName
                        if($NSGName -ne $null)
                        {
                           
                            $vnet = Get-AzVirtualNetwork -Name $_.ResourceVirtualNetworkName -ResourceGroupName $_.ResourceGroupName
                            $vNetSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $Vnet -Name $_.ResourceName
                            $vNetSubnet.NetworkSecurityGroup = $nsg
                            # $remediatedVNet = Set-AzVirtualNetwork -VirtualNetwork $vnet 
                            $remediatedVnet = $vnet | Set-AzVirtualNetwork
                            $remediatedSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $remediatedVnet -Name $_.ResourceName

                            if($remediatedSubnet.NetworkSecurityGroup -ne $null)
                            {
                                $subnet.IsNSGConfigured = $true
                                $SubnetRemediated += $subnet
                                $logResource = @{}	
                                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                                $logResource.Add("ResourceName",($_.ResourceName))	
                                $logRemediatedResources += $logResource	
                            }
                            else
                            {
                                $SubnetSkipped += $subnet
                                $logResource = @{}	
                                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                                $logResource.Add("ResourceName",($_.ResourceName))
                                $logResource.Add("Reason", "Error Configuring NSG on : [$($subnet)]")      
                                $logSkippedResources += $logResource	

                            }
                        }
                        else
                        {
                            $SubnetSkipped += $subnet
                            $logResource = @{}	
                            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                            $logResource.Add("ResourceName",($_.ResourceName))
                            $logResource.Add("Reason", "Error Configuring NSG on : [$($subnet)]")      
                            $logSkippedResources += $logResource	
                        }
                    }
                    else
                    {
                        Write-Host "Network Security Group Name or Resource Group can not be empty..." -ForegroundColor $([Constants]::MessageType.Info)
                        $SubnetSkipped += $subnet                                    
                        return;
                    }

                    
                   
                    
                
            }
            catch
            {
                $SubnetSkipped += $subnet
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
        if ($($SubnetRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Successfully configured the NSG on the Suvbnet(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            $SubnetRemediated | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $SubnetRemediatedFile = "$($backupFolderPath)\RemediatedSubnets.csv"
            $SubnetRemediated | Export-CSV -Path $SubnetRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($SubnetRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

           
        
        if ($($SubnetSkipped | Measure-Object).Count -gt 0)
        {

            Write-Host "Error while configuring NSG on the subnet(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            $SubnetSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $SubnetSkippedFile = "$($backupFolderPath)\SkippedSubnet.csv"
            $SubnetSkipped | Export-CSV -Path $SubnetSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($SubnetSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
        
       
    }
    
}

function Remove-NSGConfigurationOnSubnet
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial' Control.
        Remove NSG configuration from the subnet(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Remove-NSGConfigurationOnSubnet.

        .OUTPUTS
        None. Remove-NSGConfigurationOnSubnet does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Remove-NSGConfigurationOnSubnet -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\RemoveNSGConfiguration\RemediatedSubnets.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

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

    Write-Host "To remove NSG configuration from the Subnet(s) in a Subscription, Contributor or higher privileged role assignment on the Virtual Network(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Prepare to fetch all Subnet(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file:  [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Fetch all Subnet(s) from" -NoNewline
    Write-Host " [$($FilePath)\...]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $SubnetDetails = Import-Csv -LiteralPath $FilePath

    $validSubnetDetails = $SubnetDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalSubnet = $(($validSubnetDetails|Measure-Object).Count)

    if ($totalSubnet -eq 0)
    {
        Write-Host "No Subnet(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$(($validSubnetDetails|Measure-Object).Count)] Subnet(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"},                    
                    @{Expression={$_.VirtualNetworkName};Label="VirtualNetworkName";Width=100;Alignment="left"}
                    @{Expression={$_.ResourceId};Label="IsNSGConfigured";Width=100;Alignment="left"},
                    
        
    $validSubnetDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RemoveNSGfromSubnet"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Remove NSG Configuration from all remediated Subnet(s) in the Subscription"
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        
        Write-Host "Do you want to remove NSG Configuration from Subnet(s) mentioned in the file?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "NSG Configuration will not be rolled back on Subnet(s) mentioned in the file. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }
            Write-Host "NSG Configuration will be rolled back on Subnet(s) mentioned in the file." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. NSG Configuration will be rolled back on Subnet(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Subnet resource.
    $SubnetRolledBack = @()

    # List for storing skipped rolled back Subnet resource.
    $SubnetSkipped = @()


    $validSubnetDetails | ForEach-Object {
        $Subnet = $_
        try
        {   
            
            $vnet = Get-AzVirtualNetwork -Name $_.ResourceVirtualNetworkName -ResourceGroupName $_.ResourceGroupName
            $VnetSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $Vnet -Name $_.ResourceName
            $VnetSubnet.NetworkSecurityGroup = $null
            # $remediatedVNet = Set-AzVirtualNetwork -VirtualNetwork $vnet 
            $remediatedVnet = $vnet | Set-AzVirtualNetwork
            $remediatedSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $remediatedVnet -Name $_.ResourceName
            
            if($remediatedSubnet.NetworkSecurityGroup -eq $null)
            {
                $Subnet.IsNSGConfigured = $false
                $SubnetRolledBack += $Subnet
            }
            else
            {
                $SubnetSkipped += $Subnet
            }
            
        }
        catch
        {
            $SubnetSkipped += $Subnet
        }
    }


    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
    if ($($SubnetRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "NSG configuration has been removed on the following subnet(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
        $SubnetRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $SubnetRolledBackFile = "$($backupFolderPath)\RolledBackSubnet.csv"
        $SubnetRolledBack | Export-CSV -Path $$SubnetRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($SubnetRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
    }

    if ($($SubnetSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error while removing NSG configuration on the Subnet(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
        $SubnetSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

            
        # Write this to a file.
        $SubnetSkippedFile = "$($backupFolderPath)\RollbackSkippedSubnet.csv"
        $SubnetSkipped | Export-CSV -Path $SubnetSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to" -NoNewline
        Write-Host " [$($SubnetSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
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
