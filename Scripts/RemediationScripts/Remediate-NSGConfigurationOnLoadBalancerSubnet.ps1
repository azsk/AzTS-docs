<###
# Overview:
    This script is used to configure the NSG on Subnet being used in the Load Balancer in a Subscription.

# Control ID:
    Azure_LoadBalancer_NetSec_Enable_WAF

# Display Name:
    Load Balancer should have Web Application Firewall (WAF).

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
        Remediates 'Azure_LoadBalancer_NetSec_Enable_WAF' Control.

        .DESCRIPTION
        Remediates 'Azure_LoadBalancer_NetSec_Enable_WAF' Control.
        Add the NSG configuration on the Subnet(s) of Load Balancer in the Subscription. 

        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.

        .PARAMETER Force
        Specifies a forceful remediation without any additional prompts.
       
        .PARAMETER DryRun	
        Specifies a dry run of the actual remediation.
        
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
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies a dry run of the actual remediation")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies a dry run of the actual remediation")]
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

    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)
    
    Write-Host " To configure the NSG on the Subnet of Load Balancer in a Subscription, Contributor or higher privileged role assignment on the Virtual Network(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)  

    Write-Host "[Step 2 of 4] Fetch all Subnets(s)"
    Write-Host $([Constants]::SingleDashLine)

    # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources=@()	

    # To keep List of Load Balancers
    $LoadBalancers = @()

    # To keep List of Non-Compliant Subnets
    $NonCompliantSubnets =@()

    # Control Id	
    $controlIds = "Azure_LoadBalancer_NetSec_Enable_WAF"
    
    if ([String]::IsNullOrWhiteSpace($FilePath))	
    {	
        Write-Host "Fetching all Load Balancer(s) in Subscription: [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Get all Load Balancer(s) in a Subscription
        $LoadBalancers =  Get-AzLoadBalancer -ErrorAction Stop

        $LoadBalancers = $LoadBalancers | Select-Object @{N='ResourceId';E={$_.Id}},
                                                    @{N='ResourceGroupName';E={$_.Id.Split("/")[4]}},
                                                    @{N='ResourceName';E={$_.Name}},
                                                    @{N='ResourceSubNetId';E={$_.FrontendIPConfigurations.SubnetText}},
                                                    @{N='ResourceVirtualNetworkName';E={$_.FrontendIPConfigurations.SubnetText.Split('/')[8]}},
                                                    @{N='ResourceVirtualNetworkRGName';E={$_.FrontendIPConfigurations.SubnetText.Split('/')[4]}}


    $totalLoadBalancer = ($LoadBalancers| Measure-Object).Count

    if ($totalLoadBalancer -eq 0)
    {
        Write-Host "Load Balancer(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalLoadBalancer)] Load Balancer(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
        
    foreach($item in $LoadBalancers)
    {
        if($item.ResourceVirtualNetworkName -ne $null)
        {
            $VnetDetails = Get-AzVirtualNetwork -Name $item.ResourceVirtualNetworkName
            
            Foreach($subnet in $VnetDetails.Subnets)
            {
                $subnetDetails = $item.ResourceSubNetId | ConvertFrom-Json

                Foreach($Vnetsubnet in $subnetDetails)
                {
                    if($subnet.Id -eq $Vnetsubnet.Id)
                    {
                        if($subnet.NetworkSecurityGroup.Id -eq $null)
                        {  
                            $LoadbalancerObj = [NonCompliantLoadBalancerSubnet]:: new()
                            
                            $LoadbalancerObj.IsNSGConfigured = $false
                            $LoadbalancerObj.NonCompliantSubnetId = $Vnetsubnet.Id
                            $LoadbalancerObj.NonCompliantSubnetName = $Vnetsubnet.Id.Split('/')[10]
                            $LoadbalancerObj.ResourceId = $item.ResourceId
                            $LoadbalancerObj.ResourceVirtualNetworkName = $item.ResourceVirtualNetworkName
                            $LoadbalancerObj.ResourceVirtualNetworkRGName = $item.ResourceVirtualNetworkRGName
                            $LoadbalancerObj.ResourceGroupName = $item.ResourceGroupName
                            $LoadbalancerObj.ResourceName = $item.ResourceName

                           $NonCompliantSubnets += $LoadbalancerObj
                                
                        }
                    }
                }
             }
          }
          }
       
    }	
    else	
    {   
     
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)	
            return
        }

        Write-Host "Fetch all Subnet(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $LoadBalancerSubnetResources = Import-Csv -LiteralPath $FilePath

        $validLoadBalancerSubnetResources = $LoadBalancerSubnetResources| Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

        foreach($item in $validLoadBalancerSubnetResources)
        {
            if($item.ResourceVirtualNetworkName -ne $null)
            {
                $VnetDetails = Get-AzVirtualNetwork -Name $item.ResourceVirtualNetworkName
                Foreach($subnet in $VnetDetails.Subnets)
                {
                    $subnetDetails = $item.NonCompliantSubnetId
                    
                        if($subnet.Id -eq $subnetDetails)
                        {
                            if($subnet.NetworkSecurityGroup.Id -eq $null)
                            {
                                $NonCompliantSubnets += $item
                            }
                        }
                    
                }
            }
        }
 }                                                     
    
    $totalLoadBalancerSubnet = ($NonCompliantSubnets| Measure-Object).Count

    if ($totalLoadBalancerSubnet -eq 0)
    {
        Write-Host "No non Compliant Subnet(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }
  
    Write-Host "Found [$($totalLoadBalancerSubnet)] non Compliant Subnets(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceVirtualNetworkName};Label="ResourceVirtualNetworkName";Width=100;Alignment="left"},
                    @{Expression={$_.ResourceVirtualNetworkRGName};Label="ResourceVirtualNetworkRGName";Width=100;Alignment="left"},
                    @{Expression={$_.NonCompliantSubnetId};Label="NonCompliantSubnetId";Width=100;Alignment="left"},
                    @{Expression={$_.NonCompliantSubnetName};Label="NonCompliantSubnetName";Width=100;Alignment="left"},
                    @{Expression={$_.IsNSGConfigured};Label="IsNSGConfigured";Width=100;Alignment="left"}
     
    Write-Host "Subnet(s) without NSG configuration are as follows:"
    $NonCompliantSubnets | Format-Table -Property $colsProperty -Wrap
    Write-Host $([Constants]::SingleDashLine)

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
        $NonCompliantSubnets | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Subnet(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enable the WAF(Web Application Firewall) on Subnet(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)
        
        if (-not $Force)
        {
            Write-Host "Do you want to configure NSG on the Subnet(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if($userInput -ne "Y")
            {
                Write-Host "we are not starting the procedure to configure the NSG on the Subnet(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
            Write-Host $([Constants]::SingleDashLine)
        }
        # List for storing remediated Subnet(s)
        $SubnetRemediated = @()

        # List for storing skipped Subnet(s)
        $SubnetSkipped = @()

        Write-Host "Enabling the NSG on Subnet(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "To Start configuring the NSG on the Subnet(s), Please enter the Network Security Group Name and Resource Group Name" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        foreach ($item in $NonCompliantSubnets) 
        {
            $SubNetName = $item.NonCompliantSubnetName
            $vnet = Get-AzVirtualNetwork -Name $item.ResourceVirtualNetworkName -ResourceGroupName $item.ResourceVirtualNetworkRGName
            $vNetSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name $item.NonCompliantSubnetName

            if($null -eq $vNetSubnet.NetworkSecurityGroup)
            {
                $NSGName = Read-Host -Prompt "Please enter name of Network Security Group for [$SubNetName]"
                Write-Host $([Constants]::SingleDashLine)
                $NSGRGName = Read-Host -Prompt "Please enter Resource Group of Network Security Group for [$SubNetName]"
                Write-Host $([Constants]::SingleDashLine)
                if($NSGName -ne $null -and $NSGRGName -ne $null)
                {
                   $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $NSGRGName -Name $NSGName
                    if($nsg -ne $null)
                    {
                        Write-Host "Configuring Network Security group for [$SubNetName]" -ForegroundColor $([Constants]::MessageType.Info)
                        Write-Host $([Constants]::SingleDashLine)
                        $vNetSubnet.NetworkSecurityGroup = $nsg
                        $remediatedVnet = $vnet | Set-AzVirtualNetwork
                        $remediatedSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $remediatedVnet -Name $SubNetName

                        if($remediatedSubnet.NetworkSecurityGroup -ne $null)
                        {
                            Write-Host "Successfully configured the NSG on Subnet : [$SubNetName]" -ForegroundColor $([Constants]::MessageType.Update)
                            Write-Host $([Constants]::SingleDashLine)
                            $item.IsNSGConfigured = $true
                            $SubnetRemediated += $item
                            $logResource = @{}	
                            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                            $logResource.Add("ResourceName",($_.ResourceName))	
                            $logRemediatedResources += $logResource	
                        }
                        else
                        {
                            $SubnetSkipped += $item
                            $logResource = @{}	
                            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                            $logResource.Add("ResourceName",($_.ResourceName))
                            $logResource.Add("Reason", "Error Configuring NSG on : [$($item)]")      
                            $logSkippedResources += $logResource	
                        }
                    }
                    else
                    {
                        $SubnetSkipped += $item
                        $logResource = @{}	
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))	
                        $logResource.Add("ResourceName",($_.ResourceName))
                        $logResource.Add("Reason", "Error Configuring NSG on : [$($item)]")      
                        $logSkippedResources += $logResource	
                    }
                }
                else
                {
                    Write-Host "Network Security Group Name or Resource Group can not be empty..." -ForegroundColor $([Constants]::MessageType.Info)
                    $SubnetSkipped += $item                                    
                    return;
                }                                               
            }
            else
            {
                Write-Host "Network Security Group is already configured on [$SubNetName]" -ForegroundColor $([Constants]::MessageType.Info)
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
        Rolls back remediation done for 'Azure_LoadBalancer_NetSec_Enable_WAF' Control.
        .DESCRIPTION
        Rolls back remediation done for 'Azure_LoadBalancer_NetSec_Enable_WAF' Control.
        Remove NSG configuration from the subnet(s) of Load Balancer in the Subscription. 
        
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
                    @{Expression={$_.ResourceVirtualNetworkName};Label="VirtualNetworkName";Width=100;Alignment="left"},
                    @{Expression={$_.ResourceVirtualNetworkRGName};Label="VirtualNetworkRGName";Width=100;Alignment="left"},
                    @{Expression={$_.NonCompliantSubnetId};Label="CompliantSubnetId";Width=100;Alignment="left"},
                    @{Expression={$_.NonCompliantSubnetName};Label="CompliantSubnetName";Width=100;Alignment="left"},
                    @{Expression={$_.IsNSGConfigured};Label="IsNSGConfigured";Width=100;Alignment="left"}
                    
        
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
        Write-Host $([Constants]::SingleDashLine)
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)

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

    foreach($item in $validSubnetDetails)
    {
        if($item.IsNSGConfigured -eq $true)
        {
             $subnetName = $item.NonCompliantSubnetName
             $vnet = Get-AzVirtualNetwork -Name $item.ResourceVirtualNetworkName -ResourceGroupName $item.ResourceVirtualNetworkRGName
             $VnetSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $Vnet -Name $item.NonCompliantSubnetName
             if($VnetSubnet.NetworkSecurityGroup -ne $null)
             {
                Write-Host "Removing network security group from subnet : [$subnetName]"  -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                $VnetSubnet.NetworkSecurityGroup = $null
                $remediatedVnet = $vnet | Set-AzVirtualNetwork
                $remediatedSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $remediatedVnet -Name $item.NonCompliantSubnetName
                if($remediatedSubnet.NetworkSecurityGroup -eq $null)
                {
                    $item.IsNSGConfigured = $false
                    $SubnetRolledBack += $item
                }
                else
                {
                    $SubnetSkipped += $item
                }       
             }
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
        $SubnetRolledBack | Export-CSV -Path $SubnetRolledBackFile -NoTypeInformation
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

    if ($($SubnetRolledBack | Measure-Object).Count -eq 0)
    {
        $([Constants]::SingleDashLine)
        Write-Host "No Subnets found to Roll Back." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
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

class NonCompliantLoadBalancerSubnet
{
    [string] $ResourceName
    [string] $ResourceId
    [string] $ResourceGroupName
    [string] $ResourceVirtualNetworkName
    [string] $ResourceVirtualNetworkRGName
    [string] $NonCompliantSubnetId
    [string] $NonCompliantSubnetName
    [bool] $IsNSGConfigured
}