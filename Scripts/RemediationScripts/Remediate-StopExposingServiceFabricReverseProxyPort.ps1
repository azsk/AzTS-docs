<###
# Overview:
    This script is used to stop exposing the reverse proxy port publically for Service Fabric in a Subscription.

# Control ID:
    Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port

# Display Name:
    Reverse proxy port must not be exposed publicly.

# Prerequisites:
    
    Owner or higher priviliged role on the Service Fabric(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Service Fabric(s) in a Subscription that have Reverse proxy enabled and port exposed.
        3. Back up details of Service Fabric(s) that are to be remediated.
        4. Stop the Reverse proxy port to be explosed publically on Service Fabric(s) in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Service Fabric(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Enabled the Reverse proxy and expose the port publically for Service Fabric(s) in the Subscription.

# Instructions to execute the script:

    Description: 
        The Reverse proxy port can be exposed via Load balancer rule. The rule must expose the port as backend port which has been added as
        Reverse proxy port for the Service Fabric.
        To disable the Reverse proxy port, the respectiving Load balancer rule should be deleted. 
        In this script, we are deleting the rule which is exposing the Reverse proxy port. 
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to stop the Reverse porxy port to be exposed on Service Fabric(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to expose the Reverse proxy port publically on Service Fabric(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Service Fabric(s) in a Subscription that will be remediated:
    
           Disable-ReverseProxyPortForServiceFabric -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. The Reverse proxy must not b exposed publically for Service Fabric(s) in the Subscription:
       
           Disable-ReverseProxyPortForServiceFabric -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. The Reverse proxy must not b exposed publically for Service Fabric(s) in the Subscription, from a previously taken snapshot:
       
           Disable-ReverseProxyPortForServiceFabric -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\DoNotExposeReverseProxyforServiceFabric\ServiceFabricWithReverseProxyExposed.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Disable-ReverseProxyPortForServiceFabric -Detailed

    To roll back:
        1. Expose the Reverse proxy port publically for Service Fabric(s) in the Subscription, from a previously taken snapshot:
           Enable-ReverseProxyPortForServiceFabric -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\DoNotExposeReverseProxyPortforServiceFabric\RemediatedServiceFabric.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Enable-ReverseProxyPortForServiceFabric -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.ServiceFabric")

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


function Disable-ReverseProxyPortForServiceFabric
{
    <#
        .SYNOPSIS
        Remediates 'Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port' Control.

        .DESCRIPTION
        Remediates 'Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port' Control.
        Prevent exposing Reverse proxy port for Service Fabric(s) in the Subscription. 
        
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
        None. You cannot pipe objects to Disable-ReverseProxyPortForServiceFabric.

        .OUTPUTS
        None. Disable-ReverseProxyPortForServiceFabric does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-ReverseProxyPortForServiceFabric -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Disable-ReverseProxyPortForServiceFabric -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Disable-ReverseProxyPortForServiceFabric -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ServiceFabricWithReverseProxyExposed\ServiceFabricDetailsBackUp.csv

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
	    
    Write-Host "*** To Change the Reverse Proxy Settings for Service Fabric in a Subscription, Contributor or higher privileges on the Service Fabric(s) are required.***" -ForegroundColor $([Constants]::MessageType.Info)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Service Fabric(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Container details.
    $ServiceFabricDetails = @()

    # No file path provided as input to the script. Fetch all Service Fabric(s) in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Host "Fetching all Service Fabric(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all Service Fabric(s) in a Subscription
        $ServiceFabricDetails =  Get-AzServiceFabricCluster -ErrorAction Stop

        # Seperating required properties
        $ServiceFabricDetails = $ServiceFabricDetails | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                          @{N='ResourceGroupName';E={$_.Id.Split("/")[4]}},
                                                                          @{N='ResourceName';E={$_.Name}},
                                                                          @{N='IsReverseProxyPortEnabled';E={if($_.NodeTypes.ReverseProxyEndpointPort.Count -gt 0){$true}else{$false}}},
                                                                          @{N='ReverseProxyPorts';E={if($_.NodeTypes.ReverseProxyEndpointPort.Count -gt 0)
                                                                          { 
                                                                                $_.NodeTypes.ReverseProxyEndpointPort
                                                                          }                                                                          
                                                                          }}

    }
    else
    {
        if (-not (Test-Path -Path $FilePath))
        {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }

        Write-Host "Fetching all Service Fabric(s) from [$($FilePath)]..." 

        $ServiceFabricResources = Import-Csv -LiteralPath $FilePath
        $validServiceFabricResources = $ServiceFabricResources| Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
        
        $validServiceFabricResources| ForEach-Object {
            $resourceId = $_.ResourceId

            try
            {                
                $ServiceFabricResource =  Get-AzServiceFabricCluster -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
            
                $ServiceFabricDetails += $ServiceFabricResource  | Select-Object @{N='ResourceId';E={$_.Id}},
                                                                          @{N='ResourceGroupName';E={$_.Id.Split("/")[4]}},
                                                                          @{N='ResourceName';E={$_.Name}},
                                                                          @{N='IsReverseProxyPortEnabled';E={if($_.NodeTypes.ReverseProxyEndpointPort.Count -gt 0){$true} else{$false}}},
                                                                          @{N='ReverseProxyPorts';E={if($_.NodeTypes.ReverseProxyEndpointPort.Count -gt 0)
                                                                          { 
                                                                                $_.NodeTypes.ReverseProxyEndpointPort
                                                                          }                                                                          
                                                                          }}
            }
            catch
            {
                Write-Host "Error fetching Service Fabric(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
    }

    $totalServiceFabric = ($ServiceFabricDetails| Measure-Object).Count

    if ($totalServiceFabric -eq 0)
    {
        Write-Host "No Service Fabric(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalServiceFabric)] Service Fabric(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Service Fabric(s) for which Reverse proxy port are exposed.
    $ServiceFabricWithReverseProxyPortExposed = @()

    Write-Host "Separating Service Fabric(s) for which Reverse proxy port are exposed..."
    $ERvNetRGNames = @()
    $ERvNetRGNames += "ERNetwork","ERNetwork-DMZ","ERNetwork-PvtApp","ERNetwork-DB","ERNetwork-InetApp","ERNetwork-SVC","ERNetwork-LAB","ERNetwork-MVD","ERNetwork-WVD"

    $ServiceFabricDetails | ForEach-Object {
        $ServiceFabric = $_        
            if($_.IsReverseProxyPortEnabled -eq $true)
            {
                # Fetching the Load balancer and rule details 
                $loadBalancerInCurrentRG = Get-AzLoadBalancer -ResourceGroupName $_.ResourceGroupName
                $loadBalancerCollection = $loadBalancerInCurrentRG | Where-Object{$_.Tag.Value -eq $_.ResourceName}
                $isPortExposed = $false
                $ports = $_.ReverseProxyPorts
                foreach($lb in $loadBalancerCollection)
                {
                    $Rules = $lb.LoadBalancingRules
                    foreach($element in $ports)
                    {
                        if($Rules.BackendPort -contains $element)
                        {
                            $isPortExposed = $true
                        }
                    }
                }
             $ServiceFabricDetails =  Get-AzServiceFabricCluster -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
             

            foreach($node in $ServiceFabricDetails.NodeTypes)
            { 
    
                $nodeName = $node.Name
                $virtualmachineSS = Get-AzVmss -ResourceGroupName $_.ResourceGroupName -VMScaleSetName $nodeName
                $networkconfigurations = $virtualmachineSS.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations
                $virtualnetworkName = ''
                $isServiceFabricERvNetType = $false
                foreach($networkconfig in $networkconfigurations)
                {
                    foreach($ipconfig in $networkconfig.IpConfigurations)
                        {
                            if($ipconfig.Subnet.id.contains('virtualNetworks'))
                            {
                                $virtualnetworkName = $ipconfig.Subnet.id.Split('/')[8]
                                $virtualnetwork = Get-AzVirtualNetwork -Name $virtualnetworkName
                                if($ERvNetRGNames.Contains($virtualnetwork.ResourceGroupName))
                                {
                                    $isServiceFabricERvNetType = $true
                                    break
                                }
                
                            foreach($subnet in $virtualnetwork.Subnets)
                                {
                                    foreach($ipconfigdetails in $subnet.IpConfigurations)
                                        {
                                            if($ipconfigdetails.id.contains('virtualNetworkGateways'))
                                                {
                                                $gatewayName = $ipconfigdetails.id.Split('/')[8]
                                                $gateway = Get-AzVirtualNetworkGateway -ResourceGroupName $_.ResourceGroupName -name $gatewayName
                                                 if($gateway.GatewayType -eq "ExpressRoute")
                                                    {
                                                    $isServiceFabricERvNetType = $true
                                                     break
                                                    }
                                                }
                                        }
                                }               
                            }
                    }
   
                }
            }
            if($isPortExposed -eq $true -and $isServiceFabricERvNetType -eq $false)
                {
                    $ServiceFabricWithReverseProxyPortExposed += $ServiceFabric
                }
            }
    }
   
    $totalServiceFabricWithReverseProxyPortExposed  = ($ServiceFabricWithReverseProxyPortExposed | Measure-Object).Count

    if ($totalServiceFabricWithReverseProxyPortExposed  -eq 0)
    {
        Write-Host "No Service Fabric(s) found with Reverse porxy port exposed. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$($totalServiceFabricWithReverseProxyPortExposed)] Service Fabric(s) for which Reverse Proxy port has been exposed publically." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"},
                    @{Expression={$_.IsReverseProxyPortEnabled};Label="IsReverseProxyPortEnabled";Width=100;Alignment="left"},
                    @{Expression={$_.ReverseProxyPorts};Label="Reverse Proxy Ports";Width=100;Alignment="left"}

        
    $ServiceFabricWithReverseProxyPortExposed | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ServiceFabricWithReverseProxyPortExposed"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up Service Fabric(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
    
        # Backing up Service Fabric(s) details.
        $backupFile = "$($backupFolderPath)\ServiceFabricDetailsBackUp.csv"

        $ServiceFabricWithReverseProxyPortExposed | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Service Fabric(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Delete Load balancer rules which are exopsing Reverse Proxy port publically for Service Fabric(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)
        

        Write-Host "Do you want to delete the Load balaner rules which are exposing Reverse proxy port publically for Service Fabric(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            
        $userInput = Read-Host -Prompt "(Y|N)"

        if($userInput -ne "Y")
        {
            Write-Host "Load balancer Rules will be deleted to prevent exposing the Reverse proxy ports for Service Fabric(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }
       

        # List for storing remediated Service Fabric(s)
        $ServiceFabricRemediated = @()

        # List for storing skipped Service Fabric(s)
        $ServiceFabricSkipped = @()

        Write-Host "Starting to delete the Load balancer rules exposing the Reverse proxy ports for Service Fabric(s)." -ForegroundColor $([Constants]::MessageType.Info)

        # Loop through the list of Service Fabric(s) which needs to be remediated.
        $ServiceFabricWithReverseProxyPortExposed | ForEach-Object {
            $ServiceFabric = $_
            $sfName = $_.ResourceName
            try
            {
                # Checking the Service Fabric if they are not of ERvnet types

                $ServiceFabricDetails =  Get-AzServiceFabricCluster -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
             
                $loadBalancerInCurrentRG = Get-AzLoadBalancer -ResourceGroupName $_.ResourceGroupName
                $loadBalancerCollection = $loadBalancerInCurrentRG | Where-Object{$_.Tag.clusterName -eq $sfName}
                $isPortExposed = $false
                $ports = $_.ReverseProxyPorts
                foreach($loadbalancer in $loadBalancerCollection)
                {
                    $servicefabricnodename = $loadbalancer.Name.Split('-')[3]
                    $virtualmachineSS = Get-AzVmss -ResourceGroupName $_.ResourceGroupName -VMScaleSetName $servicefabricnodename
                    $networkconfigurations = $virtualmachineSS.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations
                    $virtualnetworkName = ''
                    $isServiceFabricERvNetType = $false
                    foreach($networkconfig in $networkconfigurations)
                    {
                        foreach($ipconfig in $networkconfig.IpConfigurations)
                            {
                                if($ipconfig.Subnet.id.contains('virtualNetworks'))
                                {
                                    $virtualnetworkName = $ipconfig.Subnet.id.Split('/')[8]
                                    $virtualnetwork = Get-AzVirtualNetwork -Name $virtualnetworkName
                                    if($ERvNetRGNames.Contains($virtualnetwork.ResourceGroupName))
                                    {
                                        Write-Host "Skipping this Service Fabric node as this is of ERvNet type." -ForegroundColor $([Constants]::MessageType.Warning)
                                        $isServiceFabricERvNetType = $true
                                        break
                                    }
                
                                foreach($subnet in $virtualnetwork.Subnets)
                                    {
                                        foreach($ipconfigdetails in $subnet.IpConfigurations)
                                            {
                                                if($ipconfigdetails.id.contains('virtualNetworkGateways'))
                                                    {
                                                    $gatewayName = $ipconfigdetails.id.Split('/')[8]
                                                    $gateway = Get-AzVirtualNetworkGateway -ResourceGroupName $_.ResourceGroupName -name $gatewayName
                                                     if($gateway.GatewayType -eq "ExpressRoute")
                                                        {
                                                        $isServiceFabricERvNetType = $true
                                                         break
                                                        }
                                                    }
                                            }
                                    }               
                                }
                        }
   
                    }
                    if($isServiceFabricERvNetType -eq $false){
                        $lbRules = $loadbalancer.LoadBalancingRules
                        foreach($i in (0..($lbRules.Lists.length-1)))
                        {
                            if($ports -contains $lbRules[$i].BackendPort)
                            {
                            $ruleToKeep = $lbRules[$i];
                            $portToRemediate = $lbRules[$i].BackendPort
                            $lbRuleConfiguration = @{
                                            Name = $lbRules[$i].Name;
                                            Protocol = $lbRules[$i].Protocol;
                                            LoadDistribution = $lbRules[$i].LoadDistribution;
                                            FrontendPort = $lbRules[$i].FrontendPort;
                                            BackendPort = $lbRules[$i].BackendPort;
                                            IdleTimeoutInMinutes = $lbRules[$i].IdleTimeoutInMinutes;
                                            EnableFloatingIP = $lbRules[$i].EnableFloatingIP;
                                            EnableTcpReset = $lbRules[$i].EnableTcpReset;
                                            FrontendIPConfigurationName = $lbRules[$i].FrontendIPConfiguration.Id.Split('/')[10];
                                            BackendAddressPoolName = $lbRules[$i].BackendAddressPool.Id.Split('/')[10];
                                            Probe = $lbRules[$i].Probe.Id.Split('/')[10];}

                            $LBRuleDetails = $lbRuleConfiguration | ConvertTo-Json
                           
                            $fabricDetails = @([pscustomobject]@{
                                            ResourceId=$_.ResourceId;
                                            ResourceGroupName= $_.ResourceGroupName;
                                            ResourceName= $_.ResourceName;
                                            IsReverseProxyPortEnabled = $_.IsReverseProxyPortEnabled;
                                            ReverseProxyPorts = $_.ReverseProxyPorts;
                                            LBName = $loadbalancer.Name;
                                            LBRuleConfigurations = $LBRuleDetails; })

                             $fabricDetails = $fabricDetails | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                            @{N='ResourceName';E= {$_.ResourceName}},
                                            @{N='IsReverseProxyPortEnabled';E= {$_.IsReverseProxyPortEnabled}},
                                            @{N='ReverseProxyPorts';E= {$_.ReverseProxyPorts}},
                                            @{N='LBName';E={$_.LBName}},
                                            @{N='LBRuleConfigurations';E={$_.LBRuleConfigurations}}

                            
                            Write-Host "Please confirm the Load balancer – "$loadbalancer.Name" associated with the Service Fabric "$sf.Name"." -ForegroundColor $([Constants]::MessageType.Warning)
                            $userInput = Read-Host -Prompt "(Y|N)"
                            if($userInput -eq "Y")
                            {
                            Write-Host "Please confirm the Load balancer Rule – "$lbRules[$i].Name" exposing the Reverse proxy port on the Load balancer "$loadbalancer.Name"." -ForegroundColor $([Constants]::MessageType.Warning)
                            $userInput = Read-Host -Prompt "(Y|N)"
                            if($userInput -eq "Y")
                            {                            
                            Write-Host "Would you like to delete the Load balancer Rule – "$lbRules[$i].Name". Please note, this operation may impact other associated processes if there is any." -ForegroundColor $([Constants]::MessageType.Warning)
                            $userInput = Read-Host -Prompt "(Y|N)"
                            if($userInput -eq "Y")
                            {
                            Write-Host "Started deleting the associated Load balancer rule... "
                            $Ruledeleting = Remove-AzLoadBalancerRuleConfig -Name $lbRules[$i].Name -LoadBalancer $lb
                            $updatedLB = Set-AzLoadBalancer -LoadBalancer $lb
                            $RuleExist = $updatedLB.LoadBalancingRules | Where-Object {$_.BackendPort -eq $portToRemediate}
                                if($RuleExist -eq $null){
                                    $ServiceFabricRemediated += $fabricDetails 
                                }
                                else
                                {
                                    $ServiceFabricSkipped += $fabricDetails 
                                }
                            }
                            else
                            {
                                Write-Host "User declined to delete the Load balancing rule. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                                $ServiceFabricSkipped += $fabricDetails                                            
                                 break

                            }
                            }
                            else
                            {
                                Write-Host "As per User input, association of  Load balancer Rules and Load balancer(s) are not approved. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                                $ServiceFabricSkipped += $fabricDetails
                                 break
                            }    
                            }
                            else
                            {
                                Write-Host "As per User input, association of  Load balancer and Service Fabric(s) are not approved. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                                $ServiceFabricSkipped += $fabricDetails
                                 break
                                                           
                            }

                            }
                         }
                }
                else
                {
                    Write-Host "Skipping this Load balancer as this is of ERvNet type...." -ForegroundColor $([Constants]::MessageType.Warning)

                    $ServiceFabricSkipped += $ServiceFabric
                    
                }
               
            }
            }
            
            catch
            {
                Write-Host $_
                $ServiceFabricSkipped += $ServiceFabric
            }
        }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)

      $colsPropertyNew = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"},
                        @{Expression={$_.IsReverseProxyPortEnabled};Label="IsReverseProxyPortEnabled";Width=100;Alignment="left"},
                        @{Expression={$_.ReverseProxyPorts};Label="Reverse Proxy Ports";Width=100;Alignment="left"},
                        @{Expression={$_.LBName};Label="LB Name";Width=30;Alignment="left"}
                        @{Expression={$_.LBRuleConfigurations};Label="LB Rule Configurations";Width=30;Alignment="left"}


        if ($($ServiceFabricRemediated | Measure-Object).Count -gt 0)
        {
            Write-Host "Reverse proxy ports are not exposed publically now' for the following ServiceFabric(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
           
            $ServiceFabricRemediated | Format-Table -Property $colsPropertyNew -Wrap

            # Write this to a file.
            $ServiceFabricRemediatedFile = "$($backupFolderPath)\RemediatedServiceFabric.csv"
            $ServiceFabricRemediated | Export-CSV -Path $ServiceFabricRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($ServiceFabricRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($ServiceFabricSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError while deleting the Load balancer rules exposing the Reverse proxy port for Service Fabric(s)in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
            $ServiceFabricSkipped | Format-Table -Property $colsPropertyNew -Wrap
            
            # Write this to a file.
            $ServiceFabricSkippedFile = "$($backupFolderPath)\SkippedServiceFabric.csv"
            $ServiceFabricSkipped | Export-CSV -Path $ServiceFabricSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($ServiceFabricSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    else
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Add LB Rule to expose Reverse proxy port Service Fabric(s) in the Subscription..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "`nNext steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "*    Run the same command with -FilePath $($backupFile) and without -DryRun, Stop exposing Reverse proxy port for Service Fabric(s) listed in the file."
    }
}

function Enable-ReverseProxyPortForServiceFabric
{
    <#
        .SYNOPSIS
        Roll back remediation done for 'Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port' Control.
        Create Load balancer rule to expose Reverse proxy port on Service Fabric(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Force parameter will not be supported by this BRS.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Enable-ReverseProxyPortForServiceFabric.

        .OUTPUTS
        None. Enable-ReverseProxyPortForServiceFabric does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-ReverseProxyPortForServiceFabric -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\ExposeReverseProtOnServiceFabric\RemediatedServiceFabric.csv

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

    Write-Host "*** To delete the Load balancer rule exposing the Reverse proxy port for Service Fabric in a Subscription, Contributor or higher privileges on the Service Fabric are required.***" -ForegroundColor $([Constants]::MessageType.Info)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Service Fabric(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Service Fabric(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $ServiceFabricDetails = Import-Csv -LiteralPath $FilePath

    $validServiceFabricDetails = $ServiceFabricDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalServiceFabric = $(($validServiceFabricDetails|Measure-Object).Count)

    if ($totalServiceFabric -eq 0)
    {
        Write-Host "No Service Fabric(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($validServiceFabricDetails|Measure-Object).Count)] Service Fabric(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                        @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"},
                        @{Expression={$_.IsReverseProxyPortEnabled};Label="IsReverseProxyPortEnabled";Width=100;Alignment="left"},
                        @{Expression={$_.ReverseProxyPorts};Label="Reverse Proxy Ports";Width=100;Alignment="left"},
                        @{Expression={$_.NodeVMCount};Label="Node VM Instance Count";Width=100;Alignment="left"}
                        @{Expression={$_.LBName};Label="LB Name";Width=30;Alignment="left"},                        
                        @{Expression={$_.LBRuleConfigurations};Label="LB Rule Configurations";Width=30;Alignment="left"}

        
    $validServiceFabricDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ExposeReverseProtOnServiceFabric"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Create Load balancing rule to expose Reverse proxy port publically for Service Fabric(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

   
    Write-Host "Do you want to add Load balancer rule to expose Reverse proxy port for all Service Fabric(s) mentioned the file in the ?"  -ForegroundColor $([Constants]::MessageType.Warning)
    $userInput = Read-Host -Prompt "(Y|N)"

    if($userInput -ne "Y")
    {
        Write-Host "Load balancer rule to expose Reverse proxy will not be added for Service Fabric(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
    Write-Host "Load balancer rule to expose Reverse proxy port will be added for Service Fabric(s) in the Subscription." -ForegroundColor $([Constants]::MessageType.Update)


    # List for storing rolled back Service Fabric resource.
    $ServiceFabricRolledBack = @()

    # List for storing skipped rolled back ServiceFabric resource.
    $ServiceFabricSkipped = @()


    $validServiceFabricDetails | ForEach-Object {
        $ServiceFabric = $_
        try
        {
        
        if($_.IsReverseProxyPortEnabled -eq $true)
        {
            
            $reverseProxyPort = $_.ReverseProxyPorts

            $lbRuleConfiguration = $_.LBRuleConfigurations | ConvertFrom-Json
            $loadbalancer = Get-AzLoadBalancer -Name $_.LBName -ResourceGroupName $_.ResourceGroupName

            # find the backend port to expose via LB rule.
            if(($loadbalancer.LoadBalancingRules | Where-Object {$_.BackendPort -eq $reverseProxyPort}) -eq $null){
                Write-Host "Started adding the Load balancer rule with the available configuration...." -ForegroundColor $([Constants]::MessageType.Info)

                # Get the front end IP Configuration.
                $frontendIP = Get-AzLoadBalancerFrontendIpConfig -Name $lbRuleConfiguration.FrontendIPConfigurationName -LoadBalancer $loadbalancer

                 # Get the back end pool Configuration.
                $backendPool = Get-AzLoadBalancerBackendAddressPoolConfig -Name $lbRuleConfiguration.BackendAddressPoolName -LoadBalancer $loadbalancer

                 # Get the health probe Configuration.
                $probe = Get-AzLoadBalancerProbeConfig -Name $lbRuleConfiguration.Probe -LoadBalancer $loadbalancer

                  # Add the new Rule.
                $newrule = Add-AzLoadBalancerRuleConfig -Name $lbRuleConfiguration.Name -LoadBalancer $loadbalancer -BackendAddressPool $backendPool -BackendPort $lbRuleConfiguration.BackendPort -FrontendIpConfiguration $frontendIP -FrontendPort $lbRuleConfiguration.FrontendPort -LoadDistribution $lbRuleConfiguration.LoadDistribution -Probe $probe -Protocol $lbRuleConfiguration.Protocol -IdleTimeoutInMinutes $lbRuleConfiguration.IdleTimeoutInMinutes
                $updatedLB = Set-AzLoadBalancer -LoadBalancer $loadbalancer
            }

            else
            {
                Write-Host "Load balancer rule is already available. exiting...." -ForegroundColor $([Constants]::MessageType.Info)
                break
            }
            if(($updatedLB.LoadBalancingRules | Where-Object {$_.BackendPort -eq $reverseProxyPort}) -ne $null){
                $ServiceFabricRolledBack += $ServiceFabric
            }
            else
            {
                $ServiceFabricSkipped += $ServiceFabric
                
            }


        }
        }
        catch
        {
            Write-Host $_
            $ServiceFabricSkipped += $ServiceFabric
        }
    }


    if ($($ServiceFabricRolledBack | Measure-Object).Count -gt 0 -or $($ServiceFabricSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($ServiceFabricRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Load balancer rule have been added to expose Reverse proxy ports for the following Service Fabric(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Update)
            $ServiceFabricRolledBack | Format-Table -Property $colsProperty -Wrap

            # Write this to a file.
            $ServiceFabricRolledBackFile = "$($backupFolderPath)\RolledBackServiceFabric.csv"
            $ServiceFabricRolledBack | Export-CSV -Path $ServiceFabricRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($ServiceFabricRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
        }

        if ($($ServiceFabricSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "`nError while adding the Load balancer rule to expose Reverse proxy ports for Service Fabric(s) in the Subscription.:" -ForegroundColor $([Constants]::MessageType.Error)
            $ServiceFabricSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $ServiceFabricSkippedFile = "$($backupFolderPath)\RollbackSkippedServiceFabric.csv"
            $ServiceFabricSkipped | Export-CSV -Path $ServiceFabricSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($ServiceFabricSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
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
