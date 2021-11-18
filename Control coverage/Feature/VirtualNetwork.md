# VirtualNetwork

**Resource Type:** Microsoft.Network/virtualNetworks

___ 

## Azure_ERvNet_NetSec_Dont_Use_PublicIPs 

### DisplayName 
Remove public IPs on ER connected VMs

### Rationale 
Public IP addresses on an ER-connected virtual network can expose the corporate network to security attacks from the internet. 

### Control Spec 

> **Passed:** 
> No NICs found on the ERvNet. Or, no Public IP is configured for any NIC on the ERvNet.
> 
> **Failed:** 
> Public IP(s) are configured for one or more NICs attached to ERvNet.
> 
> **NotApplicable:** 
> Current VNet resource object is not connected to ExpressRoute gateway.
> 
### Recommendation 

- **Azure Portal** 
	
	Step 1 : Go to Azure portal --> Virtual Machines --> Select the virtual machine you want to disassociate the public IP address from.

	Step 2 : Under **Overview** section of the VM, select the **Public IP address** which will navigate to the Public IP address resource type.​

	Step 3 : Under Overview of Public IP, select **"Dissociate"** to remove the Public IP address.​

- **PowerShell** 

	 ```powershell 
	 	$nic = Get-AzNetworkInterface -Name '<NIC Name>' -ResourceGroup '<RG Name>'
		$nic.IpConfigurations.publicipaddress.id = $null
		Set-AzNetworkInterface -NetworkInterface $nic
	 ```  

<!----
- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  --->

### Azure Policy or ARM API used for evaluation 

- ARM API to list Network Interfaces at subscription level:- <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01 <br />
**Properties:** properties.ipConfigurations[*].properties.subnet.id, properties.ipConfigurations[*].properties.publicIPAddress.id

- ARM API to list Virtual Network Gateways at subscription level:- <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2019-04-01 <br />
**Properties:** properties.gatewayType

<br />

___ 

## Azure_ERvNet_NetSec_Dont_Use_Multi_NIC_VMs 

### DisplayName 
There must not be multiple NICs on ExpressRoute-connected VMs

### Rationale 
Using multiple NICs, one can route traffic between the ER-connected virtual network and another non-ER-connected virtual network. This can put the corporate network at risk. (Multi-NIC VMs on an ER-connected virtual network may be required in some advanced scenarios. You should engage the network security team for a review in such cases.)

### Control Spec 

> **Passed:** 
> No NICs found on the ERvNet. Or, no VMs attached to ERvNet which have multiple NICs.
> 
> **Failed:** 
> One or more VMs in the ERvNet are connected to multiple NICs.
> 
> **NotApplicable:** 
> Current VNet resource object is not connected to ExpressRoute gateway.
> 
### Recommendation 

- **Azure Portal** 

	 Remove any additional NICs on VMs which are on an ER-connected virtual network. Refer: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-network-interface-vm#remove-a-network-interface-from-a-vm 

<!----
- **PowerShell** 

	 ```powershell 
	 # NA
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policy or ARM API used for evaluation 

- ARM API to list Network Interfaces at subscription level:-<br /> 
/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01 <br />
**Properties:** properties.ipConfigurations[*].properties.subnet.id, properties.virtualMachine.id

- ARM API to list Virtual Network Gateways at subscription level:-<br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2019-04-01 <br />
**Properties:** properties.gatewayType

<br />

___ 

## Azure_ERvNet_NetSec_Dont_Enable_IPForwarding_for_NICs 

### DisplayName 
Set 'EnableIPForwarding' flag to false for NICs in the ExpressRoute-connected vNet

### Rationale 
Using IP Forwarding one can change the routing of packets from an ER-connected virtual network. This can lead to bypass of network protections that are required and applicable for corpnet traffic. (IP Forwarding on an ER-connected virtual network may be required only in advanced scenarios such as Network Virtual Appliances. You should engage the network security team for a review in such cases.)

### Control Spec 

> **Passed:** 
> No NICs found on the ERvNet. Or, no NICs found with EnableIPForwarding turned on the ERvNet.
> 
> **Failed:** 
> IP Forwarding is enabled for one or more NIC(s) in ERvNet.
> 
> **NotApplicable:** 
> Current VNet resource object is not connected to ExpressRoute gateway.
> 
### Recommendation 

- **Azure Portal** 

	Step 1 : Go to Azure portal --> Network interfaces --> Select the Network interface for which you want to disbale the 'IP Forwarding'.

	Step 2 : Go to Settings --> IP Configurations.​

	Step 3 : Set 'IP forwarding' switch to 'Disabled'.

	For more information refer: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-udr-overview 

<!----
- **PowerShell** 

	 ```powershell 
	 # NA
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policy or ARM API used for evaluation 

- ARM API to list Network Interfaces at subscription level:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01 <br />
**Properties:** properties.ipConfigurations[*].properties.subnet.id, properties.enableIPForwarding

- ARM API to list Virtual Network Gateways at subscription level:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2019-04-01 <br />
**Properties:** properties.gatewayType

<br />

___ 

## Azure_ERvNet_NetSec_Dont_Add_UDRs_on_Subnets 

### DisplayName 
There must not be a UDR on *any* subnet in an ExpressRoute-connected vNet 

### Rationale 
Using UDRs on any subnet of an ER-connected virtual network can lead to security exposure for corpnet traffic by allowing it to be routed in a way that evades inspection from network security scanners.

### Control Settings 
```json 
{
    "ApprovedRoutes": [
        {
            "AddressPrefix": "0.0.0.0/0",
            "NextHopType": "VirtualAppliance",
            "ResourceGroup": "ERNetwork-LAB"
        },
        {
            "AddressPrefix": "0.0.0.0/0",
            "NextHopType": "VirtualAppliance",
            "ResourceGroup": "ERNetwork-MVD"
        }
    ]
}
 ```

### Control Spec 

> **Passed:** 
> No UDRs found on any Subnet of ERvNet. Or, only exempted UDR(s) are defined in subnet of ERvNet.
> 
> **Failed:** 
> UDRs are attached to one or more subnets in ERvNet.
> 
> **NotApplicable:** 
> Current VNet resource object is not connected to ExpressRoute gateway.
> 
### Recommendation 

<!----
- **Azure Portal** 

	 Remove association between any UDRs you may have added and respective subnets using the 'Remove-AzureSubnetRouteTable' command. Run 'Get-Help Remove-AzureSubnetRouteTable -full' for more help. --->

- **PowerShell** 

	 Remove association between any UDRs you may have added and respective subnets using the 'Remove-AzureSubnetRouteTable' command. Run 'Get-Help Remove-AzureSubnetRouteTable -full' for more help.  

<!----
- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policy or ARM API used for evaluation 

- ARM API to list Virtual Networks and route table associated with each subnet of VNet at subscription level:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01 <br />
 **Properties:** properties.subnets[*].properties.routeTable.id

- ARM API to list Virtual Network Gateways at subscription level:-<br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2019-04-01 <br />
 **Properties:** properties.gatewayType

- ARM API to list all Route Tables at subscription level:-<br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/routeTables?api-version=2020-03-01 <br />
 **Properties:** properties.routes[*].name, properties.routes[*].properties.addressPrefix, properties.routes[*].properties.nextHopType

<br />

___ 

## Azure_ERvNet_NetSec_Dont_Add_VPN_Gateways 

### DisplayName 
There must not be another virtual network gateway (GatewayType = Vpn) in an ExpressRoute-connected vNet 

### Rationale 
Using other gateway types on an ER-connected virtual network can lead to pathways for corpnet traffic where the traffic can get exposed to the internet or evade inspection from network security scanners. This creates a direct risk to corpnet security.

### Control Spec 

> **Passed:** 
> No other types of gateways found on the VNet other than ExpressRoute.
> 
> **Failed:** 
> Gateways of type other than ExpressRoute are found on the VNet.
> 
> **NotApplicable:** 
> Current VNet resource object is not connected to ExpressRoute gateway.
> 
### Recommendation 

<!----
- **Azure Portal** 

	 Remove any VPN Gateways from the ExpressRoute-connected virtual network. Refer: https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-delete-vnet-gateway-powershell  --->

- **PowerShell** 

	 Remove any VPN Gateways from the ExpressRoute-connected virtual network. Refer: https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-delete-vnet-gateway-powershell 

<!----
- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) --->

### Azure Policy or ARM API used for evaluation 

- ARM API to list Virtual Networks and their subnets at subscription level:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01 <br />
 **Properties:** properties.subnets[*].id

- ARM API to list Virtual Network Gateways at subscription level:-<br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2019-04-01 <br />
 **Properties:** properties.gatewayType

<br />

___ 

## Azure_ERvNet_NetSec_Dont_Use_VNet_Peerings 

### DisplayName 
Peering must not be allowed on ExpressRoute connected Virtual Network

### Rationale 
A virtual network peering on an ER-connected circuit establishes a link to another virtual network whereby traffic egress and ingress can evade inspection from network security appliances. This creates a direct risk to corpnet security. 

### Control Settings 
```json 
{
    "ApprovedPeerings": [
        {
            "RemoteNetworkIdPrefix": "",
            "ResourceGroup": "ERNetwork-LAB"
        },
        {
            "RemoteNetworkIdPrefix": "",
            "ResourceGroup": "ERNetwork-MVD"
        },
        {
            "RemoteNetworkIdPrefix": "",
            "ResourceGroup": "ERNetwork-PvtApp"
        },
        {
            "RemoteNetworkIdPrefix": "",
            "ResourceGroup": "ERNetwork-InetApp"
        },
        {
            "RemoteNetworkIdPrefix": "",
            "ResourceGroup": "ERNetwork-SVC"
        },
        {
            "RemoteNetworkIdPrefix": "",
            "ResourceGroup": "ERNetwork-DB"
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> No peering found on ERvNet. Or, only exempted peering are defined in ERvNet.
> 
> **Failed:** 
> One or more non exempted peering found on ERvNet.
>  
> **NotApplicable:** 
> Current VNet resource object is not connected to ExpressRoute gateway.
> 
### Recommendation 

<!----
- **Azure Portal** 

	 Remove any VNet peering you added using the 'Remove-AzVirtualNetworkPeering' PS command. Run 'Get-Help Remove-AzVirtualNetworkPeering -full' for more help. --->

- **PowerShell** 

	 Remove any VNet peering you added using the 'Remove-AzVirtualNetworkPeering' PS command. Run 'Get-Help Remove-AzVirtualNetworkPeering -full' for more help. 

<!----
- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) ---> 

### Azure Policy or ARM API used for evaluation 

- ARM API to list Virtual Networks and their peering at subscription level:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01 <br /> 
 **Properties:** properties.virtualNetworkPeerings[*].id, properties.virtualNetworkPeerings[*].properties.remoteVirtualNetwork.id

- ARM API to list Virtual Network Gateways at subscription level:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2019-04-01 <br />
 **Properties:** properties.gatewayType

<br />

___ 

## Azure_ERvNet_SI_Add_Only_Network_Resources 

### DisplayName 
Add only Microsoft.Network/* resources to the ERNetwork resource group

### Rationale 
The ERNetwork resource group is a critical component that facilitates provisioning of an ER-connection for your subscription. This resource group is deployed and managed by the networking team and should not be used as a general purpose resource group or as a container for non-networking resources as it can impact the ER-connectivity of your subscription.

### Control Settings 
```json 
{
    "ExemptedResourceTypes": "providers/microsoft.eventgrid/"
}
 ``` 

### Control Spec 

> **Passed:** 
> No other resource type (except "Microsoft.Network/*") found in RG.
> 
> **Failed:** 
> Other resource types (except "Microsoft.Network/*") present in RG.
> 
> **NotApplicable:** 
> Current VNet resource object is not connected to ExpressRoute gateway.
> 
### Recommendation 

- **Azure Portal** 

	 Move all other resources except Microsoft.Network/* to another resource group. To move a resource, simply go to the Overview tab for it in the Azure portal and select the Move option. 
<!--- 
- **PowerShell** 

	 ```powershell 
	 #NA 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
--->

### Azure Policy or ARM API used for evaluation 

- ARM API to list all Virtual Networks in a Subscription:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01 <br />
 **Properties:** properties.id

<br />

___ 

## Azure_ERvNet_SI_Dont_Remove_Resource_Lock 

### DisplayName 
Ensure that the ERNetwork resource group is protected with a resource lock

### Rationale 
The ERNetwork resource group is a critical component that facilitates provisioning of an ER-connection for your subscription. A resource lock is deployed on the ERNetwork resource group to keep you from deleting it accidentally. Removing this lock increases the chances of accidental write/delete of this resource group and that can impact ER-connectivity of your subscription.

### Control Settings 
```json 
{
    "LockLevel": ""
}
 ``` 

### Control Spec 

> **Passed:** 
> Required Lock is added at RG scope.
> 
> **Failed:** 
> Required Lock is not added at RG scope.
> 
> **NotApplicable:** 
> Current VNet resource object is not connected to ExpressRoute gateway.
> 

### Recommendation 

<!--- 
- **Azure Portal** 

	 Create a ReadOnly resource lock for every ER Network resource group using command New-AzResourceLock -LockName '{LockName}' -LockLevel 'ReadOnly' -Scope '/subscriptions/{SubscriptionId}/resourceGroups/{ERNetworkResourceGroup}'. Run 'Get-Help New-AzResourceLock -full' for more help. 
--->
- **PowerShell** 

	Create a ReadOnly resource lock for every ER Network resource group using command 'New-AzResourceLock'.
	 ```powershell 
	 	New-AzResourceLock -LockName '{LockName}' -LockLevel 'ReadOnly' -Scope '/subscriptions/{SubscriptionId}/resourceGroups/{ERNetworkResourceGroup}
	 ```  
	 Run 'Get-Help New-AzResourceLock -full' for more help.

<!--- 
- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
---> 

### Azure Policy or ARM API used for evaluation 

- ARM API to list all Virtual Networks in a Subscription:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01 <br />
 **Properties:** properties.id

- ARM API to list all Locks in a Subscription:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/locks?api-version=2015-01-01 <br />
 **Properties:** properties.level, id

<br />

___ 

## Azure_ERvNet_NetSec_Revoke_PublicIPs_On_Sub 

### DisplayName 
There must not be any Public IPs on Subscription with ExpressRoute connection

### Rationale 
Public IP addresses on an ER-connected virtual network can expose the corporate network to security attacks from the internet.

### Control Spec 

> **Passed:** 
> No Public IPs found on subscription.
> 
> **Failed:** 
> One or more Public IP(s) found on subscription.
> 
> **NotApplicable:** 
> Current VNet resource object is not connected to ExpressRoute gateway.
> 
### Recommendation 

<!---

- **Azure Portal** 

	 Any Public IP addresses you added to an ER-connected virtual network must be removed. Refer: https://docs.microsoft.com/en-us/powershell/module/az.network/Remove-AzPublicIpAddress 
-->
- **PowerShell** 

	Any Public IP addresses you added to a subscription which has an ER-connected virtual network must be removed. 

	 ```powershell 
	 Remove-AzPublicIpAddress -Name 'publicIpName' -ResourceGroupName 'rgName' 
	 ```  
	For more information, refer: https://docs.microsoft.com/en-us/powershell/module/az.network/Remove-AzPublicIpAddress
<!---
- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policy or ARM API used for evaluation 

- ARM API to list all Public IP addresses in a Subscription:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/publicIPAddresses?api-version=2019-11-01 <br />
 **Properties:** id

<br />

___ 

## Azure_VNet_NetSec_Justify_Peering 

### DisplayName 
Assure virtual network peering is not allowed 

### Rationale 
Resources in the peered virtual networks can communicate with each other directly. If the two peered networks are on different sides of a security boundary (e.g., corpnet v. private vNet), this can lead to exposure of corporate data. Hence any VNet peerings should be closely scrutinized and approved by the network security team.

### Control Spec 

> **Passed:** 
> No peerings found on vNet.
> 
> **Failed:** 
> One or more peerings found on vNet.
> 
> **NotApplicable:** 
> Current vNet resource object is connected to ExpressRoute gateway.
> 
### Recommendation 

<!--- 
- **Azure Portal** 

	 You can remove any virtual network peerings using the Remove-AzVirtualNetworkPeering command (unless their presence has been approved by network security team). Run 'Get-Help Remove-AzVirtualNetworkPeering -full' for more help. 
--->

- **PowerShell** 

	You can remove any virtual network peerings using the Remove-AzVirtualNetworkPeering command (unless their presence has been approved by network security team). 

	 ```powershell 
	 # Remove the virtual network peering named myVnet1TomyVnet2 located in myVnet1 in the resource group named myResourceGroup.

	Remove-AzVirtualNetworkPeering -Name "myVnet1TomyVnet2" -VirtualNetworkName "myVnet" -ResourceGroupName "myResourceGroup"
	 ```  
	Run 'Get-Help Remove-AzVirtualNetworkPeering -full' for more help.

<!---
- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policy or ARM API used for evaluation 

- ARM API to list all Virtual Networks in a Subscription:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01 <br />
 **Properties:** properties.virtualNetworkPeerings

<br />

___ 

## Azure_VNet_NetSec_Configure_NSG 

### DisplayName 
Associate Subnets with a Network Security Group 

### Rationale 
Restricting inbound and outbound traffic via NSGs limits the network exposure of the subnets within a virtual network and limits the attack surface 

### Control Settings 
```json 
{
    "AssessmentNotAvailableCausesForFallback": [
        "",
        "Exempt",
        "OffByPolicy"
    ],
    "SubnetsToExcludeFromEvaluation": [
        "gatewaysubnet",
        "azurefirewallsubnet"
    ]
}
 ``` 
 
### Control Spec 

> **Passed:** 
> All Subnets in the VNet have an associated NSG configured.
> 
> **Failed:** 
> Subnets without associated NSG are found on the VNet.
> 
> **Verify:** 
> The recommendation is disabled in the policy. VNet Kind is not available for the evaluation.
> 
> **NotApplicable:** 
> Current VNet resource object is connected to an ExpressRoute gateway.
>
> **Error:** 
> The Assessment details are not present in the Control JSON.
>
> **NotScanned:** 
> The data required for evaluation by the Reader is not available.
>
### Recommendation 

- **Azure Portal** 

	 Configure NSG rules to be as restrictive as possible via: (a) Azure Portal -> Network security groups -> <Your NSG> -> Inbound security rules -> Edit 'Allow' action rules. (b) Azure Portal -> Network security groups. -> <Your NSG> -> Outbound security rules -> Edit 'Allow' action rules 


### Azure Policy or ARM API used for evaluation 

- ARM API to list Virtual Networks and their constituent Subnets at subscription level:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01  <br />
 **Properties:** properties.subnets[*].properties.networkSecurityGroup.id
 
<br />

___ 

## Azure_VNet_NetSec_Justify_PublicIPs 

### DisplayName 
Minimize the number of Public IPs (i.e. NICs with PublicIP) on a virtual network 

### Rationale 
Public IPs provide direct access over the internet exposing the resource(s) to all type of attacks over the public network. 

### Control Spec 

> **Passed:** 
> No NICs found on the vNet.
Or, no Public IP is configured for any NIC on the vNet.
> 
> **Failed:** 
> One or more Public IP address is associated with vNet.
> 
> **NotApplicable:** 
> Current VNet resource object is connected to an ExpressRoute gateway.
> 
### Recommendation 

- **PowerShell** 

	 Unutilized Public IP address must be removed from virtual network. For more information visit: https://docs.microsoft.com/en-us/powershell/module/az.network/remove-azpublicipaddress 


### Azure Policy or ARM API used for evaluation 

- ARM API to list Network Interfaces at subscription level:- <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01 <br />
 **Properties:** properties.ipConfigurations[*].properties.subnet.id,
properties.ipConfigurations[*].properties.publicIPAddress.id

- ARM API to list Virtual Network Gateways at subscription level:- <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2019-04-01  <br />
 **Properties:** properties.gatewayType

<br />

___ 

## Azure_VNet_NetSec_Justify_Gateways 

### DisplayName 
Presence of any virtual network gateways (GatewayType = VPN/ExpressRoute) in the virtual network must be justified 

### Rationale 
Virtual network gateways enable network traffic between a virtual network and other networks. All such connectivity must be carefully scrutinized to ensure that corporate data is not subject to exposure on untrusted networks. 

### Control Spec 

> **Passed:** 
> There are NO Gateways found on the vNet.
> 
> **Failed:** 
> There are Gateways found on the vNet.
> 
> **NotApplicable:** 
> VNet resource object is connected to an ExpressRoute gateway.
> 
### Recommendation 

- **PowerShell** 

	 You can remove virtual network gateways using the Remove-AzVirtualNetworkGateway command (unless their presence has been approved by network security team). Run 'Get-Help Remove-AzVirtualNetworkGateway -full' for more help. 


### Azure Policy or ARM API used for evaluation 

- ARM API to list Virtual Networks and their subnets at subscription level:-<br />
 /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01 <br /> 
 **Properties:** properties.subnets[*].id

- ARM API to list Virtual Network Gateways at subscription level:- <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2019-04-01  <br />
**Properties:** properties.gatewayType

<br />

___ 

## Azure_VNet_NetSec_Justify_IPForwarding_for_NICs 

### DisplayName 
Use of IP Forwarding on any NIC in a virtual network should be scrutinized 

### Rationale 
Enabling IP Forwarding on a VM NIC allows the VM to receive traffic addressed to other destinations. IP forwarding is required only in rare scenarios (e.g., using the VM as a network virtual appliance) and those should be reviewed with the network security team. 

### Control Spec 

> **Passed:** 
> No NICs found on the vNet.
Or, there are no NICs with EnableIPForwarding turned on the vNet.
> 
> **Failed:** 
> IP Forwarding is enabled for one or more NIC(s) in vNet.
> 
> **NotApplicable:** 
> VNet resource object is connected to ExpressRoute gateway.
> 
### Recommendation 

- **Azure Portal** 

	 Disable IP Forwarding unless it has been reviewed and approved by network security team. Go to Azure Portal --> Navigate to VM NIC (where IP Forwarding is enabled) --> IP Configurations --> IP Forwarding settings --> Click on 'Disabled'. 

### Azure Policy or ARM API used for evaluation 

- ARM API to list Network Interfaces at subscription level:- <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01 <br /> 
**Properties:** properties.ipConfigurations[*].properties.subnet.id,
properties.enableIPForwarding

- ARM API to list Virtual Network Gateways at subscription level:- <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2019-04-01 <br /> 
**Properties:** properties.gatewayType

<br />

___ 
