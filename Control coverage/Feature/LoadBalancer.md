# LoadBalancer

**Resource Type:** Microsoft.Network/loadBalancers 

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_LoadBalancer_NetSec_Enable_WAF_Trial](#Azure_LoadBalancer_NetSec_Enable_WAF_Trial)

<!-- /TOC -->
<br/>

___ 

## Azure_LoadBalancer_NetSec_Enable_WAF_Trial 

### Display Name 
[Trial] Load Balancer should have Web Application Firewall (WAF)

### Rationale 
WAF enforcement on the Load Balancer further strengthens the security posture of your applications by protecting them from the common web vulnerabilities. This allows you to secure both your internet-facing as well as your internal application workloads.

### Control Spec 

> **Passed:** 
> 1. Web Application Firewall has been configured on Load Balancer. <b>OR</b>
> 2. Network Security Group is configured on the subnets associated with the Load Balancer.
> 
> **Failed:** 
> 1. Web Application Firewall is not configured on Load Balancer. <b>OR</b>
> 2. Network Security Group is not configured on the subnets associated with the Load Balancer.
> 
> **Error:** 
>There was an error fetching WAF Configuration details of Load Balancer.
 
### Recommendation
- **Azure Portal** 

	 To Remediate WAF on Load balancer attach every subnet of virtual network with NSG/Azure Firewall.

- **PowerShell** 
	# Below commands will be useful to Configure WAF on Load Balancer
    Connect-AzAccount
	Set-AzContext -SubscriptionId "<sub id>"
	# Get Load Balancer
	Get-AzLoadBalancer -ResourceGroupName "<ResourceGroup>" -Name "<ResourceName>"
	
	# Get Virtual Network and its Subnets
	Get-AzVirtualNetwork -Name "<ResourceVNName>" -ResourceGroupName "<ResourceVNRGName>"
    Get-AzVirtualNetworkSubnetConfig -VirtualNetwork "<VirtualNetwork>" -Name "<SubNetName>"
	
	# To remediate with the given NSG configuration
    Set-AzVirtualNetwork
                                
	# For more help run:
		Get-Help Remove-NSGConfigurationOnSubnet -Detailed
		Get-Help Add-NSGConfigurationOnSubnet -Detailed 

### Azure Policy or ARM API used for evaluation 

- ARM API to list FrontendIP Configuration at Subscription level: /subscriptions/{0}/providers/Microsoft.Network/loadBalancers?api-version=2019-12-01<br />
**Properties:** properties.SubnetIds <br />

- ARM API to list Backend Configuration of LoadBalancer: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/loadBalancers/{2}/backendAddressPools?api-version=2022-01-01 <br />
**Properties:** properties.BackendVnets<br />

<br />

___ 

