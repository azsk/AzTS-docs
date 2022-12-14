# LoadBalancer

**Resource Type:** Microsoft.Network/loadBalancers 

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_LoadBalancer_NetSec_Enable_WAF](#Azure_LoadBalancer_NetSec_Enable_WAF)

<!-- /TOC -->
<br/>

___ 

## Azure_LoadBalancer_NetSec_Enable_WAF 

### Display Name 
Load Balancer should have Web Application Firewall (WAF)

### Rationale 
WAF enforcement on the Load Balancer further strengthens the security posture of your applications by protecting them from the common web vulnerabilities. This allows you to secure both your internet-facing as well as your internal application workloads.

### Control Spec 

> **Passed:** 
>1. Network Security Group is configured on the subnets associated with the Load Balancer.
> 
> **Failed:** 
>
>1. Network Security Group is not configured on the subnets associated with the Load Balancer.
> 
> **Error:** 
>There was an error fetching WAF Configuration details of Load Balancer.
 
### Recommendation
- **Azure Portal** 

	 To Remediate WAF on Load balancer attach every subnet of virtual network with NSG/Azure Firewall.


 **For more help run:**

	Get-Help Remove-NSGConfigurationOnSubnet -Detailed
	#cGet-Help Add-NSGConfigurationOnSubnet -Detailed 

### Azure Policy or ARM API used for evaluation 

- ARM API to list FrontendIP Configuration at Subscription level: /subscriptions/{0}/providers/Microsoft.Network/loadBalancers?api-version=2019-12-01<br />
**Properties:** properties.SubnetIds <br />

- ARM API to list Backend Configuration of LoadBalancer: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/loadBalancers/{2}/backendAddressPools?api-version=2022-01-01 <br />
**Properties:** properties.BackendVnets<br />

<br />

___ 

