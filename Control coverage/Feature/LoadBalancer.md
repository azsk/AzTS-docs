# LoadBalancer

**Resource Type:** Microsoft.Network/loadBalancers 

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_LoadBalancer_NetSec_Restrict_Network_Traffic](#Azure_LoadBalancer_NetSec_Restrict_Network_Traffic)
- [Azure_LoadBalancer_NetSec_Enable_DDoS_Protection](#azure_loadbalancer_netsec_enable_ddoS_protection)
- [Azure_LoadBalancer_SI_Remove_Inactive_LoadBalancer](#Azure_LoadBalancer_SI_Remove_Inactive_LoadBalancer)

<!-- /TOC -->
<br/>

___ 

## Azure_LoadBalancer_NetSec_Restrict_Network_Traffic 

### Display Name 
Protect Internet First Applications by restricting traffic on Azure Load Balancer

### Rationale 
Restricting traffic on the Load Balancer further strengthens the security posture of your applications by protecting them from the common web vulnerabilities. This allows you to secure both your internet-facing as well as your internal application workloads.

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
	Get-Help Add-NSGConfigurationOnSubnet -Detailed 

### Azure Policy or ARM API used for evaluation 

- ARM API to list FrontendIP Configuration at Subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/loadBalancers?api-version=2019-12-01<br />
**Properties:** properties.SubnetIds <br />

- ARM API to list Backend Configuration of LoadBalancer: /subscriptions/{subscriptionId}/resourceGroups/{1}/providers/Microsoft.Network/loadBalancers/{2}/backendAddressPools?api-version=2022-01-01 <br />
**Properties:** properties.BackendVnets<br />

<br />

___ 


## Azure_LoadBalancer_NetSec_Enable_DDoS_Protection 

### Display Name 
Protect Internet First Applications with Azure Load Balancer and Azure DDoS protection

### Rationale 
Enabling DDOS on Virtual Network of front end configurations, provides protection and defense for Azure resources against the impacts of DDoS attacks.

### Control Spec 

> **Passed:** 
> DDoS Protection Plan is configured on the Virtual Network of Load Balancer
OR <br/>No Virtual Network found attached either with FrontEnd or Backend of Load Balancer.
> 
> **Failed:** 
>
>1. DDoS must be enabled on the Virtual network of subnets being used in Load balancer Frontends or Backends.
 
### Recommendation
- **Azure Portal** 

	To Remediate, Enable DDOS on the Virtual Network of every frontend IP configuration of Load balancer or refer [link](https://learn.microsoft.com/en-us/azure/ddos-protection/manage-ddos-protection#enable-ddos-protection-for-an-existing-virtual-network).

### Azure Policy or ARM API used for evaluation 

- ARM API to list FrontendIP Configuration at Subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/loadBalancers?api-version=2019-12-01<br />
**Properties:** properties.SubnetIds <br />

- ARM API to list Backend Configuration of LoadBalancer: /subscriptions/{subscriptionId}/resourceGroups/{1}/providers/Microsoft.Network/loadBalancers/{2}/backendAddressPools?api-version=2022-01-01 <br />
**Properties:** properties.BackendVnets<br />

- ARM API to get propoerties of associated Virtual Network: /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01<br />

**Properties:** properties.enableDdosProtection
<br />

___ 

## Azure_LoadBalancer_SI_Remove_Inactive_LoadBalancer

### Display Name 
Azure Load Balancer with no backend pools should be removed

### Rationale 
Load balancer distributes inbound flows that arrive at the load balancer's front end to backend pool instances. If there are no backend pool(s), Load balancer is simply unused. Cleaning up unused Load balancer is suggested as a good hygiene practice.

### Control Spec 

> **Passed:** 
> if Backend pools are attached with the Load balancer.
> 
> **Failed:** 
> if Backend pools are not attached with the Load balancer.
>
 
### Recommendation
- **Azure Portal** 

	Go to Azure portal -> Load Balancer -> Backend pools -> If there are no pools, either delete it or attach it to a relevant pool.

### Azure Policy or ARM API used for evaluation 

- ARM API to list Backend Configuration of LoadBalancer: /subscriptions/{0}/providers/Microsoft.Network/loadBalancers?api-version=2022-07-01 <br />
**Properties:** properties.backendAddressPools<br />
<br />

___ 

