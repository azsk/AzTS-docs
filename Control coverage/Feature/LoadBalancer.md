# LoadBalancer

**Resource Type:** Microsoft.Network/loadBalancers

<!-- TOC -->
- [Azure_LoadBalancer_NetSec_Enable_WAF_And_DDoS_Protection_Trial](#Azure_LoadBalancer_NetSec_Enable_WAF_And_DDoS_Protection_Trial)

<!-- /TOC -->
<br />

___ 

## Azure_LoadBalancer_NetSec_Enable_WAF_And_DDoS_Protection_Trial

### Display Name 
[Trial] Load Balancer should have Web Application Firewall (WAF) and DDoS configured

### Rationale 
WAF enforcement on the Load Balancer further strengthens the security posture of your applications by protecting them from the common web vulnerabilities. This allows you to secure both your internet-facing as well as your internal application workloads. Enabling DDOS on Vnet of front end configurations, provides protection and defense for Azure resources against the impacts of DDoS attacks.

### Control Spec 

> **Passed:** 
> - No Virtual Network found attached in FrontEnd as well as Backend in Load Balancer.
>-  WAF is configured on Load Balancer.
> 
> **Failed:** 
> - Subnet(s) for Load Balancer must be part of a Network Security Group or AzureFirewall.
> - DDoS must be enabled on the Virtual network being used in Load balancer Backends.
> 
### Recommendation 

- **Azure Portal** 

	 To Remediate WAF on Load balancer, Enable DDOS on the Virtual Network of every frontend IP configuration or Backend Configuration of Load balancer and attach every subnet with NSG/Azure Firewall.

### Azure Policy or ARM API used for evaluation 

- ARM API to List all Load Balancers in a subscription: <br />
/subscriptions/{0}/providers/Microsoft.Network/loadBalancers?api-version=2019-12-01
 <br />
 **Properties:**<br />
properties.logs.SubnetIds, <br />

- ARM API to list all Backend Address Pools of Load Balancers: <br />
/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/loadBalancers/{2}/backendAddressPools?api-version=2022-01-01
 <br />
 **Properties:** properties.BackendVnets<br />

<br />

___ 
