# LoadBalancer

**Resource Type:** Microsoft.Network/loadBalancers 

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_LoadBalancer_NetSec_Enable_WAF_And_DDoS_Protection_Trial](#Azure_LoadBalancer_NetSec_Enable_WAF_And_DDoS_Protection_Trial)

<!-- /TOC -->
<br/>

___ 

## Azure_LoadBalancer_NetSec_Enable_WAF_And_DDoS_Protection_Trial 

### Display Name 
[Trial] Load Balancer should have Web Application Firewall (WAF) and DDoS configured

### Rationale 
WAF enforcement on the Load Balancer further strengthens the security posture of your applications by protecting them from the common web vulnerabilities. This allows you to secure both your internet-facing as well as your internal application workloads. Enabling DDOS on Vnet of front end configurations and Backends, provides protection and defense for Azure resources against the impacts of DDoS attacks.

### Control Spec 

> **Passed:** 
> 1. Web Application Firewall has been configured on Load Balancer. 
> 2. DDoS is enabled on the Virtual Network assoicated with the Load Balancer.
> 3. Network Security Group is configured on the subnets assoicated with the Load Balancer.
> 
> **Failed:** 
>1. Web Application Firewall is not configured on Load Balancer.
>2.  DDoS is not enabled on the Virtual Network assoicated with the Load Balancer.
>3. Network Security Group is not configured on the subnets assoicated with the Load Balancer.
> 
> **Error:** 
>There was an error fetching WAF Configuration details of Load Balancer.
 
 

### Recommendation
- **Azure Portal** 

	 To Remediate WAF on Load balancer, Enable DDOS on the Virtual Network of every frontend IP configuration and Backend Configuration of Load balancer and attach every subnet with NSG/Azure Firewall.

- **PowerShell** 

	Run command :
		
		Run Retrieve -LoadBalancerVirtualNetworkDDoSNotConfigured
		to retrieve the list of Load Balancer virtual network where DDoS is not enabled.
		
		Run Enable-DDoSProtectionPlanOnVirtualNetwork to remediate the Virtual Network(s) retrieved from above command. 
	Run command : 
		
		Retrieve-LoadBalancerSubnetNSGNotConfigured to retrieve the list of LoadBalancer subnet where NSG is not configured.
		
		Run Add-NSGConfigurationOnSubnet to remediate the Subnet(s) retrieved from above command. 			   			
		

	# For more help run:
	 	Get-Help Retrieve-LoadBalancerVirtualNetworkDDoSNotConfigured -Detailed
	 	Get-Help Enable-DDoSProtectionPlanOnVirtualNetwork -Detailed
	 	Get-Help Retrieve-LoadBalancerSubnetNSGNotConfigured -Detailed
	 	Get-Help Add-NSGConfigurationOnSubnet -Detailed

### Azure Policy or ARM API used for evaluation 

- ARM API to list FrontendIP Configuration at Subscription level: /subscriptions/{0}/providers/Microsoft.Network/loadBalancers?api-version=2019-12-01<br />
**Properties:** properties.SubnetIds <br />

- ARM API to list Backend Configuration of LoadBalancer: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/loadBalancers/{2}/backendAddressPools?api-version=2022-01-01 <br />
**Properties:** properties.BackendVnets<br />

<br />

___ 

