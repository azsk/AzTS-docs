# TrafficManager

**Resource Type:** Microsoft.Network/TrafficManager

<!-- TOC -->

- [Azure_TrafficManager_DP_Enable_HTTPS](#azure_trafficmanager_dp_enable_https)

<!-- /TOC -->
<br/>


___ 

## Azure_TrafficManager_DP_Enable_HTTPS 

### Display Name 
Traffic Manager profile should use HTTPS protocol for endpoint monitoring 

### Rationale 
Use of HTTPS ensures server/service authentication and protects data in transit from network layer man-in-the-middle, eavesdropping, session-hijacking attacks. 

### Control Spec 

> **Passed:** 
> 1. No endpoints are present in the traffic manager profile.
> 2. All endpoints are disabled
> 3. Endpoints are enabled with HTTPS protocol.
> 
> **Failed:** 
> Endpoints are enabled without HTTPS protocol.
> <!--
> **Verify:** 
> Verify condition
> -->
> **NotApplicable:** 
> TCP protocol is enabled for endpoint monitoring.
> 
### Recommendation 

- **Azure Portal** 

	 To enable HTTPS protocol for endpoint monitoring, go to Azure Portal --> your Traffic Manager Profile --> Configuration --> Select HTTPS --> Save. 
<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policies or REST APIs used for evaluation 

- ARM API to lists all Traffic Manager profiles within a subscription:
/subscriptions/{subscriptionId}/providers/Microsoft.Network/trafficmanagerprofiles?api-version=2018-04-01<br />
**Properties:** properties.endpoints[*],
 properties.monitorConfig.protocol
 <br />
<!--
- Example-2 ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />
-->
<br />

___ 

