﻿# ApplicationGateway

**Resource Type:** Microsoft.Network/applicationGateways

<!-- TOC -->

- [Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial](#azure_applicationgateway_netsec_enable_waf_configuration_trial)

<!-- /TOC -->
<br/>

___ 

## Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration_Trial 

### Display Name 
[Trial] Application Gateway should have Web Application Firewall configured

### Rationale 
Web application firewall configuration protects Application Gateway from internet based vulnerabilities and attacks without modification to back-end code.

### Control Spec 

> **Passed:** 
> Web Application Firewall has been configured on Application Gateway. 
> Configured WAF Policy mode must be Prevention only. 
> DDoS is enabled on the Virtual Network assoicated with the Application Gateway.
> Network Security Group is configured on the subnet assoicated with the Application Gateway.
> 
> **Failed:** 
> WAF is not configured on Application Gateway.
> Configured WAF Policy mode is not Prevention.
> DDoS is not enabled on the Virtual Network assoicated with the Application Gateway.
> Network Security Group is not configured on the subnet assoicated with the Application Gateway.
> 
> **Error:** 
> There was an error fetching WAF Configuration details of Application Gateway.
> 
### Recommendation 

- **Azure Portal** 

	 Use the Azure portal to configure WAF on the Application Gateway.

- **PowerShell** 

	 ```powershell 

	# Below commands will be useful to Configure WAF on Application Gateway
    Connect-AzAccount
	Set-AzContext -SubscriptionId "<sub id>"`
	#Get Application Gateway and existing policy object
	$appgw = Get-AzApplicationGateway -Name "applicationgatewayName" -ResourceGroupName   "RgName"
	$policy = Get-AzApplicationGatewayFirewallPolicy -Name "WAFPolicyName" -ResourceGroupName "RgName"
		
	#Attach the policy to an Application Gateway
	$appgw.FirewallPolicy = $policy		
	#Save the Application Gateway
	Set-AzApplicationGateway -ApplicationGateway $appgw

	#Below commands will be useful to configure the WAF at the listener level in the Application Gateway:  
	Connect-AzAccount
	Set-AzContext -SubscriptionId "<sub id>"`
	#Get Application Gateway, Listener and existing policy object
	$appgw = Get-AzApplicationGateway -Name "applicationgatewayName" -ResourceGroupName   "RgName"
	$policy = Get-AzApplicationGatewayFirewallPolicy -Name "WAFPolicyName" -ResourceGroupName "RgName"
	$listener = Get-AzApplicationGatewayHttpListener -Name "L1" -ApplicationGateway $appgw
	#Attach the policy to an Application Gateway Listener
	$listener.FirewallPolicy = $policy
		
	#Save the Application Gateway Listener
	Set-AzApplicationGatewayHttpListener  -FirewallPolicy  $policy -ApplicationGateway $appgw

	Below commands could be run to change the Policy Mode to Prevention mode:
	Connect-AzAccount
	Set-AzContext -SubscriptionId "<sub id>"`
	#Get Application Gateway Firewall policy
	$policy = Get-azapplicationGatewayFirewallPolicy -Name "WAFPolicyName" -ResourceGroupName "RGName"
	#Get the Policy Settings and Set the Mode to prevention
	$Policysettings = $policy.PolicySettings
	$Policysettings.Mode = "Prevention"
	#Save the WAF Policy
	Set-AzApplicationGatewayFirewallPolicy -PolicySetting $Policysettings -InputObject $policy

	Run command 
	Retrieve-ApplicationGatewayVirtualNetworkDDoSNotConfigured - to retrieve the list of Application Gateway virtual network where DDoS is not enabled.
	Run Enable-DDoSProtectionPlanOnVirtualNetwork to remediate the Virtual Network(s) retrieved from above command. 

	Run command Retrieve-ApplicationGatewaySubnetNSGNotConfigured to retrieve the list of Application Gateway subnet where NSG is not configured.
	Run Add-NSGConfigurationOnSubnet to remediate the Subnet(s) retrieved from above command. 

     # For more help run:
	 Get-Help Retrieve-ApplicationGatewayVirtualNetworkDDoSNotConfigured -Detailed
	 Get-Help Enable-DDoSProtectionPlanOnVirtualNetwork -Detailed
	 Get-Help Retrieve-ApplicationGatewaySubnetNSGNotConfigured -Detailed
	 Get-Help Add-NSGConfigurationOnSubnet -Detailed
	 ```  

### Azure Policy or ARM API used for evaluation 

- ARM API to list all Application Gateway: /subscriptions/{0}/providers/Microsoft.Network/applicationGateways?api-version=2022-01-01<br />
**Properties:** properties.rights
 <br />

<br />

___ 

