# ApplicationGateway

**Resource Type:** Microsoft.Network/applicationGateways

<!-- TOC -->

- [Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration](#azure_applicationgateway_netsec_enable_waf_configuration)
- [Azure_ApplicationGateway_NetSec_Enable_DDoS_Protection](#azure_applicationGateway_netsec_enable_ddos_protection)

<!-- /TOC -->
<br/>

___ 

## Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration 

### Display Name 
Application Gateway should have Web Application Firewall configured

### Rationale 
Web application firewall configuration protects Application Gateway from internet based vulnerabilities and attacks without modification to back-end code.

### Control Spec 

> **Passed:** 
> Web Application Firewall has been configured on Application Gateway. <b>AND</b>
> Configured WAF Policy mode must be in Prevention only. <b>AND</b>
> Network Security Group is configured on the subnet assoicated with the Application Gateway. 
> 
> **Failed:** 
> WAF is not configured on Application Gateway. <b>OR</b>
> Configured WAF Policy mode is not Prevention. <b>OR</b>
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

	Run Add-NSGConfigurationOnSubnet to configure the Network Security Group on the Subnet(s) being used in the Application Gateway. 

     # For more help run:
	 Get-Help Add-NSGConfigurationOnSubnet -Detailed
	 ```  

### Azure Policy or ARM API used for evaluation 

- ARM API to list all Application Gateway: /subscriptions/{subscriptionId}/providers/Microsoft.Network/applicationGateways?api-version=2022-01-01<br />

- ARM API to list all Web Application Firewall Policies of type Application Gateway: /subscriptions/{subscriptionId}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies?api-version=2022-01-01<br />

**Properties:** properties.rights
 <br />

<br />

## Azure_ApplicationGateway_NetSec_Enable_DDoS_Protection 

### Display Name 
Protect Internet First Applications with Azure AppGateway and DDoS Protection

### Rationale 
Enabling DDOS on Vnet of Application Gateway, provides protection and defense for Azure resources against the impacts of DDoS attacks

### Control Spec 

> **Passed:** 
>  DDoS Protection Plan is configured on the Virtual Network of Application Gateway.
> 
> **Failed:** 
> DDoS Protection Plan is not configured on the Virtual Network of Application Gateway.
> 
### Recommendation 

- **Azure Portal** 

 Enable the DDOS on the associated Virtual Network being used in App Gateway.Refer [link](https://learn.microsoft.com/en-us/azure/ddos-protection/manage-ddos-protection#enable-ddos-protection-for-an-existing-virtual-network).


### Azure Policy or ARM API used for evaluation 

- ARM API to list all Application Gateway: /subscriptions/{subscriptionId}/providers/Microsoft.Network/applicationGateways?api-version=2022-01-01<br />

- ARM API to get propoerties of associated Virtual Network: /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01<br />

**Properties:** properties.enableDdosProtection
 <br />

___ 

