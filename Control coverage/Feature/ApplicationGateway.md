# ApplicationGateway

**Resource Type:** Microsoft.Network/applicationGateways

<!-- TOC -->

- [Azure_ApplicationGateway_NetSec_Enable_WAF_Configuration](#azure_applicationgateway_netsec_enable_waf_configuration)
- [Azure_ApplicationGateway_NetSec_Enable_DDoS_Protection](#azure_applicationGateway_netsec_enable_ddos_protection)
- [Azure_ApplicationGateway_DP_Use_Secure_TLS_Version](#Azure_ApplicationGateway_DP_Use_Secure_TLS_Version)
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
	Set-AzContext -SubscriptionId "<sub id>"
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
	Set-AzContext -SubscriptionId "<sub id>"
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

<br/>
 

## Azure_ApplicationGateway_DP_Use_Secure_TLS_Version

### Display Name 
Use approved version of TLS for AppGateways.

### Rationale 
Enabling HTTPS for Application Gateway ensures server/service authentication and protects data in transit from network layer eavesdropping attacks. TLS provides confidentiality and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions.

### Control Spec 

> **Passed:** 
> HTTPS is enabled at Listener settings of the Application Gateway. <b>AND</b>
> HTTPS is enabled at the backend settings of the Application Gateway.  <b>AND</b>
> SSL policy if being used, is set to TLS 1.2 or higher.
> 
> **Failed:** 
> HTTPS is not enabled at Listener settings of the Application Gateway. <b>OR</b>
> HTTPS is not enabled at the backend settings of the Application Gateway. <b>OR</b>
> SSL policy if being used, is not set to TLS 1.2 or higher.
> 
> **Error:** 
> There was an error fetching Configuration details of Application Gateway.
> 
### Recommendation 

- **Azure Portal** 

	 Use the Azure portal to enable HTTPs protocol for Listeners and Backend settings.Also configure SSL Policy to use TLSv1_2 as Min protocol version.Please refer below links for detailed steps:<br>
	  https://learn.microsoft.com/en-us/azure/application-gateway/end-to-end-ssl-portal <br> 
	  https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-configure-listener-specific-ssl-policy

- **PowerShell** 

	 ```powershell 

	# Below commands will be useful to configure the HTTPs at the Listener Level in the Application Gateway
    Connect-AzAccount
	Set-AzContext -SubscriptionId "<sub id>"
	#Get Application Gateway 
	$appgw = Get-AzApplicationGateway -Name "applicationgatewayName" -ResourceGroupName "RgName"
	#Remove Listener settings having HTTP protocol
	Remove-AzApplicationGatewayHttpListener -ApplicationGateway $AppGw -Name "ListnerName"	
	#Save the Application Gateway
	Set-AzApplicationGateway -ApplicationGateway $appgw

	#Adding Listener settings having HTTPs protocol
	#Get Application Gateway, FrontendIpConfiguration,FrontendPort and SslCertificate
	$appgw = Get-AzApplicationGateway -Name "applicationgatewayName" -ResourceGroupName "RgName"
	$FP01 = Get-AzApplicationGatewayFrontendPort -Name "FrontendPortName" -ApplicationGateway $AppGw
	$FIP01=  Get-AzApplicationGatewayFrontendIPConfig -Name "FrontendIPConfigName" -ApplicationGateway $AppGw
	$SSLCert01 = Get-AzApplicationGatewaySslCertificate -Name "SslCertificateName" -ApplicationGateway $AppGW
	$AppGw = Add-AzApplicationGatewayHttpListener -ApplicationGateway $AppGw -Name "ListnerName" -Protocol "Https" -FrontendIpConfiguration $FIP01 -FrontendPort $FP01 -SslCertificate $SSLCert01
	#Save the Application Gateway
	Set-AzApplicationGateway -ApplicationGateway $AppGw

	# Note: Listners setting protocol cannot be updated from HTTP to HTTPs, so delete Listener settings having HTTP protocol and add Listener settings having HTTPs protocol

	# Below commands will be useful to configure the HTTPs at the Backend Settings in the Application Gateway
	Connect-AzAccount
	Set-AzContext -SubscriptionId "<sub id>"
	#Get Application Gateway 
	$appgw = Get-AzApplicationGateway -Name "applicationgatewayName" -ResourceGroupName "RgName"
	#Update HTTP to HTTPs protocol
	$AppGw =Set-AzApplicationGatewayBackendHttpSetting -ApplicationGateway $AppGw -CookieBasedAffinity Enabled -Name 'BackendSettingName' -Port <Int32>  -Protocol https -RequestTimeout <Int32>
	#Save the Application Gateway
	Set-AzApplicationGateway -ApplicationGateway $AppGw

	# Below commands will be useful to configure TLS to 1.2 on root level in the Application Gateway
	Connect-AzAccount
	Set-AzContext -SubscriptionId "<sub id>"
	#Get Application Gateway 
	$AppGw = get-Azapplicationgateway -Name "applicationgatewayName" -ResourceGroupName "RgName"
	# Choose either custom policy or predefined policy 
	# TLS Custom Policy
	 Set-AzApplicationGatewaySslPolicy -PolicyType Custom -MinProtocolVersion TLSv1_2 -CipherSuite "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256" -ApplicationGateway $AppGw
	 # TLS Predefined Policy
	 Set-AzApplicationGatewaySslPolicy -PolicyType Predefined -PolicyName "AppGwSslPolicy20170401S" -ApplicationGateway $AppGW
	 #Save the Application Gateway
	Set-AzApplicationGateway -ApplicationGateway $AppGw

	# Below commands will be useful to configure TLS to 1.2 on SSL Profile in the Application Gateway
	Connect-AzAccount
	Set-AzContext -SubscriptionId "<sub id>"
	#Get Application Gateway 
	$AppGw = get-Azapplicationgateway -Name "applicationgatewayName" -ResourceGroupName "RgName"
	#Get SSL Policy from root level
	$sslpolicy = Get-AzApplicationGatewaySslPolicy -ApplicationGateway $AppGW
	$AppGw = set-AzApplicationGatewaySslProfile -ApplicationGateway $AppGw -Name "SSLProfileName" -SslPolicy $sslpolicy
	 #Save the Application Gateway
	Set-AzApplicationGateway -ApplicationGateway $AppGw

	#Note :1) To configure TLS on SSL Profile, TLS must be set on root level 
	#2)If you're using a custom SSL policy in Application Gateway v1 SKU (Standard or WAF), make sure that you add the mandatory cipher "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" to the list. This cipher is required to enable metrics and logging in the Application Gateway v1 SKU. This is not mandatory for Application Gateway v2 SKU (Standard_v2 or WAF_v2)

     
	 ```  

### Azure Policy or ARM API used for evaluation 

- ARM API to list all Application Gateway: /subscriptions/{subscriptionId}/providers/Microsoft.Network/applicationGateways?api-version=2022-01-01<br />
- ARM API to list all SSL Options predefined policies in Application Gateway: /subscriptions/{0}/providers/Microsoft.Network/applicationGatewayAvailableSslOptions/default/predefinedPolicies?api-version=2022-09-01
<br />

___ 

